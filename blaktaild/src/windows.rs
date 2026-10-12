//! Windows userspace tunnel. WinTun carries plaintext packets. boringtun, via
//! the shared C ABI, turns them into WireGuard ciphertext on a UDP socket.
//!
//! Addresses and per-peer routes are set with the IP Helper API on the
//! adapter's LUID, kept in step with `apply`, and removed on teardown. Two
//! threads move packets: one blocks on WinTun's read-wait event (with the
//! session's shutdown event), the other on the UDP socket with a short
//! timeout that also drives WireGuard timers, so an idle tunnel uses no CPU.

use crate::{peer_key_hex, Error, Network, Peer, PeerChange};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2,
    DeleteUnicastIpAddressEntry, FreeMibTable, GetIpForwardTable2, GetIpInterfaceEntry,
    GetUnicastIpAddressTable, InitializeIpForwardEntry, InitializeIpInterfaceEntry,
    InitializeUnicastIpAddressEntry, SetIpInterfaceEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::Networking::WinSock::{
    IpDadStatePreferred, IpPrefixOriginManual, AF_INET, AF_INET6, AF_UNSPEC, MIB_IPPROTO_NETMGMT,
    SOCKADDR_INET,
};

extern "C" {
    fn blaktail_tunnel_create(private_key: *const u8) -> *mut c_void;
    fn blaktail_tunnel_free(tunnel: *mut c_void);
    fn blaktail_tunnel_add_peer(
        tunnel: *mut c_void,
        public_key: *const u8,
        allowed_ips: *const std::ffi::c_char,
        keepalive_seconds: u16,
    ) -> i32;
    fn blaktail_tunnel_remove_peer(tunnel: *mut c_void, public_key: *const u8) -> i32;
    fn blaktail_tunnel_encapsulate(
        tunnel: *mut c_void,
        src: *const u8,
        src_len: usize,
        dst: *mut u8,
        dst_cap: usize,
        dst_len: *mut usize,
        peer_public_out: *mut u8,
    ) -> i32;
    fn blaktail_tunnel_decapsulate(
        tunnel: *mut c_void,
        src: *const u8,
        src_len: usize,
        dst: *mut u8,
        dst_cap: usize,
        dst_len: *mut usize,
        peer_public_out: *mut u8,
    ) -> i32;
    fn blaktail_tunnel_last_handshake(tunnel: *mut c_void, public_key: *const u8) -> u64;
    fn blaktail_tunnel_peer_stats(
        tunnel: *mut c_void,
        public_key: *const u8,
        handshake_unix: *mut u64,
        tx_bytes: *mut u64,
        rx_bytes: *mut u64,
    ) -> i32;
    fn blaktail_tunnel_update_timers(
        tunnel: *mut c_void,
        dst: *mut u8,
        dst_cap: usize,
        dst_len: *mut usize,
        peer_public_out: *mut u8,
    ) -> i32;
}

/// The engine pointer, shared by the packet threads. The engine serialises
/// every call behind its own mutex.
#[derive(Clone, Copy)]
struct RawTunnel(*mut c_void);
unsafe impl Send for RawTunnel {}
unsafe impl Sync for RawTunnel {}

const WRITE_NETWORK: i32 = 1;
const WRITE_TUNNEL: i32 = 2;
const KEEPALIVE_SECONDS: u16 = 25;
/// WireGuard timers (handshake retry, keepalive, rekey) need a tick a few
/// times a second, not a busy loop.
const TIMER_TICK: Duration = Duration::from_millis(250);
/// WinTun ring size per direction.
const RING_CAPACITY: u32 = 0x40_0000;
/// Upper bound on timer packets drained per tick.
const MAX_TIMER_PACKETS: usize = 256;
/// Per-peer status lines after the first handshake, at most this often.
const STATUS_LOG_INTERVAL: Duration = Duration::from_secs(600);
const WINTUN_VERSION: &str = "0.14.1";

type Endpoints = Arc<Mutex<HashMap<[u8; 32], SocketAddr>>>;

pub struct WindowsNetwork {
    /// Engine pointer; null until `setup`.
    tunnel: RawTunnel,
    /// Full peer set: `apply` receives diffs.
    peers: Vec<Peer>,
    endpoints: Endpoints,
    listen: Option<SocketAddr>,
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
    session: Option<Arc<wintun::Session>>,
    adapter: Option<Arc<wintun::Adapter>>,
    /// Interface LUID, zero until the adapter exists.
    luid: u64,
    guid: u128,
    interface: String,
    /// Addresses (CIDR) this agent put on the adapter.
    addresses: Vec<String>,
    /// Peer routes this agent added.
    routes: BTreeSet<String>,
    /// When each peer was last reported in the log, by public key.
    reported: HashMap<[u8; 32], Instant>,
}

impl Default for WindowsNetwork {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsNetwork {
    pub fn new() -> Self {
        Self {
            tunnel: RawTunnel(std::ptr::null_mut()),
            peers: Vec::new(),
            endpoints: Arc::new(Mutex::new(HashMap::new())),
            listen: None,
            stop: Arc::new(AtomicBool::new(false)),
            workers: Vec::new(),
            session: None,
            adapter: None,
            luid: 0,
            guid: 0,
            interface: String::new(),
            addresses: Vec::new(),
            routes: BTreeSet::new(),
            reported: HashMap::new(),
        }
    }

    fn raw(&self) -> Result<*mut c_void, Error> {
        if self.tunnel.0.is_null() {
            Err(Error::Message("windows tunnel is not open".into()))
        } else {
            Ok(self.tunnel.0)
        }
    }

    /// Removes routes, addresses and the adapter, and frees the engine.
    /// Safe to call more than once.
    fn teardown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(session) = &self.session {
            // Wakes the WinTun reader blocked on its read-wait event.
            let _ = session.shutdown();
        }
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
        if self.luid != 0 {
            for route in std::mem::take(&mut self.routes) {
                if let Err(error) = delete_route(self.luid, &route) {
                    warn!(%route, %error, "could not remove WinTun route");
                }
            }
            for address in std::mem::take(&mut self.addresses) {
                if let Err(error) = delete_address(self.luid, &address) {
                    warn!(%address, %error, "could not remove WinTun address");
                }
            }
        }
        self.session = None;
        if self.adapter.take().is_some() {
            info!(interface = %self.interface, "WinTun adapter removed");
        }
        self.luid = 0;
        if !self.tunnel.0.is_null() {
            unsafe { blaktail_tunnel_free(self.tunnel.0) };
            self.tunnel = RawTunnel(std::ptr::null_mut());
        }
        self.peers.clear();
        self.reported.clear();
        if let Ok(mut endpoints) = self.endpoints.lock() {
            endpoints.clear();
        }
        self.listen = None;
    }

    fn reconcile_routes(&mut self) -> Result<(), Error> {
        if self.luid == 0 {
            return Ok(());
        }
        // Exit routes are Linux-only, as on macOS.
        let desired: BTreeSet<String> = self
            .peers
            .iter()
            .flat_map(|peer| peer.allowed_ips.iter())
            .filter(|route| route.as_str() != "0.0.0.0/0" && route.as_str() != "::/0")
            .filter_map(|route| normalise_cidr(route))
            .collect();
        let stale: Vec<String> = self.routes.difference(&desired).cloned().collect();
        for route in stale {
            delete_route(self.luid, &route)?;
            self.routes.remove(&route);
        }
        let missing: Vec<String> = desired.difference(&self.routes).cloned().collect();
        for route in missing {
            add_route(self.luid, &route)?;
            self.routes.insert(route);
        }
        Ok(())
    }

    fn reconcile_addresses(&mut self, addresses: &[String]) -> Result<(), Error> {
        let desired: Vec<(IpAddr, u8)> = addresses
            .iter()
            .map(|address| parse_cidr(address))
            .collect::<Result<_, _>>()?;
        // Anything manual on the adapter that is not wanted goes, including
        // a renumbered address and leftovers from an earlier run.
        for (ip, prefix) in manual_addresses(self.luid)? {
            if !desired.contains(&(ip, prefix)) {
                delete_address(self.luid, &format!("{ip}/{prefix}"))?;
            }
        }
        for (ip, prefix) in &desired {
            add_address(self.luid, *ip, *prefix)?;
        }
        self.addresses = desired
            .iter()
            .map(|(ip, prefix)| format!("{ip}/{prefix}"))
            .collect();
        Ok(())
    }

    fn log_peer_status(&mut self, raw: *mut c_void) {
        for peer in &self.peers {
            let Ok(key) = decode_key(&peer.wg_public_key) else {
                continue;
            };
            let Some((handshake, tx, rx)) = peer_stats(raw, &key) else {
                continue;
            };
            debug!(peer = %peer.name, handshake, tx_bytes = tx, rx_bytes = rx, "WireGuard peer counters");
            if handshake == 0 {
                continue;
            }
            match self.reported.get(&key) {
                None => {
                    info!(
                        peer = %peer.name,
                        handshake,
                        tx_bytes = tx,
                        rx_bytes = rx,
                        "WireGuard handshake completed"
                    );
                }
                Some(at) if at.elapsed() >= STATUS_LOG_INTERVAL => {
                    info!(
                        peer = %peer.name,
                        handshake,
                        tx_bytes = tx,
                        rx_bytes = rx,
                        "WireGuard peer status"
                    );
                }
                Some(_) => continue,
            }
            self.reported.insert(key, Instant::now());
        }
    }
}

impl Drop for WindowsNetwork {
    fn drop(&mut self) {
        self.teardown();
    }
}

impl Network for WindowsNetwork {
    fn setup(&mut self, interface: &str, key: &Path, addresses: &[String]) -> Result<(), Error> {
        self.teardown();
        self.stop.store(false, Ordering::SeqCst);
        self.interface = interface.to_owned();
        let encoded = std::fs::read_to_string(key)?;
        let private = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .map_err(|_| Error::Message("private key file is not valid base64".into()))?;
        if private.len() != 32 {
            return Err(Error::Message("private key must be 32 bytes".into()));
        }

        let library = load_wintun()?;
        self.guid = adapter_guid(interface);
        let adapter = wintun::Adapter::create(&library, interface, "BlakTail", Some(self.guid))
            .map_err(|error| {
                Error::Message(format!(
                    "could not create the WinTun adapter {interface}: {error} (is another blaktaild using this interface name? Run elevated: an administrator or the BlakTail service)"
                ))
            })?;
        self.luid = unsafe { adapter.get_luid().Value };
        self.adapter = Some(adapter.clone());
        // An adapter recreated with the same GUID can carry routes from a
        // run that ended without teardown.
        flush_routes(self.luid);
        set_mtu(self.luid, crate::TUNNEL_MTU_BYTES as u32);
        self.reconcile_addresses(addresses)?;

        let raw = unsafe { blaktail_tunnel_create(private.as_ptr()) };
        if raw.is_null() {
            return Err(Error::Message(
                "could not create the Windows WireGuard engine".into(),
            ));
        }
        self.tunnel = RawTunnel(raw);

        let udp = UdpSocket::bind("0.0.0.0:0").map_err(|error| {
            Error::Message(format!("could not bind Windows UDP socket: {error}"))
        })?;
        udp.set_read_timeout(Some(TIMER_TICK))
            .map_err(|error| Error::Message(format!("UDP socket timeout: {error}")))?;
        // Relay injection matches the loopback source kernel and userspace
        // WireGuard use when the peer endpoint is 127.0.0.1.
        self.listen = udp
            .local_addr()
            .ok()
            .map(|bound| SocketAddr::from((Ipv4Addr::LOCALHOST, bound.port())));

        let session = Arc::new(adapter.start_session(RING_CAPACITY).map_err(|error| {
            Error::Message(format!("could not start the WinTun session: {error}"))
        })?);
        self.session = Some(session.clone());
        let udp = Arc::new(udp);
        let tunnel = self.tunnel;
        let inbound = {
            let (session, udp, stop, endpoints) = (
                session.clone(),
                udp.clone(),
                self.stop.clone(),
                self.endpoints.clone(),
            );
            thread::Builder::new()
                .name("blaktail-tun-read".into())
                .spawn(move || tun_to_network(tunnel, &session, &udp, &stop, &endpoints))
        };
        let outbound = {
            let (stop, endpoints) = (self.stop.clone(), self.endpoints.clone());
            thread::Builder::new()
                .name("blaktail-udp-read".into())
                .spawn(move || network_to_tun(tunnel, &session, &udp, &stop, &endpoints))
        };
        for worker in [inbound, outbound] {
            self.workers.push(worker.map_err(|error| {
                Error::Message(format!("could not start packet thread: {error}"))
            })?);
        }
        info!(
            interface,
            luid = self.luid,
            addresses = %self.addresses.join(","),
            listen = ?self.listen,
            "WinTun adapter up"
        );
        Ok(())
    }

    fn set_addresses(&mut self, _interface: &str, addresses: &[String]) -> Result<(), Error> {
        if self.luid == 0 {
            return Err(Error::Message("windows tunnel is not open".into()));
        }
        self.reconcile_addresses(addresses)
    }

    fn apply(&mut self, _interface: &str, changes: &[PeerChange]) -> Result<(), Error> {
        let raw = self.raw()?;
        {
            let mut endpoints = self
                .endpoints
                .lock()
                .map_err(|_| Error::Message("endpoint lock poisoned".into()))?;
            for change in changes {
                match change {
                    PeerChange::Remove(key) => {
                        self.peers.retain(|p| &p.wg_public_key != key);
                        if let Ok(key) = decode_key(key) {
                            endpoints.remove(&key);
                            self.reported.remove(&key);
                            unsafe { blaktail_tunnel_remove_peer(raw, key.as_ptr()) };
                        }
                    }
                    PeerChange::Upsert(peer) => {
                        let public = decode_key(&peer.wg_public_key)?;
                        let existing = self
                            .peers
                            .iter_mut()
                            .find(|p| p.wg_public_key == peer.wg_public_key);
                        // Only a new peer or changed allowed IPs rebuilds the
                        // engine's peer; that drops its session.
                        let rebuild = existing
                            .as_ref()
                            .is_none_or(|current| current.allowed_ips != peer.allowed_ips);
                        match existing {
                            Some(current) => *current = peer.clone(),
                            None => self.peers.push(peer.clone()),
                        }
                        if rebuild {
                            add_peer(raw, &public, peer)?;
                        }
                        // Same as `wg set ... endpoint` on Linux: the
                        // coordinator's endpoint is where packets go.
                        if let Some(endpoint) = peer
                            .endpoint
                            .as_deref()
                            .and_then(|endpoint| endpoint.parse::<SocketAddr>().ok())
                        {
                            endpoints.insert(public, endpoint);
                        }
                    }
                }
            }
        }
        self.reconcile_routes()
    }

    fn down(&mut self, _interface: &str) -> Result<(), Error> {
        // The adapter belongs to the process that created it (WinTun removes
        // it when that process exits), so only the owning agent can remove it.
        self.teardown();
        Ok(())
    }

    fn set_peer_endpoint(
        &mut self,
        _interface: &str,
        peer_key_b64: &str,
        endpoint: &str,
    ) -> Result<(), Error> {
        let key = decode_key(peer_key_b64)?;
        let address: SocketAddr = endpoint
            .parse()
            .map_err(|_| Error::Message(format!("peer endpoint {endpoint} is invalid")))?;
        self.endpoints
            .lock()
            .map_err(|_| Error::Message("endpoint lock poisoned".into()))?
            .insert(key, address);
        Ok(())
    }

    fn latest_handshakes(&mut self, _interface: &str) -> Result<HashMap<String, u64>, Error> {
        let raw = self.raw()?;
        let mut out = HashMap::new();
        for peer in &self.peers {
            let Ok(key) = decode_key(&peer.wg_public_key) else {
                continue;
            };
            // The completed handshake, or failing that the last decrypted
            // packet (both mean the peer is answering).
            let stamp = peer_stats(raw, &key)
                .map(|(handshake, _, _)| handshake)
                .filter(|stamp| *stamp > 0)
                .unwrap_or_else(|| unsafe { blaktail_tunnel_last_handshake(raw, key.as_ptr()) });
            if stamp > 0 {
                if let Some(hex) = peer_key_hex(&peer.wg_public_key) {
                    out.insert(hex, stamp);
                }
            }
        }
        self.log_peer_status(raw);
        Ok(out)
    }

    /// Inbound policy for the shared userspace filter, which sits between
    /// decrypt and the WinTun write inside the dataplane.
    fn apply_ingress(&mut self, _interface: &str, peers: &[Peer]) -> Result<(), Error> {
        let raw = self.raw()?;
        let policy_peers: Vec<blaktail_ios_wg::filter::PolicyPeer> = serde_json::to_value(peers)
            .and_then(serde_json::from_value)
            .map_err(|error| Error::Message(format!("filter policy: {error}")))?;
        let policy = blaktail_ios_wg::filter::Policy::compile(&policy_peers, None);
        unsafe { blaktail_ios_wg::filter::set_policy(raw.cast(), policy) };
        Ok(())
    }

    fn inbound_filter_active(&self) -> bool {
        self.raw().is_ok()
    }

    fn set_traffic(&mut self, _interface: &str, enabled: bool) {
        if let Ok(raw) = self.raw() {
            unsafe { blaktail_ios_wg::filter::set_traffic(raw.cast(), enabled) };
        }
    }

    fn flow_events(
        &mut self,
        _interface: &str,
        _scope: &crate::flow_capture::Scope,
    ) -> Vec<crate::flow_events::FlowEvent> {
        self.raw()
            .ok()
            .and_then(|raw| unsafe { blaktail_ios_wg::filter::take_events(raw.cast()) })
            .map(|(_, events)| events)
            .unwrap_or_default()
    }

    fn traffic_counts(
        &mut self,
        _interface: &str,
        _peers: &[Peer],
    ) -> Result<Vec<crate::flow_report::FlowCount>, Error> {
        let raw = self.raw()?;
        Ok(unsafe { blaktail_ios_wg::filter::take_report(raw.cast()) }
            .map(|report| report.flow_counts())
            .unwrap_or_default())
    }

    fn listen_endpoint(&mut self, _interface: &str) -> Result<Option<SocketAddr>, Error> {
        Ok(self.listen)
    }
}

/// A stable adapter GUID per interface name, so Windows keeps one network
/// profile per BlakTail interface instead of a new one on every start.
fn adapter_guid(interface: &str) -> u128 {
    let digest = Sha256::digest(format!("BlakTail WinTun adapter {interface}").as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // RFC 4122 variant, version 5 (name-based) layout.
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    u128::from_be_bytes(bytes)
}

fn load_wintun() -> Result<wintun::Wintun, Error> {
    // Only the copy beside the executable is loaded, never one found on PATH
    // or in the working directory.
    let path = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("wintun.dll")))
        .unwrap_or_else(|| PathBuf::from("wintun.dll"));
    if !path.is_file() {
        return Err(Error::Message(format!(
            "wintun.dll was not found at {}. Download WinTun {WINTUN_VERSION} from https://www.wintun.net (or run packaging\\windows\\fetch-wintun.ps1), and copy bin\\{}\\wintun.dll beside blaktaild.exe",
            path.display(),
            wintun_arch()
        )));
    }
    unsafe { wintun::load_from_path(&path) }.map_err(|error| {
        Error::Message(format!(
            "could not load {}: {error}. It must be the {} build of WinTun {WINTUN_VERSION}",
            path.display(),
            wintun_arch()
        ))
    })
}

fn wintun_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "x86",
        "arm" => "arm",
        other => other,
    }
}

fn decode_key(peer_key_b64: &str) -> Result<[u8; 32], Error> {
    base64::engine::general_purpose::STANDARD
        .decode(peer_key_b64.trim())
        .map_err(|_| Error::Message("peer key is not valid base64".into()))?
        .try_into()
        .map_err(|_| Error::Message("peer key must be 32 bytes".into()))
}

fn add_peer(raw: *mut c_void, public: &[u8; 32], peer: &Peer) -> Result<(), Error> {
    let allowed = std::ffi::CString::new(peer.allowed_ips.join(","))
        .map_err(|_| Error::Message("peer allowed IPs contain a null".into()))?;
    let code = unsafe {
        blaktail_tunnel_add_peer(raw, public.as_ptr(), allowed.as_ptr(), KEEPALIVE_SECONDS)
    };
    if code < 0 {
        return Err(Error::Message(format!(
            "could not add Windows peer {}",
            peer.name
        )));
    }
    Ok(())
}

fn peer_stats(raw: *mut c_void, key: &[u8; 32]) -> Option<(u64, u64, u64)> {
    let (mut handshake, mut tx, mut rx) = (0u64, 0u64, 0u64);
    let code =
        unsafe { blaktail_tunnel_peer_stats(raw, key.as_ptr(), &mut handshake, &mut tx, &mut rx) };
    (code == 0).then_some((handshake, tx, rx))
}

// ---------------------------------------------------------------------------
// Packet threads
// ---------------------------------------------------------------------------

fn send_to_peer(udp: &UdpSocket, endpoints: &Endpoints, peer: &[u8; 32], packet: &[u8]) {
    if let Some(endpoint) = endpoints.lock().ok().and_then(|map| map.get(peer).copied()) {
        let _ = udp.send_to(packet, endpoint);
    }
}

/// Plaintext from Windows → ciphertext to peers. Sleeps on the WinTun
/// read-wait event; `Session::shutdown` wakes it to exit.
fn tun_to_network(
    tunnel: RawTunnel,
    session: &Arc<wintun::Session>,
    udp: &UdpSocket,
    stop: &AtomicBool,
    endpoints: &Endpoints,
) {
    let mut cipher = vec![0u8; 65_536 + 32];
    while !stop.load(Ordering::Relaxed) {
        let packet = match session.receive_blocking() {
            Ok(packet) => packet,
            Err(_) => break,
        };
        let mut length = 0usize;
        let mut peer = [0u8; 32];
        let code = unsafe {
            let bytes = packet.bytes();
            blaktail_tunnel_encapsulate(
                tunnel.0,
                bytes.as_ptr(),
                bytes.len(),
                cipher.as_mut_ptr(),
                cipher.len(),
                &mut length,
                peer.as_mut_ptr(),
            )
        };
        drop(packet);
        if code == WRITE_NETWORK {
            send_to_peer(udp, endpoints, &peer, &cipher[..length]);
        }
    }
}

/// Ciphertext from peers → plaintext to Windows, plus WireGuard timers.
/// Blocks on the socket for at most one timer tick.
fn network_to_tun(
    tunnel: RawTunnel,
    session: &Arc<wintun::Session>,
    udp: &UdpSocket,
    stop: &AtomicBool,
    endpoints: &Endpoints,
) {
    let mut received = vec![0u8; 65_536];
    let mut plain = vec![0u8; 65_536];
    let mut cipher = vec![0u8; 2_048];
    let mut next_tick = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        // An error is either the timeout (the timer tick) or Windows
        // reporting an ICMP port-unreachable for an earlier send
        // (WSAECONNRESET); neither stops the tunnel.
        if let Ok((count, source)) = udp.recv_from(&mut received) {
            decapsulate(tunnel, udp, session, &mut plain, &received[..count], source);
        }
        if Instant::now() >= next_tick {
            next_tick = Instant::now() + TIMER_TICK;
            for _ in 0..MAX_TIMER_PACKETS {
                let mut length = 0usize;
                let mut peer = [0u8; 32];
                let code = unsafe {
                    blaktail_tunnel_update_timers(
                        tunnel.0,
                        cipher.as_mut_ptr(),
                        cipher.len(),
                        &mut length,
                        peer.as_mut_ptr(),
                    )
                };
                if code != WRITE_NETWORK {
                    break;
                }
                send_to_peer(udp, endpoints, &peer, &cipher[..length]);
            }
        }
    }
}

fn decapsulate(
    tunnel: RawTunnel,
    udp: &UdpSocket,
    session: &Arc<wintun::Session>,
    plain: &mut [u8],
    initial: &[u8],
    source: SocketAddr,
) {
    let mut incoming: &[u8] = initial;
    loop {
        let mut length = 0usize;
        let mut peer = [0u8; 32];
        let code = unsafe {
            blaktail_tunnel_decapsulate(
                tunnel.0,
                if incoming.is_empty() {
                    std::ptr::null()
                } else {
                    incoming.as_ptr()
                },
                incoming.len(),
                plain.as_mut_ptr(),
                plain.len(),
                &mut length,
                peer.as_mut_ptr(),
            )
        };
        match code {
            // Handshake responses, cookies, and packets queued while the
            // handshake was in flight: keep draining until the engine is done.
            WRITE_NETWORK => {
                let _ = udp.send_to(&plain[..length], source);
            }
            WRITE_TUNNEL => {
                if let Ok(size) = u16::try_from(length) {
                    if let Ok(mut outgoing) = session.allocate_send_packet(size) {
                        outgoing.bytes_mut().copy_from_slice(&plain[..length]);
                        session.send_packet(outgoing);
                    }
                }
            }
            _ => break,
        }
        incoming = &[];
    }
}

// ---------------------------------------------------------------------------
// IP Helper: addresses, routes and MTU on the adapter LUID
// ---------------------------------------------------------------------------

fn win32(code: u32, what: &str) -> Result<(), Error> {
    if code == 0 {
        Ok(())
    } else {
        Err(Error::Message(format!(
            "{what}: {}",
            std::io::Error::from_raw_os_error(code as i32)
        )))
    }
}

fn parse_cidr(value: &str) -> Result<(IpAddr, u8), Error> {
    let (ip, prefix) = value
        .split_once('/')
        .ok_or_else(|| Error::Message(format!("address {value} must use CIDR notation")))?;
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| Error::Message(format!("address {value} is invalid")))?;
    let prefix: u8 = prefix
        .parse()
        .ok()
        .filter(|bits| *bits <= if ip.is_ipv4() { 32 } else { 128 })
        .ok_or_else(|| Error::Message(format!("prefix in {value} is invalid")))?;
    Ok((ip, prefix))
}

/// The network form of a CIDR (host bits cleared), as Windows stores routes.
fn normalise_cidr(value: &str) -> Option<String> {
    let (ip, prefix) = parse_cidr(value).ok()?;
    let network = match ip {
        IpAddr::V4(v4) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
        }
        IpAddr::V6(v6) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
    };
    Some(format!("{network}/{prefix}"))
}

fn sockaddr(ip: IpAddr) -> SOCKADDR_INET {
    let mut address = SOCKADDR_INET::default();
    match ip {
        IpAddr::V4(v4) => {
            address.Ipv4.sin_family = AF_INET;
            address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
        }
        IpAddr::V6(v6) => {
            address.Ipv6.sin6_family = AF_INET6;
            address.Ipv6.sin6_addr.u.Byte = v6.octets();
        }
    }
    address
}

fn from_sockaddr(address: &SOCKADDR_INET) -> Option<IpAddr> {
    unsafe {
        match address.si_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
                address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
            ))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(address.Ipv6.sin6_addr.u.Byte))),
            _ => None,
        }
    }
}

fn add_address(luid: u64, ip: IpAddr, prefix: u8) -> Result<(), Error> {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid.Value = luid;
    row.Address = sockaddr(ip);
    row.OnLinkPrefixLength = prefix;
    // No duplicate address detection on a point-to-point tunnel, so the
    // address is usable (and MagicDNS can bind) at once.
    row.DadState = IpDadStatePreferred;
    let code = unsafe { CreateUnicastIpAddressEntry(&row) };
    if code == ERROR_OBJECT_ALREADY_EXISTS {
        return Ok(());
    }
    win32(
        code,
        &format!("could not assign {ip}/{prefix} on the WinTun adapter"),
    )
}

fn delete_address(luid: u64, cidr: &str) -> Result<(), Error> {
    let (ip, _) = parse_cidr(cidr)?;
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid.Value = luid;
    row.Address = sockaddr(ip);
    let code = unsafe { DeleteUnicastIpAddressEntry(&row) };
    if code == ERROR_NOT_FOUND || code == windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    win32(
        code,
        &format!("could not remove {cidr} from the WinTun adapter"),
    )
}

/// Manually assigned (not link-local or autoconfigured) addresses on the
/// adapter, with their prefix lengths.
fn manual_addresses(luid: u64) -> Result<Vec<(IpAddr, u8)>, Error> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    win32(
        unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) },
        "could not list interface addresses",
    )?;
    let mut out = Vec::new();
    unsafe {
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        for row in rows {
            if row.InterfaceLuid.Value == luid && row.PrefixOrigin == IpPrefixOriginManual {
                if let Some(ip) = from_sockaddr(&row.Address) {
                    out.push((ip, row.OnLinkPrefixLength));
                }
            }
        }
        FreeMibTable(table.cast());
    }
    Ok(out)
}

fn route_row(luid: u64, cidr: &str) -> Result<MIB_IPFORWARD_ROW2, Error> {
    let (ip, prefix) = parse_cidr(cidr)?;
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid.Value = luid;
    row.DestinationPrefix.Prefix = sockaddr(ip);
    row.DestinationPrefix.PrefixLength = prefix;
    // On-link: the next hop is the unspecified address of the same family.
    row.NextHop = sockaddr(match ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    });
    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    Ok(row)
}

fn add_route(luid: u64, cidr: &str) -> Result<(), Error> {
    let row = route_row(luid, cidr)?;
    let code = unsafe { CreateIpForwardEntry2(&row) };
    if code == ERROR_OBJECT_ALREADY_EXISTS {
        return Ok(());
    }
    win32(
        code,
        &format!("could not add route {cidr} via the WinTun adapter"),
    )
}

fn delete_route(luid: u64, cidr: &str) -> Result<(), Error> {
    let row = route_row(luid, cidr)?;
    let code = unsafe { DeleteIpForwardEntry2(&row) };
    if code == ERROR_NOT_FOUND || code == windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    win32(code, &format!("could not remove route {cidr}"))
}

/// Removes every static route on the adapter (left by an earlier run).
fn flush_routes(luid: u64) {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) } != 0 {
        return;
    }
    unsafe {
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        for row in rows {
            if row.InterfaceLuid.Value == luid && row.Protocol == MIB_IPPROTO_NETMGMT {
                let _ = DeleteIpForwardEntry2(row);
            }
        }
        FreeMibTable(table.cast());
    }
}

/// Same 1280-byte tunnel MTU as Linux and macOS, for both families.
fn set_mtu(luid: u64, mtu: u32) {
    for family in [AF_INET, AF_INET6] {
        let mut row = MIB_IPINTERFACE_ROW::default();
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = family;
        row.InterfaceLuid.Value = luid;
        if unsafe { GetIpInterfaceEntry(&mut row) } != 0 {
            continue;
        }
        row.NlMtu = mtu;
        // SitePrefixLength must be zero for IPv4 when writing the row back.
        if family == AF_INET {
            row.SitePrefixLength = 0;
        }
        if let Err(error) = win32(
            unsafe { SetIpInterfaceEntry(&mut row) },
            "could not set the tunnel MTU",
        ) {
            warn!(%error, family, "keeping the default WinTun MTU");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_parsing_and_normalising() {
        assert_eq!(
            parse_cidr("100.64.0.7/32").unwrap(),
            ("100.64.0.7".parse().unwrap(), 32)
        );
        assert_eq!(
            parse_cidr("fd7a:115c:a1e0::7/128").unwrap(),
            ("fd7a:115c:a1e0::7".parse().unwrap(), 128)
        );
        assert!(parse_cidr("100.64.0.7").is_err());
        assert!(parse_cidr("100.64.0.7/33").is_err());
        assert_eq!(
            normalise_cidr("10.1.2.3/24").as_deref(),
            Some("10.1.2.0/24")
        );
        assert_eq!(
            normalise_cidr("fd00::1:2/112").as_deref(),
            Some("fd00::1:0/112")
        );
    }

    #[test]
    fn sockaddr_round_trip() {
        for ip in ["100.64.0.9", "fd7a:115c:a1e0::9"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert_eq!(from_sockaddr(&sockaddr(ip)), Some(ip));
        }
    }

    #[test]
    fn adapter_guid_is_stable_per_interface() {
        assert_eq!(adapter_guid("blaktail0"), adapter_guid("blaktail0"));
        assert_ne!(adapter_guid("blaktail0"), adapter_guid("blaktail1"));
        let bytes = adapter_guid("blaktail0").to_be_bytes();
        assert_eq!(bytes[6] >> 4, 5);
        assert_eq!(bytes[8] >> 6, 0b10);
    }
}
