//! Windows userspace tunnel. WinTun carries plaintext packets. boringtun, via
//! the shared C ABI, turns them into WireGuard ciphertext on a UDP socket.

use blaktail_ios_wg as _;

use crate::{peer_key_hex, Error, Network, Peer, PeerChange};
use base64::Engine;
use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

extern "C" {
    fn blaktail_tunnel_create(private_key: *const u8) -> *mut c_void;
    fn blaktail_tunnel_free(tunnel: *mut c_void);
    fn blaktail_tunnel_clear_peers(tunnel: *mut c_void);
    fn blaktail_tunnel_add_peer(
        tunnel: *mut c_void,
        public_key: *const u8,
        allowed_ips: *const std::ffi::c_char,
        keepalive_seconds: u16,
    ) -> i32;
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
    fn blaktail_tunnel_update_timers(
        tunnel: *mut c_void,
        dst: *mut u8,
        dst_cap: usize,
        dst_len: *mut usize,
        peer_public_out: *mut u8,
    ) -> i32;
}

struct RawTunnel(*mut c_void);
unsafe impl Send for RawTunnel {}

const WRITE_NETWORK: i32 = 1;
const WRITE_TUNNEL: i32 = 2;

pub struct WindowsNetwork {
    tunnel: Mutex<Option<TunnelHandle>>,
    endpoints: Arc<Mutex<HashMap<[u8; 32], SocketAddr>>>,
    handshakes: Arc<Mutex<HashMap<String, u64>>>,
    listen: Arc<Mutex<Option<SocketAddr>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

struct TunnelHandle {
    raw: *mut c_void,
}

unsafe impl Send for TunnelHandle {}

impl WindowsNetwork {
    pub fn new() -> Self {
        Self {
            tunnel: Mutex::new(None),
            endpoints: Arc::new(Mutex::new(HashMap::new())),
            handshakes: Arc::new(Mutex::new(HashMap::new())),
            listen: Arc::new(Mutex::new(None)),
            stop: Arc::new(AtomicBool::new(false)),
            worker: None,
        }
    }

    fn raw(&self) -> Result<*mut c_void, Error> {
        self.tunnel
            .lock()
            .map_err(|_| Error::Message("windows tunnel lock poisoned".into()))?
            .as_ref()
            .map(|handle| handle.raw)
            .ok_or_else(|| Error::Message("windows tunnel is not open".into()))
    }
}

impl Drop for WindowsNetwork {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        if let Ok(mut guard) = self.tunnel.lock() {
            if let Some(handle) = guard.take() {
                unsafe { blaktail_tunnel_free(handle.raw) };
            }
        }
    }
}

impl Network for WindowsNetwork {
    fn setup(&mut self, _interface: &str, key: &Path, addresses: &[String]) -> Result<(), Error> {
        let encoded = std::fs::read_to_string(key)?;
        let private = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .map_err(|_| Error::Message("private key file is not valid base64".into()))?;
        if private.len() != 32 {
            return Err(Error::Message("private key must be 32 bytes".into()));
        }
        let raw = unsafe { blaktail_tunnel_create(private.as_ptr()) };
        if raw.is_null() {
            return Err(Error::Message("could not create the Windows WireGuard engine".into()));
        }
        *self
            .tunnel
            .lock()
            .map_err(|_| Error::Message("windows tunnel lock poisoned".into()))? = Some(TunnelHandle { raw });

        let udp = UdpSocket::bind("0.0.0.0:0")
            .map_err(|error| Error::Message(format!("could not bind Windows UDP socket: {error}")))?;
        udp.set_nonblocking(true).ok();
        if let Ok(bound) = udp.local_addr() {
            // Relay injection matches the loopback source kernel and userspace
            // WireGuard use when the peer endpoint is 127.0.0.1.
            *self.listen.lock().unwrap() = Some(SocketAddr::from((
                std::net::Ipv4Addr::LOCALHOST,
                bound.port(),
            )));
        }
        let library = unsafe { wintun::load() }
            .map_err(|error| Error::Message(format!("wintun.dll is required beside blaktaild: {error}")))?;
        let adapter = wintun::Adapter::create(&library, "BlakTail", "BlakTail", None)
            .map_err(|error| Error::Message(format!("could not create the WinTun adapter: {error}")))?;
        assign_addresses(&addresses)?;
        let session = Arc::new(
            adapter
                .start_session(0x20_0000)
                .map_err(|error| Error::Message(format!("could not start the WinTun session: {error}")))?,
        );
        self.stop.store(false, Ordering::Relaxed);
        let stop = self.stop.clone();
        let endpoints = self.endpoints.clone();
        let handshakes = self.handshakes.clone();
        let tunnel = RawTunnel(raw);
        self.worker = Some(thread::spawn(move || {
            pump(tunnel, session, udp, stop, endpoints, handshakes);
        }));
        Ok(())
    }

    fn set_addresses(&mut self, _interface: &str, addresses: &[String]) -> Result<(), Error> {
        assign_addresses(addresses)
    }

    fn apply(&mut self, _interface: &str, changes: &[PeerChange]) -> Result<(), Error> {
        let raw = self.raw()?;
        unsafe { blaktail_tunnel_clear_peers(raw) };
        for change in changes {
            let PeerChange::Upsert(peer) = change else {
                continue;
            };
            add_peer(raw, peer)?;
        }
        Ok(())
    }

    fn down(&mut self, _interface: &str) -> Result<(), Error> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        if let Ok(mut guard) = self.tunnel.lock() {
            if let Some(handle) = guard.take() {
                unsafe { blaktail_tunnel_free(handle.raw) };
            }
        }
        let _ = std::process::Command::new("netsh")
            .args(["interface", "set", "interface", "name=BlakTail", "admin=disabled"])
            .status();
        Ok(())
    }

    fn set_peer_endpoint(
        &mut self,
        _interface: &str,
        peer_key_b64: &str,
        endpoint: &str,
    ) -> Result<(), Error> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(peer_key_b64.trim())
            .map_err(|_| Error::Message("peer key is not valid base64".into()))?;
        if raw.len() != 32 {
            return Err(Error::Message("peer key must be 32 bytes".into()));
        }
        let address: SocketAddr = endpoint
            .parse()
            .map_err(|_| Error::Message(format!("peer endpoint {endpoint} is invalid")))?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&raw);
        self.endpoints
            .lock()
            .map_err(|_| Error::Message("endpoint lock poisoned".into()))?
            .insert(key, address);
        Ok(())
    }

    fn latest_handshakes(&mut self, _interface: &str) -> Result<HashMap<String, u64>, Error> {
        let raw = self.raw()?;
        let endpoints = self
            .endpoints
            .lock()
            .map_err(|_| Error::Message("endpoint lock poisoned".into()))?
            .clone();
        let mut out = HashMap::new();
        for key in endpoints.keys() {
            let stamp = unsafe { blaktail_tunnel_last_handshake(raw, key.as_ptr()) };
            if stamp > 0 {
                if let Some(hex) = peer_key_hex(&base64::engine::general_purpose::STANDARD.encode(key)) {
                    out.insert(hex, stamp);
                }
            }
        }
        let cached = self
            .handshakes
            .lock()
            .map_err(|_| Error::Message("handshake lock poisoned".into()))?;
        for (key, stamp) in cached.iter() {
            out.entry(key.clone()).or_insert(*stamp);
        }
        Ok(out)
    }

    fn listen_endpoint(&mut self, _interface: &str) -> Result<Option<SocketAddr>, Error> {
        Ok(*self
            .listen
            .lock()
            .map_err(|_| Error::Message("listen lock poisoned".into()))?)
    }
}

fn add_peer(raw: *mut c_void, peer: &Peer) -> Result<(), Error> {
    let public = base64::engine::general_purpose::STANDARD
        .decode(peer.wg_public_key.trim())
        .map_err(|_| Error::Message("peer key is not valid base64".into()))?;
    if public.len() != 32 {
        return Err(Error::Message("peer key must be 32 bytes".into()));
    }
    let allowed = std::ffi::CString::new(peer.allowed_ips.join(","))
        .map_err(|_| Error::Message("peer allowed IPs contain a null".into()))?;
    let code = unsafe {
        blaktail_tunnel_add_peer(raw, public.as_ptr(), allowed.as_ptr(), 25)
    };
    if code < 0 {
        return Err(Error::Message(format!(
            "could not add Windows peer {}",
            peer.name
        )));
    }
    Ok(())
}

fn assign_addresses(addresses: &[String]) -> Result<(), Error> {
    for address in addresses {
        let (ip, prefix) = address
            .split_once('/')
            .ok_or_else(|| Error::Message(format!("address {address} must use CIDR notation")))?;
        let status = if ip.contains(':') {
            std::process::Command::new("netsh")
                .args(["interface", "ipv6", "add", "address", "BlakTail", ip])
                .status()
        } else {
            std::process::Command::new("netsh")
                .args([
                    "interface",
                    "ip",
                    "set",
                    "address",
                    "name=BlakTail",
                    "static",
                    ip,
                    &prefix_mask(prefix)?,
                ])
                .status()
        }
        .map_err(|error| Error::Message(format!("netsh failed: {error}")))?;
        if !status.success() {
            return Err(Error::Message(format!(
                "could not assign {address} on the Windows tunnel"
            )));
        }
    }
    Ok(())
}

fn prefix_mask(prefix: &str) -> Result<String, Error> {
    let bits: u32 = prefix
        .parse()
        .map_err(|_| Error::Message(format!("prefix {prefix} is invalid")))?;
    if bits > 32 {
        return Err(Error::Message(format!("prefix {prefix} is invalid")));
    }
    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    Ok(std::net::Ipv4Addr::from(mask).to_string())
}

fn pump(
    tunnel: RawTunnel,
    session: Arc<wintun::Session>,
    udp: UdpSocket,
    stop: Arc<AtomicBool>,
    endpoints: Arc<Mutex<HashMap<[u8; 32], SocketAddr>>>,
    handshakes: Arc<Mutex<HashMap<String, u64>>>,
) {
    let tunnel = tunnel.0;
    let mut cipher = vec![0u8; 2048];
    let mut plain = vec![0u8; 2048];
    while !stop.load(Ordering::Relaxed) {
        if let Ok(Some(packet)) = session.try_receive() {
            let bytes = packet.bytes().to_vec();
            drop(packet);
            let mut dst_len = 0usize;
            let mut peer = [0u8; 32];
            let code = unsafe {
                blaktail_tunnel_encapsulate(
                    tunnel,
                    bytes.as_ptr(),
                    bytes.len(),
                    cipher.as_mut_ptr(),
                    cipher.len(),
                    &mut dst_len,
                    peer.as_mut_ptr(),
                )
            };
            if code == WRITE_NETWORK {
                if let Some(endpoint) = endpoints.lock().ok().and_then(|map| map.get(&peer).copied()) {
                    let _ = udp.send_to(&cipher[..dst_len], endpoint);
                }
            }
        }
        let mut received = [0u8; 2048];
        if let Ok((count, source)) = udp.recv_from(&mut received) {
            drive_decapsulate(
                tunnel,
                &udp,
                &session,
                &handshakes,
                &mut plain,
                &received[..count],
                source,
            );
        }
        let mut dst_len = 0usize;
        let mut peer = [0u8; 32];
        let code = unsafe {
            blaktail_tunnel_update_timers(
                tunnel,
                cipher.as_mut_ptr(),
                cipher.len(),
                &mut dst_len,
                peer.as_mut_ptr(),
            )
        };
        if code == WRITE_NETWORK {
            if let Some(endpoint) = endpoints.lock().ok().and_then(|map| map.get(&peer).copied()) {
                let _ = udp.send_to(&cipher[..dst_len], endpoint);
            }
        }
        thread::sleep(std::time::Duration::from_millis(1));
    }
    let _ = session.shutdown();
}

fn drive_decapsulate(
    tunnel: *mut c_void,
    udp: &UdpSocket,
    session: &Arc<wintun::Session>,
    handshakes: &Mutex<HashMap<String, u64>>,
    plain: &mut [u8],
    initial: &[u8],
    source: SocketAddr,
) {
    let mut incoming = initial.to_vec();
    loop {
        let mut dst_len = 0usize;
        let mut peer = [0u8; 32];
        let code = unsafe {
            blaktail_tunnel_decapsulate(
                tunnel,
                if incoming.is_empty() {
                    std::ptr::null()
                } else {
                    incoming.as_ptr()
                },
                incoming.len(),
                plain.as_mut_ptr(),
                plain.len(),
                &mut dst_len,
                peer.as_mut_ptr(),
            )
        };
        match code {
            WRITE_NETWORK => {
                let _ = udp.send_to(&plain[..dst_len], source);
            }
            WRITE_TUNNEL => {
                if let Ok(mut map) = handshakes.lock() {
                    if let Some(hex) =
                        peer_key_hex(&base64::engine::general_purpose::STANDARD.encode(peer))
                    {
                        map.insert(
                            hex,
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map(|duration| duration.as_secs())
                                .unwrap_or(0),
                        );
                    }
                }
                if let Ok(mut outgoing) = session.allocate_send_packet(dst_len as u16) {
                    outgoing.bytes_mut()[..dst_len].copy_from_slice(&plain[..dst_len]);
                    session.send_packet(outgoing);
                }
            }
            _ => break,
        }
        incoming.clear();
    }
}
