//! Inbound packet filter for the userspace WireGuard dataplanes (iOS,
//! Android, Windows). It applies the same per-peer `ingress` grants the Linux
//! agent compiles into its `BLAKTAIL-ACL` chain, in the same order:
//! established/related first, then per-source rejects, then accepts, then
//! reject everything else. Outbound packets are never filtered; they only
//! create state so replies come back.
//!
//! Differences from the Linux chain, all fail-closed: rejected packets are
//! dropped silently (no TCP reset or ICMP unreachable), a fragment whose first
//! fragment was not seen is dropped instead of reassembled, and a policy change
//! also ends inbound-initiated flows the new policy no longer allows.

use crate::{BlakTailTunnel, RESULT_DONE, RESULT_ERR};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;
use std::sync::Arc;
use std::time::Instant;

/// Connection-tracking table bound. The oldest flow is evicted when full.
pub const MAX_STATES: usize = 16_384;
/// Distinct traffic counter keys kept between reports; extra keys are counted
/// in `overflow` and dropped.
pub const MAX_TRAFFIC_KEYS: usize = 1_024;
const MAX_FRAGMENTS: usize = 256;
/// IPv6 extension headers walked before a packet is treated as malformed.
pub const MAX_EXT_HEADERS: usize = 8;
/// Ports at or above this (the dynamic range) are counted as one class.
pub const DYNAMIC_PORTS: u16 = 49_152;

const TCP_NEW_SECS: u64 = 120;
const TCP_ESTABLISHED_SECS: u64 = 7_200;
const TCP_FIN_SECS: u64 = 120;
const TCP_RST_SECS: u64 = 10;
const UDP_NEW_SECS: u64 = 60;
const UDP_REPLIED_SECS: u64 = 180;
const ICMP_SECS: u64 = 30;
const OTHER_SECS: u64 = 600;
const FRAGMENT_SECS: u64 = 30;
const PURGE_EVERY_SECS: u64 = 10;

const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMP: u8 = 1;
const ICMPV6: u8 = 58;

// ---------------------------------------------------------------------------
// Policy: the coordinator's peer-map shape (`id`, `allowed_ips`, `ingress`).

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Ingress {
    #[serde(default)]
    pub all: bool,
    #[serde(default)]
    pub tcp: Vec<String>,
    #[serde(default)]
    pub udp: Vec<String>,
    #[serde(default)]
    pub icmp: bool,
    #[serde(default)]
    pub deny_tcp: Vec<String>,
    #[serde(default)]
    pub deny_udp: Vec<String>,
    #[serde(default)]
    pub deny_icmp: bool,
    #[serde(default)]
    pub ssh_users: Vec<String>,
    #[serde(default)]
    pub ssh_deny_users: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct PqHint {
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub capable: bool,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct PolicyPeer {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub ingress: Option<Ingress>,
    #[serde(default)]
    pub pq: Option<PqHint>,
}

/// `*`, `N` or `A-B`, as the Linux agent's `iptables_port` accepts them.
/// Anything else is ignored, exactly as Linux skips it.
pub fn port_range(spec: &str) -> Option<(u16, u16)> {
    let spec = spec.trim();
    if spec == "*" {
        return Some((1, u16::MAX));
    }
    if let Some((start, end)) = spec.split_once('-') {
        let start: u16 = start.parse().ok()?;
        let end: u16 = end.parse().ok()?;
        return (start != 0 && end != 0 && start <= end).then_some((start, end));
    }
    let port: u16 = spec.parse().ok()?;
    (port != 0).then_some((port, port))
}

/// Same rule as the Linux agent: an SSH grant naming users, or denying some,
/// needs per-user sshd limits, which only the Linux agent can verify.
pub fn ssh_restricted(ingress: &Ingress) -> bool {
    let unrestricted = ingress.ssh_users.len() == 1
        && ingress.ssh_users[0] == "*"
        && ingress.ssh_deny_users.is_empty();
    !ingress.ssh_users.is_empty() && !unrestricted
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Proto {
    Tcp,
    Udp,
    Icmp,
    Any,
}

#[derive(Clone, Copy, Debug)]
struct Rule {
    proto: Proto,
    ports: (u16, u16),
    accept: bool,
}

impl Rule {
    fn matches(&self, proto: u8, port: u16) -> bool {
        match self.proto {
            Proto::Any => true,
            Proto::Icmp => proto == ICMP || proto == ICMPV6,
            Proto::Tcp => proto == TCP && (self.ports.0..=self.ports.1).contains(&port),
            Proto::Udp => proto == UDP && (self.ports.0..=self.ports.1).contains(&port),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Prefix {
    network: IpAddr,
    bits: u8,
}

impl Prefix {
    fn parse(value: &str) -> Option<Self> {
        let (address, bits) = value.split_once('/')?;
        let network: IpAddr = address.trim().parse().ok()?;
        let bits: u8 = bits.trim().parse().ok()?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        (bits <= max).then_some(Self { network, bits })
    }

    fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = if self.bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(self.bits))
                };
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = if self.bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.bits))
                };
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }

    fn host(&self) -> Option<IpAddr> {
        let full = if self.network.is_ipv4() { 32 } else { 128 };
        (self.bits == full).then_some(self.network)
    }
}

#[derive(Clone, Debug)]
struct Source {
    peer: Option<Arc<str>>,
    rules: Vec<Rule>,
}

/// Compiled inbound policy.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    enforce: bool,
    sources: HashMap<IpAddr, Vec<Source>>,
    routes: Vec<(Prefix, Arc<str>)>,
}

fn peer_id(id: &str) -> Option<Arc<str>> {
    let id = id.trim();
    (!id.is_empty()).then(|| Arc::from(id))
}

impl Policy {
    /// No grants known (legacy coordinator): nothing is filtered.
    pub fn allow_all() -> Self {
        Self::default()
    }

    /// Enforcing with no grants: only replies to this device's own flows pass.
    pub fn deny_all() -> Self {
        Self {
            enforce: true,
            ..Self::default()
        }
    }

    /// `pq_port` opens the in-tunnel PSK exchange port to peers whose pair has
    /// post-quantum on, as the Linux chain does; pass `None` where this
    /// platform does not run the exchange.
    pub fn compile(peers: &[PolicyPeer], pq_port: Option<u16>) -> Self {
        let mut policy = Self {
            enforce: peers.iter().any(|peer| peer.ingress.is_some()),
            ..Self::default()
        };
        for peer in peers {
            let id = peer_id(&peer.id);
            let prefixes: Vec<Prefix> = peer
                .allowed_ips
                .iter()
                .filter_map(|route| Prefix::parse(route))
                .collect();
            if let Some(id) = &id {
                policy
                    .routes
                    .extend(prefixes.iter().map(|prefix| (*prefix, id.clone())));
            }
            if !policy.enforce {
                continue;
            }
            // A peer without grants in an enforcing map is treated as `all`,
            // matching the Linux agent's default for a missing `ingress`.
            let ingress = peer.ingress.clone().unwrap_or(Ingress {
                all: true,
                ..Ingress::default()
            });
            let pq = pq_port.filter(|_| {
                peer.pq
                    .as_ref()
                    .is_some_and(|pq| pq.capable && !pq.mode.is_empty() && pq.mode != "off")
            });
            let rules = compile_rules(&ingress, pq);
            for host in prefixes.iter().filter_map(Prefix::host) {
                policy.sources.entry(host).or_default().push(Source {
                    peer: id.clone(),
                    rules: rules.clone(),
                });
            }
        }
        policy
    }

    pub fn enforces(&self) -> bool {
        self.enforce
    }

    /// Verdict for a new inbound flow, plus the peer it is attributed to.
    fn decide(&self, source: IpAddr, proto: u8, port: u16) -> (bool, Option<Arc<str>>) {
        if let Some(entries) = self.sources.get(&source) {
            for entry in entries {
                for rule in &entry.rules {
                    if rule.matches(proto, port) {
                        return (!self.enforce || rule.accept, entry.peer.clone());
                    }
                }
            }
        }
        (!self.enforce, self.peer_for(source))
    }

    fn peer_for(&self, address: IpAddr) -> Option<Arc<str>> {
        if let Some(entry) = self
            .sources
            .get(&address)
            .and_then(|entries| entries.iter().find(|entry| entry.peer.is_some()))
        {
            return entry.peer.clone();
        }
        self.routes
            .iter()
            .find(|(prefix, _)| prefix.contains(address))
            .map(|(_, id)| id.clone())
    }
}

fn compile_rules(ingress: &Ingress, pq_port: Option<u16>) -> Vec<Rule> {
    let mut rules = Vec::new();
    let mut push = |proto, ports, accept| {
        rules.push(Rule {
            proto,
            ports,
            accept,
        })
    };
    if let Some(port) = pq_port {
        push(Proto::Tcp, (port, port), true);
    }
    let mut deny_tcp = ingress.deny_tcp.clone();
    // No per-user sshd enforcement outside Linux: close TCP 22 to sources
    // whose SSH grant is user-limited (the Linux `fail_closed_ssh` backstop).
    if ssh_restricted(ingress) && !deny_tcp.iter().any(|spec| spec == "22") {
        deny_tcp.push("22".into());
    }
    for range in deny_tcp.iter().filter_map(|spec| port_range(spec)) {
        push(Proto::Tcp, range, false);
    }
    for range in ingress.deny_udp.iter().filter_map(|spec| port_range(spec)) {
        push(Proto::Udp, range, false);
    }
    if ingress.deny_icmp {
        push(Proto::Icmp, (0, 0), false);
    }
    if ingress.all {
        push(Proto::Any, (0, 0), true);
        return rules;
    }
    for range in ingress.tcp.iter().filter_map(|spec| port_range(spec)) {
        push(Proto::Tcp, range, true);
    }
    for range in ingress.udp.iter().filter_map(|spec| port_range(spec)) {
        push(Proto::Udp, range, true);
    }
    if ingress.icmp {
        push(Proto::Icmp, (0, 0), true);
    }
    rules
}

// ---------------------------------------------------------------------------
// Packet parsing

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct FragmentKey {
    source: IpAddr,
    destination: IpAddr,
    proto: u8,
    ident: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fragment {
    Whole,
    First(FragmentKey),
    Later(FragmentKey),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum L4 {
    Ports {
        source: u16,
        destination: u16,
        flags: u8,
    },
    Icmp {
        kind: u8,
        ident: u16,
        body: usize,
    },
    Other,
}

#[derive(Clone, Copy, Debug)]
struct Packet {
    source: IpAddr,
    destination: IpAddr,
    proto: u8,
    l4: L4,
    fragment: Fragment,
    len: usize,
}

fn be16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*data.get(at)?, *data.get(at + 1)?]))
}

/// Parses one IP packet. `None` means malformed or truncated, which the
/// inbound path drops.
fn parse(data: &[u8]) -> Option<Packet> {
    parse_packet(data, false)
}

/// `embedded` relaxes the TCP header to its ports, which is all an ICMP
/// error is guaranteed to quote.
fn parse_packet(data: &[u8], embedded: bool) -> Option<Packet> {
    let (source, destination, mut proto, mut offset, fragment, data) = match data.first()? >> 4 {
        4 => {
            let ihl = usize::from(data.first()? & 0x0f) * 4;
            let total = usize::from(be16(data, 2)?);
            if ihl < 20 || total < ihl || total > data.len() {
                return None;
            }
            let data = &data[..total];
            let proto = data[9];
            let source = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
            let destination = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));
            let flags = be16(data, 6)?;
            let key = FragmentKey {
                source,
                destination,
                proto,
                ident: u32::from(be16(data, 4)?),
            };
            let fragment = if flags & 0x1fff != 0 {
                Fragment::Later(key)
            } else if flags & 0x2000 != 0 {
                Fragment::First(key)
            } else {
                Fragment::Whole
            };
            (source, destination, proto, ihl, fragment, data)
        }
        6 => {
            if data.len() < 40 {
                return None;
            }
            let total = 40 + usize::from(be16(data, 4)?);
            if total > data.len() {
                return None;
            }
            let data = &data[..total];
            let source = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).ok()?));
            let destination = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).ok()?));
            (source, destination, data[6], 40, Fragment::Whole, data)
        }
        _ => return None,
    };
    let mut fragment = fragment;
    if source.is_ipv6() {
        let mut walked = 0;
        loop {
            let header_len = match proto {
                0 | 43 | 60 => (usize::from(*data.get(offset + 1)?) + 1) * 8,
                51 => (usize::from(*data.get(offset + 1)?) + 2) * 4,
                44 => {
                    let field = be16(data, offset + 2)?;
                    let ident =
                        u32::from_be_bytes(data.get(offset + 4..offset + 8)?.try_into().ok()?);
                    let next = *data.get(offset)?;
                    let key = FragmentKey {
                        source,
                        destination,
                        proto: next,
                        ident,
                    };
                    fragment = if field >> 3 != 0 {
                        Fragment::Later(key)
                    } else if field & 1 != 0 {
                        Fragment::First(key)
                    } else {
                        fragment
                    };
                    8
                }
                _ => break,
            };
            walked += 1;
            if walked > MAX_EXT_HEADERS {
                return None;
            }
            proto = *data.get(offset)?;
            offset += header_len;
            if offset > data.len() {
                return None;
            }
            if matches!(fragment, Fragment::Later(_)) {
                break;
            }
        }
    }
    let l4 = if matches!(fragment, Fragment::Later(_)) {
        L4::Other
    } else {
        match proto {
            TCP => {
                if !embedded && data.len() < offset + 20 {
                    return None;
                }
                L4::Ports {
                    source: be16(data, offset)?,
                    destination: be16(data, offset + 2)?,
                    flags: data.get(offset + 13).copied().unwrap_or(0),
                }
            }
            UDP => {
                be16(data, offset + 6)?;
                L4::Ports {
                    source: be16(data, offset)?,
                    destination: be16(data, offset + 2)?,
                    flags: 0,
                }
            }
            ICMP if source.is_ipv4() => icmp(data, offset)?,
            ICMPV6 if source.is_ipv6() => icmp(data, offset)?,
            _ => L4::Other,
        }
    };
    Some(Packet {
        source,
        destination,
        proto,
        l4,
        fragment,
        len: data.len(),
    })
}

fn icmp(data: &[u8], offset: usize) -> Option<L4> {
    be16(data, offset + 6)?;
    Some(L4::Icmp {
        kind: data[offset],
        ident: be16(data, offset + 4)?,
        body: offset + 8,
    })
}

fn is_echo_request(proto: u8, kind: u8) -> bool {
    (proto == ICMP && kind == 8) || (proto == ICMPV6 && kind == 128)
}

fn is_echo(proto: u8, kind: u8) -> bool {
    is_echo_request(proto, kind) || (proto == ICMP && kind == 0) || (proto == ICMPV6 && kind == 129)
}

fn is_error(proto: u8, kind: u8) -> bool {
    (proto == ICMP && matches!(kind, 3 | 11 | 12)) || (proto == ICMPV6 && matches!(kind, 1..=4))
}

// ---------------------------------------------------------------------------
// Connection tracking and counters

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct FlowKey {
    proto: u8,
    local: IpAddr,
    remote: IpAddr,
    local_port: u16,
    remote_port: u16,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Flow started by a peer towards this device.
    Inbound,
    /// Flow started by this device.
    Outbound,
}

#[derive(Clone, Debug)]
struct State {
    initiator: Direction,
    peer: Option<Arc<str>>,
    service_port: u16,
    replied: bool,
    expires: u64,
    generation: u64,
}

#[derive(Clone, Debug)]
struct FragmentState {
    allow: bool,
    counter: Option<TrafficKey>,
    expires: u64,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct TrafficKey {
    peer: Option<Arc<str>>,
    direction: Direction,
    proto: u8,
    port: u16,
    allowed: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Counter {
    bytes: u64,
    packets: u64,
}

/// One aggregate the host reports: never an address, payload or name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TrafficSample {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_id: Option<String>,
    pub direction: Direction,
    /// `tcp`, `udp`, `icmp` or `other`.
    pub proto: &'static str,
    /// Service port (destination of the flow's first packet); dynamic ports
    /// are folded into 49152; zero for ICMP and other protocols.
    pub port: u16,
    /// `allowed` or `denied`.
    pub decision: &'static str,
    pub bytes: u64,
    pub packets: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct TrafficReport {
    pub samples: Vec<TrafficSample>,
    /// Packets whose counter key did not fit in `MAX_TRAFFIC_KEYS`.
    pub overflow: u64,
}

fn proto_label(proto: u8) -> &'static str {
    match proto {
        TCP => "tcp",
        UDP => "udp",
        ICMP | ICMPV6 => "icmp",
        _ => "other",
    }
}

fn port_class(port: u16) -> u16 {
    port.min(DYNAMIC_PORTS)
}

pub struct Filter {
    policy: Policy,
    states: HashMap<FlowKey, State>,
    order: VecDeque<(FlowKey, u64)>,
    generation: u64,
    fragments: HashMap<FragmentKey, FragmentState>,
    traffic: Option<HashMap<TrafficKey, Counter>>,
    overflow: u64,
    last_purge: u64,
    epoch: Instant,
    /// Unix time the current traffic bucket started.
    pub bucket_started: i64,
}

impl Default for Filter {
    fn default() -> Self {
        Self::new()
    }
}

impl Filter {
    pub fn new() -> Self {
        Self {
            policy: Policy::allow_all(),
            states: HashMap::new(),
            order: VecDeque::new(),
            generation: 0,
            fragments: HashMap::new(),
            traffic: None,
            overflow: 0,
            last_purge: 0,
            epoch: Instant::now(),
            bucket_started: 0,
        }
    }

    fn now(&self) -> u64 {
        self.epoch.elapsed().as_secs()
    }

    /// Installs a new policy. Outbound flows keep their state; inbound-started
    /// flows survive only if the new policy still admits them.
    pub fn set_policy(&mut self, policy: Policy) {
        self.policy = policy;
        let policy = &self.policy;
        self.states.retain(|key, state| {
            state.initiator == Direction::Outbound
                || policy.decide(key.remote, key.proto, state.service_port).0
        });
        self.fragments.clear();
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Turns traffic counting on or off. Turning it off discards every
    /// counter immediately.
    pub fn set_traffic(&mut self, enabled: bool) {
        if !enabled {
            self.traffic = None;
            self.overflow = 0;
        } else if self.traffic.is_none() {
            self.traffic = Some(HashMap::new());
            self.bucket_started = unix_seconds();
        }
    }

    pub fn traffic_enabled(&self) -> bool {
        self.traffic.is_some()
    }

    /// Current counters, without resetting them.
    pub fn traffic_report(&self) -> TrafficReport {
        let mut samples: Vec<TrafficSample> = self
            .traffic
            .iter()
            .flatten()
            .map(|(key, counter)| TrafficSample {
                peer_id: key.peer.as_deref().map(str::to_owned),
                direction: key.direction,
                proto: proto_label(key.proto),
                port: key.port,
                decision: if key.allowed { "allowed" } else { "denied" },
                bytes: counter.bytes,
                packets: counter.packets,
            })
            .collect();
        samples.sort_by(|a, b| {
            (&a.peer_id, a.proto, a.port, a.decision)
                .cmp(&(&b.peer_id, b.proto, b.port, b.decision))
        });
        TrafficReport {
            samples,
            overflow: self.overflow,
        }
    }

    /// Returns and resets the counters.
    pub fn take_traffic(&mut self) -> TrafficReport {
        let report = self.traffic_report();
        if let Some(traffic) = &mut self.traffic {
            traffic.clear();
        }
        self.overflow = 0;
        report
    }

    pub fn state_count(&self) -> usize {
        self.states.len()
    }

    pub fn inbound_now(&mut self, packet: &[u8]) -> bool {
        let now = self.now();
        self.inbound(packet, now)
    }

    pub fn outbound_now(&mut self, packet: &[u8]) {
        let now = self.now();
        self.outbound(packet, now);
    }

    /// Decides one decrypted packet before it reaches the tunnel device.
    pub fn inbound(&mut self, data: &[u8], now: u64) -> bool {
        self.maybe_purge(now);
        let Some(packet) = parse(data) else {
            self.count_unattributed(data, now);
            return false;
        };
        if let Fragment::Later(key) = packet.fragment {
            return self.later_fragment(key, packet.len, now, packet.source);
        }
        let key = inbound_key(&packet);
        if let Some(key) = key {
            if self.touch(&key, &packet, Direction::Inbound, now) {
                return true;
            }
        }
        if let L4::Icmp { kind, body, .. } = packet.l4 {
            if is_error(packet.proto, kind) {
                if let Some(state) = self.related(&data[..packet.len], body, now) {
                    let counter = TrafficKey {
                        peer: state.peer.clone(),
                        direction: state.initiator,
                        proto: packet.proto,
                        port: port_class(state.service_port),
                        allowed: true,
                    };
                    self.count(counter.clone(), packet.len);
                    self.remember_fragment(&packet, true, Some(counter), now);
                    return true;
                }
            }
        }
        let port = match packet.l4 {
            L4::Ports { destination, .. } => destination,
            _ => 0,
        };
        let (allow, peer) = self.policy.decide(packet.source, packet.proto, port);
        if allow {
            if let Some(key) = key {
                self.insert(
                    key,
                    State {
                        initiator: Direction::Inbound,
                        peer: peer.clone(),
                        service_port: port,
                        replied: false,
                        expires: now + initial_timeout(packet.proto),
                        generation: 0,
                    },
                    now,
                );
                self.touch(&key, &packet, Direction::Inbound, now);
            }
        }
        let counter = TrafficKey {
            peer,
            direction: Direction::Inbound,
            proto: packet.proto,
            port: port_class(port),
            allowed: allow,
        };
        if key.is_none() || !allow {
            self.count(counter.clone(), packet.len);
        }
        self.remember_fragment(&packet, allow, Some(counter), now);
        allow
    }

    /// Records one packet this device sends into the tunnel. Never blocks.
    pub fn outbound(&mut self, data: &[u8], now: u64) {
        self.maybe_purge(now);
        let Some(packet) = parse(data) else {
            return;
        };
        if let Fragment::Later(key) = packet.fragment {
            if let Some(counter) = self
                .fragments
                .get(&key)
                .filter(|entry| entry.expires > now)
                .and_then(|entry| entry.counter.clone())
            {
                self.count(counter, packet.len);
            }
            return;
        }
        let Some(key) = outbound_key(&packet) else {
            let counter = TrafficKey {
                peer: self.policy.peer_for(packet.destination),
                direction: Direction::Outbound,
                proto: packet.proto,
                port: 0,
                allowed: true,
            };
            self.count(counter.clone(), packet.len);
            self.remember_fragment(&packet, true, Some(counter), now);
            return;
        };
        if !self.touch(&key, &packet, Direction::Outbound, now) {
            let service_port = match packet.l4 {
                L4::Ports { destination, .. } => destination,
                _ => 0,
            };
            self.insert(
                key,
                State {
                    initiator: Direction::Outbound,
                    peer: self.policy.peer_for(packet.destination),
                    service_port,
                    replied: false,
                    expires: now + initial_timeout(packet.proto),
                    generation: 0,
                },
                now,
            );
            self.touch(&key, &packet, Direction::Outbound, now);
        }
        let counter = self.states.get(&key).map(|state| TrafficKey {
            peer: state.peer.clone(),
            direction: state.initiator,
            proto: packet.proto,
            port: port_class(state.service_port),
            allowed: true,
        });
        self.remember_fragment(&packet, true, counter, now);
    }

    /// Refreshes a live flow for a packet travelling `via`, counting it.
    /// Returns false when no live state exists.
    fn touch(&mut self, key: &FlowKey, packet: &Packet, via: Direction, now: u64) -> bool {
        let Some(state) = self.states.get_mut(key) else {
            return false;
        };
        if state.expires <= now {
            self.states.remove(key);
            return false;
        }
        if via != state.initiator {
            state.replied = true;
        }
        state.expires = now
            + match (packet.proto, packet.l4) {
                (TCP, L4::Ports { flags, .. }) if flags & 0x04 != 0 => TCP_RST_SECS,
                (TCP, L4::Ports { flags, .. }) if flags & 0x01 != 0 => TCP_FIN_SECS,
                (TCP, _) if state.replied => TCP_ESTABLISHED_SECS,
                (TCP, _) => TCP_NEW_SECS,
                (UDP, _) if state.replied => UDP_REPLIED_SECS,
                (UDP, _) => UDP_NEW_SECS,
                (ICMP | ICMPV6, _) => ICMP_SECS,
                _ => OTHER_SECS,
            };
        let counter = TrafficKey {
            peer: state.peer.clone(),
            direction: state.initiator,
            proto: packet.proto,
            port: port_class(state.service_port),
            allowed: true,
        };
        self.count(counter, packet.len);
        true
    }

    /// ICMP error carrying the header of a packet this device sent on a
    /// tracked flow (Linux `RELATED`).
    fn related(&self, data: &[u8], body: usize, now: u64) -> Option<State> {
        let inner = parse_embedded(data.get(body..)?)?;
        let key = outbound_key(&inner)?;
        self.states
            .get(&key)
            .filter(|state| state.expires > now)
            .cloned()
    }

    fn later_fragment(&mut self, key: FragmentKey, len: usize, now: u64, source: IpAddr) -> bool {
        match self.fragments.get(&key).filter(|entry| entry.expires > now) {
            Some(entry) => {
                let (allow, counter) = (entry.allow, entry.counter.clone());
                if let Some(counter) = counter {
                    self.count(counter, len);
                }
                allow
            }
            None => {
                let counter = TrafficKey {
                    peer: self.policy.peer_for(source),
                    direction: Direction::Inbound,
                    proto: key.proto,
                    port: 0,
                    allowed: false,
                };
                self.count(counter, len);
                false
            }
        }
    }

    fn remember_fragment(
        &mut self,
        packet: &Packet,
        allow: bool,
        counter: Option<TrafficKey>,
        now: u64,
    ) {
        let Fragment::First(key) = packet.fragment else {
            return;
        };
        if self.fragments.len() >= MAX_FRAGMENTS {
            self.fragments.retain(|_, entry| entry.expires > now);
            if self.fragments.len() >= MAX_FRAGMENTS {
                // Full: later fragments of this packet are dropped (fail closed).
                return;
            }
        }
        self.fragments.insert(
            key,
            FragmentState {
                allow,
                counter,
                expires: now + FRAGMENT_SECS,
            },
        );
    }

    fn insert(&mut self, key: FlowKey, mut state: State, now: u64) {
        // At most one full sweep a second when full; otherwise FIFO eviction.
        if self.states.len() >= MAX_STATES && now > self.last_purge {
            self.purge(now);
        }
        while self.states.len() >= MAX_STATES {
            let Some((oldest, generation)) = self.order.pop_front() else {
                break;
            };
            if self
                .states
                .get(&oldest)
                .is_some_and(|state| state.generation == generation)
            {
                self.states.remove(&oldest);
            }
        }
        self.generation += 1;
        state.generation = self.generation;
        self.order.push_back((key, self.generation));
        self.states.insert(key, state);
        if self.order.len() > MAX_STATES * 2 {
            let states = &self.states;
            self.order.retain(|(key, generation)| {
                states
                    .get(key)
                    .is_some_and(|state| state.generation == *generation)
            });
        }
    }

    fn maybe_purge(&mut self, now: u64) {
        if now >= self.last_purge + PURGE_EVERY_SECS {
            self.purge(now);
        }
    }

    fn purge(&mut self, now: u64) {
        self.last_purge = now;
        self.states.retain(|_, state| state.expires > now);
        self.fragments.retain(|_, entry| entry.expires > now);
        if self.order.len() > self.states.len() * 2 + 64 {
            let states = &self.states;
            self.order.retain(|(key, generation)| {
                states
                    .get(key)
                    .is_some_and(|state| state.generation == *generation)
            });
        }
    }

    fn count(&mut self, key: TrafficKey, len: usize) {
        let Some(traffic) = &mut self.traffic else {
            return;
        };
        if !traffic.contains_key(&key) && traffic.len() >= MAX_TRAFFIC_KEYS {
            self.overflow += 1;
            return;
        }
        let counter = traffic.entry(key).or_default();
        counter.bytes = counter.bytes.saturating_add(len as u64);
        counter.packets = counter.packets.saturating_add(1);
    }

    fn count_unattributed(&mut self, data: &[u8], _now: u64) {
        self.count(
            TrafficKey {
                peer: None,
                direction: Direction::Inbound,
                proto: 0,
                port: 0,
                allowed: false,
            },
            data.len(),
        );
    }
}

fn initial_timeout(proto: u8) -> u64 {
    match proto {
        TCP => TCP_NEW_SECS,
        UDP => UDP_NEW_SECS,
        ICMP | ICMPV6 => ICMP_SECS,
        _ => OTHER_SECS,
    }
}

/// Flow key of a packet arriving from a peer, or `None` for packets that
/// never create state (ICMP other than echo).
fn inbound_key(packet: &Packet) -> Option<FlowKey> {
    let (local_port, remote_port) = match packet.l4 {
        L4::Ports {
            source,
            destination,
            ..
        } => (destination, source),
        L4::Icmp { kind, ident, .. } if is_echo(packet.proto, kind) => (ident, 0),
        L4::Icmp { .. } => return None,
        L4::Other => (0, 0),
    };
    Some(FlowKey {
        proto: packet.proto,
        local: packet.destination,
        remote: packet.source,
        local_port,
        remote_port,
    })
}

fn outbound_key(packet: &Packet) -> Option<FlowKey> {
    let (local_port, remote_port) = match packet.l4 {
        L4::Ports {
            source,
            destination,
            ..
        } => (source, destination),
        L4::Icmp { kind, ident, .. } if is_echo(packet.proto, kind) => (ident, 0),
        L4::Icmp { .. } => return None,
        L4::Other => (0, 0),
    };
    Some(FlowKey {
        proto: packet.proto,
        local: packet.source,
        remote: packet.destination,
        local_port,
        remote_port,
    })
}

/// The truncated original packet inside an ICMP error: an IP header plus at
/// least the first 8 bytes of its payload. Lengths are not checked against
/// the (cut-off) total length field.
fn parse_embedded(data: &[u8]) -> Option<Packet> {
    let mut copy = data.to_vec();
    match copy.first()? >> 4 {
        4 => {
            let len = u16::try_from(copy.len()).ok()?;
            copy.get_mut(2..4)?.copy_from_slice(&len.to_be_bytes());
            // An embedded fragment header is irrelevant to the lookup.
            copy.get_mut(6..8)?.copy_from_slice(&[0, 0]);
        }
        6 => {
            let payload = u16::try_from(copy.len().checked_sub(40)?).ok()?;
            copy.get_mut(4..6)?.copy_from_slice(&payload.to_be_bytes());
        }
        _ => return None,
    }
    let mut packet = parse_packet(&copy, true)?;
    packet.fragment = Fragment::Whole;
    Some(packet)
}

// ---------------------------------------------------------------------------
// C ABI for the iOS/Android hosts and the Windows agent.

/// Replaces the inbound policy from the coordinator's `peers` JSON array.
/// Invalid JSON installs a deny-all policy (fail closed) and returns -1.
///
/// # Safety
/// `tunnel` must be live; `json` must be valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn blaktail_tunnel_set_policy(
    tunnel: *mut BlakTailTunnel,
    json: *const u8,
    len: usize,
) -> i32 {
    if tunnel.is_null() || (json.is_null() && len != 0) {
        return RESULT_ERR;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let raw = if json.is_null() {
            &[][..]
        } else {
            slice::from_raw_parts(json, len)
        };
        let parsed = serde_json::from_slice::<Vec<PolicyPeer>>(raw);
        let Ok(mut inner) = (*tunnel).inner.lock() else {
            return RESULT_ERR;
        };
        match parsed {
            Ok(peers) => {
                inner.filter.set_policy(Policy::compile(&peers, None));
                RESULT_DONE
            }
            Err(_) => {
                inner.filter.set_policy(Policy::deny_all());
                RESULT_ERR
            }
        }
    }))
    .unwrap_or(RESULT_ERR)
}

/// Turns traffic counters on (non-zero) or off; off discards them.
///
/// # Safety
/// `tunnel` must be live.
#[no_mangle]
pub unsafe extern "C" fn blaktail_tunnel_set_traffic(
    tunnel: *mut BlakTailTunnel,
    enabled: i32,
) -> i32 {
    if tunnel.is_null() {
        return RESULT_ERR;
    }
    catch_unwind(AssertUnwindSafe(|| match (*tunnel).inner.lock() {
        Ok(mut inner) => {
            inner.filter.set_traffic(enabled != 0);
            RESULT_DONE
        }
        Err(_) => RESULT_ERR,
    }))
    .unwrap_or(RESULT_ERR)
}

/// Writes the coordinator upload body (`{"records":[...]}`) for the counters
/// since the last successful call and resets them. Sampling uses the
/// coordinator's own draw. `transport` is `direct`, `udp_relay` or
/// `https_relay`. When `dst_cap` is too small, sets `dst_len` to the size
/// needed, keeps the counters and returns -1. With counting off, writes an
/// empty batch.
///
/// # Safety
/// `tunnel` must be live; the strings NUL-terminated; `dst`/`dst_len` valid
/// for `dst_cap` bytes.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn blaktail_tunnel_take_flow_upload(
    tunnel: *mut BlakTailTunnel,
    org_id: *const std::os::raw::c_char,
    device_id: *const std::os::raw::c_char,
    transport: *const std::os::raw::c_char,
    sampling_rate: f64,
    dst: *mut u8,
    dst_cap: usize,
    dst_len: *mut usize,
) -> i32 {
    if tunnel.is_null()
        || org_id.is_null()
        || device_id.is_null()
        || transport.is_null()
        || dst.is_null()
        || dst_len.is_null()
    {
        return RESULT_ERR;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let text = |value| std::ffi::CStr::from_ptr(value).to_str().ok();
        let (Some(org_id), Some(device_id), Some(transport)) =
            (text(org_id), text(device_id), text(transport))
        else {
            return RESULT_ERR;
        };
        let Ok(mut inner) = (*tunnel).inner.lock() else {
            return RESULT_ERR;
        };
        let end = unix_seconds();
        let upload = crate::flow_report::build(
            &crate::flow_report::Bucket {
                org_id,
                device_id,
                start: inner.filter.bucket_started,
                end,
                transport,
                relayed_peers: &[],
                sampling_rate,
            },
            &inner.filter.traffic_report().flow_counts(),
        );
        let Ok(json) = serde_json::to_vec(&upload) else {
            return RESULT_ERR;
        };
        *dst_len = json.len();
        if json.len() > dst_cap {
            return RESULT_ERR;
        }
        slice::from_raw_parts_mut(dst, json.len()).copy_from_slice(&json);
        inner.filter.take_traffic();
        inner.filter.bucket_started = end;
        RESULT_DONE
    }))
    .unwrap_or(RESULT_ERR)
}

fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

/// Takes the traffic counters of a tunnel from `blaktail_tunnel_create`, for
/// in-process hosts (the Windows agent).
///
/// # Safety
/// `tunnel` must be live.
pub unsafe fn take_report(tunnel: *mut BlakTailTunnel) -> Option<TrafficReport> {
    let mut inner = tunnel.as_ref()?.inner.lock().ok()?;
    Some(inner.filter.take_traffic())
}

/// Turns counting on or off for an in-process host.
///
/// # Safety
/// `tunnel` must be live.
pub unsafe fn set_traffic(tunnel: *mut BlakTailTunnel, enabled: bool) {
    if let Some(mut inner) = tunnel.as_ref().and_then(|tunnel| tunnel.inner.lock().ok()) {
        inner.filter.set_traffic(enabled);
    }
}

/// Installs a compiled policy for an in-process host.
///
/// # Safety
/// `tunnel` must be live.
pub unsafe fn set_policy(tunnel: *mut BlakTailTunnel, policy: Policy) {
    if let Some(mut inner) = tunnel.as_ref().and_then(|tunnel| tunnel.inner.lock().ok()) {
        inner.filter.set_policy(policy);
    }
}

impl TrafficReport {
    /// Counters in the shared upload builder's shape.
    pub fn flow_counts(&self) -> Vec<crate::flow_report::FlowCount> {
        self.samples
            .iter()
            .map(|sample| crate::flow_report::FlowCount {
                peer_id: sample.peer_id.clone(),
                direction: match sample.direction {
                    Direction::Inbound => "inbound",
                    Direction::Outbound => "outbound",
                },
                proto: sample.proto,
                port: sample.port,
                allowed: sample.decision == "allowed",
                bytes: sample.bytes,
                packets: sample.packets,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
