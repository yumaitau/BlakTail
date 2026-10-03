//! Per-flow traffic events on Linux (draft 17).
//!
//! Two read-only sources, both running only while the organisation has
//! traffic diagnostics on:
//!
//! - **Connections**: `conntrack -E -e NEW,DESTROY -o timestamp,extended`
//!   (conntrack-tools) as a child process. `NEW` becomes a `start` event,
//!   `DESTROY` an `end` event with the entry's byte and packet counters
//!   (`net.netfilter.nf_conntrack_acct`, turned on while reporting and
//!   restored afterwards). Only connections from or to this device's overlay
//!   addresses, or forwarded for an overlay peer (routing peers), are kept.
//! - **Drops**: the `BLAKTAIL-ACL` and `BLAKTAIL-FWD` chains carry a
//!   rate-limited `NFLOG` rule before each `REJECT` (group
//!   [`NFLOG_GROUP`], prefix naming the chain and rule kind). A netlink
//!   socket bound to that group reads the first 128 bytes of each rejected
//!   packet: addresses, protocol, ports or ICMP type. Nothing listens while
//!   reporting is off, so the kernel discards those copies.
//!
//! Both feed bounded queues; the agent drains them every upload window.
//! Payload bytes beyond the transport header are never read.

use crate::flow_events::{self, Direction, FlowEvent, Kind};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// NFLOG group the BlakTail chains log rejected packets to.
pub const NFLOG_GROUP: u16 = 7841;
/// Raw records held between uploads (each source).
pub const MAX_QUEUED: usize = 8_192;
/// Connections remembered between their start and end.
pub const MAX_OPEN_FLOWS: usize = 16_384;
/// Distinct drops merged per window; more are counted and discarded.
pub const MAX_DROPS_PER_WINDOW: usize = 1_024;
/// Bytes of each rejected packet the kernel copies to the agent.
pub const NFLOG_COPY_BYTES: u32 = 128;

// ---------------------------------------------------------------------------
// conntrack event lines

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CtKind {
    New,
    Destroy,
}

/// One conntrack event, original direction tuple plus counters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CtEvent {
    pub kind: CtKind,
    /// Unix seconds (from `-o timestamp`), if printed.
    pub at: Option<i64>,
    pub proto: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub icmp: Option<(u8, u8, u16)>,
    pub orig_packets: u64,
    pub orig_bytes: u64,
    pub reply_packets: u64,
    pub reply_bytes: u64,
}

fn proto_number(name: &str) -> Option<u8> {
    match name {
        "tcp" => Some(6),
        "udp" => Some(17),
        "icmp" => Some(1),
        "icmpv6" => Some(58),
        "sctp" => Some(132),
        "udplite" => Some(136),
        "dccp" => Some(33),
        "gre" => Some(47),
        _ => None,
    }
}

/// Parses one `conntrack -E` line (with or without `-o timestamp` and
/// `-o extended`). Returns `None` for other event types and for lines it
/// cannot read.
pub fn parse_conntrack_line(line: &str) -> Option<CtEvent> {
    let mut at = None;
    let mut kind = None;
    let mut proto = None;
    let mut tokens = line.split_whitespace().peekable();
    let mut fields: Vec<(&str, &str)> = Vec::new();
    while let Some(token) = tokens.next() {
        if let Some(stamp) = token.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
            match stamp {
                "NEW" => kind = Some(CtKind::New),
                "DESTROY" => kind = Some(CtKind::Destroy),
                "UPDATE" => return None,
                other => {
                    if let Some(seconds) = other.split('.').next().and_then(|s| s.parse().ok()) {
                        at = Some(seconds);
                    }
                }
            }
            continue;
        }
        if let Some((key, value)) = token.split_once('=') {
            fields.push((key, value));
            continue;
        }
        if proto.is_none() {
            if let Some(number) = proto_number(token) {
                proto = Some(number);
            } else if token == "unknown" {
                // `unknown <number>`: another IP protocol.
                proto = tokens.peek().and_then(|next| next.parse().ok());
            }
        }
    }
    let kind = kind?;
    let proto = proto?;
    // Fields before the second `src=` are the original direction.
    let reply_at = fields
        .iter()
        .enumerate()
        .filter(|(_, (key, _))| *key == "src")
        .nth(1)
        .map(|(index, _)| index)
        .unwrap_or(fields.len());
    let (orig, reply) = fields.split_at(reply_at);
    fn get<'a>(side: &[(&str, &'a str)], key: &str) -> Option<&'a str> {
        side.iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| *value)
    }
    let number = |side: &[(&str, &str)], key: &str| -> u64 {
        get(side, key).and_then(|v| v.parse().ok()).unwrap_or(0)
    };
    let src: IpAddr = get(orig, "src")?.parse().ok()?;
    let dst: IpAddr = get(orig, "dst")?.parse().ok()?;
    let icmp = if matches!(proto, 1 | 58) {
        Some((
            number(orig, "type") as u8,
            number(orig, "code") as u8,
            number(orig, "id") as u16,
        ))
    } else {
        None
    };
    Some(CtEvent {
        kind,
        at,
        proto,
        src,
        dst,
        sport: number(orig, "sport") as u16,
        dport: number(orig, "dport") as u16,
        icmp,
        orig_packets: number(orig, "packets"),
        orig_bytes: number(orig, "bytes"),
        reply_packets: number(reply, "packets"),
        reply_bytes: number(reply, "bytes"),
    })
}

// ---------------------------------------------------------------------------
// NFLOG messages and rejected packets

/// Packet tuple of a rejected packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dropped {
    /// The rule's NFLOG prefix, e.g. `bt:acl:default`.
    pub prefix: String,
    pub at: Option<i64>,
    pub proto: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub icmp: Option<(u8, u8)>,
    pub length: u64,
}

fn be16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*data.get(at)?, *data.get(at + 1)?]))
}

/// Source, destination, protocol, source port, destination port, ICMP type
/// and code, and total length.
pub type Header = (IpAddr, IpAddr, u8, u16, u16, Option<(u8, u8)>, u64);

/// Reads addresses, protocol and ports from the start of an IP packet.
/// `length` is the packet's own total length (the copy may be cut short).
pub fn parse_ip_header(data: &[u8]) -> Option<Header> {
    let (src, dst, mut proto, mut offset, length) = match data.first()? >> 4 {
        4 => {
            let ihl = usize::from(data.first()? & 0x0f) * 4;
            if ihl < 20 || data.len() < 20 {
                return None;
            }
            let src = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
            let dst = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));
            // Later fragments carry no transport header.
            if be16(data, 6)? & 0x1fff != 0 {
                return Some((src, dst, data[9], 0, 0, None, u64::from(be16(data, 2)?)));
            }
            (src, dst, data[9], ihl, u64::from(be16(data, 2)?))
        }
        6 => {
            if data.len() < 40 {
                return None;
            }
            let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).ok()?));
            let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).ok()?));
            (src, dst, data[6], 40, 40 + u64::from(be16(data, 4)?))
        }
        _ => return None,
    };
    if src.is_ipv6() {
        // Walk a few extension headers; give up on fragments.
        for _ in 0..8 {
            match proto {
                0 | 43 | 60 => {
                    let next = *data.get(offset)?;
                    offset += (usize::from(*data.get(offset + 1)?) + 1) * 8;
                    proto = next;
                }
                44 => return Some((src, dst, *data.get(offset)?, 0, 0, None, length)),
                _ => break,
            }
        }
    }
    let (sport, dport, icmp) = match proto {
        6 | 17 | 132 | 136 => (be16(data, offset)?, be16(data, offset + 2)?, None),
        1 | 58 => (0, 0, Some((*data.get(offset)?, *data.get(offset + 1)?))),
        _ => (0, 0, None),
    };
    Some((src, dst, proto, sport, dport, icmp, length))
}

fn ne16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes([*data.get(at)?, *data.get(at + 1)?]))
}

fn ne32(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

const NFNL_SUBSYS_ULOG: u16 = 4;
const NFULNL_MSG_PACKET: u16 = 0;
const NFULA_TIMESTAMP: u16 = 3;
const NFULA_PAYLOAD: u16 = 9;
const NFULA_PREFIX: u16 = 10;

/// Parses one netlink datagram from an NFLOG socket into rejected packets.
pub fn parse_nflog_datagram(buffer: &[u8]) -> Vec<Dropped> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 16 <= buffer.len() {
        let Some(length) = ne32(buffer, at).map(|v| v as usize) else {
            break;
        };
        if length < 16 || at + length > buffer.len() {
            break;
        }
        let kind = ne16(buffer, at + 4).unwrap_or(0);
        if kind == (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET {
            // nlmsghdr (16) + nfgenmsg (4), then attributes.
            let message = &buffer[at..at + length];
            let mut prefix = String::new();
            let mut payload: Option<&[u8]> = None;
            let mut stamp = None;
            let mut cursor = 20;
            while cursor + 4 <= message.len() {
                let attr_len = usize::from(ne16(message, cursor).unwrap_or(0));
                let attr_type = ne16(message, cursor + 2).unwrap_or(0) & 0x3fff;
                if attr_len < 4 || cursor + attr_len > message.len() {
                    break;
                }
                let value = &message[cursor + 4..cursor + attr_len];
                match attr_type {
                    NFULA_PREFIX => {
                        prefix = String::from_utf8_lossy(value)
                            .trim_end_matches('\0')
                            .chars()
                            .take(32)
                            .collect();
                    }
                    NFULA_PAYLOAD => payload = Some(value),
                    NFULA_TIMESTAMP if value.len() >= 8 => {
                        stamp = Some(u64::from_be_bytes(value[..8].try_into().unwrap()) as i64);
                    }
                    _ => {}
                }
                cursor += (attr_len + 3) & !3;
            }
            if let Some((src, dst, proto, sport, dport, icmp, length)) =
                payload.and_then(parse_ip_header)
            {
                out.push(Dropped {
                    prefix,
                    at: stamp,
                    proto,
                    src,
                    dst,
                    sport,
                    dport,
                    icmp,
                    length,
                });
            }
        }
        at += (length + 3) & !3;
    }
    out
}

/// NFLOG rules to insert before each REJECT of a chain, as `-I <chain>
/// <position> ...` argument lists. `bodies` are the chain's rules without
/// the leading `-A <chain>`; `forward` selects the forward chain's prefixes.
/// Installed best-effort after the chain: a kernel without NFLOG keeps full
/// enforcement and only loses per-flow drop events.
pub fn drop_log_inserts(chain: &str, bodies: &[Vec<String>], forward: bool) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut inserted = 0;
    for (index, body) in bodies.iter().enumerate() {
        let Some(jump) = body.iter().position(|arg| arg == "-j") else {
            continue;
        };
        if body.get(jump + 1).map(String::as_str) != Some("REJECT") {
            continue;
        }
        let matches = &body[..jump];
        let explicit = if forward {
            matches.iter().any(|arg| arg == "-d")
        } else {
            matches.iter().any(|arg| arg == "--dport")
                || matches
                    .windows(2)
                    .any(|pair| pair[0] == "-p" && pair[1].starts_with("icmp"))
        };
        let prefix = match (forward, explicit) {
            (false, true) => "bt:acl:deny-rule",
            (false, false) => "bt:acl:default",
            (true, true) => "bt:fwd:deny-rule",
            (true, false) => "bt:fwd:default",
        };
        let mut rule = vec![
            "-I".to_string(),
            chain.to_string(),
            (index + 1 + inserted).to_string(),
        ];
        rule.extend(matches.iter().cloned());
        rule.extend(
            [
                "-m",
                "limit",
                "--limit",
                "50/second",
                "--limit-burst",
                "100",
                "-j",
                "NFLOG",
                "--nflog-group",
                &NFLOG_GROUP.to_string(),
                "--nflog-prefix",
                prefix,
            ]
            .map(str::to_owned),
        );
        out.push(rule);
        inserted += 1;
    }
    out
}

/// `rule_hint` for an NFLOG prefix.
pub fn hint_for(prefix: &str) -> Option<&'static str> {
    Some(match prefix {
        "bt:acl:deny-rule" => "acl:deny-rule",
        "bt:acl:default" => "acl:default",
        "bt:fwd:deny-rule" => "fwd:deny-rule",
        "bt:fwd:default" => "fwd:default",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Turning raw records into events

#[derive(Clone, Copy, Debug)]
struct Prefix {
    network: IpAddr,
    bits: u8,
}

impl Prefix {
    fn parse(value: &str) -> Option<Self> {
        let (address, bits) = match value.trim().split_once('/') {
            Some((address, bits)) => (address.parse().ok()?, bits.parse().ok()?),
            None => {
                let address: IpAddr = value.trim().parse().ok()?;
                (address, if address.is_ipv4() { 32 } else { 128 })
            }
        };
        let max = if address.is_ipv4() { 32 } else { 128 };
        (bits <= max).then_some(Self {
            network: address,
            bits,
        })
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

    fn host(&self) -> bool {
        self.bits == if self.network.is_ipv4() { 32 } else { 128 }
    }
}

/// This device's view of the overlay: its own addresses and which peer
/// carries which prefix.
#[derive(Clone, Debug, Default)]
pub struct Scope {
    own: Vec<IpAddr>,
    /// (prefix, peer id), most specific first.
    peers: Vec<(Prefix, String)>,
    relayed: Vec<String>,
}

impl Scope {
    /// `own` are this device's tunnel addresses (CIDR or bare); `peers` the
    /// peer map as (device id, allowed IPs); `relayed` peers on the relay.
    pub fn new(own: &[String], peers: &[(String, Vec<String>)], relayed: &[String]) -> Self {
        let mut list: Vec<(Prefix, String)> = peers
            .iter()
            .flat_map(|(id, ips)| {
                ips.iter()
                    .filter_map(|ip| Prefix::parse(ip))
                    .map(move |prefix| (prefix, id.clone()))
            })
            .collect();
        list.sort_by_key(|entry| std::cmp::Reverse(entry.0.bits));
        Self {
            own: own
                .iter()
                .filter_map(|value| Prefix::parse(value).map(|prefix| prefix.network))
                .collect(),
            peers: list,
            relayed: relayed.to_vec(),
        }
    }

    fn own(&self, address: IpAddr) -> bool {
        self.own.contains(&address)
    }

    fn peer_host(&self, address: IpAddr) -> bool {
        self.peers
            .iter()
            .any(|(prefix, _)| prefix.host() && prefix.network == address)
    }

    fn peer_for(&self, address: IpAddr) -> Option<String> {
        self.peers
            .iter()
            .find(|(prefix, _)| prefix.contains(address))
            .map(|(_, id)| id.clone())
    }

    /// Direction, connection type and carrying peer, or `None` when the
    /// connection is not overlay traffic of this device.
    fn classify(
        &self,
        src: IpAddr,
        dst: IpAddr,
    ) -> Option<(Direction, &'static str, Option<String>)> {
        let (own_src, own_dst) = (self.own(src), self.own(dst));
        let (direction, routed, peer) = match (own_src, own_dst) {
            (true, true) => return None,
            (true, false) => (Direction::Outbound, false, self.peer_for(dst)?),
            (false, true) => (Direction::Inbound, false, self.peer_for(src)?),
            // Forwarded for an overlay client (routing peer).
            (false, false) if self.peer_host(src) => {
                (Direction::Inbound, true, self.peer_for(src)?)
            }
            (false, false) => return None,
        };
        let connection = if routed {
            "routed"
        } else if self.relayed.contains(&peer) {
            "relay"
        } else {
            "p2p"
        };
        Some((direction, connection, Some(peer)))
    }
}

type TupleKey = (u8, IpAddr, IpAddr, u16, u16, u16);

/// Converts conntrack and NFLOG records into events, remembering which
/// connections started while reporting was on.
#[derive(Debug)]
pub struct Converter {
    instance: u32,
    next: u64,
    open: HashMap<TupleKey, (String, Direction, &'static str, Option<String>)>,
    order: VecDeque<TupleKey>,
    /// Drops merged per window; reset by `drain_drops`.
    drops: BTreeMap<TupleKey, FlowEvent>,
    pub drop_overflow: u64,
}

impl Default for Converter {
    fn default() -> Self {
        Self::new(std::process::id())
    }
}

impl Converter {
    pub fn new(instance: u32) -> Self {
        Self {
            instance,
            next: 0,
            open: HashMap::new(),
            order: VecDeque::new(),
            drops: BTreeMap::new(),
            drop_overflow: 0,
        }
    }

    fn flow_id(&mut self, tag: &str) -> String {
        self.next += 1;
        format!("{tag}{:x}-{:x}", self.instance, self.next)
    }

    fn key(proto: u8, src: IpAddr, dst: IpAddr, sport: u16, dport: u16, icmp_id: u16) -> TupleKey {
        (proto, src, dst, sport, dport, icmp_id)
    }

    /// One conntrack record; `now` stands in for a missing timestamp.
    pub fn connection(&mut self, record: &CtEvent, scope: &Scope, now: i64) -> Option<FlowEvent> {
        let key = Self::key(
            record.proto,
            record.src,
            record.dst,
            record.sport,
            record.dport,
            record.icmp.map_or(0, |(_, _, id)| id),
        );
        let at = record.at.unwrap_or(now);
        match record.kind {
            CtKind::New => {
                let (direction, connection, peer) = scope.classify(record.src, record.dst)?;
                let flow_id = self.flow_id("ct");
                if self.open.len() >= MAX_OPEN_FLOWS {
                    if let Some(oldest) = self.order.pop_front() {
                        self.open.remove(&oldest);
                    }
                }
                self.open
                    .insert(key, (flow_id.clone(), direction, connection, peer.clone()));
                self.order.push_back(key);
                let mut event = flow_events::event(
                    flow_id,
                    Kind::Start,
                    at,
                    direction,
                    record.proto,
                    (record.src, record.sport),
                    (record.dst, record.dport),
                    record.icmp.map(|(kind, code, _)| (kind, code)),
                );
                event.peer_id = peer;
                event.connection_type = connection;
                Some(event)
            }
            CtKind::Destroy => {
                // Only connections whose start was reported get an end.
                let (flow_id, direction, connection, peer) = self.open.remove(&key)?;
                let mut event = flow_events::event(
                    flow_id,
                    Kind::End,
                    at,
                    direction,
                    record.proto,
                    (record.src, record.sport),
                    (record.dst, record.dport),
                    record.icmp.map(|(kind, code, _)| (kind, code)),
                );
                event.peer_id = peer;
                event.connection_type = connection;
                // The original direction is what the initiator sent.
                if direction == Direction::Outbound {
                    event.tx_bytes = record.orig_bytes;
                    event.tx_packets = record.orig_packets;
                    event.rx_bytes = record.reply_bytes;
                    event.rx_packets = record.reply_packets;
                } else {
                    event.rx_bytes = record.orig_bytes;
                    event.rx_packets = record.orig_packets;
                    event.tx_bytes = record.reply_bytes;
                    event.tx_packets = record.reply_packets;
                }
                Some(event)
            }
        }
    }

    /// One rejected packet; repeats of a connection within the window add to
    /// its counters.
    pub fn dropped(&mut self, record: &Dropped, scope: &Scope, now: i64) {
        let key = Self::key(
            record.proto,
            record.src,
            record.dst,
            record.sport,
            record.dport,
            0,
        );
        if let Some(event) = self.drops.get_mut(&key) {
            event.rx_packets = event.rx_packets.saturating_add(1);
            event.rx_bytes = event.rx_bytes.saturating_add(record.length);
            return;
        }
        if self.drops.len() >= MAX_DROPS_PER_WINDOW {
            self.drop_overflow += 1;
            return;
        }
        let forwarded = record.prefix.starts_with("bt:fwd:");
        let (connection, peer) = if forwarded {
            ("routed", scope.peer_for(record.src))
        } else {
            match scope.classify(record.src, record.dst) {
                Some((_, connection, peer)) => (connection, peer),
                None => ("p2p", scope.peer_for(record.src)),
            }
        };
        let flow_id = self.flow_id("nf");
        let mut event = flow_events::event(
            flow_id,
            Kind::Drop,
            record.at.unwrap_or(now),
            Direction::Inbound,
            record.proto,
            (record.src, record.sport),
            (record.dst, record.dport),
            record.icmp,
        );
        event.peer_id = peer;
        event.connection_type = connection;
        event.rule_hint = hint_for(&record.prefix);
        event.rx_packets = 1;
        event.rx_bytes = record.length;
        self.drops.insert(key, event);
    }

    pub fn drain_drops(&mut self) -> Vec<FlowEvent> {
        std::mem::take(&mut self.drops).into_values().collect()
    }

    pub fn open_flows(&self) -> usize {
        self.open.len()
    }
}

// ---------------------------------------------------------------------------
// Linux runtime: conntrack child processes and the NFLOG socket.

#[cfg(target_os = "linux")]
pub use runtime::Capture;

#[cfg(target_os = "linux")]
mod runtime {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use tracing::{info, warn};

    const ACCT: &str = "/proc/sys/net/netfilter/nf_conntrack_acct";

    #[derive(Default)]
    struct Queues {
        connections: VecDeque<CtEvent>,
        drops: VecDeque<Dropped>,
        overflow: u64,
    }

    fn push<T>(queue: &mut VecDeque<T>, overflow: &mut u64, item: T) {
        if queue.len() >= MAX_QUEUED {
            queue.pop_front();
            *overflow += 1;
        }
        queue.push_back(item);
    }

    /// Running capture. Dropping it stops everything.
    pub struct Capture {
        children: Vec<Child>,
        stop: Arc<AtomicBool>,
        threads: Vec<JoinHandle<()>>,
        queues: Arc<Mutex<Queues>>,
        acct_before: Option<String>,
        pub converter: Converter,
    }

    impl Capture {
        pub fn start() -> Self {
            let queues = Arc::new(Mutex::new(Queues::default()));
            let stop = Arc::new(AtomicBool::new(false));
            let acct_before = std::fs::read_to_string(ACCT).ok();
            if acct_before.as_deref().map(str::trim) != Some("1") {
                if let Err(error) = std::fs::write(ACCT, "1") {
                    warn!(%error, "could not turn on conntrack accounting; flow end events will carry no byte counts");
                }
            }
            let mut children = Vec::new();
            let mut threads = Vec::new();
            for family in ["ipv4", "ipv6"] {
                match Command::new("conntrack")
                    .args([
                        "-E",
                        "-e",
                        "NEW,DESTROY",
                        "-o",
                        "timestamp,extended",
                        "-f",
                        family,
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                {
                    Ok(mut child) => {
                        let stdout = child.stdout.take();
                        let queues = queues.clone();
                        children.push(child);
                        if let Some(stdout) = stdout {
                            threads.push(std::thread::spawn(move || {
                                for line in BufReader::new(stdout).lines() {
                                    let Ok(line) = line else { break };
                                    if let Some(record) = parse_conntrack_line(&line) {
                                        if let Ok(mut queues) = queues.lock() {
                                            let queues = &mut *queues;
                                            push(
                                                &mut queues.connections,
                                                &mut queues.overflow,
                                                record,
                                            );
                                        }
                                    }
                                }
                            }));
                        }
                    }
                    Err(error) => {
                        warn!(%error, "conntrack (conntrack-tools) is not available; no per-connection start/end events");
                        break;
                    }
                }
            }
            match nflog::Socket::open(NFLOG_GROUP) {
                Ok(socket) => {
                    let queues = queues.clone();
                    let stop = stop.clone();
                    threads.push(std::thread::spawn(move || {
                        let mut buffer = vec![0u8; 65_536];
                        while !stop.load(Ordering::Relaxed) {
                            let Some(length) = socket.receive(&mut buffer) else {
                                continue;
                            };
                            let records = parse_nflog_datagram(&buffer[..length]);
                            if let Ok(mut queues) = queues.lock() {
                                let queues = &mut *queues;
                                for record in records {
                                    push(&mut queues.drops, &mut queues.overflow, record);
                                }
                            }
                        }
                    }));
                }
                Err(error) => {
                    warn!(%error, "could not bind the NFLOG group; no per-connection drop events");
                }
            }
            info!(
                conntrack = !children.is_empty(),
                "per-flow traffic capture started"
            );
            Self {
                children,
                stop,
                threads,
                queues,
                acct_before,
                converter: Converter::default(),
            }
        }

        /// Events since the last call, oldest first.
        pub fn drain(&mut self, scope: &Scope, now: i64) -> Vec<FlowEvent> {
            let (connections, drops, overflow) = match self.queues.lock() {
                Ok(mut queues) => (
                    std::mem::take(&mut queues.connections),
                    std::mem::take(&mut queues.drops),
                    std::mem::take(&mut queues.overflow),
                ),
                Err(_) => return Vec::new(),
            };
            if overflow > 0 {
                warn!(
                    overflow,
                    "traffic capture queue was full; oldest records dropped"
                );
            }
            let mut events: Vec<FlowEvent> = connections
                .iter()
                .filter_map(|record| self.converter.connection(record, scope, now))
                .collect();
            for record in &drops {
                self.converter.dropped(record, scope, now);
            }
            events.extend(self.converter.drain_drops());
            events
        }
    }

    impl Drop for Capture {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            for child in &mut self.children {
                let _ = child.kill();
                let _ = child.wait();
            }
            for thread in self.threads.drain(..) {
                let _ = thread.join();
            }
            if let Some(before) = &self.acct_before {
                if before.trim() != "1" {
                    let _ = std::fs::write(ACCT, before.trim());
                }
            }
        }
    }

    mod nflog {
        use super::super::NFLOG_COPY_BYTES;
        use std::io;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        const NETLINK_NETFILTER: libc::c_int = 12;
        const NFNL_SUBSYS_ULOG: u16 = 4;
        const NFULNL_MSG_CONFIG: u16 = 1;
        const NFULA_CFG_CMD: u16 = 1;
        const NFULA_CFG_MODE: u16 = 2;
        const NFULNL_CFG_CMD_BIND: u8 = 1;
        const NFULNL_COPY_PACKET: u8 = 2;

        pub struct Socket {
            fd: OwnedFd,
        }

        fn attribute(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
            let length = 4 + value.len();
            out.extend_from_slice(&(length as u16).to_ne_bytes());
            out.extend_from_slice(&kind.to_ne_bytes());
            out.extend_from_slice(value);
            while !out.len().is_multiple_of(4) {
                out.push(0);
            }
        }

        fn config(group: u16, attributes: &[(u16, Vec<u8>)], sequence: u32) -> Vec<u8> {
            let mut body = vec![libc::AF_UNSPEC as u8, 0];
            body.extend_from_slice(&group.to_be_bytes());
            for (kind, value) in attributes {
                attribute(&mut body, *kind, value);
            }
            let mut message = Vec::with_capacity(16 + body.len());
            message.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
            message.extend_from_slice(&((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG).to_ne_bytes());
            message
                .extend_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16).to_ne_bytes());
            message.extend_from_slice(&sequence.to_ne_bytes());
            message.extend_from_slice(&0u32.to_ne_bytes());
            message.extend_from_slice(&body);
            message
        }

        impl Socket {
            pub fn open(group: u16) -> io::Result<Self> {
                // SAFETY: plain socket(2); the descriptor is owned below.
                let raw = unsafe {
                    libc::socket(
                        libc::AF_NETLINK,
                        libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                        NETLINK_NETFILTER,
                    )
                };
                if raw < 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: `raw` is a fresh descriptor we own.
                let socket = Self {
                    fd: unsafe { OwnedFd::from_raw_fd(raw) },
                };
                // SAFETY: zeroed sockaddr_nl is valid; family set below.
                let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
                address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
                // SAFETY: valid pointer and length for sockaddr_nl.
                let bound = unsafe {
                    libc::bind(
                        socket.fd.as_raw_fd(),
                        std::ptr::addr_of!(address).cast(),
                        std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                    )
                };
                if bound < 0 {
                    return Err(io::Error::last_os_error());
                }
                let timeout = libc::timeval {
                    tv_sec: 1,
                    tv_usec: 0,
                };
                // SAFETY: valid timeval for SO_RCVTIMEO.
                unsafe {
                    libc::setsockopt(
                        socket.fd.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_RCVTIMEO,
                        std::ptr::addr_of!(timeout).cast(),
                        std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                    );
                }
                socket.request(&config(
                    group,
                    &[(NFULA_CFG_CMD, vec![NFULNL_CFG_CMD_BIND])],
                    1,
                ))?;
                let mut mode = NFLOG_COPY_BYTES.to_be_bytes().to_vec();
                mode.extend_from_slice(&[NFULNL_COPY_PACKET, 0]);
                socket.request(&config(group, &[(NFULA_CFG_MODE, mode)], 2))?;
                Ok(socket)
            }

            /// Sends a config request and checks the kernel's ack.
            fn request(&self, message: &[u8]) -> io::Result<()> {
                // SAFETY: valid buffer for send(2).
                let sent = unsafe {
                    libc::send(
                        self.fd.as_raw_fd(),
                        message.as_ptr().cast(),
                        message.len(),
                        0,
                    )
                };
                if sent < 0 {
                    return Err(io::Error::last_os_error());
                }
                let mut buffer = [0u8; 1024];
                let length = self
                    .receive(&mut buffer)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "no NFLOG ack"))?;
                if length >= 20
                    && u16::from_ne_bytes([buffer[4], buffer[5]]) == libc::NLMSG_ERROR as u16
                {
                    let code = i32::from_ne_bytes(buffer[16..20].try_into().unwrap());
                    if code != 0 {
                        return Err(io::Error::from_raw_os_error(-code));
                    }
                }
                Ok(())
            }

            pub fn receive(&self, buffer: &mut [u8]) -> Option<usize> {
                // SAFETY: valid buffer for recv(2).
                let length = unsafe {
                    libc::recv(
                        self.fd.as_raw_fd(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                        0,
                    )
                };
                (length > 0).then_some(length as usize)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NEW: &str = "[1782000000.123456]\t    [NEW] ipv4     2 tcp      6 120 SYN_SENT src=100.64.0.2 dst=100.64.0.3 sport=40000 dport=22 [UNREPLIED] src=100.64.0.3 dst=100.64.0.2 sport=22 dport=40000";
    const DESTROY: &str = "[1782000030.5]\t [DESTROY] ipv4     2 tcp      6 src=100.64.0.2 dst=100.64.0.3 sport=40000 dport=22 packets=12 bytes=2400 src=100.64.0.3 dst=100.64.0.2 sport=22 dport=40000 packets=10 bytes=9000 [ASSURED]";
    const PING: &str = "[1782000001.0] [NEW] ipv4 2 icmp 1 30 src=100.64.0.3 dst=100.64.0.2 type=8 code=0 id=4321 [UNREPLIED] src=100.64.0.2 dst=100.64.0.3 type=0 code=0 id=4321";
    const ROUTED: &str = "    [NEW] tcp      6 120 SYN_SENT src=100.64.0.3 dst=10.20.5.7 sport=50000 dport=5432 [UNREPLIED] src=10.20.5.7 dst=10.20.0.2 sport=5432 dport=50000";

    fn scope() -> Scope {
        Scope::new(
            &["100.64.0.2/32".into()],
            &[
                ("peer-b".into(), vec!["100.64.0.3/32".into()]),
                (
                    "router".into(),
                    vec!["100.64.0.9/32".into(), "10.30.0.0/16".into()],
                ),
            ],
            &[],
        )
    }

    #[test]
    fn conntrack_lines_parse_with_and_without_timestamps() {
        let new = parse_conntrack_line(NEW).unwrap();
        assert_eq!(new.kind, CtKind::New);
        assert_eq!(new.at, Some(1_782_000_000));
        assert_eq!((new.proto, new.sport, new.dport), (6, 40_000, 22));
        let destroy = parse_conntrack_line(DESTROY).unwrap();
        assert_eq!(
            (
                destroy.orig_packets,
                destroy.orig_bytes,
                destroy.reply_bytes
            ),
            (12, 2400, 9000)
        );
        let ping = parse_conntrack_line(PING).unwrap();
        assert_eq!(ping.icmp, Some((8, 0, 4321)));
        let routed = parse_conntrack_line(ROUTED).unwrap();
        assert_eq!(routed.at, None);
        assert_eq!(routed.dst, "10.20.5.7".parse::<IpAddr>().unwrap());
        assert!(parse_conntrack_line("[UPDATE] tcp 6 src=1.1.1.1 dst=2.2.2.2").is_none());
        assert!(parse_conntrack_line("garbage").is_none());
    }

    #[test]
    fn connections_become_start_and_end_events_for_overlay_traffic_only() {
        let scope = scope();
        let mut converter = Converter::new(1);
        let start = converter
            .connection(&parse_conntrack_line(NEW).unwrap(), &scope, 0)
            .unwrap();
        assert_eq!(start.kind, Kind::Start);
        assert_eq!(start.direction, Direction::Outbound);
        assert_eq!(start.peer_id.as_deref(), Some("peer-b"));
        assert_eq!(start.connection_type, "p2p");
        let end = converter
            .connection(&parse_conntrack_line(DESTROY).unwrap(), &scope, 0)
            .unwrap();
        assert_eq!(end.flow_id, start.flow_id);
        assert_eq!((end.tx_bytes, end.rx_bytes), (2400, 9000));
        assert_eq!(end.at, 1_782_000_030);
        // An end whose start was not seen is not reported.
        assert!(converter
            .connection(&parse_conntrack_line(DESTROY).unwrap(), &scope, 0)
            .is_none());
        let ping = converter
            .connection(&parse_conntrack_line(PING).unwrap(), &scope, 0)
            .unwrap();
        assert_eq!(ping.direction, Direction::Inbound);
        assert_eq!((ping.icmp_type, ping.src_port), (Some(8), 0));
        // Not overlay traffic of this device: skipped.
        let lan = "[NEW] tcp 6 120 SYN_SENT src=192.168.1.5 dst=192.168.1.1 sport=1 dport=2";
        assert!(converter
            .connection(&parse_conntrack_line(lan).unwrap(), &scope, 0)
            .is_none());
        // Forwarded for an overlay peer: routed, attributed to that peer.
        let routed = converter
            .connection(&parse_conntrack_line(ROUTED).unwrap(), &scope, 77)
            .unwrap();
        assert_eq!(routed.connection_type, "routed");
        assert_eq!(routed.direction, Direction::Inbound);
        assert_eq!(routed.at, 77);
        assert_eq!(routed.peer_id.as_deref(), Some("peer-b"));
    }

    fn ipv4_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&60u16.to_be_bytes());
        packet[9] = 6;
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dst);
        packet[20..22].copy_from_slice(&sport.to_be_bytes());
        packet[22..24].copy_from_slice(&dport.to_be_bytes());
        packet
    }

    fn nflog_message(prefix: &str, payload: &[u8]) -> Vec<u8> {
        let mut attrs = Vec::new();
        let mut add = |kind: u16, value: &[u8]| {
            attrs.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
            attrs.extend_from_slice(&kind.to_ne_bytes());
            attrs.extend_from_slice(value);
            while !attrs.len().is_multiple_of(4) {
                attrs.push(0);
            }
        };
        let mut text = prefix.as_bytes().to_vec();
        text.push(0);
        add(NFULA_PREFIX, &text);
        add(NFULA_PAYLOAD, payload);
        let mut message = Vec::new();
        message.extend_from_slice(&((20 + attrs.len()) as u32).to_ne_bytes());
        message.extend_from_slice(&((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET).to_ne_bytes());
        message.extend_from_slice(&0u16.to_ne_bytes());
        message.extend_from_slice(&[0u8; 8]);
        message.extend_from_slice(&[2, 0, 0x1e, 0xa1]);
        message.extend_from_slice(&attrs);
        message
    }

    #[test]
    fn nflog_datagrams_become_merged_drop_events() {
        let packet = ipv4_tcp([100, 64, 0, 3], [100, 64, 0, 2], 40_001, 3389);
        let mut datagram = nflog_message("bt:acl:deny-rule", &packet);
        datagram.extend(nflog_message("bt:acl:deny-rule", &packet));
        let fwd = ipv4_tcp([100, 64, 0, 3], [10, 30, 9, 9], 40_002, 80);
        datagram.extend(nflog_message("bt:fwd:default", &fwd));
        let records = parse_nflog_datagram(&datagram);
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].prefix, "bt:acl:deny-rule");
        assert_eq!(
            (records[0].sport, records[0].dport, records[0].length),
            (40_001, 3389, 60)
        );
        let scope = scope();
        let mut converter = Converter::new(1);
        for record in &records {
            converter.dropped(record, &scope, 500);
        }
        let drops = converter.drain_drops();
        assert_eq!(drops.len(), 2);
        let rdp = drops.iter().find(|e| e.dst_port == 3389).unwrap();
        assert_eq!((rdp.rx_packets, rdp.rule_hint), (2, Some("acl:deny-rule")));
        assert_eq!(rdp.peer_id.as_deref(), Some("peer-b"));
        let routed = drops.iter().find(|e| e.dst_port == 80).unwrap();
        assert_eq!(routed.connection_type, "routed");
        assert_eq!(routed.rule_hint, Some("fwd:default"));
        assert!(converter.drain_drops().is_empty());
        // Truncated or foreign messages are ignored.
        assert!(parse_nflog_datagram(&datagram[..10]).is_empty());
    }

    #[test]
    fn drop_logs_go_before_each_reject_with_the_right_prefix() {
        let bodies: Vec<Vec<String>> = [
            "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-s 100.64.0.3 -p tcp --dport 3389 -j REJECT --reject-with tcp-reset",
            "-s 100.64.0.3 -p tcp --dport 22 -j ACCEPT",
            "-s 100.64.0.3 -p tcp -j REJECT --reject-with tcp-reset",
            "-j REJECT --reject-with icmp-port-unreachable",
        ]
        .iter()
        .map(|rule| rule.split(' ').map(str::to_owned).collect())
        .collect();
        let inserts = drop_log_inserts("BLAKTAIL-ACL", &bodies, false);
        let lines: Vec<String> = inserts.iter().map(|rule| rule.join(" ")).collect();
        assert_eq!(lines.len(), 3);
        assert!(
            lines[0].starts_with("-I BLAKTAIL-ACL 2 -s 100.64.0.3 -p tcp --dport 3389 -m limit")
        );
        assert!(lines[0].ends_with("--nflog-prefix bt:acl:deny-rule"));
        // Positions account for the rules inserted before.
        assert!(lines[1].starts_with("-I BLAKTAIL-ACL 5 -s 100.64.0.3 -p tcp -m limit"));
        assert!(lines[1].ends_with("bt:acl:default"));
        assert!(lines[2].starts_with("-I BLAKTAIL-ACL 7 -m limit"));
        let forward = drop_log_inserts(
            "BLAKTAIL-FWD-NEW",
            &[
                "-s 100.64.0.5 -d 10.20.1.10/32 -p tcp --dport 8080 -j REJECT --reject-with tcp-reset"
                    .split(' ')
                    .map(str::to_owned)
                    .collect(),
                "-j REJECT --reject-with icmp-port-unreachable"
                    .split(' ')
                    .map(str::to_owned)
                    .collect(),
            ],
            true,
        );
        assert!(forward[0].join(" ").ends_with("bt:fwd:deny-rule"));
        assert!(forward[1].join(" ").ends_with("bt:fwd:default"));
        assert_eq!(forward[1][2], "3");
    }
}
