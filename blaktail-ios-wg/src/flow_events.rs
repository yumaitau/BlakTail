//! Per-flow traffic events (`POST /v1/nodes/{id}/flow-events`). Shared
//! verbatim by `blaktaild` (`#[path]` include) so every platform uploads the
//! same shape, sampling and bounds.
//!
//! An event carries: the reporter's flow id, start/end/drop, when, direction,
//! protocol (ICMP type and code), overlay source and destination addresses
//! and ports, the WireGuard peer that carried it, byte and packet counters
//! and how it travelled. Never a payload, URL, DNS name or HTTP data.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;

/// Seconds between event uploads (the aggregation window).
pub const UPLOAD_EVERY_SECS: i64 = 30;
/// Coordinator batch cap (`flow_events::MAX_EVENTS_PER_BATCH`).
pub const MAX_BATCH: usize = 1_000;
/// Events held between uploads; older ones are dropped and counted.
pub const MAX_BUFFERED: usize = 4_096;
/// Coordinator window cap (`flow_events::MAX_WINDOW_SECS`).
pub const MAX_WINDOW_SECS: i64 = 3_600;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Start,
    End,
    Drop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
}

/// One event in the coordinator's wire shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FlowEvent {
    pub flow_id: String,
    #[serde(rename = "type")]
    pub kind: Kind,
    pub at: i64,
    pub direction: Direction,
    /// `tcp`, `udp`, `icmp`, `icmpv6` or `other`.
    pub protocol: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_number: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_type: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_code: Option<u8>,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_id: Option<String>,
    /// `p2p`, `routed` or `relay`.
    pub connection_type: &'static str,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_hint: Option<&'static str>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub aggregated: bool,
}

/// Protocol label and number from an IP protocol number.
pub fn protocol(number: u8) -> (&'static str, Option<u8>) {
    match number {
        6 => ("tcp", None),
        17 => ("udp", None),
        1 => ("icmp", None),
        58 => ("icmpv6", None),
        other => ("other", Some(other)),
    }
}

/// Builds an event from a connection's endpoints, fixing the fields the
/// coordinator requires per protocol (no ports for ICMP and other
/// protocols; an ICMP type for ICMP).
#[allow(clippy::too_many_arguments)]
pub fn event(
    flow_id: String,
    kind: Kind,
    at: i64,
    direction: Direction,
    proto: u8,
    source: (IpAddr, u16),
    destination: (IpAddr, u16),
    icmp: Option<(u8, u8)>,
) -> FlowEvent {
    let (protocol, protocol_number) = protocol(proto);
    let ports = matches!(protocol, "tcp" | "udp");
    let icmp = if matches!(protocol, "icmp" | "icmpv6") {
        Some(icmp.unwrap_or(if protocol == "icmp" { (8, 0) } else { (128, 0) }))
    } else {
        None
    };
    FlowEvent {
        flow_id,
        kind,
        at,
        direction,
        protocol,
        protocol_number,
        icmp_type: icmp.map(|(kind, _)| kind),
        icmp_code: icmp.map(|(_, code)| code),
        src_ip: source.0.to_string(),
        src_port: if ports { source.1 } else { 0 },
        dst_ip: destination.0.to_string(),
        dst_port: if ports { destination.1 } else { 0 },
        peer_id: None,
        connection_type: "p2p",
        rx_bytes: 0,
        tx_bytes: 0,
        rx_packets: 0,
        tx_packets: 0,
        rule_hint: None,
        aggregated: false,
    }
}

impl FlowEvent {
    /// Whether the coordinator would accept this event's ports.
    pub fn uploadable(&self) -> bool {
        match self.protocol {
            "tcp" | "udp" => self.dst_port != 0 && (self.src_port != 0 || self.aggregated),
            _ => true,
        }
    }
}

/// Bounded event queue between uploads.
#[derive(Debug, Default)]
pub struct Buffer {
    events: VecDeque<FlowEvent>,
    /// Events dropped because the buffer was full.
    pub overflow: u64,
}

impl Buffer {
    pub fn push(&mut self, event: FlowEvent) {
        if self.events.len() >= MAX_BUFFERED {
            self.events.pop_front();
            self.overflow += 1;
        }
        self.events.push_back(event);
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn clear(&mut self) {
        self.events.clear();
        self.overflow = 0;
    }

    /// Takes up to `max` events, oldest first.
    pub fn take(&mut self, max: usize) -> Vec<FlowEvent> {
        let count = self.events.len().min(max);
        self.events.drain(..count).collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = &FlowEvent> {
        self.events.iter()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Upload {
    pub org_id: String,
    pub window_start: i64,
    pub window_end: i64,
    pub events: Vec<FlowEvent>,
}

/// Coordinator's per-flow sampling draw (`flow_events::sample_draw`).
pub fn sample_draw(org_id: &str, reporter_id: &str, flow_id: &str) -> u64 {
    let digest = Sha256::digest(format!("{org_id}|{reporter_id}|{flow_id}").as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes)
}

pub fn sampled(rate: f64, draw: u64) -> bool {
    if !rate.is_finite() || rate <= 0.0 {
        return false;
    }
    rate >= 1.0 || (draw as f64 / u64::MAX as f64) < rate
}

pub struct Window<'a> {
    pub org_id: &'a str,
    pub device_id: &'a str,
    pub start: i64,
    pub end: i64,
    pub sampling_rate: f64,
    /// Peers currently reached through a relay: their events say `relay`.
    pub relayed_peers: &'a [String],
}

/// Builds one upload: drops sampled-out and malformed events, marks relayed
/// peers, clamps the window to what the coordinator accepts and keeps every
/// event's time inside it, and caps the batch.
pub fn build(window: &Window<'_>, events: Vec<FlowEvent>) -> Upload {
    let end = window.end.max(window.start);
    let start = window.start.max(end - MAX_WINDOW_SECS).max(0);
    let events: Vec<FlowEvent> = events
        .into_iter()
        .filter(FlowEvent::uploadable)
        .filter(|event| {
            sampled(
                window.sampling_rate,
                sample_draw(window.org_id, window.device_id, &event.flow_id),
            )
        })
        .map(|mut event| {
            event.at = event.at.clamp(start, end);
            if event.connection_type == "p2p"
                && event
                    .peer_id
                    .as_ref()
                    .is_some_and(|peer| window.relayed_peers.contains(peer))
            {
                event.connection_type = "relay";
            }
            event
        })
        .take(MAX_BATCH)
        .collect();
    Upload {
        org_id: window.org_id.to_owned(),
        window_start: start,
        window_end: end,
        events,
    }
}

/// Aggregated events for platforms that only see per-rule counters (macOS
/// pf): one honest `aggregated` event per peer, protocol, port and verdict
/// for the window, from the peer's overlay address to this device's. The
/// source port is unknown and sent as 0.
pub fn aggregated(
    counts: &[crate::flow_report::FlowCount],
    peer_addresses: &BTreeMap<String, Vec<IpAddr>>,
    own: &[IpAddr],
    window_start: i64,
    window_end: i64,
) -> Vec<FlowEvent> {
    let mut out = Vec::new();
    for count in counts {
        if count.bytes == 0 && count.packets == 0 {
            continue;
        }
        let proto = match count.proto {
            "tcp" => 6,
            "udp" => 17,
            "icmp" => 1,
            // Not split by protocol or port: nothing honest to say per flow.
            _ => continue,
        };
        if matches!(proto, 6 | 17) && count.port == 0 {
            continue;
        }
        let Some(peer) = count.peer_id.as_ref() else {
            continue;
        };
        let Some(remote) = peer_addresses.get(peer).and_then(|list| list.first()) else {
            continue;
        };
        let Some(local) = own
            .iter()
            .find(|address| address.is_ipv4() == remote.is_ipv4())
        else {
            continue;
        };
        let inbound = count.direction != "outbound";
        let (source, destination) = if inbound {
            ((*remote, 0), (*local, count.port))
        } else {
            ((*local, 0), (*remote, count.port))
        };
        let proto = if proto == 1 && remote.is_ipv6() {
            58
        } else {
            proto
        };
        let mut event = event(
            format!(
                "agg-{window_start}-{peer}-{}-{}-{}",
                count.proto,
                count.port,
                if count.allowed { "a" } else { "d" }
            )
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .take(64)
            .collect(),
            if count.allowed {
                Kind::Start
            } else {
                Kind::Drop
            },
            window_start,
            if inbound {
                Direction::Inbound
            } else {
                Direction::Outbound
            },
            proto,
            source,
            destination,
            None,
        );
        event.at = window_end;
        event.peer_id = Some(peer.clone());
        event.aggregated = true;
        if inbound {
            event.rx_bytes = count.bytes;
            event.rx_packets = count.packets;
        } else {
            event.tx_bytes = count.bytes;
            event.tx_packets = count.packets;
        }
        out.push(event);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(flow: &str) -> FlowEvent {
        event(
            flow.into(),
            Kind::Start,
            100,
            Direction::Outbound,
            6,
            ("100.64.0.2".parse().unwrap(), 50_000),
            ("100.64.0.3".parse().unwrap(), 22),
            None,
        )
    }

    #[test]
    fn events_follow_the_protocol_rules_and_carry_no_payload_fields() {
        let ping = event(
            "p".into(),
            Kind::Start,
            1,
            Direction::Outbound,
            1,
            ("100.64.0.2".parse().unwrap(), 77),
            ("100.64.0.3".parse().unwrap(), 0),
            None,
        );
        assert_eq!((ping.src_port, ping.icmp_type), (0, Some(8)));
        let gre = event(
            "g".into(),
            Kind::Drop,
            1,
            Direction::Inbound,
            47,
            ("100.64.0.2".parse().unwrap(), 0),
            ("100.64.0.3".parse().unwrap(), 0),
            None,
        );
        assert_eq!((gre.protocol, gre.protocol_number), ("other", Some(47)));
        let json = serde_json::to_value(tcp("a")).unwrap();
        let allowed = [
            "flow_id",
            "type",
            "at",
            "direction",
            "protocol",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "connection_type",
            "rx_bytes",
            "tx_bytes",
            "rx_packets",
            "tx_packets",
        ];
        for key in json.as_object().unwrap().keys() {
            assert!(allowed.contains(&key.as_str()), "{key}");
        }
    }

    #[test]
    fn buffer_is_bounded_and_upload_samples_whole_flows() {
        let mut buffer = Buffer::default();
        for i in 0..MAX_BUFFERED + 10 {
            buffer.push(tcp(&format!("f{i}")));
        }
        assert_eq!(buffer.len(), MAX_BUFFERED);
        assert_eq!(buffer.overflow, 10);
        let taken = buffer.take(MAX_BATCH);
        assert_eq!(taken.len(), MAX_BATCH);
        assert_eq!(taken[0].flow_id, "f10");
        let window = Window {
            org_id: "org",
            device_id: "dev",
            start: 90,
            end: 120,
            sampling_rate: 0.5,
            relayed_peers: &[],
        };
        let mut events = Vec::new();
        for i in 0..200 {
            let mut start = tcp(&format!("x{i}"));
            let mut end = start.clone();
            end.kind = Kind::End;
            start.at = 10; // clamped into the window
            events.push(start);
            events.push(end);
        }
        let upload = build(&window, events);
        assert_eq!(upload.events.len() % 2, 0);
        assert!(upload.events.len() > 100 && upload.events.len() < 300);
        assert!(upload.events.iter().all(|e| (90..=120).contains(&e.at)));
        assert!(build(
            &Window {
                sampling_rate: 0.0,
                ..window
            },
            vec![tcp("z")]
        )
        .events
        .is_empty());
    }

    #[test]
    fn relayed_peers_are_marked_and_portless_tcp_is_dropped() {
        let relayed = ["peer-1".to_owned()];
        let mut via_relay = tcp("r");
        via_relay.peer_id = Some("peer-1".into());
        let mut broken = tcp("b");
        broken.src_port = 0;
        let upload = build(
            &Window {
                org_id: "o",
                device_id: "d",
                start: 0,
                end: 200,
                sampling_rate: 1.0,
                relayed_peers: &relayed,
            },
            vec![via_relay, tcp("p"), broken],
        );
        assert_eq!(upload.events.len(), 2);
        assert_eq!(upload.events[0].connection_type, "relay");
        assert_eq!(upload.events[1].connection_type, "p2p");
    }

    #[test]
    fn aggregated_events_are_marked_and_attributed() {
        let counts = vec![
            crate::flow_report::FlowCount {
                peer_id: Some("peer".into()),
                direction: "inbound",
                proto: "tcp",
                port: 22,
                allowed: false,
                bytes: 120,
                packets: 2,
            },
            crate::flow_report::FlowCount {
                peer_id: Some("peer".into()),
                direction: "inbound",
                proto: "all",
                port: 0,
                allowed: false,
                bytes: 1,
                packets: 1,
            },
        ];
        let mut peers = BTreeMap::new();
        peers.insert("peer".to_owned(), vec!["100.64.0.9".parse().unwrap()]);
        let events = aggregated(&counts, &peers, &["100.64.0.2".parse().unwrap()], 60, 90);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert!(event.aggregated && event.uploadable());
        assert_eq!(event.kind, Kind::Drop);
        assert_eq!((event.src_ip.as_str(), event.dst_port), ("100.64.0.9", 22));
        assert_eq!(event.rx_packets, 2);
    }
}
