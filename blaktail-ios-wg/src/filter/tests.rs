use super::*;
use serde::Deserialize;

const LOCAL: &str = "100.64.0.1";
const PEER: &str = "100.64.0.2";
const LOCAL6: &str = "fd7a:115c:a1e0::1";
const PEER6: &str = "fd7a:115c:a1e0::2";

fn ip(value: &str) -> IpAddr {
    value.parse().unwrap()
}

fn ipv4(src: &str, dst: &str, proto: u8, payload: &[u8]) -> Vec<u8> {
    let (IpAddr::V4(src), IpAddr::V4(dst)) = (ip(src), ip(dst)) else {
        panic!("ipv4 addresses");
    };
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = proto;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    packet.extend_from_slice(payload);
    packet
}

fn ipv6(src: &str, dst: &str, next: u8, payload: &[u8]) -> Vec<u8> {
    let (IpAddr::V6(src), IpAddr::V6(dst)) = (ip(src), ip(dst)) else {
        panic!("ipv6 addresses");
    };
    let mut packet = vec![0u8; 40];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    packet[6] = next;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&src.octets());
    packet[24..40].copy_from_slice(&dst.octets());
    packet.extend_from_slice(payload);
    packet
}

fn tcp(sport: u16, dport: u16, flags: u8) -> Vec<u8> {
    let mut header = vec![0u8; 20];
    header[0..2].copy_from_slice(&sport.to_be_bytes());
    header[2..4].copy_from_slice(&dport.to_be_bytes());
    header[12] = 0x50;
    header[13] = flags;
    header
}

fn udp(sport: u16, dport: u16) -> Vec<u8> {
    let mut header = vec![0u8; 8];
    header[0..2].copy_from_slice(&sport.to_be_bytes());
    header[2..4].copy_from_slice(&dport.to_be_bytes());
    header[4..6].copy_from_slice(&8u16.to_be_bytes());
    header
}

fn icmp_msg(kind: u8, ident: u16, body: &[u8]) -> Vec<u8> {
    let mut header = vec![0u8; 8];
    header[0] = kind;
    header[4..6].copy_from_slice(&ident.to_be_bytes());
    header.extend_from_slice(body);
    header
}

fn packet_for(src: &str, dst: &str, proto: &str, port: u16) -> Vec<u8> {
    let v6 = src.contains(':');
    let build = |next: u8, payload: Vec<u8>| {
        if v6 {
            ipv6(src, dst, next, &payload)
        } else {
            ipv4(src, dst, next, &payload)
        }
    };
    match proto {
        "tcp" => build(TCP, tcp(40_000, port, 0x02)),
        "udp" => build(UDP, udp(40_000, port)),
        "icmp" if v6 => build(ICMPV6, icmp_msg(128, 7, &[])),
        "icmp" => build(ICMP, icmp_msg(8, 7, &[])),
        "gre" => build(47, vec![0u8; 8]),
        other => panic!("unknown proto {other}"),
    }
}

fn peer(id: &str, ips: &[&str], ingress: Option<Ingress>) -> PolicyPeer {
    PolicyPeer {
        id: id.into(),
        allowed_ips: ips.iter().map(|value| value.to_string()).collect(),
        ingress,
        pq: None,
    }
}

fn filter_with(peers: &[PolicyPeer]) -> Filter {
    let mut filter = Filter::new();
    filter.set_policy(Policy::compile(peers, None));
    filter
}

fn deny_all() -> Filter {
    let mut filter = Filter::new();
    filter.set_policy(Policy::deny_all());
    filter
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    peers: Vec<PolicyPeer>,
    checks: Vec<(String, String, u16, bool)>,
}

/// The same vectors drive `blaktaild`'s Linux chain test, so both enforce
/// the same decisions for new inbound flows.
#[test]
fn shared_vectors_match_linux_semantics() {
    let vectors: Vec<Vector> =
        serde_json::from_str(include_str!("../filter_vectors.json")).unwrap();
    assert!(vectors.len() >= 8);
    for vector in vectors {
        for (src, proto, port, expect) in &vector.checks {
            let mut filter = filter_with(&vector.peers);
            let dst = if src.contains(':') { LOCAL6 } else { LOCAL };
            let packet = packet_for(src, dst, proto, *port);
            assert_eq!(
                filter.inbound(&packet, 1),
                *expect,
                "{}: {src} {proto}/{port}",
                vector.name
            );
        }
    }
}

#[test]
fn replies_to_outbound_flows_pass_a_deny_all_policy() {
    let mut filter = deny_all();
    filter.outbound(&ipv4(LOCAL, PEER, TCP, &tcp(50_000, 443, 0x02)), 1);
    assert!(filter.inbound(&ipv4(PEER, LOCAL, TCP, &tcp(443, 50_000, 0x12)), 2));
    // Same peer, different port pair: a new connection, denied.
    assert!(!filter.inbound(&ipv4(PEER, LOCAL, TCP, &tcp(443, 50_001, 0x12)), 2));
    assert!(!filter.inbound(&ipv4(PEER, LOCAL, TCP, &tcp(50_000, 22, 0x02)), 2));

    filter.outbound(&ipv4(LOCAL, PEER, UDP, &udp(5353, 53)), 3);
    assert!(filter.inbound(&ipv4(PEER, LOCAL, UDP, &udp(53, 5353)), 4));
    assert!(!filter.inbound(&ipv4(PEER, LOCAL, UDP, &udp(54, 5353)), 4));

    filter.outbound(&ipv6(LOCAL6, PEER6, TCP, &tcp(50_000, 22, 0x02)), 5);
    assert!(filter.inbound(&ipv6(PEER6, LOCAL6, TCP, &tcp(22, 50_000, 0x12)), 6));
}

#[test]
fn icmp_echo_replies_and_requests() {
    let mut filter = deny_all();
    filter.outbound(&ipv4(LOCAL, PEER, ICMP, &icmp_msg(8, 99, &[])), 1);
    assert!(filter.inbound(&ipv4(PEER, LOCAL, ICMP, &icmp_msg(0, 99, &[])), 2));
    assert!(!filter.inbound(&ipv4(PEER, LOCAL, ICMP, &icmp_msg(0, 98, &[])), 2));
    assert!(!filter.inbound(&ipv4(PEER, LOCAL, ICMP, &icmp_msg(8, 5, &[])), 2));

    filter.outbound(&ipv6(LOCAL6, PEER6, ICMPV6, &icmp_msg(128, 3, &[])), 3);
    assert!(filter.inbound(&ipv6(PEER6, LOCAL6, ICMPV6, &icmp_msg(129, 3, &[])), 4));

    let mut granted = filter_with(&[peer(
        "p",
        &["100.64.0.2/32"],
        Some(Ingress {
            icmp: true,
            ..Ingress::default()
        }),
    )]);
    assert!(granted.inbound(&ipv4(PEER, LOCAL, ICMP, &icmp_msg(8, 5, &[])), 1));
    // Our echo reply belongs to the inbound flow, and is never blocked.
    granted.outbound(&ipv4(LOCAL, PEER, ICMP, &icmp_msg(0, 5, &[])), 1);
    assert_eq!(granted.state_count(), 1);
}

#[test]
fn icmp_errors_pass_only_when_related_to_a_tracked_flow() {
    let mut filter = deny_all();
    let sent = ipv4(LOCAL, PEER, UDP, &udp(5000, 9999));
    filter.outbound(&sent, 1);
    let unreachable = ipv4(PEER, LOCAL, ICMP, &icmp_msg(3, 0, &sent[..28]));
    assert!(filter.inbound(&unreachable, 2));
    let unrelated = ipv4(LOCAL, PEER, UDP, &udp(5001, 9999));
    assert!(!filter.inbound(
        &ipv4(PEER, LOCAL, ICMP, &icmp_msg(3, 0, &unrelated[..28])),
        2
    ));
    // A truncated embedded header is dropped, not trusted.
    assert!(!filter.inbound(&ipv4(PEER, LOCAL, ICMP, &icmp_msg(3, 0, &sent[..22])), 2));

    let sent6 = ipv6(LOCAL6, PEER6, TCP, &tcp(41_000, 443, 0x02));
    filter.outbound(&sent6, 3);
    let too_big = ipv6(PEER6, LOCAL6, ICMPV6, &icmp_msg(2, 0, &sent6[..48]));
    assert!(filter.inbound(&too_big, 4));
}

fn fragment_v4(
    src: &str,
    dst: &str,
    ident: u16,
    offset_words: u16,
    more: bool,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = ipv4(src, dst, UDP, payload);
    packet[4..6].copy_from_slice(&ident.to_be_bytes());
    let flags = offset_words | if more { 0x2000 } else { 0 };
    packet[6..8].copy_from_slice(&flags.to_be_bytes());
    packet
}

#[test]
fn fragments_follow_their_first_fragment_or_are_dropped() {
    let allow_dns = [peer(
        "p",
        &["100.64.0.2/32"],
        Some(Ingress {
            udp: vec!["53".into()],
            ..Ingress::default()
        }),
    )];
    let mut filter = filter_with(&allow_dns);
    let mut first_payload = udp(40_000, 53);
    first_payload.extend_from_slice(&[0u8; 16]);
    assert!(filter.inbound(&fragment_v4(PEER, LOCAL, 7, 0, true, &first_payload), 1));
    assert!(filter.inbound(&fragment_v4(PEER, LOCAL, 7, 3, false, &[0u8; 24]), 1));
    // Orphan later fragment: no first fragment seen.
    assert!(!filter.inbound(&fragment_v4(PEER, LOCAL, 8, 3, false, &[0u8; 24]), 1));
    // Denied first fragment: its later fragments are dropped too.
    let mut denied = udp(40_000, 54);
    denied.extend_from_slice(&[0u8; 16]);
    assert!(!filter.inbound(&fragment_v4(PEER, LOCAL, 9, 0, true, &denied), 1));
    assert!(!filter.inbound(&fragment_v4(PEER, LOCAL, 9, 3, false, &[0u8; 24]), 1));
    // Cached decisions expire.
    assert!(filter.inbound(&fragment_v4(PEER, LOCAL, 10, 0, true, &first_payload), 1));
    assert!(!filter.inbound(&fragment_v4(PEER, LOCAL, 10, 3, false, &[0u8; 24]), 100));

    // IPv6 fragment header.
    let mut filter = filter_with(&[peer(
        "p",
        &["fd7a:115c:a1e0::2/128"],
        Some(Ingress {
            udp: vec!["53".into()],
            ..Ingress::default()
        }),
    )]);
    let frag6 = |offset: u16, more: bool, body: &[u8]| {
        let mut header = vec![UDP, 0, 0, 0, 0, 0, 0, 42];
        header[2..4].copy_from_slice(&((offset << 3) | u16::from(more)).to_be_bytes());
        header.extend_from_slice(body);
        ipv6(PEER6, LOCAL6, 44, &header)
    };
    assert!(filter.inbound(&frag6(0, true, &first_payload), 1));
    assert!(filter.inbound(&frag6(3, false, &[0u8; 16]), 1));
    let mut wrong_port = udp(40_000, 80);
    wrong_port.extend_from_slice(&[0u8; 16]);
    let mut filter2 = deny_all();
    assert!(!filter2.inbound(&frag6(0, true, &wrong_port), 1));
    assert!(!filter2.inbound(&frag6(3, false, &[0u8; 16]), 1));
}

fn ext_header(next: u8) -> Vec<u8> {
    vec![next, 0, 0, 0, 0, 0, 0, 0]
}

#[test]
fn ipv6_extension_headers_are_walked_with_a_bound() {
    let allow = [peer(
        "p",
        &["fd7a:115c:a1e0::2/128"],
        Some(Ingress {
            tcp: vec!["443".into()],
            ..Ingress::default()
        }),
    )];
    let mut chained = ext_header(60);
    chained.extend(ext_header(TCP));
    chained.extend(tcp(40_000, 443, 0x02));
    let mut filter = filter_with(&allow);
    assert!(filter.inbound(&ipv6(PEER6, LOCAL6, 0, &chained), 1));

    let mut denied = ext_header(TCP);
    denied.extend(tcp(40_000, 22, 0x02));
    assert!(!filter.inbound(&ipv6(PEER6, LOCAL6, 60, &denied), 1));

    // More than MAX_EXT_HEADERS headers: malformed, dropped even for `all`.
    let all = [peer(
        "p",
        &["fd7a:115c:a1e0::2/128"],
        Some(Ingress {
            all: true,
            ..Ingress::default()
        }),
    )];
    let mut long = Vec::new();
    for _ in 0..MAX_EXT_HEADERS {
        long.extend(ext_header(60));
    }
    long.extend(ext_header(TCP));
    long.extend(tcp(40_000, 443, 0x02));
    let mut filter = filter_with(&all);
    assert!(!filter.inbound(&ipv6(PEER6, LOCAL6, 60, &long), 1));
    // Header length pointing past the packet.
    let truncated = vec![TCP, 200, 0, 0, 0, 0, 0, 0];
    assert!(!filter.inbound(&ipv6(PEER6, LOCAL6, 60, &truncated), 1));
}

#[test]
fn malformed_packets_are_dropped() {
    let all = [peer(
        "p",
        &["100.64.0.2/32"],
        Some(Ingress {
            all: true,
            ..Ingress::default()
        }),
    )];
    let mut filter = filter_with(&all);
    assert!(filter.inbound(&ipv4(PEER, LOCAL, TCP, &tcp(1, 443, 2)), 1));
    assert!(!filter.inbound(&ipv4(PEER, LOCAL, TCP, &tcp(1, 443, 2)[..10]), 1));
    assert!(!filter.inbound(&[], 1));
    assert!(!filter.inbound(&[0x55; 40], 1));
    let mut lying = ipv4(PEER, LOCAL, TCP, &tcp(1, 443, 2));
    lying[2..4].copy_from_slice(&200u16.to_be_bytes());
    assert!(!filter.inbound(&lying, 1));
    let mut short_ihl = ipv4(PEER, LOCAL, TCP, &tcp(1, 443, 2));
    short_ihl[0] = 0x44;
    assert!(!filter.inbound(&short_ihl, 1));
}

#[test]
fn state_table_is_bounded_and_evicts_oldest() {
    let mut filter = deny_all();
    let total = MAX_STATES + 100;
    for index in 0..total {
        let port = 1024 + (index % 60_000) as u16;
        let host = format!("100.64.{}.{}", 1 + index / 60_000, 2);
        filter.outbound(&ipv4(LOCAL, &host, UDP, &udp(port, 53)), 1);
    }
    assert!(filter.state_count() <= MAX_STATES);
    assert!(filter.order.len() <= MAX_STATES * 2);
    // Oldest flow evicted; newest still tracked.
    assert!(!filter.inbound(&ipv4("100.64.1.2", LOCAL, UDP, &udp(53, 1024)), 1));
    let last = total - 1;
    let host = format!("100.64.{}.{}", 1 + last / 60_000, 2);
    let port = 1024 + (last % 60_000) as u16;
    assert!(filter.inbound(&ipv4(&host, LOCAL, UDP, &udp(53, port)), 1));
}

#[test]
fn states_expire() {
    let mut filter = deny_all();
    filter.outbound(&ipv4(LOCAL, PEER, UDP, &udp(5000, 53)), 0);
    assert!(!filter.inbound(&ipv4(PEER, LOCAL, UDP, &udp(53, 5000)), UDP_NEW_SECS + 1));
    filter.outbound(&ipv4(LOCAL, PEER, TCP, &tcp(5000, 443, 0x02)), 0);
    assert!(filter.inbound(&ipv4(PEER, LOCAL, TCP, &tcp(443, 5000, 0x12)), 5));
    assert!(filter.inbound(&ipv4(PEER, LOCAL, TCP, &tcp(443, 5000, 0x10)), 3_000));
    filter.outbound(&ipv4(LOCAL, PEER, TCP, &tcp(5000, 443, 0x04)), 3_001);
    assert!(!filter.inbound(
        &ipv4(PEER, LOCAL, TCP, &tcp(443, 5000, 0x10)),
        3_001 + TCP_RST_SECS + 1
    ));
    assert_eq!(filter.state_count(), 0);
}

#[test]
fn policy_change_ends_inbound_flows_it_no_longer_allows() {
    let grant = |ports: &[&str]| {
        [peer(
            "p",
            &["100.64.0.2/32"],
            Some(Ingress {
                tcp: ports.iter().map(|port| port.to_string()).collect(),
                ..Ingress::default()
            }),
        )]
    };
    let mut filter = filter_with(&grant(&["22", "80"]));
    assert!(filter.inbound(&ipv4(PEER, LOCAL, TCP, &tcp(40_000, 22, 0x02)), 1));
    assert!(filter.inbound(&ipv4(PEER, LOCAL, TCP, &tcp(40_001, 80, 0x02)), 1));
    filter.outbound(&ipv4(LOCAL, PEER, TCP, &tcp(50_000, 443, 0x02)), 1);
    filter.set_policy(Policy::compile(&grant(&["80"]), None));
    assert!(!filter.inbound(&ipv4(PEER, LOCAL, TCP, &tcp(40_000, 22, 0x10)), 2));
    assert!(filter.inbound(&ipv4(PEER, LOCAL, TCP, &tcp(40_001, 80, 0x10)), 2));
    assert!(filter.inbound(&ipv4(PEER, LOCAL, TCP, &tcp(443, 50_000, 0x12)), 2));
}

#[test]
fn pq_port_opens_only_when_requested_and_pair_has_pq() {
    let mut with_pq = peer("p", &["100.64.0.2/32"], Some(Ingress::default()));
    with_pq.pq = Some(PqHint {
        mode: "prefer".into(),
        capable: true,
    });
    let packet = ipv4(PEER, LOCAL, TCP, &tcp(40_000, 51_822, 0x02));
    let mut filter = Filter::new();
    filter.set_policy(Policy::compile(
        std::slice::from_ref(&with_pq),
        Some(51_822),
    ));
    assert!(filter.inbound(&packet, 1));
    let mut filter = Filter::new();
    filter.set_policy(Policy::compile(&[with_pq], None));
    assert!(!filter.inbound(&packet, 1));
}

fn sample<'a>(
    report: &'a TrafficReport,
    direction: Direction,
    decision: &str,
) -> Vec<&'a TrafficSample> {
    report
        .samples
        .iter()
        .filter(|sample| sample.direction == direction && sample.decision == decision)
        .collect()
}

#[test]
fn traffic_counters_aggregate_by_peer_direction_and_service() {
    let peers = [peer(
        "peer-a",
        &["100.64.0.2/32"],
        Some(Ingress {
            tcp: vec!["22".into()],
            ..Ingress::default()
        }),
    )];
    let mut filter = filter_with(&peers);
    // Disabled by default: nothing is counted.
    assert!(filter.inbound(&ipv4(PEER, LOCAL, TCP, &tcp(40_000, 22, 0x02)), 1));
    assert!(filter.traffic_report().samples.is_empty());

    filter.set_traffic(true);
    let syn = ipv4(PEER, LOCAL, TCP, &tcp(40_002, 22, 0x02));
    assert!(filter.inbound(&syn, 1));
    filter.outbound(&ipv4(LOCAL, PEER, TCP, &tcp(22, 40_002, 0x12)), 1);
    assert!(!filter.inbound(&ipv4(PEER, LOCAL, TCP, &tcp(40_003, 3389, 0x02)), 1));
    assert!(!filter.inbound(&ipv4(PEER, LOCAL, UDP, &udp(40_003, 60_000)), 1));
    filter.outbound(&ipv4(LOCAL, PEER, TCP, &tcp(50_000, 443, 0x02)), 1);
    assert!(filter.inbound(&ipv4(PEER, LOCAL, TCP, &tcp(443, 50_000, 0x12)), 1));

    let report = filter.take_traffic();
    let inbound_allowed = sample(&report, Direction::Inbound, "allowed");
    assert_eq!(inbound_allowed.len(), 1);
    assert_eq!(inbound_allowed[0].peer_id.as_deref(), Some("peer-a"));
    assert_eq!(
        (inbound_allowed[0].proto, inbound_allowed[0].port),
        ("tcp", 22)
    );
    assert_eq!(inbound_allowed[0].packets, 2);
    assert_eq!(inbound_allowed[0].bytes, 80);
    let denied = sample(&report, Direction::Inbound, "denied");
    assert_eq!(denied.len(), 2);
    assert!(denied.iter().any(|s| s.proto == "tcp" && s.port == 3389));
    assert!(denied
        .iter()
        .any(|s| s.proto == "udp" && s.port == DYNAMIC_PORTS));
    let outbound = sample(&report, Direction::Outbound, "allowed");
    assert_eq!(outbound.len(), 1);
    assert_eq!((outbound[0].port, outbound[0].packets), (443, 2));

    // Taking resets; turning off discards and stops counting immediately.
    assert!(filter.traffic_report().samples.is_empty());
    filter.inbound(&ipv4(PEER, LOCAL, TCP, &tcp(40_009, 23, 0x02)), 2);
    assert!(!filter.traffic_report().samples.is_empty());
    filter.set_traffic(false);
    assert!(filter.traffic_report().samples.is_empty());
    filter.inbound(&ipv4(PEER, LOCAL, TCP, &tcp(40_010, 23, 0x02)), 2);
    assert!(filter.traffic_report().samples.is_empty());
}

#[test]
fn flow_events_report_start_end_and_drop_with_ports_and_counters() {
    let peers = [peer(
        "peer-a",
        &["100.64.0.2/32"],
        Some(Ingress {
            tcp: vec!["22".into()],
            deny_tcp: vec!["3389".into()],
            icmp: true,
            ..Ingress::default()
        }),
    )];
    let mut filter = filter_with(&peers);
    // Off: nothing is recorded.
    assert!(filter.inbound(&ipv4(PEER, LOCAL, TCP, &tcp(40_000, 22, 0x02)), 1));
    assert!(filter.take_events().is_empty());
    filter.set_traffic(true);
    let base = filter.epoch_unix;

    // Inbound SSH: start at first packet; counters follow both directions.
    assert!(filter.inbound(&ipv4(PEER, LOCAL, TCP, &tcp(40_002, 22, 0x02)), 2));
    filter.outbound(&ipv4(LOCAL, PEER, TCP, &tcp(22, 40_002, 0x12)), 2);
    assert!(filter.inbound(&ipv4(PEER, LOCAL, TCP, &tcp(40_002, 22, 0x10)), 3));
    // Explicitly denied and default-denied attempts; a SYN retry merges.
    let rdp = ipv4(PEER, LOCAL, TCP, &tcp(40_003, 3389, 0x02));
    assert!(!filter.inbound(&rdp, 4));
    assert!(!filter.inbound(&rdp, 5));
    assert!(!filter.inbound(&ipv4(PEER, LOCAL, UDP, &udp(40_004, 53)), 5));
    // Outbound ping.
    filter.outbound(&ipv4(LOCAL, PEER, ICMP, &icmp_msg(8, 9, &[])), 6);
    let events = filter.take_events();
    let ssh: Vec<_> = events.iter().filter(|e| e.dst_port == 22).collect();
    assert_eq!(ssh.len(), 1);
    let start = ssh[0];
    assert_eq!(start.kind, flow_events::Kind::Start);
    assert_eq!(start.direction, flow_events::Direction::Inbound);
    assert_eq!((start.src_ip.as_str(), start.src_port), (PEER, 40_002));
    assert_eq!((start.dst_ip.as_str(), start.dst_port), (LOCAL, 22));
    assert_eq!(start.peer_id.as_deref(), Some("peer-a"));
    assert_eq!(start.at, base + 2);
    let drops: Vec<_> = events
        .iter()
        .filter(|e| e.kind == flow_events::Kind::Drop)
        .collect();
    assert_eq!(drops.len(), 2);
    let rdp_drop = drops.iter().find(|e| e.dst_port == 3389).unwrap();
    assert_eq!(rdp_drop.rx_packets, 2);
    assert_eq!(rdp_drop.rule_hint, Some("acl:deny-rule"));
    let dns_drop = drops.iter().find(|e| e.protocol == "udp").unwrap();
    assert_eq!(dns_drop.rule_hint, Some("acl:default"));
    let ping = events.iter().find(|e| e.protocol == "icmp").unwrap();
    assert_eq!(ping.direction, flow_events::Direction::Outbound);
    assert_eq!(
        (ping.icmp_type, ping.src_port, ping.dst_port),
        (Some(8), 0, 0)
    );
    assert!(filter.take_events().is_empty(), "taken");

    // Expiry ends the flow with its totals, timed at the last packet.
    filter.purge(3 + TCP_ESTABLISHED_SECS + 1);
    let ends = filter.take_events();
    let end = ends.iter().find(|e| e.dst_port == 22).unwrap();
    assert_eq!(end.kind, flow_events::Kind::End);
    assert_eq!(end.flow_id, start.flow_id);
    assert_eq!((end.rx_packets, end.tx_packets), (2, 1));
    assert_eq!((end.rx_bytes, end.tx_bytes), (80, 40));
    assert_eq!(end.at, base + 3);
    assert!(ends
        .iter()
        .any(|e| e.protocol == "icmp" && e.kind == flow_events::Kind::End));

    // Off: events are discarded at once and nothing more is recorded.
    assert!(!filter.inbound(&rdp, 5_000));
    assert_eq!(filter.pending_events(), 1);
    filter.set_traffic(false);
    assert_eq!(filter.pending_events(), 0);
    assert!(!filter.inbound(&rdp, 5_001));
    assert!(filter.take_events().is_empty());
}

#[test]
fn pending_drops_are_bounded() {
    let mut filter = deny_all();
    filter.set_traffic(true);
    for port in 0..(MAX_PENDING_DROPS as u16 + 20) {
        filter.inbound(&ipv4(PEER, LOCAL, TCP, &tcp(10_000 + port, 22, 0x02)), 1);
    }
    assert_eq!(filter.drop_overflow, 20);
    assert_eq!(filter.take_events().len(), MAX_PENDING_DROPS);
}

#[test]
fn traffic_keys_are_bounded() {
    let mut filter = deny_all();
    filter.set_traffic(true);
    for port in 1..=(MAX_TRAFFIC_KEYS as u16 + 50) {
        filter.inbound(&ipv4(PEER, LOCAL, TCP, &tcp(40_000, port, 0x02)), 1);
    }
    let report = filter.traffic_report();
    assert_eq!(report.samples.len(), MAX_TRAFFIC_KEYS);
    assert_eq!(report.overflow, 50);
}

#[test]
fn traffic_report_json_carries_no_addresses_or_payload() {
    let mut filter = filter_with(&[peer(
        "11111111-1111-1111-1111-111111111111",
        &["100.64.0.2/32", "fd7a:115c:a1e0::2/128"],
        Some(Ingress {
            all: true,
            ..Ingress::default()
        }),
    )]);
    filter.set_traffic(true);
    let mut payload = udp(40_000, 53);
    payload.extend_from_slice(b"\x07example\x03org\x00secret-token");
    filter.inbound(&ipv4(PEER, LOCAL, UDP, &payload), 1);
    filter.inbound(&ipv6(PEER6, LOCAL6, TCP, &tcp(40_000, 443, 0x02)), 1);
    filter.inbound(&ipv4("100.99.0.9", LOCAL, TCP, &tcp(40_000, 443, 0x02)), 1);
    let json = serde_json::to_value(filter.traffic_report()).unwrap();
    let text = json.to_string();
    for forbidden in ["100.64", "100.99", "fd7a", "example", "secret", "40000"] {
        assert!(!text.contains(forbidden), "{forbidden} leaked: {text}");
    }
    let allowed_keys = [
        "peer_id",
        "direction",
        "proto",
        "port",
        "decision",
        "bytes",
        "packets",
    ];
    for sample in json["samples"].as_array().unwrap() {
        for key in sample.as_object().unwrap().keys() {
            assert!(allowed_keys.contains(&key.as_str()), "unexpected key {key}");
        }
    }
}

// ---------------------------------------------------------------------------
// Through the C ABI, as the iOS/Android hosts and the Windows agent use it.

fn handshake(alice: *mut BlakTailTunnel, bob: *mut BlakTailTunnel) {
    let mut buffer = vec![0u8; 2048];
    let mut length = 0usize;
    let mut peer = [0u8; 32];
    let first = ipv4(LOCAL, PEER, 47, &[0u8; 8]);
    unsafe {
        assert_eq!(
            crate::blaktail_tunnel_encapsulate(
                alice,
                first.as_ptr(),
                first.len(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut length,
                peer.as_mut_ptr()
            ),
            1
        );
        let initiation = buffer[..length].to_vec();
        assert_eq!(
            crate::blaktail_tunnel_decapsulate(
                bob,
                initiation.as_ptr(),
                initiation.len(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut length,
                peer.as_mut_ptr()
            ),
            1
        );
        let response = buffer[..length].to_vec();
        assert_eq!(
            crate::blaktail_tunnel_decapsulate(
                alice,
                response.as_ptr(),
                response.len(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut length,
                peer.as_mut_ptr()
            ),
            1
        );
        let keepalive = buffer[..length].to_vec();
        crate::blaktail_tunnel_decapsulate(
            bob,
            keepalive.as_ptr(),
            keepalive.len(),
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut length,
            peer.as_mut_ptr(),
        );
    }
}

fn send(alice: *mut BlakTailTunnel, bob: *mut BlakTailTunnel, packet: &[u8]) -> (i32, Vec<u8>) {
    let mut cipher = vec![0u8; 2048];
    let mut plain = vec![0u8; 2048];
    let mut length = 0usize;
    let mut peer = [0u8; 32];
    unsafe {
        assert_eq!(
            crate::blaktail_tunnel_encapsulate(
                alice,
                packet.as_ptr(),
                packet.len(),
                cipher.as_mut_ptr(),
                cipher.len(),
                &mut length,
                peer.as_mut_ptr()
            ),
            1
        );
        let code = crate::blaktail_tunnel_decapsulate(
            bob,
            cipher.as_ptr(),
            length,
            plain.as_mut_ptr(),
            plain.len(),
            &mut length,
            peer.as_mut_ptr(),
        );
        (code, plain[..length].to_vec())
    }
}

#[test]
fn tunnel_drops_denied_packets_between_decrypt_and_tunnel_write() {
    use x25519_dalek::{PublicKey, StaticSecret};
    let alice_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let bob_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let alice = unsafe { crate::blaktail_tunnel_create(alice_secret.to_bytes().as_ptr()) };
    let bob = unsafe { crate::blaktail_tunnel_create(bob_secret.to_bytes().as_ptr()) };
    let to_bob = std::ffi::CString::new("100.64.0.2/32").unwrap();
    let to_alice = std::ffi::CString::new("100.64.0.1/32").unwrap();
    unsafe {
        crate::blaktail_tunnel_add_peer(
            alice,
            PublicKey::from(&bob_secret).as_bytes().as_ptr(),
            to_bob.as_ptr(),
            0,
        );
        crate::blaktail_tunnel_add_peer(
            bob,
            PublicKey::from(&alice_secret).as_bytes().as_ptr(),
            to_alice.as_ptr(),
            0,
        );
    }
    // Bob grants Alice (100.64.0.1) TCP 22 only.
    let policy = br#"[{"id":"alice","allowed_ips":["100.64.0.1/32"],"ingress":{"tcp":["22"]}}]"#;
    assert_eq!(
        unsafe { blaktail_tunnel_set_policy(bob, policy.as_ptr(), policy.len()) },
        RESULT_DONE
    );
    assert_eq!(unsafe { blaktail_tunnel_set_traffic(bob, 1) }, RESULT_DONE);
    handshake(alice, bob);

    let ssh = ipv4(LOCAL, PEER, TCP, &tcp(40_000, 22, 0x02));
    let (code, plain) = send(alice, bob, &ssh);
    assert_eq!(code, 2);
    assert_eq!(plain, ssh);
    let rdp = ipv4(LOCAL, PEER, TCP, &tcp(40_001, 3389, 0x02));
    let (code, plain) = send(alice, bob, &rdp);
    assert_eq!(code, RESULT_DONE);
    assert!(plain.is_empty());

    // Bob's own outbound flow: Alice's reply passes Bob's filter.
    let out = ipv4(PEER, LOCAL, UDP, &udp(6000, 7000));
    let (code, _) = send(bob, alice, &out);
    assert_eq!(code, 2);
    let reply = ipv4(LOCAL, PEER, UDP, &udp(7000, 6000));
    assert_eq!(send(alice, bob, &reply).0, 2);

    let org = std::ffi::CString::new("org-1").unwrap();
    let device = std::ffi::CString::new("bob").unwrap();
    let transport = std::ffi::CString::new("direct").unwrap();
    let take = |buffer: &mut [u8], length: &mut usize| unsafe {
        blaktail_tunnel_take_flow_upload(
            bob,
            org.as_ptr(),
            device.as_ptr(),
            transport.as_ptr(),
            1.0,
            buffer.as_mut_ptr(),
            buffer.len(),
            length,
        )
    };
    let mut small = [0u8; 4];
    let mut needed = 0usize;
    assert_eq!(take(&mut small, &mut needed), RESULT_ERR);
    let mut buffer = vec![0u8; needed];
    let mut written = 0usize;
    assert_eq!(take(&mut buffer, &mut written), RESULT_DONE);
    let upload: serde_json::Value = serde_json::from_slice(&buffer[..written]).unwrap();
    let records = upload["records"].as_array().unwrap();
    assert!(records
        .iter()
        .all(|r| r["org_id"] == "org-1" && r["device_id"] == "bob"));
    assert!(records.iter().any(|r| r["decision"] == "denied"
        && r["port"] == 3389
        && r["service"] == "rdp"
        && r["peer_id"] == "alice"));
    assert!(records.iter().any(|r| r["decision"] == "allowed"
        && r["service"] == "ssh"
        && r["direction"] == "inbound"));
    assert!(records
        .iter()
        .any(|r| r["direction"] == "outbound" && r["proto"] == "udp" && r["port"] == 7000));
    // Per-flow events: the SSH start and the RDP drop, with ports.
    let take_events = |buffer: &mut [u8], length: &mut usize| unsafe {
        blaktail_tunnel_take_flow_events(
            bob,
            org.as_ptr(),
            device.as_ptr(),
            1.0,
            buffer.as_mut_ptr(),
            buffer.len(),
            length,
        )
    };
    let mut needed = 0usize;
    assert_eq!(take_events(&mut small, &mut needed), RESULT_ERR);
    let mut events_buffer = vec![0u8; needed];
    assert_eq!(take_events(&mut events_buffer, &mut written), RESULT_DONE);
    let upload: serde_json::Value = serde_json::from_slice(&events_buffer[..written]).unwrap();
    assert_eq!(upload["org_id"], "org-1");
    let events = upload["events"].as_array().unwrap();
    assert!(events.iter().any(|e| e["type"] == "start"
        && e["dst_port"] == 22
        && e["src_port"] == 40_000
        && e["src_ip"] == LOCAL
        && e["peer_id"] == "alice"));
    assert!(events
        .iter()
        .any(|e| e["type"] == "drop" && e["dst_port"] == 3389 && e["rule_hint"] == "acl:default"));
    assert!(events
        .iter()
        .any(|e| e["type"] == "start" && e["direction"] == "outbound" && e["dst_port"] == 7000));
    let mut empty = vec![0u8; 256];
    assert_eq!(take_events(&mut empty, &mut written), RESULT_DONE);
    let upload: serde_json::Value = serde_json::from_slice(&empty[..written]).unwrap();
    assert!(upload["events"].as_array().unwrap().is_empty());

    // Taken: the next batch is empty.
    let mut buffer = vec![0u8; 256];
    assert_eq!(take(&mut buffer, &mut written), RESULT_DONE);
    assert_eq!(&buffer[..written], br#"{"records":[]}"#);
    // Counting off: nothing is collected or reported.
    assert_eq!(unsafe { blaktail_tunnel_set_traffic(bob, 0) }, RESULT_DONE);
    send(alice, bob, &rdp);
    assert_eq!(take(&mut buffer, &mut written), RESULT_DONE);
    assert_eq!(&buffer[..written], br#"{"records":[]}"#);

    // Unparseable policy fails closed.
    let broken = b"{not json";
    assert_eq!(
        unsafe { blaktail_tunnel_set_policy(bob, broken.as_ptr(), broken.len()) },
        RESULT_ERR
    );
    assert_eq!(
        send(alice, bob, &ipv4(LOCAL, PEER, TCP, &tcp(40_002, 22, 0x02))).0,
        RESULT_DONE
    );

    unsafe {
        crate::blaktail_tunnel_free(alice);
        crate::blaktail_tunnel_free(bob);
    }
}

/// Relayed traffic takes the same decrypt -> filter -> tunnel path as direct
/// traffic: the relay only unwraps the ciphertext, it never bypasses policy.
#[test]
fn relayed_inbound_packets_are_filtered_and_reported_as_relayed() {
    use crate::relay::{
        blaktail_relay_begin_peers, blaktail_relay_configure, blaktail_relay_end_peers,
        blaktail_relay_inbound, blaktail_relay_set_peer,
    };
    use blaktail_relay_proto::{mobile::parse_node_id, FORWARDED};
    use x25519_dalek::{PublicKey, StaticSecret};
    const ALICE_ID: &str = "00000000-0000-4000-8000-0000000000a1";
    const BOB_ID: &str = "00000000-0000-4000-8000-0000000000b0";
    const RELAY: &str = "relay-a.example.au:3478";

    let alice_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let bob_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let alice_public = PublicKey::from(&alice_secret);
    let alice = unsafe { crate::blaktail_tunnel_create(alice_secret.to_bytes().as_ptr()) };
    let bob = unsafe { crate::blaktail_tunnel_create(bob_secret.to_bytes().as_ptr()) };
    let to_bob = std::ffi::CString::new("100.64.0.2/32").unwrap();
    let to_alice = std::ffi::CString::new("100.64.0.1/32").unwrap();
    unsafe {
        crate::blaktail_tunnel_add_peer(
            alice,
            PublicKey::from(&bob_secret).as_bytes().as_ptr(),
            to_bob.as_ptr(),
            0,
        );
        crate::blaktail_tunnel_add_peer(
            bob,
            alice_public.as_bytes().as_ptr(),
            to_alice.as_ptr(),
            0,
        );
    }
    let policy = format!(
        r#"[{{"id":"{ALICE_ID}","allowed_ips":["100.64.0.1/32"],"ingress":{{"tcp":["22"]}}}}]"#
    );
    assert_eq!(
        unsafe { blaktail_tunnel_set_policy(bob, policy.as_ptr(), policy.len()) },
        RESULT_DONE
    );
    assert_eq!(unsafe { blaktail_tunnel_set_traffic(bob, 1) }, RESULT_DONE);

    // Bob reaches Alice only through the relay (no direct endpoint).
    let self_id = std::ffi::CString::new(BOB_ID).unwrap();
    let token = std::ffi::CString::new("ab".repeat(32)).unwrap();
    let relays = std::ffi::CString::new(format!("{RELAY}\tap-southeast-2\t\n")).unwrap();
    let alice_id = std::ffi::CString::new(ALICE_ID).unwrap();
    unsafe {
        assert_eq!(
            blaktail_relay_configure(
                bob,
                self_id.as_ptr(),
                token.as_ptr(),
                4_000_000_000,
                relays.as_ptr(),
                0,
            ),
            0
        );
        blaktail_relay_begin_peers(bob);
        assert_eq!(
            blaktail_relay_set_peer(bob, alice_public.as_bytes().as_ptr(), alice_id.as_ptr(), 0),
            0
        );
        blaktail_relay_end_peers(bob);
    }
    handshake(alice, bob);

    let endpoint = std::ffi::CString::new(RELAY).unwrap();
    // Alice encrypts, the relay forwards, Bob unwraps then decapsulates.
    let relayed = |packet: &[u8]| -> (i32, Vec<u8>) {
        let mut cipher = vec![0u8; 2048];
        let mut length = 0usize;
        let mut peer = [0u8; 32];
        unsafe {
            assert_eq!(
                crate::blaktail_tunnel_encapsulate(
                    alice,
                    packet.as_ptr(),
                    packet.len(),
                    cipher.as_mut_ptr(),
                    cipher.len(),
                    &mut length,
                    peer.as_mut_ptr()
                ),
                1
            );
            let mut frame = vec![FORWARDED];
            frame.extend_from_slice(&parse_node_id(ALICE_ID).unwrap());
            frame.extend_from_slice(&cipher[..length]);
            let mut unwrapped = vec![0u8; 2048];
            let mut unwrapped_len = 0usize;
            let mut sender = [0u8; 32];
            assert_eq!(
                blaktail_relay_inbound(
                    bob,
                    frame.as_ptr(),
                    frame.len(),
                    0,
                    endpoint.as_ptr(),
                    unwrapped.as_mut_ptr(),
                    unwrapped.len(),
                    &mut unwrapped_len,
                    sender.as_mut_ptr(),
                ),
                1
            );
            assert_eq!(&sender, alice_public.as_bytes());
            let mut plain = vec![0u8; 2048];
            let code = crate::blaktail_tunnel_decapsulate(
                bob,
                unwrapped.as_ptr(),
                unwrapped_len,
                plain.as_mut_ptr(),
                plain.len(),
                &mut length,
                peer.as_mut_ptr(),
            );
            (code, plain[..length].to_vec())
        }
    };
    let ssh = ipv4(LOCAL, PEER, TCP, &tcp(40_000, 22, 0x02));
    assert_eq!(relayed(&ssh), (2, ssh.clone()));
    let rdp = ipv4(LOCAL, PEER, TCP, &tcp(40_001, 3389, 0x02));
    assert_eq!(relayed(&rdp), (RESULT_DONE, Vec::new()));

    // The flow upload reports the relay's actual transport, whatever the
    // host passed.
    let org = std::ffi::CString::new("org-1").unwrap();
    let device = std::ffi::CString::new(BOB_ID).unwrap();
    let transport = std::ffi::CString::new("direct").unwrap();
    let mut buffer = vec![0u8; 8192];
    let mut written = 0usize;
    assert_eq!(
        unsafe {
            blaktail_tunnel_take_flow_upload(
                bob,
                org.as_ptr(),
                device.as_ptr(),
                transport.as_ptr(),
                1.0,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut written,
            )
        },
        RESULT_DONE
    );
    let upload: serde_json::Value = serde_json::from_slice(&buffer[..written]).unwrap();
    let records = upload["records"].as_array().unwrap();
    assert!(records.iter().any(|r| r["decision"] == "denied"
        && r["service"] == "rdp"
        && r["peer_id"] == ALICE_ID
        && r["transport"] == "udp_relay"));
    assert!(records
        .iter()
        .any(|r| r["decision"] == "allowed" && r["service"] == "ssh"));
    assert!(records.iter().all(|r| r["transport"] == "udp_relay"));

    unsafe {
        crate::blaktail_tunnel_free(alice);
        crate::blaktail_tunnel_free(bob);
    }
}
