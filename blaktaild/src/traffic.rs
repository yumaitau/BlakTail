//! Opt-in traffic reporting (draft 17). While the organisation has traffic
//! diagnostics on, the peer map carries `traffic`; the agent then counts and,
//! about once a minute, uploads aggregate records built by the shared
//! `flow_report` module. When the setting disappears (or the coordinator
//! answers that it is off) counting stops and counters are discarded.
//!
//! Counter sources, all cheap reads of counters the kernel or dataplane keeps
//! anyway:
//! - Linux: per-rule packet/byte counters of the `BLAKTAIL-ACL` chain
//!   (`iptables -L -v -x`). Accept and reject rules come after the
//!   established rule, so they count the first packet of each new inbound
//!   flow: allowed attempts by peer, protocol and port; denied attempts by
//!   peer (per-source catch-all rejects) or by port where a deny rule names
//!   it. Bytes per peer
//!   come from WireGuard's transfer counters (`wg show <if> transfer`),
//!   reported as service `tunnel` with direction = byte direction.
//! - macOS: per-rule `pf` counters of the BlakTail anchor (state-tracked, so
//!   whole flows) — see `pf_filter`.
//! - Windows (and iOS/Android in their hosts): the shared userspace filter's
//!   per-flow counters.

use crate::flow_report::FlowCount;
use crate::Peer;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Seconds between uploads (and so the bucket width).
pub const REPORT_EVERY_SECS: i64 = 60;

/// The peer map's `traffic` field. Absent means off.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct Settings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub sampling_rate: f64,
    #[serde(default)]
    pub org_id: String,
}

impl Settings {
    pub fn active(settings: Option<&Settings>) -> Option<&Settings> {
        settings.filter(|settings| {
            settings.enabled && settings.sampling_rate > 0.0 && !settings.org_id.is_empty()
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Nothing to do.
    Idle,
    /// Counting must start now.
    Start,
    /// Counting must stop and counters be discarded.
    Stop,
    /// Collect and upload the bucket `[start, end)`.
    Report { start: i64, end: i64 },
}

/// When to start, stop and report. Pure so the timing is testable.
#[derive(Debug, Default)]
pub struct Reporter {
    active: bool,
    bucket_start: i64,
}

impl Reporter {
    pub fn step(&mut self, settings: Option<&Settings>, now: i64) -> Step {
        match (Settings::active(settings).is_some(), self.active) {
            (false, false) => Step::Idle,
            (false, true) => {
                self.active = false;
                Step::Stop
            }
            (true, false) => {
                self.active = true;
                self.bucket_start = now;
                Step::Start
            }
            (true, true) if now - self.bucket_start >= REPORT_EVERY_SECS => {
                let start = self.bucket_start;
                self.bucket_start = now;
                Step::Report { start, end: now }
            }
            (true, true) => Step::Idle,
        }
    }

    /// The coordinator said reporting is off: stop until it is on again.
    pub fn halt(&mut self) {
        self.active = false;
    }
}

/// Cumulative kernel counters to per-interval deltas. A counter that went
/// down (chain or anchor rebuilt) counts from zero.
#[derive(Debug, Default)]
pub struct Deltas {
    last: HashMap<String, (u64, u64)>,
}

impl Deltas {
    pub fn delta(&mut self, key: String, packets: u64, bytes: u64) -> (u64, u64) {
        let previous = self.last.insert(key, (packets, bytes));
        match previous {
            Some((last_packets, last_bytes)) if packets >= last_packets && bytes >= last_bytes => {
                (packets - last_packets, bytes - last_bytes)
            }
            _ => (packets, bytes),
        }
    }

    pub fn clear(&mut self) {
        self.last.clear();
    }
}

/// One rule row of `iptables -L BLAKTAIL-ACL -n -v -x`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleCounter {
    /// Stable identity for delta tracking: the row without its counters.
    pub key: String,
    pub source: Option<IpAddr>,
    pub proto: &'static str,
    pub port: u16,
    pub allowed: bool,
    pub packets: u64,
    pub bytes: u64,
}

fn proto_name(value: &str) -> &'static str {
    match value {
        "tcp" | "6" => "tcp",
        "udp" | "17" => "udp",
        "icmp" | "1" | "icmpv6" | "ipv6-icmp" | "58" => "icmp",
        _ => "all",
    }
}

/// Parses the chain listing. The established/related rule is skipped: its
/// packets belong to flows already counted (and to the `tunnel` bytes).
pub fn parse_iptables(output: &str) -> Vec<RuleCounter> {
    let mut rules = Vec::new();
    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 4 || line.contains("ESTABLISHED") {
            continue;
        }
        let (Ok(packets), Ok(bytes)) = (tokens[0].parse::<u64>(), tokens[1].parse::<u64>()) else {
            continue;
        };
        let allowed = match tokens[2] {
            "ACCEPT" => true,
            "REJECT" | "DROP" => false,
            _ => continue,
        };
        // First address column is the source; a `/0` source is "anyone".
        let source = tokens[4..]
            .iter()
            .find_map(|token| {
                let (address, prefix) = token.split_once('/').unwrap_or((token, ""));
                Some((address.parse::<IpAddr>().ok()?, prefix))
            })
            .and_then(|(address, prefix)| (prefix != "0").then_some(address));
        let port = tokens
            .iter()
            .find_map(|token| {
                token
                    .strip_prefix("dpt:")
                    .or_else(|| token.strip_prefix("dpts:"))
            })
            .and_then(|value| value.split(':').next())
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        rules.push(RuleCounter {
            key: tokens[2..].join(" "),
            source,
            proto: proto_name(tokens[3]),
            port,
            allowed,
            packets,
            bytes,
        });
    }
    rules
}

/// `wg show <if> transfer`: `<public key> <rx bytes> <tx bytes>` per peer.
pub fn parse_wg_transfer(output: &str) -> Vec<(String, u64, u64)> {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let key = fields.next()?.to_owned();
            let rx = fields.next()?.parse().ok()?;
            let tx = fields.next()?.parse().ok()?;
            Some((key, rx, tx))
        })
        .collect()
}

/// Linux counts since the previous call. `families` holds one chain listing
/// per address family.
pub fn linux_counts(
    families: &[(&str, &str)],
    transfer: &str,
    peers: &[Peer],
    deltas: &mut Deltas,
) -> Vec<FlowCount> {
    let mut by_address: HashMap<IpAddr, String> = HashMap::new();
    for peer in peers {
        for address in crate::acl_filter::overlay_host_addrs(&peer.allowed_ips) {
            if let Ok(address) = address.parse() {
                by_address.insert(address, peer.id.to_string());
            }
        }
    }
    let mut counts = Vec::new();
    for (family, listing) in families {
        for (index, rule) in parse_iptables(listing).into_iter().enumerate() {
            let (packets, bytes) = deltas.delta(
                format!("{family}|{index}|{}", rule.key),
                rule.packets,
                rule.bytes,
            );
            if packets == 0 && bytes == 0 {
                continue;
            }
            counts.push(FlowCount {
                peer_id: rule
                    .source
                    .and_then(|source| by_address.get(&source).cloned()),
                direction: "inbound",
                proto: rule.proto,
                port: rule.port,
                allowed: rule.allowed,
                bytes,
                packets,
            });
        }
    }
    for (key, rx, tx) in parse_wg_transfer(transfer) {
        let Some(peer) = peers.iter().find(|peer| peer.wg_public_key.trim() == key) else {
            continue;
        };
        for (direction, total) in [("inbound", rx), ("outbound", tx)] {
            let (_, bytes) = deltas.delta(format!("wg|{key}|{direction}"), 0, total);
            if bytes > 0 {
                counts.push(FlowCount {
                    peer_id: Some(peer.id.to_string()),
                    direction,
                    proto: "tunnel",
                    port: 0,
                    allowed: true,
                    bytes,
                    packets: 0,
                });
            }
        }
    }
    counts
}

/// Flow-record transport of relayed peers: the relay's current link.
pub fn relay_transport_label(over_https: bool) -> &'static str {
    if over_https {
        "https_relay"
    } else {
        "udp_relay"
    }
}

/// Flow-record transport for the device-level path summary.
pub fn transport_label(summary: Option<&str>, over_https: bool) -> &'static str {
    match summary {
        Some("relay") => relay_transport_label(over_https),
        _ => "direct",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow_report::{build, Bucket};
    use uuid::Uuid;

    const IPTABLES: &str = "Chain BLAKTAIL-ACL (1 references)
    pkts      bytes target     prot opt in     out     source               destination
     900   720000 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
       3      180 ACCEPT     tcp  --  *      *       100.64.0.2           0.0.0.0/0            tcp dpt:22
       2      120 REJECT     tcp  --  *      *       100.64.0.2           0.0.0.0/0            tcp dpt:3389 reject-with tcp-reset
       1       60 ACCEPT     udp  --  *      *       100.64.0.2           0.0.0.0/0            udp dpts:1000:2000
       0        0 ACCEPT     icmp --  *      *       100.64.0.2           0.0.0.0/0
       6      360 REJECT     tcp  --  *      *       100.64.0.2           0.0.0.0/0            reject-with tcp-reset
       4      240 REJECT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            reject-with tcp-reset
       5      300 REJECT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            reject-with icmp-port-unreachable
";
    const IP6TABLES: &str = "Chain BLAKTAIL-ACL (1 references)
    pkts      bytes target     prot opt in     out     source               destination
       2      160 ACCEPT     tcp      *      *       fd7a:115c:a1e0::2/128  ::/0                 tcp dpt:22
";

    fn peer() -> Peer {
        Peer {
            id: Uuid::from_u128(7),
            name: "server".into(),
            wg_public_key: "cGVlcmtleQ==".into(),
            endpoint: None,
            allowed_ips: vec!["100.64.0.2/32".into(), "fd7a:115c:a1e0::2/128".into()],
            dns_name: String::new(),
            tags: vec![],
            relay_endpoint: None,
            ingress: None,
            pq: None,
        }
    }

    #[test]
    fn reporter_starts_reports_each_minute_and_stops_at_once() {
        let on = Settings {
            enabled: true,
            sampling_rate: 1.0,
            org_id: "org".into(),
        };
        let mut reporter = Reporter::default();
        assert_eq!(reporter.step(None, 0), Step::Idle);
        assert_eq!(reporter.step(Some(&on), 10), Step::Start);
        assert_eq!(reporter.step(Some(&on), 40), Step::Idle);
        assert_eq!(
            reporter.step(Some(&on), 70),
            Step::Report { start: 10, end: 70 }
        );
        assert_eq!(reporter.step(None, 71), Step::Stop);
        assert_eq!(reporter.step(None, 500), Step::Idle);
        let off = Settings {
            enabled: false,
            ..on.clone()
        };
        assert_eq!(reporter.step(Some(&off), 600), Step::Idle);
        assert_eq!(reporter.step(Some(&on), 700), Step::Start);
        reporter.halt();
        assert_eq!(reporter.step(Some(&on), 800), Step::Start);
        let unnamed = Settings {
            org_id: String::new(),
            ..on
        };
        let mut reporter = Reporter::default();
        assert_eq!(reporter.step(Some(&unnamed), 0), Step::Idle);
    }

    #[test]
    fn iptables_rows_become_attributed_deltas() {
        let mut deltas = Deltas::default();
        let peers = [peer()];
        let transfer = "cGVlcmtleQ==\t5000\t7000\nunknown\t1\t1\n";
        let counts = linux_counts(
            &[("ipv4", IPTABLES), ("ipv6", IP6TABLES)],
            transfer,
            &peers,
            &mut deltas,
        );
        let id = Uuid::from_u128(7).to_string();
        let find = |proto: &str, port: u16, allowed: bool| {
            counts
                .iter()
                .filter(|c| c.proto == proto && c.port == port && c.allowed == allowed)
                .collect::<Vec<_>>()
        };
        assert_eq!(find("tcp", 22, true).len(), 2);
        assert!(find("tcp", 22, true)
            .iter()
            .all(|c| c.peer_id.as_deref() == Some(id.as_str())));
        let rdp = find("tcp", 3389, false);
        assert_eq!((rdp[0].packets, rdp[0].bytes), (2, 120));
        assert_eq!(find("udp", 1000, true).len(), 1);
        // Per-source catch-all reject attributes the attempt to the peer;
        // the chain's final reject cannot.
        let unattributed = find("tcp", 0, false);
        assert!(unattributed
            .iter()
            .any(|c| c.peer_id.as_deref() == Some(id.as_str()) && c.packets == 6));
        assert!(unattributed.iter().any(|c| c.peer_id.is_none()));
        assert_eq!(find("all", 0, false)[0].packets, 5);
        assert!(!counts.iter().any(|c| c.packets == 900));
        let tunnel: Vec<_> = counts.iter().filter(|c| c.proto == "tunnel").collect();
        assert_eq!(tunnel.len(), 2);
        assert!(tunnel
            .iter()
            .any(|c| c.direction == "outbound" && c.bytes == 7000));

        // Unchanged counters report nothing; a rebuilt chain counts afresh.
        assert!(linux_counts(&[("ipv4", IPTABLES)], transfer, &peers, &mut deltas).is_empty());
        let rebuilt = IPTABLES.replace("       2      120 REJECT", "       1       60 REJECT");
        let again = linux_counts(&[("ipv4", &rebuilt)], transfer, &peers, &mut deltas);
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].packets, 1);
    }

    #[test]
    fn uploads_never_carry_addresses_keys_or_names() {
        let mut deltas = Deltas::default();
        let peers = [peer()];
        let counts = linux_counts(
            &[("ipv4", IPTABLES), ("ipv6", IP6TABLES)],
            "cGVlcmtleQ==\t5000\t7000\n",
            &peers,
            &mut deltas,
        );
        let upload = build(
            &Bucket {
                org_id: "org",
                device_id: "dev",
                start: 0,
                end: 60,
                transport: "direct",
                relayed_peers: &[],
                relay_transport: "udp_relay",
                sampling_rate: 1.0,
            },
            &counts,
        );
        assert!(!upload.records.is_empty());
        let text = serde_json::to_string(&upload).unwrap();
        for forbidden in ["100.64", "fd7a", "cGVlcmtleQ", "server", "0.0.0.0"] {
            assert!(!text.contains(forbidden), "{forbidden} in {text}");
        }
    }

    #[test]
    fn transport_labels_match_the_coordinator() {
        assert_eq!(transport_label(Some("relay"), false), "udp_relay");
        assert_eq!(transport_label(Some("relay"), true), "https_relay");
        assert_eq!(transport_label(Some("mixed"), true), "direct");
        assert_eq!(transport_label(None, false), "direct");
        assert_eq!(relay_transport_label(true), "https_relay");
    }
}
