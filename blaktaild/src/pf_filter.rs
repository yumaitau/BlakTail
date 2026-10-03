//! macOS inbound filter. boringtun's device writes decrypted packets straight
//! to the utun interface with no callback, so the shared userspace filter
//! cannot sit between decrypt and the tunnel write here. The kernel's `pf`
//! sees exactly those packets next, so the same peer grants are compiled into
//! a `pf` anchor on the utun interface, in the Linux chain's order: replies
//! to this Mac's own flows (pf state), per-source rejects, accepts, then
//! reject everything else.
//!
//! The anchor lives under `com.apple/`, which the stock `/etc/pf.conf`
//! evaluates, so no system file is edited. Enforcement is only claimed after
//! the agent has verified pf is enabled, the main ruleset still evaluates
//! `com.apple/*`, and the anchor holds the rules.

use crate::acl_filter::overlay_host_addrs;
use crate::flow_report::FlowCount;
use crate::{pq, Peer, PeerIngress};

pub const ANCHOR: &str = "com.apple/blaktail";

/// What a rule's counters mean for traffic reporting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleMeta {
    pub peer_id: Option<String>,
    pub direction: &'static str,
    pub proto: &'static str,
    pub port: u16,
    pub allowed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PfRule {
    pub text: String,
    pub meta: RuleMeta,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PfPlan {
    pub enforce: bool,
    pub rules: Vec<PfRule>,
}

impl PfPlan {
    pub fn ruleset(&self) -> String {
        let mut out = String::new();
        for rule in &self.rules {
            out.push_str(&rule.text);
            out.push('\n');
        }
        out
    }
}

fn pf_port(spec: &str) -> Option<(String, u16)> {
    let range = crate::acl_filter::iptables_port(spec)?;
    let start = range
        .split(':')
        .next()
        .and_then(|value| value.parse().ok())?;
    Some((range, start))
}

/// Interface names come from the kernel (`utunN`); anything else is refused
/// so nothing odd reaches the ruleset.
fn valid_interface(name: &str) -> bool {
    name.starts_with("utun")
        && name.len() <= 15
        && name[4..].chars().all(|ch| ch.is_ascii_digit())
        && name.len() > 4
}

/// Compiles the anchor for `interface` from the same peer grants the Linux
/// chain uses. `None` when the interface name is not a utun device.
pub fn plan(interface: &str, peers: &[Peer]) -> Option<PfPlan> {
    if !valid_interface(interface) {
        return None;
    }
    if !peers.iter().any(|peer| peer.ingress.is_some()) {
        return Some(PfPlan::default());
    }
    let mut rules = Vec::new();
    let id = |peer: &Peer| Some(peer.id.to_string());
    // This Mac's own flows: state carries the replies back in.
    for peer in peers {
        for address in overlay_host_addrs(&peer.allowed_ips) {
            rules.push(PfRule {
                text: format!(
                    "pass out quick on {interface} from any to {address} flags any keep state"
                ),
                meta: RuleMeta {
                    peer_id: id(peer),
                    direction: "outbound",
                    proto: "all",
                    port: 0,
                    allowed: true,
                },
            });
        }
    }
    rules.push(PfRule {
        text: format!("pass out quick on {interface} all flags any keep state"),
        meta: RuleMeta {
            peer_id: None,
            direction: "outbound",
            proto: "all",
            port: 0,
            allowed: true,
        },
    });
    for peer in peers {
        let ingress = peer.ingress.clone().unwrap_or(PeerIngress {
            all: true,
            ..PeerIngress::default()
        });
        let pq_exchange = peer
            .pq
            .as_ref()
            .is_some_and(|pq| pq.mode != pq::Mode::Off && pq.capable);
        for address in overlay_host_addrs(&peer.allowed_ips) {
            let icmp = if address.contains(':') {
                "icmp6"
            } else {
                "icmp"
            };
            let family = if address.contains(':') {
                "inet6"
            } else {
                "inet"
            };
            let mut push = |text: String, proto: &'static str, port: u16, allowed: bool| {
                rules.push(PfRule {
                    text,
                    meta: RuleMeta {
                        peer_id: id(peer),
                        direction: "inbound",
                        proto,
                        port,
                        allowed,
                    },
                })
            };
            if pq_exchange {
                push(
                    format!(
                        "pass in quick on {interface} proto tcp from {address} to any port {} keep state",
                        pq::PORT
                    ),
                    "tcp",
                    pq::PORT,
                    true,
                );
            }
            for (proto, specs) in [("tcp", &ingress.deny_tcp), ("udp", &ingress.deny_udp)] {
                for (range, start) in specs.iter().filter_map(|spec| pf_port(spec)) {
                    push(
                        format!("block return in quick on {interface} proto {proto} from {address} to any port {range}"),
                        if proto == "tcp" { "tcp" } else { "udp" },
                        start,
                        false,
                    );
                }
            }
            if ingress.deny_icmp {
                push(
                    format!("block return in quick on {interface} {family} proto {icmp} from {address} to any"),
                    "icmp",
                    0,
                    false,
                );
            }
            if ingress.all {
                push(
                    format!("pass in quick on {interface} from {address} to any keep state"),
                    "all",
                    0,
                    true,
                );
                continue;
            }
            for (proto, specs) in [("tcp", &ingress.tcp), ("udp", &ingress.udp)] {
                for (range, start) in specs.iter().filter_map(|spec| pf_port(spec)) {
                    push(
                        format!("pass in quick on {interface} proto {proto} from {address} to any port {range} keep state"),
                        if proto == "tcp" { "tcp" } else { "udp" },
                        start,
                        true,
                    );
                }
            }
            if ingress.icmp {
                push(
                    format!("pass in quick on {interface} {family} proto {icmp} from {address} to any keep state"),
                    "icmp",
                    0,
                    true,
                );
            }
            // Same action as the final rule; its counters name the peer.
            push(
                format!("block return in quick on {interface} from {address} to any"),
                "all",
                0,
                false,
            );
        }
    }
    rules.push(PfRule {
        text: format!("block return in quick on {interface} all"),
        meta: RuleMeta {
            peer_id: None,
            direction: "inbound",
            proto: "all",
            port: 0,
            allowed: false,
        },
    });
    Some(PfPlan {
        enforce: true,
        rules,
    })
}

/// `(packets, bytes)` per rule, in order, from `pfctl -a ANCHOR -v -s rules`.
pub fn parse_rule_counters(output: &str) -> Vec<(u64, u64)> {
    let field = |line: &str, name: &str| -> Option<u64> {
        let rest = &line[line.find(name)? + name.len()..];
        rest.split_whitespace().next()?.parse().ok()
    };
    output
        .lines()
        .filter(|line| line.contains("[ Evaluations:"))
        .filter_map(|line| Some((field(line, "Packets:")?, field(line, "Bytes:")?)))
        .collect()
}

/// Turns cumulative rule counters into counts since the previous read.
pub fn counts(
    plan: &PfPlan,
    counters: &[(u64, u64)],
    deltas: &mut crate::traffic::Deltas,
) -> Vec<FlowCount> {
    if counters.len() != plan.rules.len() {
        // pfctl expanded or dropped a rule; attribution would be wrong.
        return Vec::new();
    }
    plan.rules
        .iter()
        .zip(counters)
        .enumerate()
        .filter_map(|(index, (rule, (packets, bytes)))| {
            let (packets, bytes) =
                deltas.delta(format!("pf|{index}|{}", rule.text), *packets, *bytes);
            (packets > 0 || bytes > 0).then(|| FlowCount {
                peer_id: rule.meta.peer_id.clone(),
                direction: rule.meta.direction,
                proto: rule.meta.proto,
                port: rule.meta.port,
                allowed: rule.meta.allowed,
                bytes,
                packets,
            })
        })
        .collect()
}

/// Token from `pfctl -E` ("Token : 123"), needed to release our reference.
pub fn enable_token(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == "Token")
            .then(|| value.trim().to_owned())
            .filter(|token| !token.is_empty() && token.chars().all(|ch| ch.is_ascii_digit()))
    })
}

/// The anchor only takes effect while pf is on and the main ruleset still
/// evaluates `com.apple/*` anchors.
pub fn verified(info: &str, main_rules: &str, anchor_rules: &str, plan: &PfPlan) -> bool {
    let enabled = info
        .lines()
        .any(|line| line.trim_start().starts_with("Status: Enabled"));
    let hooked = main_rules
        .lines()
        .any(|line| line.trim() == "anchor \"com.apple/*\" all");
    let loaded = anchor_rules
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with(' '))
        .count()
        == plan.rules.len();
    enabled && hooked && loaded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PeerIngress;
    use uuid::Uuid;

    fn peer(ingress: Option<PeerIngress>) -> Peer {
        Peer {
            id: Uuid::from_u128(2),
            name: "store".into(),
            wg_public_key: "key".into(),
            endpoint: None,
            allowed_ips: vec!["100.64.0.2/32".into(), "fd7a:115c:a1e0::2/128".into()],
            dns_name: "store.blaktail".into(),
            tags: vec![],
            relay_endpoint: None,
            pq: None,
            ingress,
        }
    }

    #[test]
    fn rules_follow_linux_order_and_end_in_reject() {
        let plan = plan(
            "utun7",
            &[peer(Some(PeerIngress {
                tcp: vec!["22".into(), "1000-2000".into()],
                deny_tcp: vec!["8081".into()],
                icmp: true,
                ..PeerIngress::default()
            }))],
        )
        .unwrap();
        assert!(plan.enforce);
        let text = plan.ruleset();
        let at = |needle: &str| {
            text.find(needle)
                .unwrap_or_else(|| panic!("{needle}\n{text}"))
        };
        assert!(
            at("pass out quick on utun7 from any to 100.64.0.2 flags any keep state")
                < at("pass in")
        );
        assert!(
            at("block return in quick on utun7 proto tcp from 100.64.0.2 to any port 8081")
                < at("pass in quick on utun7 proto tcp from 100.64.0.2 to any port 22 keep state")
        );
        assert!(text.contains("proto tcp from 100.64.0.2 to any port 1000:2000 keep state"));
        assert!(text.contains(
            "pass in quick on utun7 inet6 proto icmp6 from fd7a:115c:a1e0::2 to any keep state"
        ));
        assert!(text.ends_with("block return in quick on utun7 all\n"));
        let rdp = plan
            .rules
            .iter()
            .find(|rule| rule.meta.port == 8081)
            .unwrap();
        assert!(!rdp.meta.allowed);
        assert_eq!(
            rdp.meta.peer_id.as_deref(),
            Some(Uuid::from_u128(2).to_string().as_str())
        );
    }

    #[test]
    fn legacy_maps_and_odd_interfaces_install_nothing() {
        assert!(!plan("utun3", &[peer(None)]).unwrap().enforce);
        for bad in ["en0", "utun", "utun1; pass", "utun12345678901234"] {
            assert!(
                plan(bad, &[peer(Some(PeerIngress::default()))]).is_none(),
                "{bad}"
            );
        }
    }

    #[test]
    fn counters_turn_into_deltas_per_rule() {
        let plan = plan(
            "utun7",
            &[peer(Some(PeerIngress {
                tcp: vec!["22".into()],
                ..PeerIngress::default()
            }))],
        )
        .unwrap();
        let n = plan.rules.len();
        let rendered: String = plan
            .rules
            .iter()
            .enumerate()
            .map(|(index, rule)| {
                format!(
                    "{}\n  [ Evaluations: 9  Packets: {}  Bytes: {}  States: 0 ]\n  [ Inserted: uid 0 pid 1 State Creations: 0 ]\n",
                    rule.text,
                    index,
                    index * 100
                )
            })
            .collect();
        let counters = parse_rule_counters(&rendered);
        assert_eq!(counters.len(), n);
        let mut deltas = crate::traffic::Deltas::default();
        let first = counts(&plan, &counters, &mut deltas);
        assert_eq!(first.len(), n - 1);
        assert!(counts(&plan, &counters, &mut deltas).is_empty());
        assert!(counts(&plan, &counters[1..], &mut deltas).is_empty());
        let denied: Vec<_> = first.iter().filter(|count| !count.allowed).collect();
        assert!(denied.iter().all(|count| count.proto == "all"));
        assert!(denied.iter().any(|count| count.peer_id.is_none()));
        assert!(denied.iter().any(|count| count.peer_id.is_some()));
    }

    #[test]
    fn verification_needs_pf_on_hook_present_and_rules_loaded() {
        let plan = plan("utun7", &[peer(Some(PeerIngress::default()))]).unwrap();
        let anchor = plan.ruleset();
        let main =
            "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n";
        assert!(verified("Status: Enabled for 0 days", main, &anchor, &plan));
        assert!(!verified("Status: Disabled", main, &anchor, &plan));
        assert!(!verified("Status: Enabled", "pass all\n", &anchor, &plan));
        assert!(!verified("Status: Enabled", main, "", &plan));
        assert_eq!(
            enable_token("pf enabled\nToken : 12345\n").as_deref(),
            Some("12345")
        );
        assert_eq!(enable_token("Token : ;rm"), None);
    }

    /// Syntax check with the real parser where available (`pfctl -n` parses
    /// without loading and needs no root).
    #[cfg(target_os = "macos")]
    #[test]
    fn pfctl_accepts_the_generated_ruleset() {
        use std::io::Write as _;
        let plan = plan(
            "utun7",
            &[peer(Some(PeerIngress {
                tcp: vec!["22".into(), "1000-2000".into()],
                udp: vec!["*".into()],
                deny_tcp: vec!["8081".into()],
                deny_udp: vec!["53".into()],
                deny_icmp: true,
                ..PeerIngress::default()
            }))],
        )
        .unwrap();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(plan.ruleset().as_bytes()).unwrap();
        let Ok(output) = std::process::Command::new("/sbin/pfctl")
            .args(["-n", "-f"])
            .arg(file.path())
            .output()
        else {
            return;
        };
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
