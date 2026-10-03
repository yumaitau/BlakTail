use crate::Peer;
use std::net::IpAddr;

pub const ACL_CHAIN: &str = "BLAKTAIL-ACL";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FilterPlan {
    pub enforce: bool,
    pub ipv4: Vec<Vec<String>>,
    pub ipv6: Vec<Vec<String>>,
}

pub fn overlay_host_addrs(allowed_ips: &[String]) -> Vec<String> {
    allowed_ips
        .iter()
        .filter_map(|route| {
            let (address, prefix) = route.split_once('/')?;
            let parsed: IpAddr = address.parse().ok()?;
            let prefix: u8 = prefix.parse().ok()?;
            match parsed {
                IpAddr::V4(_) if prefix == 32 => Some(parsed.to_string()),
                IpAddr::V6(_) if prefix == 128 => Some(parsed.to_string()),
                _ => None,
            }
        })
        .collect()
}

pub fn iptables_port(spec: &str) -> Option<String> {
    let spec = spec.trim();
    if spec == "*" {
        return Some("1:65535".into());
    }
    if let Some((start, end)) = spec.split_once('-') {
        let start: u16 = start.parse().ok()?;
        let end: u16 = end.parse().ok()?;
        if start == 0 || end == 0 || start > end {
            return None;
        }
        return Some(if start == end {
            start.to_string()
        } else {
            format!("{start}:{end}")
        });
    }
    let port: u16 = spec.parse().ok()?;
    (port != 0).then(|| port.to_string())
}

pub fn plan_overlay_filter(peers: &[Peer]) -> FilterPlan {
    if !peers.iter().any(|peer| peer.ingress.is_some()) {
        return FilterPlan::default();
    }
    let mut ipv4 = vec![established()];
    let mut ipv6 = vec![established()];
    for peer in peers {
        let ingress = peer.ingress.clone().unwrap_or_else(|| crate::PeerIngress {
            all: true,
            ..crate::PeerIngress::default()
        });
        let pq_exchange = peer
            .pq
            .as_ref()
            .is_some_and(|pq| pq.mode != crate::pq::Mode::Off && pq.capable);
        for address in overlay_host_addrs(&peer.allowed_ips) {
            let rules = if address.contains(':') {
                &mut ipv6
            } else {
                &mut ipv4
            };
            if pq_exchange {
                // The in-tunnel PSK exchange must work even when policy
                // grants this peer nothing else.
                rules.push(accept_port(&address, "tcp", &crate::pq::PORT.to_string()));
            }
            append_peer_rules(rules, &address, &ingress);
        }
    }
    ipv4.extend(final_reject(false));
    ipv6.extend(final_reject(true));
    FilterPlan {
        enforce: true,
        ipv4,
        ipv6,
    }
}

/// True when an SSH grant names specific users or denies some, so only a
/// verified sshd drop-in can express it.
pub fn ssh_restricted(ingress: &crate::PeerIngress) -> bool {
    let unrestricted = ingress.ssh_users.len() == 1
        && ingress.ssh_users[0] == "*"
        && ingress.ssh_deny_users.is_empty();
    !ingress.ssh_users.is_empty() && !unrestricted
}

/// Without proven per-user sshd limits, reject TCP 22 from every source
/// whose SSH grant is user-limited. The coordinator does the same; this is
/// the agent's own fail-closed backstop.
pub fn fail_closed_ssh(peers: &[Peer], users_enforced: bool) -> Vec<Peer> {
    let mut peers = peers.to_vec();
    if users_enforced {
        return peers;
    }
    for peer in &mut peers {
        if let Some(ingress) = &mut peer.ingress {
            if ssh_restricted(ingress) && !ingress.deny_tcp.iter().any(|spec| spec == "22") {
                ingress.deny_tcp.push("22".into());
            }
        }
    }
    peers
}

fn valid_login(user: &str) -> bool {
    let mut chars = user.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_alphabetic() || first == '_')
        && user.len() <= 32
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

/// sshd `Match Address` blocks for user-limited sources. Ends with `Match
/// all` so nothing after an include is captured by the last block. A login
/// that is not a plain name denies every user from that source.
pub fn sshd_policy_config(peers: &[Peer]) -> String {
    let mut out = String::from("# managed by blaktaild\n");
    let mut wrote = false;
    for peer in peers {
        let Some(ingress) = &peer.ingress else {
            continue;
        };
        if !ssh_restricted(ingress) {
            continue;
        }
        let addresses = overlay_host_addrs(&peer.allowed_ips);
        if addresses.is_empty() {
            continue;
        }
        wrote = true;
        out.push_str("Match Address ");
        out.push_str(&addresses.join(","));
        out.push('\n');
        let allow: Vec<&String> = ingress.ssh_users.iter().filter(|u| *u != "*").collect();
        let names_ok = allow
            .iter()
            .copied()
            .chain(ingress.ssh_deny_users.iter())
            .all(|user| valid_login(user));
        if !names_ok {
            out.push_str("    DenyUsers *\n");
            continue;
        }
        if !allow.is_empty() {
            out.push_str("    AllowUsers ");
            out.push_str(
                &allow
                    .iter()
                    .map(|user| user.as_str())
                    .collect::<Vec<_>>()
                    .join(" "),
            );
            out.push('\n');
        }
        if !ingress.ssh_deny_users.is_empty() {
            out.push_str("    DenyUsers ");
            out.push_str(&ingress.ssh_deny_users.join(" "));
            out.push('\n');
        }
    }
    if wrote {
        out.push_str("Match all\n");
    }
    out
}

fn established() -> Vec<String> {
    vec![
        "-A".into(),
        ACL_CHAIN.into(),
        "-m".into(),
        "conntrack".into(),
        "--ctstate".into(),
        "RELATED,ESTABLISHED".into(),
        "-j".into(),
        "ACCEPT".into(),
    ]
}

fn append_peer_rules(rules: &mut Vec<Vec<String>>, source: &str, ingress: &crate::PeerIngress) {
    for spec in &ingress.deny_tcp {
        if let Some(port) = iptables_port(spec) {
            rules.push(reject_port(source, "tcp", &port, true));
        }
    }
    for spec in &ingress.deny_udp {
        if let Some(port) = iptables_port(spec) {
            rules.push(reject_port(source, "udp", &port, false));
        }
    }
    if ingress.deny_icmp {
        rules.push(reject_icmp(source));
    }
    if ingress.all {
        rules.push(accept_source(source));
        return;
    }
    for spec in &ingress.tcp {
        if let Some(port) = iptables_port(spec) {
            rules.push(accept_port(source, "tcp", &port));
        }
    }
    for spec in &ingress.udp {
        if let Some(port) = iptables_port(spec) {
            rules.push(accept_port(source, "udp", &port));
        }
    }
    if ingress.icmp {
        rules.push(accept_icmp(source));
    }
    rules.extend(source_reject(source));
}

fn accept_source(source: &str) -> Vec<String> {
    vec![
        "-A".into(),
        ACL_CHAIN.into(),
        "-s".into(),
        source.into(),
        "-j".into(),
        "ACCEPT".into(),
    ]
}

fn accept_port(source: &str, protocol: &str, port: &str) -> Vec<String> {
    vec![
        "-A".into(),
        ACL_CHAIN.into(),
        "-s".into(),
        source.into(),
        "-p".into(),
        protocol.into(),
        "--dport".into(),
        port.into(),
        "-j".into(),
        "ACCEPT".into(),
    ]
}

fn accept_icmp(source: &str) -> Vec<String> {
    let protocol = if source.contains(':') {
        "icmpv6"
    } else {
        "icmp"
    };
    vec![
        "-A".into(),
        ACL_CHAIN.into(),
        "-s".into(),
        source.into(),
        "-p".into(),
        protocol.into(),
        "-j".into(),
        "ACCEPT".into(),
    ]
}

fn reject_port(source: &str, protocol: &str, port: &str, tcp: bool) -> Vec<String> {
    let mut rule = vec![
        "-A".into(),
        ACL_CHAIN.into(),
        "-s".into(),
        source.into(),
        "-p".into(),
        protocol.into(),
        "--dport".into(),
        port.into(),
        "-j".into(),
        "REJECT".into(),
        "--reject-with".into(),
    ];
    rule.push(if tcp {
        "tcp-reset".into()
    } else if source.contains(':') {
        "icmp6-port-unreachable".into()
    } else {
        "icmp-port-unreachable".into()
    });
    rule
}

fn reject_icmp(source: &str) -> Vec<String> {
    let (protocol, reject) = if source.contains(':') {
        ("icmpv6", "icmp6-port-unreachable")
    } else {
        ("icmp", "icmp-port-unreachable")
    };
    vec![
        "-A".into(),
        ACL_CHAIN.into(),
        "-s".into(),
        source.into(),
        "-p".into(),
        protocol.into(),
        "-j".into(),
        "REJECT".into(),
        "--reject-with".into(),
        reject.into(),
    ]
}

/// The chain's final rejects, scoped to one source: same action, but their
/// counters attribute denied attempts to the peer (traffic reporting).
fn source_reject(source: &str) -> [Vec<String>; 2] {
    final_reject(source.contains(':')).map(|mut rule| {
        rule.splice(2..2, ["-s".to_string(), source.to_string()]);
        rule
    })
}

fn final_reject(ipv6: bool) -> [Vec<String>; 2] {
    let icmp = if ipv6 {
        "icmp6-port-unreachable"
    } else {
        "icmp-port-unreachable"
    };
    [
        vec![
            "-A".into(),
            ACL_CHAIN.into(),
            "-p".into(),
            "tcp".into(),
            "-j".into(),
            "REJECT".into(),
            "--reject-with".into(),
            "tcp-reset".into(),
        ],
        vec![
            "-A".into(),
            ACL_CHAIN.into(),
            "-j".into(),
            "REJECT".into(),
            "--reject-with".into(),
            icmp.into(),
        ],
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Peer, PeerIngress};
    use uuid::Uuid;

    fn peer(ingress: PeerIngress) -> Peer {
        Peer {
            id: Uuid::from_u128(2),
            name: "store".into(),
            wg_public_key: "key".into(),
            endpoint: None,
            allowed_ips: vec!["100.64.0.2/32".into(), "fd12:3456::2/128".into()],
            dns_name: "store.blaktail".into(),
            tags: vec![],
            relay_endpoint: None,
            pq: None,
            ingress: Some(ingress),
        }
    }

    /// Walks the generated chain like the kernel would for a new inbound
    /// packet: first matching ACCEPT/REJECT wins, conntrack rule skipped.
    fn chain_accepts(plan: &FilterPlan, source: &str, proto: &str, port: u16) -> bool {
        if !plan.enforce {
            return true;
        }
        let rules = if source.contains(':') {
            &plan.ipv6
        } else {
            &plan.ipv4
        };
        for rule in rules {
            if rule.iter().any(|token| token == "conntrack") {
                continue;
            }
            let value = |flag: &str| {
                rule.iter()
                    .position(|token| token == flag)
                    .and_then(|index| rule.get(index + 1))
                    .map(String::as_str)
            };
            if value("-s").is_some_and(|s| s != source) {
                continue;
            }
            let protocol_matches = match value("-p") {
                None => true,
                Some("icmp") | Some("icmpv6") => proto == "icmp",
                Some(other) => other == proto,
            };
            if !protocol_matches {
                continue;
            }
            if let Some(range) = value("--dport") {
                let (start, end) = range.split_once(':').unwrap_or((range, range));
                let (start, end): (u16, u16) = (start.parse().unwrap(), end.parse().unwrap());
                if !(start..=end).contains(&port) {
                    continue;
                }
            }
            return value("-j") == Some("ACCEPT");
        }
        true
    }

    #[derive(serde::Deserialize)]
    struct VectorPeer {
        allowed_ips: Vec<String>,
        #[serde(default)]
        ingress: Option<PeerIngress>,
    }

    #[derive(serde::Deserialize)]
    struct Vector {
        name: String,
        peers: Vec<VectorPeer>,
        checks: Vec<(String, String, u16, bool)>,
    }

    /// The vectors the userspace filter (iOS, Android, Windows) is tested
    /// with: the Linux chain must reach the same decisions.
    #[test]
    fn shared_vectors_decide_like_the_userspace_filter() {
        let vectors: Vec<Vector> = serde_json::from_str(include_str!(
            "../../blaktail-ios-wg/src/filter_vectors.json"
        ))
        .unwrap();
        for vector in vectors {
            let peers: Vec<Peer> = vector
                .peers
                .iter()
                .enumerate()
                .map(|(index, entry)| Peer {
                    id: Uuid::from_u128(index as u128 + 1),
                    allowed_ips: entry.allowed_ips.clone(),
                    ingress: entry.ingress.clone(),
                    ..peer(PeerIngress::default())
                })
                .collect();
            let plan = plan_overlay_filter(&fail_closed_ssh(&peers, false));
            for (source, proto, port, expect) in &vector.checks {
                assert_eq!(
                    chain_accepts(&plan, source, proto, *port),
                    *expect,
                    "{}: {source} {proto}/{port}",
                    vector.name
                );
            }
        }
    }

    #[test]
    fn missing_ingress_leaves_legacy_peers_unfiltered() {
        let mut legacy = peer(PeerIngress::default());
        legacy.ingress = None;
        assert!(!plan_overlay_filter(&[legacy]).enforce);
    }

    #[test]
    fn restricted_tcp_and_ssh_compile_accept_and_reject_rules() {
        let plan = plan_overlay_filter(&[peer(PeerIngress {
            tcp: vec!["22".into(), "8080".into()],
            deny_tcp: vec!["8081".into()],
            ssh_users: vec!["blaktail".into()],
            ..PeerIngress::default()
        })]);
        assert!(plan.enforce);
        let joined: Vec<String> = plan.ipv4.iter().map(|rule| rule.join(" ")).collect();
        assert!(joined
            .iter()
            .any(|rule| rule.contains("-s 100.64.0.2 -p tcp --dport 8080 -j ACCEPT")));
        assert!(joined
            .iter()
            .any(|rule| rule.contains("-s 100.64.0.2 -p tcp --dport 8081 -j REJECT")));
        assert!(joined
            .iter()
            .any(|rule| rule.ends_with("-p tcp -j REJECT --reject-with tcp-reset")));
        let v6: Vec<String> = plan.ipv6.iter().map(|rule| rule.join(" ")).collect();
        assert!(v6
            .iter()
            .any(|rule| rule.contains("-s fd12:3456::2 -p tcp --dport 22 -j ACCEPT")));
    }

    #[test]
    fn sshd_match_blocks_list_allowed_users_per_source() {
        let config = sshd_policy_config(&[peer(PeerIngress {
            ssh_users: vec!["blaktail".into()],
            ..PeerIngress::default()
        })]);
        assert!(config.contains("Match Address 100.64.0.2,fd12:3456::2"));
        assert!(config.contains("AllowUsers blaktail"));
        assert!(config.ends_with("Match all\n"));
    }

    #[test]
    fn sshd_star_with_denies_and_injection_fail_closed() {
        let config = sshd_policy_config(&[peer(PeerIngress {
            all: true,
            ssh_users: vec!["*".into()],
            ssh_deny_users: vec!["root".into()],
            ..PeerIngress::default()
        })]);
        assert!(config.contains("    DenyUsers root\n"));
        assert!(!config.contains("AllowUsers"));
        let unrestricted = sshd_policy_config(&[peer(PeerIngress {
            all: true,
            ssh_users: vec!["*".into()],
            ..PeerIngress::default()
        })]);
        assert_eq!(unrestricted, "# managed by blaktaild\n");
        let injected = sshd_policy_config(&[peer(PeerIngress {
            ssh_users: vec!["ok\nMatch all\nPermitRootLogin yes".into()],
            ..PeerIngress::default()
        })]);
        assert!(injected.contains("    DenyUsers *\n"));
        assert!(!injected.contains("PermitRootLogin"));
    }

    #[test]
    fn unverified_sshd_closes_port_22_for_user_limited_sources_only() {
        let limited = peer(PeerIngress {
            tcp: vec!["22".into(), "8080".into()],
            ssh_users: vec!["deploy".into()],
            ..PeerIngress::default()
        });
        let mut open = peer(PeerIngress {
            tcp: vec!["22".into()],
            ssh_users: vec!["*".into()],
            ..PeerIngress::default()
        });
        open.allowed_ips = vec!["100.64.0.3/32".into()];
        let closed = fail_closed_ssh(&[limited.clone(), open.clone()], false);
        assert_eq!(closed[0].ingress.as_ref().unwrap().deny_tcp, vec!["22"]);
        assert!(closed[1].ingress.as_ref().unwrap().deny_tcp.is_empty());
        let plan = plan_overlay_filter(&closed);
        let rules: Vec<String> = plan.ipv4.iter().map(|rule| rule.join(" ")).collect();
        let reject = rules
            .iter()
            .position(|r| r.contains("-s 100.64.0.2 -p tcp --dport 22 -j REJECT"))
            .expect("reject 22");
        let accept = rules
            .iter()
            .position(|r| r.contains("-s 100.64.0.2 -p tcp --dport 22 -j ACCEPT"))
            .expect("accept 22 still listed");
        assert!(reject < accept, "reject must precede accept");
        assert!(rules
            .iter()
            .any(|r| r.contains("-s 100.64.0.3 -p tcp --dport 22 -j ACCEPT")));
        let enforced = fail_closed_ssh(&[limited], true);
        assert!(enforced[0].ingress.as_ref().unwrap().deny_tcp.is_empty());
    }
}
