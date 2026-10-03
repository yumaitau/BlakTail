//! Routing-peer forward allow-list (Linux).
//!
//! When the coordinator sends `forward_filter`, overlay traffic this node
//! forwards (subnet routes and exit-node traffic) must match an allow entry
//! for that client, destination prefix and service; deny entries win, and
//! everything else is rejected. Rules live in `BLAKTAIL-FWD`, jumped to from
//! `FORWARD` for packets arriving on the overlay interface. Replacement is
//! atomic: the new chain is built under a staging name and jumped to before
//! the old one is removed, so there is never a window where neither applies.

use crate::{acl_filter::iptables_port, sshd::Runner, Error};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const FORWARD_CHAIN: &str = "BLAKTAIL-FWD";
pub const STAGING_CHAIN: &str = "BLAKTAIL-FWD-NEW";
const JUMP_COMMENT: &str = "blaktail-forward";

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ForwardFilter {
    #[serde(default)]
    pub deny: Vec<ForwardRule>,
    #[serde(default)]
    pub allow: Vec<ForwardRule>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ForwardRule {
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub sources: Vec<String>,
    pub destination: String,
    #[serde(default)]
    pub all: bool,
    #[serde(default)]
    pub tcp: Vec<String>,
    #[serde(default)]
    pub udp: Vec<String>,
    #[serde(default)]
    pub icmp: bool,
}

/// Takes the coordinator's filter when a response carries one. Once a filter
/// is in force, a response without `forward_filter` (an older or degraded
/// coordinator, a truncated body) keeps it: forwarding never silently
/// reverts to accept-all.
pub fn adopt(current: &mut Option<ForwardFilter>, incoming: Option<ForwardFilter>) {
    if incoming.is_some() {
        *current = incoming;
    }
}

/// Rule bodies (without `-A <chain>`) per address family.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ForwardPlan {
    pub ipv4: Vec<Vec<String>>,
    pub ipv6: Vec<Vec<String>>,
}

/// Canonical address (or network) and prefix; `None` for anything that is
/// not a well-formed CIDR or bare address.
fn parse(value: &str, host_only: bool) -> Option<(IpAddr, u8)> {
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address.parse::<IpAddr>().ok()?, prefix.parse::<u8>().ok()?),
        None => {
            let address = value.parse::<IpAddr>().ok()?;
            (address, if address.is_ipv4() { 32 } else { 128 })
        }
    };
    let max = if address.is_ipv4() { 32 } else { 128 };
    if prefix > max || (host_only && prefix != max) {
        return None;
    }
    Some((address, prefix))
}

fn reject_with(ipv6: bool, tcp: bool) -> &'static str {
    match (tcp, ipv6) {
        (true, _) => "tcp-reset",
        (false, true) => "icmp6-port-unreachable",
        (false, false) => "icmp-port-unreachable",
    }
}

fn verdict(rule: &mut Vec<String>, accept: bool, ipv6: bool, tcp: bool) {
    rule.extend(["-j".into(), if accept { "ACCEPT" } else { "REJECT" }.into()]);
    if !accept {
        rule.extend(["--reject-with".into(), reject_with(ipv6, tcp).into()]);
    }
}

fn append_rules(out: &mut ForwardPlan, entry: &ForwardRule, accept: bool) {
    let Some((network, prefix)) = parse(entry.destination.trim(), false) else {
        return;
    };
    let destination = format!("{network}/{prefix}");
    for source in &entry.sources {
        let Some((address, _)) = parse(source.trim(), true) else {
            continue;
        };
        if address.is_ipv4() != network.is_ipv4() {
            continue;
        }
        let ipv6 = address.is_ipv6();
        let base = vec![
            "-s".to_string(),
            address.to_string(),
            "-d".into(),
            destination.clone(),
        ];
        let rules = if ipv6 { &mut out.ipv6 } else { &mut out.ipv4 };
        if entry.all {
            let mut rule = base.clone();
            verdict(&mut rule, accept, ipv6, false);
            rules.push(rule);
            continue;
        }
        for (protocol, specs) in [("tcp", &entry.tcp), ("udp", &entry.udp)] {
            for spec in specs {
                // An unreadable deny spec denies the whole protocol (fail
                // closed); an unreadable allow spec grants nothing.
                let port = match (iptables_port(spec), accept) {
                    (Some(port), _) => port,
                    (None, false) => "1:65535".into(),
                    (None, true) => continue,
                };
                let mut rule = base.clone();
                rule.extend(["-p".into(), protocol.into(), "--dport".into(), port]);
                verdict(&mut rule, accept, ipv6, protocol == "tcp");
                rules.push(rule);
            }
        }
        if entry.icmp {
            let mut rule = base.clone();
            rule.extend(["-p".into(), if ipv6 { "icmpv6" } else { "icmp" }.into()]);
            verdict(&mut rule, accept, ipv6, false);
            rules.push(rule);
        }
    }
}

/// Established flows, then every deny, then every allow, then reject the
/// rest. The same filter always yields the same rules.
pub fn plan(filter: &ForwardFilter) -> ForwardPlan {
    let established = vec![
        "-m".to_string(),
        "conntrack".into(),
        "--ctstate".into(),
        "RELATED,ESTABLISHED".into(),
        "-j".into(),
        "ACCEPT".into(),
    ];
    let mut out = ForwardPlan {
        ipv4: vec![established.clone()],
        ipv6: vec![established],
    };
    for entry in &filter.deny {
        append_rules(&mut out, entry, false);
    }
    for entry in &filter.allow {
        append_rules(&mut out, entry, true);
    }
    for (rules, ipv6) in [(&mut out.ipv4, false), (&mut out.ipv6, true)] {
        rules.push(vec![
            "-p".into(),
            "tcp".into(),
            "-j".into(),
            "REJECT".into(),
            "--reject-with".into(),
            "tcp-reset".into(),
        ]);
        rules.push(vec![
            "-j".into(),
            "REJECT".into(),
            "--reject-with".into(),
            reject_with(ipv6, false).into(),
        ]);
    }
    out
}

fn must(runner: &mut dyn Runner, bin: &str, args: &[&str]) -> Result<(), Error> {
    match runner.run(bin, args) {
        Some((true, _)) => Ok(()),
        _ => Err(Error::Message(format!(
            "{bin} {} failed while installing the forward filter",
            args.iter().take(2).copied().collect::<Vec<_>>().join(" ")
        ))),
    }
}

fn jump<'a>(interface: &'a str, chain: &'a str, op: &'a str) -> Vec<&'a str> {
    let mut args = vec![op, "FORWARD"];
    if op == "-I" {
        args.push("1");
    }
    args.extend([
        "-i",
        interface,
        "-m",
        "comment",
        "--comment",
        JUMP_COMMENT,
        "-j",
        chain,
    ]);
    args
}

/// Replaces the live chain for one family with `rules`. On failure the
/// previous chain (if any) stays in force.
pub fn install(
    runner: &mut dyn Runner,
    bin: &str,
    interface: &str,
    rules: &[Vec<String>],
) -> Result<(), Error> {
    for _ in 0..4 {
        runner.run(bin, &jump(interface, STAGING_CHAIN, "-D"));
    }
    runner.run(bin, &["-F", STAGING_CHAIN]);
    runner.run(bin, &["-X", STAGING_CHAIN]);
    let staged = (|| {
        must(runner, bin, &["-N", STAGING_CHAIN])?;
        for rule in rules {
            let mut args = vec!["-A", STAGING_CHAIN];
            args.extend(rule.iter().map(String::as_str));
            must(runner, bin, &args)?;
        }
        // Rate-limited NFLOG copies of rejected packets for per-flow drop
        // events; best-effort, enforcement does not depend on them.
        for insert in crate::flow_capture::drop_log_inserts(STAGING_CHAIN, rules, true) {
            let args: Vec<&str> = insert.iter().map(String::as_str).collect();
            if !matches!(runner.run(bin, &args), Some((true, _))) {
                break;
            }
        }
        must(runner, bin, &jump(interface, STAGING_CHAIN, "-I"))
    })();
    if let Err(error) = staged {
        for _ in 0..4 {
            runner.run(bin, &jump(interface, STAGING_CHAIN, "-D"));
        }
        runner.run(bin, &["-F", STAGING_CHAIN]);
        runner.run(bin, &["-X", STAGING_CHAIN]);
        return Err(error);
    }
    for _ in 0..4 {
        runner.run(bin, &jump(interface, FORWARD_CHAIN, "-D"));
    }
    runner.run(bin, &["-F", FORWARD_CHAIN]);
    runner.run(bin, &["-X", FORWARD_CHAIN]);
    must(runner, bin, &["-E", STAGING_CHAIN, FORWARD_CHAIN])
}

/// Removes the jump and both chains for one family. Safe to repeat.
pub fn clear(runner: &mut dyn Runner, bin: &str, interface: &str) {
    for chain in [FORWARD_CHAIN, STAGING_CHAIN] {
        for _ in 0..4 {
            runner.run(bin, &jump(interface, chain, "-D"));
        }
        runner.run(bin, &["-F", chain]);
        runner.run(bin, &["-X", chain]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn entry(destination: &str) -> ForwardRule {
        ForwardRule {
            client: "client-a".into(),
            sources: vec!["100.64.0.5/32".into(), "fd7a:115c:a1e0::5/128".into()],
            destination: destination.into(),
            ..ForwardRule::default()
        }
    }

    fn joined(rules: &[Vec<String>]) -> Vec<String> {
        rules.iter().map(|rule| rule.join(" ")).collect()
    }

    #[test]
    fn plan_is_deterministic_split_by_family_and_default_denies() {
        let filter = ForwardFilter {
            deny: vec![ForwardRule {
                tcp: vec!["8080".into()],
                ..entry("10.20.1.10/32")
            }],
            allow: vec![
                ForwardRule {
                    tcp: vec!["443".into(), "8000-8080".into()],
                    ..entry("10.20.1.0/24")
                },
                ForwardRule {
                    all: true,
                    ..entry("fd00:20::/64")
                },
            ],
        };
        let first = plan(&filter);
        assert_eq!(first, plan(&filter));
        assert_eq!(
            joined(&first.ipv4),
            vec![
                "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                "-s 100.64.0.5 -d 10.20.1.10/32 -p tcp --dport 8080 -j REJECT --reject-with tcp-reset",
                "-s 100.64.0.5 -d 10.20.1.0/24 -p tcp --dport 443 -j ACCEPT",
                "-s 100.64.0.5 -d 10.20.1.0/24 -p tcp --dport 8000:8080 -j ACCEPT",
                "-p tcp -j REJECT --reject-with tcp-reset",
                "-j REJECT --reject-with icmp-port-unreachable",
            ]
        );
        assert_eq!(
            joined(&first.ipv6),
            vec![
                "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                "-s fd7a:115c:a1e0::5 -d fd00:20::/64 -j ACCEPT",
                "-p tcp -j REJECT --reject-with tcp-reset",
                "-j REJECT --reject-with icmp6-port-unreachable",
            ]
        );
    }

    #[test]
    fn empty_filter_rejects_everything_forwarded() {
        let plan = plan(&ForwardFilter::default());
        assert_eq!(plan.ipv4.len(), 3);
        assert!(plan.ipv4.last().unwrap().contains(&"REJECT".to_string()));
        assert!(!joined(&plan.ipv4).iter().any(|rule| rule.contains("-s ")));
    }

    #[test]
    fn malformed_entries_never_widen_access() {
        let filter = ForwardFilter {
            deny: vec![ForwardRule {
                udp: vec!["bogus".into()],
                ..entry("10.1.0.0/24")
            }],
            allow: vec![
                ForwardRule {
                    sources: vec!["-j ACCEPT".into(), "100.64.0.0/10".into()],
                    all: true,
                    ..entry("10.2.0.0/24")
                },
                ForwardRule {
                    all: true,
                    ..entry("not-a-prefix")
                },
                ForwardRule {
                    tcp: vec!["0".into()],
                    icmp: true,
                    ..entry("10.3.0.0/24")
                },
            ],
        };
        let rules = joined(&plan(&filter).ipv4);
        assert!(rules.contains(
            &"-s 100.64.0.5 -d 10.1.0.0/24 -p udp --dport 1:65535 -j REJECT --reject-with icmp-port-unreachable".to_string()
        ));
        assert!(!rules.iter().any(|rule| rule.contains("10.2.0.0/24")));
        assert!(!rules.iter().any(|rule| rule.contains("not-a-prefix")));
        assert!(!rules.iter().any(|rule| rule.contains("--dport 0")));
        assert!(rules.contains(&"-s 100.64.0.5 -d 10.3.0.0/24 -p icmp -j ACCEPT".to_string()));
    }

    #[test]
    fn missing_filter_keeps_the_current_one() {
        let installed = ForwardFilter {
            allow: vec![ForwardRule {
                tcp: vec!["443".into()],
                ..entry("10.20.1.0/24")
            }],
            ..ForwardFilter::default()
        };
        let mut current = None;
        adopt(&mut current, None);
        assert_eq!(current, None);
        adopt(&mut current, Some(installed.clone()));
        adopt(&mut current, None);
        assert_eq!(current, Some(installed));
        adopt(&mut current, Some(ForwardFilter::default()));
        assert_eq!(current, Some(ForwardFilter::default()));
    }

    #[test]
    fn coordinator_json_round_trips() {
        let filter: ForwardFilter = serde_json::from_value(serde_json::json!({
            "deny": [],
            "allow": [{"client":"7b0e","sources":["100.64.0.5/32"],"destination":"10.20.1.0/24","tcp":["443"]}]
        }))
        .unwrap();
        assert_eq!(filter.allow[0].tcp, vec!["443"]);
        assert!(!filter.allow[0].all);
    }

    /// Records commands and simulates chains well enough to check ordering.
    #[derive(Default)]
    struct FakeTables {
        calls: Vec<String>,
        chains: HashMap<String, Vec<String>>,
        jumps: Vec<String>,
        fail_on: Option<String>,
    }

    impl Runner for FakeTables {
        fn run(&mut self, program: &str, args: &[&str]) -> Option<(bool, String)> {
            let line = format!("{program} {}", args.join(" "));
            self.calls.push(line.clone());
            if self
                .fail_on
                .as_deref()
                .is_some_and(|needle| line.contains(needle))
            {
                return Some((false, String::new()));
            }
            let ok = match args {
                ["-N", chain] => self.chains.insert((*chain).into(), vec![]).is_none(),
                ["-F", chain] => self.chains.get_mut(*chain).map(Vec::clear).is_some(),
                ["-X", chain] => {
                    !self.jumps.iter().any(|jump| jump == chain)
                        && self.chains.remove(*chain).is_some()
                }
                ["-E", from, to] => match self.chains.remove(*from) {
                    Some(rules) => {
                        self.chains.insert((*to).into(), rules);
                        for jump in &mut self.jumps {
                            if jump == from {
                                *jump = (*to).into();
                            }
                        }
                        true
                    }
                    None => false,
                },
                ["-A", chain, rest @ ..] => match self.chains.get_mut(*chain) {
                    Some(rules) => {
                        rules.push(rest.join(" "));
                        true
                    }
                    None => false,
                },
                ["-I", "FORWARD", "1", .., chain] => {
                    self.jumps.insert(0, (*chain).into());
                    true
                }
                ["-D", "FORWARD", .., chain] => {
                    match self.jumps.iter().position(|jump| jump == chain) {
                        Some(index) => {
                            self.jumps.remove(index);
                            true
                        }
                        None => false,
                    }
                }
                _ => true,
            };
            Some((ok, String::new()))
        }
    }

    fn rules(n: usize) -> Vec<Vec<String>> {
        (0..n)
            .map(|i| {
                vec![
                    "-s".into(),
                    format!("100.64.0.{i}"),
                    "-j".into(),
                    "ACCEPT".into(),
                ]
            })
            .collect()
    }

    #[test]
    fn install_swaps_atomically_and_is_idempotent() {
        let mut tables = FakeTables::default();
        install(&mut tables, "iptables", "blaktail0", &rules(2)).unwrap();
        assert_eq!(tables.jumps, vec![FORWARD_CHAIN]);
        assert_eq!(tables.chains[FORWARD_CHAIN].len(), 2);
        assert!(tables
            .calls
            .contains(&"iptables -I FORWARD 1 -i blaktail0 -m comment --comment blaktail-forward -j BLAKTAIL-FWD-NEW".to_string()));

        tables.calls.clear();
        install(&mut tables, "iptables", "blaktail0", &rules(3)).unwrap();
        assert_eq!(tables.jumps, vec![FORWARD_CHAIN]);
        assert_eq!(tables.chains.len(), 1);
        assert_eq!(tables.chains[FORWARD_CHAIN].len(), 3);
        // The new jump is in place before the old one is removed.
        let new_jump = tables
            .calls
            .iter()
            .position(|call| {
                call.starts_with("iptables -I FORWARD 1") && call.ends_with("BLAKTAIL-FWD-NEW")
            })
            .unwrap();
        let old_removed = tables
            .calls
            .iter()
            .position(|call| {
                call.starts_with("iptables -D FORWARD") && call.ends_with("-j BLAKTAIL-FWD")
            })
            .unwrap();
        assert!(new_jump < old_removed);
    }

    #[test]
    fn failed_install_keeps_previous_chain() {
        let mut tables = FakeTables::default();
        install(&mut tables, "ip6tables", "blaktail0", &rules(2)).unwrap();
        tables.fail_on = Some("100.64.0.1".into());
        assert!(install(&mut tables, "ip6tables", "blaktail0", &rules(3)).is_err());
        assert_eq!(tables.jumps, vec![FORWARD_CHAIN]);
        assert_eq!(tables.chains[FORWARD_CHAIN].len(), 2);
        assert!(!tables.chains.contains_key(STAGING_CHAIN));
    }

    #[test]
    fn clear_removes_jumps_and_chains_and_repeats_safely() {
        let mut tables = FakeTables::default();
        install(&mut tables, "iptables", "blaktail0", &rules(1)).unwrap();
        clear(&mut tables, "iptables", "blaktail0");
        assert!(tables.jumps.is_empty());
        assert!(tables.chains.is_empty());
        clear(&mut tables, "iptables", "blaktail0");
        assert!(tables.jumps.is_empty());
    }
}
