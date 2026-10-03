//! App connector (NetBird-parity draft 06), Linux only.
//!
//! When enabled with `blaktaild up --app-connector`, the node resolves the
//! exact FQDN of every DNS network resource it is a routing peer for, from
//! its own resolver (`/etc/resolv.conf`, falling back to the libc resolver),
//! and reports the A/AAAA answers and TTLs to the coordinator. It forwards
//! only the host routes the coordinator accepted, exactly like a subnet
//! router forwards an approved prefix.

use crate::{ApiErrorResponse, Coordinator, Error, Network, NodeState};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use tracing::{info, warn};
use uuid::Uuid;

pub const CAPABILITY: &str = "app-connector";
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
/// TTL reported when only the libc resolver answered (it hides TTLs); the
/// coordinator clamps leases to at least this anyway.
const FALLBACK_TTL: u32 = 30;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;

#[derive(Debug, Deserialize)]
struct Assignment {
    resource_id: Uuid,
    fqdn: String,
}

#[derive(Debug, Deserialize)]
struct Assignments {
    interval_seconds: u64,
    resources: Vec<Assignment>,
}

#[derive(Debug, Serialize)]
struct Answer {
    address: String,
    ttl: u32,
}

#[derive(Debug, Serialize)]
struct Report<'a> {
    resource_id: Uuid,
    fqdn: &'a str,
    answers: Vec<Answer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Outcome {
    routes: Vec<String>,
}

async fn error_message(response: reqwest::Response) -> String {
    let status = response.status();
    response
        .json::<ApiErrorResponse>()
        .await
        .map(|body| body.error)
        .unwrap_or_else(|_| format!("coordinator returned {status}"))
}

impl Coordinator {
    async fn connector_assignments(&self, state: &NodeState) -> Result<Assignments, Error> {
        let response = self
            .client
            .get(format!(
                "{}/v1/nodes/{}/connector/assignments",
                self.base, state.node_id
            ))
            .bearer_auth(&state.node_token)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(Error::Message(format!(
                "connector assignments refused: {}",
                error_message(response).await
            )));
        }
        Ok(response.json().await?)
    }

    async fn report_resolution(
        &self,
        state: &NodeState,
        report: &Report<'_>,
    ) -> Result<Outcome, Error> {
        let response = self
            .client
            .post(format!(
                "{}/v1/nodes/{}/connector/resolutions",
                self.base, state.node_id
            ))
            .bearer_auth(&state.node_token)
            .json(report)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(Error::Message(error_message(response).await));
        }
        Ok(response.json().await?)
    }
}

// ---------- resolution ----------

/// Nameservers from resolv.conf text, in order.
pub fn nameservers(resolv_conf: &str) -> Vec<SocketAddr> {
    resolv_conf
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next()? == "nameserver").then(|| words.next())?
        })
        .filter_map(|value| value.split('%').next()?.parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, 53))
        .collect()
}

fn encode_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet
}

fn skip_name(packet: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let len = *packet.get(offset)?;
        if len & 0xc0 == 0xc0 {
            return Some(offset + 2);
        }
        offset += 1;
        if len == 0 {
            return Some(offset);
        }
        offset += usize::from(len);
    }
}

fn u16_at(packet: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *packet.get(offset)?,
        *packet.get(offset + 1)?,
    ]))
}

/// Address records of `qtype` in the answer section (CNAME chains are
/// followed by the recursive resolver; only the final records are taken).
/// `Ok(empty)` covers NXDOMAIN and NODATA; other failures are errors.
pub fn parse_answers(packet: &[u8], id: u16, qtype: u16) -> Result<Vec<(IpAddr, u32)>, String> {
    let malformed = || "malformed DNS response".to_owned();
    if packet.len() < 12 || u16_at(packet, 0) != Some(id) || packet[2] & 0x80 == 0 {
        return Err(malformed());
    }
    match packet[3] & 0x0f {
        0 => {}
        3 => return Ok(Vec::new()),
        code => return Err(format!("resolver answered with DNS error code {code}")),
    }
    let questions = u16_at(packet, 4).ok_or_else(malformed)?;
    let answers = u16_at(packet, 6).ok_or_else(malformed)?;
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_name(packet, offset).ok_or_else(malformed)? + 4;
    }
    let mut found = Vec::new();
    for _ in 0..answers {
        offset = skip_name(packet, offset).ok_or_else(malformed)?;
        let rtype = u16_at(packet, offset).ok_or_else(malformed)?;
        let ttl = packet
            .get(offset + 4..offset + 8)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or_else(malformed)?;
        let len = usize::from(u16_at(packet, offset + 8).ok_or_else(malformed)?);
        let data = packet
            .get(offset + 10..offset + 10 + len)
            .ok_or_else(malformed)?;
        offset += 10 + len;
        if rtype != qtype {
            continue;
        }
        let ip = match (qtype, data.len()) {
            (TYPE_A, 4) => IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
            (TYPE_AAAA, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(data);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return Err(malformed()),
        };
        found.push((ip, ttl));
    }
    Ok(found)
}

async fn query(server: SocketAddr, name: &str, qtype: u16) -> Result<Vec<(IpAddr, u32)>, String> {
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = tokio::net::UdpSocket::bind(bind)
        .await
        .map_err(|error| error.to_string())?;
    let id: u16 = rand::random();
    socket
        .send_to(&encode_query(id, name, qtype), server)
        .await
        .map_err(|error| error.to_string())?;
    let mut buffer = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + QUERY_TIMEOUT;
    loop {
        let (len, from) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer))
            .await
            .map_err(|_| format!("{server} did not answer"))?
            .map_err(|error| error.to_string())?;
        // Ignore stray datagrams from anyone but the server we asked.
        if from != server {
            continue;
        }
        return parse_answers(&buffer[..len], id, qtype);
    }
}

/// Resolves A and AAAA for `name` from the system's own resolver.
pub async fn resolve(name: &str) -> Result<Vec<(IpAddr, u32)>, String> {
    let servers = std::fs::read_to_string("/etc/resolv.conf")
        .map(|text| nameservers(&text))
        .unwrap_or_default();
    let mut last_error = String::from("no nameserver in /etc/resolv.conf");
    for server in servers {
        let (v4, v6) = tokio::join!(query(server, name, TYPE_A), query(server, name, TYPE_AAAA));
        match (v4, v6) {
            (Ok(mut v4), Ok(v6)) => {
                v4.extend(v6);
                return Ok(v4);
            }
            (Err(error), _) | (_, Err(error)) => last_error = error,
        }
    }
    // The libc resolver honours nsswitch but hides TTLs.
    match tokio::net::lookup_host((name, 0)).await {
        Ok(addresses) => {
            let unique: BTreeSet<IpAddr> = addresses.map(|address| address.ip()).collect();
            Ok(unique.into_iter().map(|ip| (ip, FALLBACK_TTL)).collect())
        }
        Err(error) => Err(format!("{last_error}; system lookup failed: {error}")),
    }
}

/// Only exact host routes are ever handed to iptables.
fn host_route(route: &str) -> bool {
    match route.split_once('/') {
        Some((ip, "32")) => ip.parse::<Ipv4Addr>().is_ok(),
        Some((ip, "128")) => ip.parse::<Ipv6Addr>().is_ok(),
        _ => false,
    }
}

// ---------- reconcile loop ----------

#[derive(Default)]
pub struct ConnectorRuntime {
    next_due: Option<Instant>,
}

fn router_routes(state: &NodeState, connector: &BTreeSet<String>) -> Vec<String> {
    let mut routes = state.advertised_routes.clone();
    routes.extend(connector.iter().cloned());
    routes.sort();
    routes.dedup();
    routes
}

fn reconcile_forwarding(
    network: &mut dyn Network,
    state: &mut NodeState,
    desired: BTreeSet<String>,
) -> Result<bool, Error> {
    let current: BTreeSet<String> = state.connector_routes.iter().cloned().collect();
    if current == desired {
        return Ok(false);
    }
    let previous = router_routes(state, &current);
    let next = router_routes(state, &desired);
    let originals = network.configure_router(
        &state.interface,
        &previous,
        &next,
        state.forwarding_originals(),
    )?;
    state.set_forwarding_originals(originals);
    info!(routes = desired.len(), "app connector forwarding updated");
    state.connector_routes = desired.into_iter().collect();
    Ok(true)
}

/// Delay before the next report. The pass runs once per control-update loop
/// (up to 25 s apart), so a deadline of exactly the interval would usually
/// be missed by one loop and stretch a 30 s interval to ~50 s; aim a little
/// early instead.
fn report_delay(interval_seconds: u64) -> Duration {
    Duration::from_secs(interval_seconds.clamp(10, 300).saturating_sub(5))
}

/// One connector pass. Returns true when `state` changed and must be saved.
pub async fn manage(
    coordinator: &Coordinator,
    network: &mut dyn Network,
    state: &mut NodeState,
    runtime: &mut ConnectorRuntime,
) -> bool {
    if !state.app_connector {
        return match reconcile_forwarding(network, state, BTreeSet::new()) {
            Ok(changed) => changed,
            Err(error) => {
                warn!(%error, "could not remove app connector forwarding");
                false
            }
        };
    }
    if runtime.next_due.is_some_and(|due| Instant::now() < due) {
        return false;
    }
    let assignments = match coordinator.connector_assignments(state).await {
        Ok(assignments) => assignments,
        Err(error) => {
            // Keep current forwarding; the coordinator withdraws leases on
            // its own TTL if this connector stays silent.
            warn!(%error, "app connector assignments unavailable");
            runtime.next_due = Some(Instant::now() + Duration::from_secs(30));
            return false;
        }
    };
    runtime.next_due = Some(Instant::now() + report_delay(assignments.interval_seconds));
    let mut desired = BTreeSet::new();
    for assignment in &assignments.resources {
        let (answers, error) = match resolve(&assignment.fqdn).await {
            Ok(answers) => (
                answers
                    .into_iter()
                    .map(|(ip, ttl)| Answer {
                        address: ip.to_string(),
                        ttl,
                    })
                    .collect(),
                None,
            ),
            Err(error) => (Vec::new(), Some(error)),
        };
        let report = Report {
            resource_id: assignment.resource_id,
            fqdn: &assignment.fqdn,
            answers,
            error,
        };
        match coordinator.report_resolution(state, &report).await {
            Ok(outcome) => desired.extend(outcome.routes.into_iter().filter(|r| host_route(r))),
            // Rejected (for example rebinding to a forbidden address): the
            // coordinator withdrew the routes, so stop forwarding them too.
            Err(error) => warn!(fqdn = %assignment.fqdn, %error, "app connector report rejected"),
        }
    }
    match reconcile_forwarding(network, state, desired) {
        Ok(changed) => changed,
        Err(error) => {
            warn!(%error, "could not update app connector forwarding");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(id: u16, rcode: u8, qtype: u16, records: &[(u16, &[u8], u32)]) -> Vec<u8> {
        let mut packet = id.to_be_bytes().to_vec();
        packet.extend_from_slice(&[0x81, 0x80 | rcode, 0, 1, 0, records.len() as u8, 0, 0, 0, 0]);
        let question = encode_query(id, "app.example.org", qtype);
        packet.extend_from_slice(&question[12..]);
        for (rtype, data, ttl) in records {
            packet.extend_from_slice(&[0xc0, 0x0c]);
            packet.extend_from_slice(&rtype.to_be_bytes());
            packet.extend_from_slice(&1u16.to_be_bytes());
            packet.extend_from_slice(&ttl.to_be_bytes());
            packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
            packet.extend_from_slice(data);
        }
        packet
    }

    #[test]
    fn parses_cname_chain_answers_with_ttls() {
        let cname = b"\x03cdn\x07example\x03net\x00";
        let packet = response(
            7,
            0,
            TYPE_A,
            &[
                (5, cname, 300),
                (TYPE_A, &[10, 0, 0, 5], 42),
                (TYPE_A, &[10, 0, 0, 6], 60),
            ],
        );
        assert_eq!(
            parse_answers(&packet, 7, TYPE_A).unwrap(),
            [
                ("10.0.0.5".parse().unwrap(), 42),
                ("10.0.0.6".parse().unwrap(), 60)
            ]
        );
        let aaaa = response(
            9,
            0,
            TYPE_AAAA,
            &[(
                TYPE_AAAA,
                &[0xfd, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5],
                5,
            )],
        );
        assert_eq!(
            parse_answers(&aaaa, 9, TYPE_AAAA).unwrap(),
            [("fd12::5".parse().unwrap(), 5)]
        );
    }

    #[test]
    fn nxdomain_is_empty_and_failures_are_errors() {
        assert!(parse_answers(&response(1, 3, TYPE_A, &[]), 1, TYPE_A)
            .unwrap()
            .is_empty());
        assert!(parse_answers(&response(1, 2, TYPE_A, &[]), 1, TYPE_A).is_err());
        assert!(parse_answers(&response(1, 0, TYPE_A, &[]), 2, TYPE_A).is_err());
        assert!(
            parse_answers(&response(1, 0, TYPE_A, &[(TYPE_A, &[1, 2], 5)]), 1, TYPE_A).is_err()
        );
        assert!(parse_answers(&[0u8; 5], 1, TYPE_A).is_err());
    }

    #[test]
    fn report_delay_fits_the_control_update_loop() {
        assert_eq!(report_delay(30), Duration::from_secs(25));
        assert_eq!(report_delay(0), Duration::from_secs(5));
        assert_eq!(report_delay(10_000), Duration::from_secs(295));
    }

    #[test]
    fn reads_nameservers_and_accepts_only_host_routes() {
        let servers = nameservers(
            "# c\nsearch x\nnameserver 127.0.0.53\nnameserver fe80::1%eth0\noptions edns0\n",
        );
        assert_eq!(
            servers,
            [
                "127.0.0.53:53".parse::<SocketAddr>().unwrap(),
                "[fe80::1]:53".parse().unwrap()
            ]
        );
        assert!(host_route("10.0.0.5/32"));
        assert!(host_route("fd12::5/128"));
        assert!(!host_route("10.0.0.0/24"));
        assert!(!host_route("10.0.0.5"));
        assert!(!host_route("-j ACCEPT/32"));
    }
}
