//! Builds the coordinator's traffic upload (`POST /v1/nodes/{id}/flows`) from
//! local counters. Shared verbatim by `blaktaild` (`#[path]` include) so every
//! platform reports the same fields, service classes and sampling.
//!
//! A record carries only: organisation and device ids, the peer's device id,
//! direction, protocol, service port class and label, bytes, packets,
//! allow/deny and transport, per time bucket. Never an address, payload, URL,
//! DNS name or user.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Coordinator batch cap (`flows::MAX_FLOW_BATCH`).
pub const MAX_RECORDS: usize = 500;
/// Coordinator bucket cap (`flows::MAX_BUCKET_SECS`).
pub const MAX_BUCKET_SECS: i64 = 3_600;
/// Ports at or above this are reported as one dynamic-range class.
pub const DYNAMIC_PORTS: u16 = 49_152;

/// One local counter before it becomes an upload record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowCount {
    pub peer_id: Option<String>,
    /// `inbound` (a peer started it) or `outbound` (this device did).
    pub direction: &'static str,
    /// `tcp`, `udp`, `icmp`, `other` (another IP protocol), `all` (not split
    /// by protocol, e.g. a catch-all filter rule) or `tunnel` (WireGuard's
    /// per-peer transfer counters; uploaded as protocol `all`).
    pub proto: &'static str,
    pub port: u16,
    pub allowed: bool,
    pub bytes: u64,
    pub packets: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UploadRecord {
    pub org_id: String,
    pub device_id: String,
    pub service: &'static str,
    pub start_bucket: i64,
    pub end_bucket: i64,
    pub proto: &'static str,
    pub port: u16,
    pub bytes: u64,
    pub packets: u64,
    pub transport: String,
    pub decision: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_id: Option<String>,
    pub direction: &'static str,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Upload {
    pub records: Vec<UploadRecord>,
}

/// Short class label for a service port; never a host or URL.
pub fn service_label(proto: &str, port: u16) -> &'static str {
    match proto {
        "icmp" => return "icmp",
        "other" => return "other",
        "all" => return "any",
        "tunnel" => return "tunnel",
        _ => {}
    }
    match (proto, port) {
        (_, 0) => "unknown",
        ("tcp", 22) => "ssh",
        (_, 53) => "dns",
        ("tcp", 80) => "http",
        ("tcp", 443) => "https",
        ("udp", 443) => "quic",
        ("tcp", 3389) => "rdp",
        ("tcp", 445) => "smb",
        (_, 88) => "kerberos",
        ("tcp", 389) | ("tcp", 636) => "ldap",
        ("udp", 123) => "ntp",
        ("udp", 5353) => "mdns",
        ("tcp", 25) | ("tcp", 587) | ("tcp", 993) => "mail",
        ("tcp", 3306) | ("tcp", 5432) | ("tcp", 1433) => "database",
        ("tcp", 8080) | ("tcp", 8000) => "http-alt",
        ("tcp", 8443) => "https-alt",
        ("udp", 51_820) => "wireguard",
        ("tcp", 51_822) => "pq-psk",
        (_, port) if port < 1_024 => "system",
        (_, port) if port < DYNAMIC_PORTS => "registered",
        _ => "dynamic",
    }
}

/// Coordinator's deterministic sampling draw (`traffic::sample_draw`), so a
/// record the agent keeps is one the coordinator keeps too.
pub fn sample_draw(record: &UploadRecord) -> u64 {
    let digest = Sha256::digest(
        format!(
            "{}|{}|{}|{}|{}|{}",
            record.org_id,
            record.device_id,
            record.start_bucket,
            record.service,
            record.proto,
            record.port
        )
        .as_bytes(),
    );
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

/// (peer, direction, protocol, port class, allowed)
type MergeKey = (Option<String>, &'static str, &'static str, u16, bool);

pub struct Bucket<'a> {
    pub org_id: &'a str,
    pub device_id: &'a str,
    pub start: i64,
    pub end: i64,
    /// `direct`, `udp_relay` or `https_relay`.
    pub transport: &'a str,
    /// Peers currently reached through a UDP relay; their records say
    /// `udp_relay` whatever `transport` is.
    pub relayed_peers: &'a [String],
    pub sampling_rate: f64,
}

/// Merges counts into one record per (peer, direction, protocol, port class,
/// decision), drops empty and sampled-out records, and caps the batch. TCP or
/// UDP counts without a port become `all` so the coordinator's port rule holds.
pub fn build(bucket: &Bucket<'_>, counts: &[FlowCount]) -> Upload {
    let end = bucket.end.max(bucket.start);
    let start = bucket.start.max(end - MAX_BUCKET_SECS).max(0);
    let mut merged: BTreeMap<MergeKey, (u64, u64)> = BTreeMap::new();
    for count in counts {
        if count.bytes == 0 && count.packets == 0 {
            continue;
        }
        let (proto, port) = match count.proto {
            "tcp" | "udp" if count.port == 0 => ("all", 0),
            "tcp" | "udp" => (count.proto, count.port.min(DYNAMIC_PORTS)),
            "icmp" => ("icmp", 0),
            "all" => ("all", 0),
            "tunnel" => ("tunnel", 0),
            _ => ("other", 0),
        };
        let direction = if count.direction == "outbound" {
            "outbound"
        } else {
            "inbound"
        };
        let entry = merged
            .entry((count.peer_id.clone(), direction, proto, port, count.allowed))
            .or_default();
        entry.0 = entry.0.saturating_add(count.bytes);
        entry.1 = entry.1.saturating_add(count.packets);
    }
    let mut records: Vec<UploadRecord> = merged
        .into_iter()
        .map(
            |((peer_id, direction, proto, port, allowed), (bytes, packets))| UploadRecord {
                org_id: bucket.org_id.to_owned(),
                device_id: bucket.device_id.to_owned(),
                service: service_label(proto, port),
                start_bucket: start,
                end_bucket: end,
                proto: if proto == "tunnel" { "all" } else { proto },
                port,
                bytes,
                packets,
                transport: if peer_id
                    .as_ref()
                    .is_some_and(|peer| bucket.relayed_peers.contains(peer))
                {
                    "udp_relay".to_owned()
                } else {
                    bucket.transport.to_owned()
                },
                decision: if allowed { "allowed" } else { "denied" },
                peer_id,
                direction,
            },
        )
        .filter(|record| sampled(bucket.sampling_rate, sample_draw(record)))
        .collect();
    // Keep the busiest records when over the batch cap.
    records.sort_by(|a, b| b.packets.cmp(&a.packets).then(b.bytes.cmp(&a.bytes)));
    records.truncate(MAX_RECORDS);
    Upload { records }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count(proto: &'static str, port: u16, allowed: bool) -> FlowCount {
        FlowCount {
            peer_id: Some("11111111-1111-1111-1111-111111111111".into()),
            direction: "inbound",
            proto,
            port,
            allowed,
            bytes: 100,
            packets: 2,
        }
    }

    fn bucket(rate: f64) -> Bucket<'static> {
        Bucket {
            org_id: "org",
            device_id: "dev",
            start: 1_000,
            end: 1_060,
            transport: "direct",
            relayed_peers: &[],
            sampling_rate: rate,
        }
    }

    #[test]
    fn merges_classes_and_never_carries_forbidden_fields() {
        let upload = build(
            &bucket(1.0),
            &[
                count("tcp", 22, true),
                count("tcp", 22, true),
                count("udp", 60_000, false),
                count("udp", 50_000, false),
                count("tcp", 0, false),
                count("icmp", 0, true),
                count("other", 0, true),
                FlowCount {
                    bytes: 0,
                    packets: 0,
                    ..count("tcp", 80, true)
                },
            ],
        );
        assert_eq!(upload.records.len(), 5);
        let ssh = upload.records.iter().find(|r| r.service == "ssh").unwrap();
        assert_eq!((ssh.packets, ssh.bytes, ssh.decision), (4, 200, "allowed"));
        let dynamic = upload
            .records
            .iter()
            .find(|r| r.service == "dynamic")
            .unwrap();
        assert_eq!((dynamic.port, dynamic.packets), (DYNAMIC_PORTS, 4));
        assert!(upload
            .records
            .iter()
            .any(|r| r.proto == "all" && r.port == 0 && r.decision == "denied"));
        let json = serde_json::to_value(&upload).unwrap();
        let allowed = [
            "org_id",
            "device_id",
            "service",
            "start_bucket",
            "end_bucket",
            "proto",
            "port",
            "bytes",
            "packets",
            "transport",
            "decision",
            "peer_id",
            "direction",
        ];
        for record in json["records"].as_array().unwrap() {
            for key in record.as_object().unwrap().keys() {
                assert!(allowed.contains(&key.as_str()), "unexpected field {key}");
            }
        }
    }

    #[test]
    fn bucket_is_clamped_to_an_hour_and_batch_is_capped() {
        let mut long = bucket(1.0);
        long.start = 0;
        long.end = 10_000;
        let counts: Vec<FlowCount> = (1..=700).map(|port| count("tcp", port, false)).collect();
        let upload = build(&long, &counts);
        assert_eq!(upload.records.len(), MAX_RECORDS);
        assert!(upload
            .records
            .iter()
            .all(|r| r.end_bucket - r.start_bucket == MAX_BUCKET_SECS));
    }

    #[test]
    fn sampling_matches_the_coordinator_draw() {
        let counts: Vec<FlowCount> = (1..=400).map(|port| count("tcp", port, true)).collect();
        let half = build(&bucket(0.5), &counts).records.len();
        assert!(half > 100 && half < 300, "{half}");
        assert!(build(&bucket(0.0), &counts).records.is_empty());
        // Deterministic: the same bucket keeps the same records.
        assert_eq!(build(&bucket(0.5), &counts), build(&bucket(0.5), &counts));
    }

    #[test]
    fn service_labels_are_short_lowercase_classes() {
        for (proto, port) in [
            ("tcp", 22),
            ("udp", 53),
            ("tcp", 9999),
            ("udp", 50_000),
            ("all", 0),
        ] {
            let label = service_label(proto, port);
            assert!(label.len() <= 32);
            assert!(label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_'));
        }
    }
}
