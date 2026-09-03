//! Aggregated flow telemetry validation (issue #50).
//!
//! Flow records are counters only (bytes/packets per bucket). Anything
//! payload-ish (URLs, bodies) is rejected at validation time so per-flow
//! content can never reach storage. Only serde/serde_json/thiserror.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Hard cap on records accepted in a single upload batch.
pub const MAX_FLOW_BATCH: usize = 500;
/// Buckets may span at most one hour.
pub const MAX_BUCKET_SECS: i64 = 3600;

/// JSON keys that must never appear anywhere in a flow upload.
const FORBIDDEN_FLOW_KEYS: &[&str] = &["url", "payload", "payload_b64", "body", "content"];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FlowError {
    #[error("flow batch has {found} records, max is {MAX_FLOW_BATCH}")]
    BatchTooLarge { found: usize },
    #[error("missing required field '{0}'")]
    MissingField(&'static str),
    #[error("invalid bucket range: start {start} end {end}")]
    BucketRange { start: i64, end: i64 },
    #[error("bucket spans {spanned}s, max is {MAX_BUCKET_SECS}s")]
    BucketTooWide { spanned: i64 },
    #[error("unsupported protocol '{0}' (want tcp, udp or icmp)")]
    BadProtocol(String),
    #[error("port {0} invalid for protocol '{1}'")]
    BadPort(u16, String),
    #[error("forbidden payload field '{0}' in flow upload")]
    PayloadField(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowTransport {
    Direct,
    UdpRelay,
    HttpsRelay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowDecision {
    Allowed,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRecord {
    pub org_id: String,
    pub device_id: String,
    pub service: String,
    pub start_bucket: i64,
    pub end_bucket: i64,
    pub proto: String,
    pub port: u16,
    pub bytes: u64,
    pub packets: u64,
    pub transport: FlowTransport,
    pub decision: FlowDecision,
}

impl FlowRecord {
    pub fn validate(&self) -> Result<(), FlowError> {
        if self.org_id.trim().is_empty() {
            return Err(FlowError::MissingField("org_id"));
        }
        if self.device_id.trim().is_empty() {
            return Err(FlowError::MissingField("device_id"));
        }
        if self.service.trim().is_empty() {
            return Err(FlowError::MissingField("service"));
        }
        if self.start_bucket < 0 || self.end_bucket < 0 || self.end_bucket < self.start_bucket {
            return Err(FlowError::BucketRange {
                start: self.start_bucket,
                end: self.end_bucket,
            });
        }
        if self.end_bucket - self.start_bucket > MAX_BUCKET_SECS {
            return Err(FlowError::BucketTooWide {
                spanned: self.end_bucket - self.start_bucket,
            });
        }
        match self.proto.as_str() {
            "tcp" | "udp" => {
                if self.port == 0 {
                    return Err(FlowError::BadPort(self.port, self.proto.clone()));
                }
            }
            "icmp" => {
                if self.port != 0 {
                    return Err(FlowError::BadPort(self.port, self.proto.clone()));
                }
            }
            other => return Err(FlowError::BadProtocol(other.to_owned())),
        }
        Ok(())
    }
}

/// Batch cap + per-record validation.
pub fn validate_batch(records: &[FlowRecord]) -> Result<(), FlowError> {
    if records.len() > MAX_FLOW_BATCH {
        return Err(FlowError::BatchTooLarge {
            found: records.len(),
        });
    }
    for record in records {
        record.validate()?;
    }
    Ok(())
}

/// Reject raw upload JSON containing payload-ish keys at any depth.
pub fn validate_flow_json(value: &serde_json::Value) -> Result<(), FlowError> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, nested) in map {
                if FORBIDDEN_FLOW_KEYS.contains(&key.as_str()) {
                    return Err(FlowError::PayloadField(key.clone()));
                }
                validate_flow_json(nested)?;
            }
            Ok(())
        }
        serde_json::Value::Array(items) => {
            for item in items {
                validate_flow_json(item)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Deterministic sampler: `uniform_u64` is caller-supplied randomness
/// (e.g. a hash of org+device+bucket) so tests don't need RNG.
pub fn should_sample(rate: f64, uniform_u64: u64) -> bool {
    if rate <= 0.0 {
        return false;
    }
    if rate >= 1.0 {
        return true;
    }
    (uniform_u64 as f64 / u64::MAX as f64) < rate
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> FlowRecord {
        FlowRecord {
            org_id: "org-1".into(),
            device_id: "dev-1".into(),
            service: "ssh".into(),
            start_bucket: 1_700_000_000,
            end_bucket: 1_700_000_300,
            proto: "tcp".into(),
            port: 22,
            bytes: 1024,
            packets: 8,
            transport: FlowTransport::Direct,
            decision: FlowDecision::Allowed,
        }
    }

    #[test]
    fn batch_cap() {
        let recs = vec![record(); MAX_FLOW_BATCH + 1];
        assert!(matches!(
            validate_batch(&recs),
            Err(FlowError::BatchTooLarge { .. })
        ));
        let ok = vec![record(); MAX_FLOW_BATCH];
        assert!(validate_batch(&ok).is_ok());
    }

    #[test]
    fn bucket_window_capped_at_one_hour() {
        let mut rec = record();
        rec.end_bucket = rec.start_bucket + MAX_BUCKET_SECS + 1;
        assert!(matches!(
            rec.validate(),
            Err(FlowError::BucketTooWide { .. })
        ));
        rec.end_bucket = rec.start_bucket - 1;
        assert!(matches!(rec.validate(), Err(FlowError::BucketRange { .. })));
    }

    #[test]
    fn payload_fields_rejected() {
        for raw in [
            r#"{"url":"https://x"}"#,
            r#"{"flows":[{"payload":"aGVsbG8="}]}"#,
            r#"{"nested":{"body":"hi"}}"#,
        ] {
            let value: serde_json::Value = serde_json::from_str(raw).unwrap();
            assert!(matches!(
                validate_flow_json(&value),
                Err(FlowError::PayloadField(_))
            ));
        }
        let clean: serde_json::Value =
            serde_json::from_str(r#"{"flows":[{"bytes":10,"packets":1}]}"#).unwrap();
        assert!(validate_flow_json(&clean).is_ok());
    }

    #[test]
    fn sampler_boundaries() {
        assert!(!should_sample(0.0, 0));
        assert!(should_sample(1.0, u64::MAX));
        assert!(should_sample(0.5, 0));
        assert!(!should_sample(0.5, u64::MAX));
    }
}
