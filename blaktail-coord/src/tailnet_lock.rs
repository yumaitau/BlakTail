//! Tailnet admission statements with HMAC-SHA256 org binding (issue #46).
//!
//! The coordinator holds an org root secret (config/KMS, never in the DB).
//! Admission statements are authenticated with HMAC-SHA256 over a canonical
//! encoding, binding node identity to exactly one org, one epoch window, and
//! protocol version 1. Only hmac + sha2 + base64 + serde + thiserror.

use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

/// Only protocol version 1 statements verify.
pub const ADMISSION_PROTO_VERSION: u32 = 1;

type AdmissionHmac = Hmac<Sha256>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AdmissionError {
    #[error("coordinator misconfigured: empty admission root secret")]
    EmptySecret,
    #[error("admission signature does not verify")]
    BadSignature,
    #[error("signature is not valid hex")]
    BadSignatureEncoding,
    #[error("statement bound to org '{found}', presented to org '{expected}'")]
    OrgMismatch { expected: String, found: String },
    #[error("epoch {found} is older than minimum {minimum}")]
    StaleEpoch { found: u64, minimum: u64 },
    #[error("statement not valid at {now} (window {from}..={to})")]
    OutsideWindow { now: i64, from: i64, to: i64 },
    #[error("invalid validity window: from {from} is after to {to}")]
    InvalidWindow { from: i64, to: i64 },
    #[error("unsupported protocol version {found}, want {ADMISSION_PROTO_VERSION}")]
    UnsupportedVersion { found: u32 },
    #[error("pubkey is not valid base64")]
    BadPubkey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionStatement {
    pub org_id: String,
    pub node_id: String,
    pub pubkey_b64: String,
    pub epoch: u64,
    pub valid_from: i64,
    pub valid_to: i64,
    pub proto_version: u32,
}

/// Canonical encoding covered by the HMAC. Field order and separator are
/// part of the protocol; change only with a proto_version bump.
fn canonical(stmt: &AdmissionStatement) -> String {
    format!(
        "blaktail-admission-v1|{}|{}|{}|{}|{}|{}|{}",
        stmt.org_id,
        stmt.node_id,
        stmt.pubkey_b64,
        stmt.epoch,
        stmt.valid_from,
        stmt.valid_to,
        stmt.proto_version
    )
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).expect("nibble is hex"));
        out.push(char::from_digit((b & 0x0f) as u32, 16).expect("nibble is hex"));
    }
    out
}

fn decode_hex(text: &str) -> Result<Vec<u8>, AdmissionError> {
    if text.len() % 2 != 0 || text.is_empty() {
        return Err(AdmissionError::BadSignatureEncoding);
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let nybble = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(AdmissionError::BadSignatureEncoding),
    };
    for pair in bytes.chunks_exact(2) {
        out.push((nybble(pair[0])? << 4) | nybble(pair[1])?);
    }
    Ok(out)
}

/// Sign a statement with the org root secret; returns lowercase hex.
pub fn sign_admission(stmt: &AdmissionStatement, root_secret: &[u8]) -> String {
    let mut mac = AdmissionHmac::new_from_slice(root_secret).expect("HMAC accepts any key length");
    mac.update(canonical(stmt).as_bytes());
    encode_hex(&mac.finalize().into_bytes())
}

/// Verify signature, org binding, epoch monotonicity, validity window, and
/// protocol version. `expected_org_id` is the org the statement is presented
/// to: cross-org replay fails here even with a valid signature.
pub fn verify_admission(
    stmt: &AdmissionStatement,
    signature_hex: &str,
    root_secret: &[u8],
    expected_org_id: &str,
    min_epoch: u64,
    now_secs: i64,
) -> Result<(), AdmissionError> {
    if root_secret.is_empty() {
        return Err(AdmissionError::EmptySecret);
    }
    STANDARD
        .decode(stmt.pubkey_b64.trim())
        .map_err(|_| AdmissionError::BadPubkey)?;
    let mut mac = AdmissionHmac::new_from_slice(root_secret).expect("HMAC accepts any key length");
    mac.update(canonical(stmt).as_bytes());
    let presented = decode_hex(signature_hex.trim())?;
    mac.verify_slice(&presented)
        .map_err(|_| AdmissionError::BadSignature)?;
    if stmt.org_id != expected_org_id {
        return Err(AdmissionError::OrgMismatch {
            expected: expected_org_id.to_owned(),
            found: stmt.org_id.clone(),
        });
    }
    if stmt.proto_version != ADMISSION_PROTO_VERSION {
        return Err(AdmissionError::UnsupportedVersion {
            found: stmt.proto_version,
        });
    }
    if stmt.epoch < min_epoch {
        return Err(AdmissionError::StaleEpoch {
            found: stmt.epoch,
            minimum: min_epoch,
        });
    }
    if stmt.valid_from > stmt.valid_to {
        return Err(AdmissionError::InvalidWindow {
            from: stmt.valid_from,
            to: stmt.valid_to,
        });
    }
    if now_secs < stmt.valid_from || now_secs > stmt.valid_to {
        return Err(AdmissionError::OutsideWindow {
            now: now_secs,
            from: stmt.valid_from,
            to: stmt.valid_to,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_A: &[u8] = b"org-a-root-secret-32-bytes-minimum!";
    const SECRET_B: &[u8] = b"org-b-root-secret-32-bytes-minimum!";

    fn stmt() -> AdmissionStatement {
        AdmissionStatement {
            org_id: "org-a".into(),
            node_id: "node-1".into(),
            pubkey_b64: STANDARD.encode(b"fake-32-byte-ed25519-public-key!"),
            epoch: 7,
            valid_from: 1_700_000_000,
            valid_to: 1_700_003_600,
            proto_version: ADMISSION_PROTO_VERSION,
        }
    }

    #[test]
    fn roundtrip() {
        let s = stmt();
        let sig = sign_admission(&s, SECRET_A);
        assert!(verify_admission(&s, &sig, SECRET_A, "org-a", 7, 1_700_000_100).is_ok());
    }

    #[test]
    fn tamper_rejected() {
        let s = stmt();
        let sig = sign_admission(&s, SECRET_A);
        let mut tampered = s.clone();
        tampered.node_id = "node-evil".into();
        assert_eq!(
            verify_admission(&tampered, &sig, SECRET_A, "org-a", 1, 1_700_000_100),
            Err(AdmissionError::BadSignature)
        );
        assert_eq!(
            verify_admission(&s, &sig, SECRET_B, "org-a", 1, 1_700_000_100),
            Err(AdmissionError::BadSignature)
        );
    }

    #[test]
    fn cross_org_reuse_rejected() {
        let s = stmt();
        let sig = sign_admission(&s, SECRET_A);
        // Valid signature for org-a, but presented to org-b.
        assert_eq!(
            verify_admission(&s, &sig, SECRET_A, "org-b", 1, 1_700_000_100),
            Err(AdmissionError::OrgMismatch {
                expected: "org-b".into(),
                found: "org-a".into(),
            })
        );
    }

    #[test]
    fn downgrade_and_stale_epoch_rejected() {
        let s = stmt();
        let mut downgrade = s.clone();
        downgrade.proto_version = 0;
        let sig = sign_admission(&downgrade, SECRET_A);
        assert_eq!(
            verify_admission(&downgrade, &sig, SECRET_A, "org-a", 1, 1_700_000_100),
            Err(AdmissionError::UnsupportedVersion { found: 0 })
        );
        let sig = sign_admission(&s, SECRET_A);
        assert_eq!(
            verify_admission(&s, &sig, SECRET_A, "org-a", 8, 1_700_000_100),
            Err(AdmissionError::StaleEpoch {
                found: 7,
                minimum: 8
            })
        );
        assert_eq!(
            verify_admission(&s, &sig, SECRET_A, "org-a", 1, 1_700_004_000),
            Err(AdmissionError::OutsideWindow {
                now: 1_700_004_000,
                from: 1_700_000_000,
                to: 1_700_003_600,
            })
        );
    }
}
