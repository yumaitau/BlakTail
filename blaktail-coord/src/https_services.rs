//! HTTPS service definitions, CSR intake, and cert binding (issue #47).
//!
//! Service names share a flat namespace with device DNS, so callers pass the
//! device-namespace reserved list in for collision checks. Private key
//! material must never reach the coordinator: any CSR request carrying it is
//! rejected. Only std + serde + thiserror.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ServiceError {
    #[error("service name '{0}' invalid: want 3-63 chars of lowercase alnum/hyphen, starting and ending alnum")]
    InvalidName(String),
    #[error("service name '{0}' collides with the device namespace")]
    NameCollision(String),
    #[error("org id must not be empty")]
    EmptyOrg,
    #[error("target node must not be empty")]
    EmptyTarget,
    #[error("port {0} out of range 1-65535")]
    BadPort(u16),
    #[error("revision {0} must be >= 1")]
    BadRevision(u64),
    #[error("CSR rejected: private key material must never be sent to the coordinator")]
    PrivateKeyPresent,
    #[error("CSR rejected: missing or malformed PKCS#10 PEM")]
    BadCsr,
    #[error("certificate binding mismatch: expected {expected}, found {found}")]
    BindingMismatch { expected: String, found: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDef {
    pub org_id: String,
    pub service_name: String,
    pub target_node: String,
    pub port: u16,
    pub revision: u64,
}

/// Lowercase alnum+hyphen, 3-63 chars, start/end alnum, and no collision
/// with the device-namespace `reserved` list (case-insensitive) or the
/// built-in `localhost`.
pub fn validate_service_name(name: &str, reserved: &[String]) -> Result<(), ServiceError> {
    if name.len() < 3 || name.len() > 63 {
        return Err(ServiceError::InvalidName(name.to_owned()));
    }
    let bytes = name.as_bytes();
    let edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !edge(bytes[0]) || !edge(bytes[bytes.len() - 1]) {
        return Err(ServiceError::InvalidName(name.to_owned()));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        return Err(ServiceError::InvalidName(name.to_owned()));
    }
    if name == "localhost" || reserved.iter().any(|r| r.eq_ignore_ascii_case(name)) {
        return Err(ServiceError::NameCollision(name.to_owned()));
    }
    Ok(())
}

impl ServiceDef {
    pub fn validate(&self, reserved: &[String]) -> Result<(), ServiceError> {
        if self.org_id.trim().is_empty() {
            return Err(ServiceError::EmptyOrg);
        }
        if self.target_node.trim().is_empty() {
            return Err(ServiceError::EmptyTarget);
        }
        if self.port == 0 {
            return Err(ServiceError::BadPort(self.port));
        }
        if self.revision < 1 {
            return Err(ServiceError::BadRevision(self.revision));
        }
        validate_service_name(&self.service_name, reserved)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrRequest {
    pub org_id: String,
    pub service_name: String,
    pub target_node: String,
    pub csr_pem: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
}

impl CsrRequest {
    pub fn validate(&self, reserved: &[String]) -> Result<(), ServiceError> {
        if self
            .private_key
            .as_ref()
            .is_some_and(|k| !k.trim().is_empty())
        {
            return Err(ServiceError::PrivateKeyPresent);
        }
        if !self.csr_pem.contains("BEGIN CERTIFICATE REQUEST") {
            return Err(ServiceError::BadCsr);
        }
        validate_service_name(&self.service_name, reserved)?;
        if self.org_id.trim().is_empty() {
            return Err(ServiceError::EmptyOrg);
        }
        if self.target_node.trim().is_empty() {
            return Err(ServiceError::EmptyTarget);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertBinding {
    pub org_id: String,
    pub service_name: String,
    pub node_id: String,
}

/// The presented certificate must bind exactly the service definition's
/// org, service name, and target node.
pub fn check_cert_binding(def: &ServiceDef, binding: &CertBinding) -> Result<(), ServiceError> {
    for (expected, found, what) in [
        (def.org_id.as_str(), binding.org_id.as_str(), "org"),
        (
            def.service_name.as_str(),
            binding.service_name.as_str(),
            "service",
        ),
        (def.target_node.as_str(), binding.node_id.as_str(), "node"),
    ] {
        if expected != found {
            return Err(ServiceError::BindingMismatch {
                expected: format!("{what}={expected}"),
                found: format!("{what}={found}"),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reserved() -> Vec<String> {
        vec!["gateway".to_owned(), "console".to_owned()]
    }

    fn def() -> ServiceDef {
        ServiceDef {
            org_id: "org-1".into(),
            service_name: "web-intranet".into(),
            target_node: "node-1".into(),
            port: 443,
            revision: 1,
        }
    }

    #[test]
    fn name_rules() {
        assert!(validate_service_name("web-intranet", &reserved()).is_ok());
        for bad in [
            "ab",
            "UPPER",
            "has space",
            "-lead",
            "trail-",
            "a..b",
            "gateway",
            "localhost",
        ] {
            assert!(
                validate_service_name(bad, &reserved()).is_err(),
                "{bad} should be rejected"
            );
        }
        let long = "a".repeat(64);
        assert!(validate_service_name(&long, &reserved()).is_err());
    }

    #[test]
    fn private_key_never_accepted() {
        let base = CsrRequest {
            org_id: "org-1".into(),
            service_name: "web-intranet".into(),
            target_node: "node-1".into(),
            csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\nabc\n-----END CERTIFICATE REQUEST-----"
                .into(),
            private_key: None,
        };
        assert!(base.validate(&reserved()).is_ok());
        let mut leaked = base.clone();
        leaked.private_key = Some("-----BEGIN PRIVATE KEY-----".into());
        assert_eq!(
            leaked.validate(&reserved()),
            Err(ServiceError::PrivateKeyPresent)
        );
        let mut no_pem = base.clone();
        no_pem.csr_pem = "not a csr".into();
        assert_eq!(no_pem.validate(&reserved()), Err(ServiceError::BadCsr));
    }

    #[test]
    fn binding_must_match_all_three() {
        let def = def();
        let ok = CertBinding {
            org_id: "org-1".into(),
            service_name: "web-intranet".into(),
            node_id: "node-1".into(),
        };
        assert!(check_cert_binding(&def, &ok).is_ok());
        let wrong_node = CertBinding {
            node_id: "node-2".into(),
            ..ok.clone()
        };
        assert!(matches!(
            check_cert_binding(&def, &wrong_node),
            Err(ServiceError::BindingMismatch { .. })
        ));
        let wrong_org = CertBinding {
            org_id: "org-2".into(),
            ..ok
        };
        assert!(check_cert_binding(&def, &wrong_org).is_err());
    }
}
