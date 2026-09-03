//! Domain app-connector definitions and DNS resolution checks (issue #49).
//!
//! App connectors map exact hostnames to ports/protocols. Wildcards,
//! single-label names, over-broad port sets, and resolutions pointing at
//! loopback/link-local/multicast/cloud-metadata IPs are rejected so a
//! compromised DNS answer cannot rebind a connector. Only std + serde +
//! thiserror.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use thiserror::Error;

/// Max ports per app; more than this is an over-broad "whole machine" grab.
pub const MAX_APP_PORTS: usize = 32;

/// Well-known cloud metadata endpoints that must never be connector targets.
const METADATA_IPS: &[&str] = &["169.254.169.254", "100.100.100.200"];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConnectorError {
    #[error("app name must not be empty")]
    EmptyName,
    #[error("at least one exact hostname is required")]
    NoHostnames,
    #[error("wildcard '{0}' rejected: connectors require exact hostnames")]
    Wildcard(String),
    #[error("hostname '{0}' rejected: single-label or bare TLD")]
    SingleLabel(String),
    #[error("hostname '{0}' is invalid")]
    BadHostname(String),
    #[error("at least one port is required")]
    NoPorts,
    #[error("{found} ports exceeds the max of {MAX_APP_PORTS} (over-broad)")]
    OverbroadPorts { found: usize },
    #[error("port {0} out of range 1-65535")]
    BadPort(u16),
    #[error("at least one protocol is required")]
    NoProtocols,
    #[error("protocol '{0}' unsupported (want tcp or udp)")]
    BadProtocol(String),
    #[error("resolution host '{0}' is not an approved exact hostname")]
    UnapprovedHost(String),
    #[error("no addresses in resolution for '{0}'")]
    NoAddresses(String),
    #[error("address '{0}' is invalid")]
    BadAddress(String),
    #[error("address '{0}' rejected: prefixes must be host routes (/32 or /128)")]
    NonHostPrefix(String),
    #[error("address '{0}' rejected: {1}")]
    UnsafeAddress(String, &'static str),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppDef {
    pub name: String,
    pub exact_hostnames: Vec<String>,
    pub ports: Vec<u16>,
    pub protocols: Vec<String>,
}

impl AppDef {
    pub fn validate(&self) -> Result<(), ConnectorError> {
        if self.name.trim().is_empty() {
            return Err(ConnectorError::EmptyName);
        }
        if self.exact_hostnames.is_empty() {
            return Err(ConnectorError::NoHostnames);
        }
        for host in &self.exact_hostnames {
            validate_hostname(host)?;
        }
        if self.ports.is_empty() {
            return Err(ConnectorError::NoPorts);
        }
        if self.ports.len() > MAX_APP_PORTS {
            return Err(ConnectorError::OverbroadPorts {
                found: self.ports.len(),
            });
        }
        for port in &self.ports {
            if *port == 0 {
                return Err(ConnectorError::BadPort(*port));
            }
        }
        if self.protocols.is_empty() {
            return Err(ConnectorError::NoProtocols);
        }
        for proto in &self.protocols {
            match proto.to_ascii_lowercase().as_str() {
                "tcp" | "udp" => {}
                _ => return Err(ConnectorError::BadProtocol(proto.clone())),
            }
        }
        Ok(())
    }
}

fn validate_hostname(host: &str) -> Result<(), ConnectorError> {
    if host.contains('*') {
        return Err(ConnectorError::Wildcard(host.to_owned()));
    }
    let lower = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if lower.is_empty() || lower.len() > 253 {
        return Err(ConnectorError::BadHostname(host.to_owned()));
    }
    if !lower.contains('.') {
        return Err(ConnectorError::SingleLabel(host.to_owned()));
    }
    for label in lower.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return Err(ConnectorError::BadHostname(host.to_owned()));
        }
    }
    let tld = lower.rsplit('.').next().expect("contains dot");
    if tld.len() < 2 || !tld.bytes().any(|b| b.is_ascii_alphabetic()) {
        return Err(ConnectorError::SingleLabel(host.to_owned()));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resolution {
    pub host: String,
    pub addrs: Vec<String>,
}

fn normalise_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Parse an address that must be a single host: plain IP or an explicit
/// /32 (v4) / /128 (v6). Anything else is a non-host prefix.
fn parse_host_addr(raw: &str) -> Result<IpAddr, ConnectorError> {
    let text = raw.trim();
    if let Some((ip_s, prefix_s)) = text.split_once('/') {
        let ip: IpAddr = ip_s
            .trim()
            .parse()
            .map_err(|_| ConnectorError::BadAddress(raw.to_owned()))?;
        let prefix: u8 = prefix_s
            .trim()
            .parse()
            .map_err(|_| ConnectorError::NonHostPrefix(raw.to_owned()))?;
        let host_prefix = matches!(ip, IpAddr::V4(_) if prefix == 32)
            || matches!(ip, IpAddr::V6(_) if prefix == 128);
        if !host_prefix {
            return Err(ConnectorError::NonHostPrefix(raw.to_owned()));
        }
        Ok(ip)
    } else {
        text.parse()
            .map_err(|_| ConnectorError::BadAddress(raw.to_owned()))
    }
}

fn unsafe_reason(ip: &IpAddr) -> Option<&'static str> {
    if METADATA_IPS.iter().any(|m| *m == ip.to_string()) {
        return Some("cloud metadata endpoint");
    }
    if ip.is_loopback() {
        return Some("loopback");
    }
    if ip.is_unspecified() {
        return Some("unspecified");
    }
    if ip.is_multicast() {
        return Some("multicast");
    }
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            if o[0] == 169 && o[1] == 254 {
                return Some("link-local");
            }
        }
        IpAddr::V6(v) => {
            if v.segments()[0] & 0xffc0 == 0xfe80 {
                return Some("link-local");
            }
        }
    }
    None
}

impl Resolution {
    /// Host must exactly match an approved hostname; every address must be a
    /// safe single-host IP (rebinding-safe).
    pub fn validate_for_app(&self, app: &AppDef) -> Result<(), ConnectorError> {
        let approved: HashSet<String> = app
            .exact_hostnames
            .iter()
            .map(|h| normalise_host(h))
            .collect();
        if !approved.contains(&normalise_host(&self.host)) {
            return Err(ConnectorError::UnapprovedHost(self.host.clone()));
        }
        if self.addrs.is_empty() {
            return Err(ConnectorError::NoAddresses(self.host.clone()));
        }
        for raw in &self.addrs {
            let ip = parse_host_addr(raw)?;
            if let Some(reason) = unsafe_reason(&ip) {
                return Err(ConnectorError::UnsafeAddress(raw.clone(), reason));
            }
        }
        Ok(())
    }
}

/// Render host routes for an approved address set (`/32` for v4, `/128` v6).
pub fn host_routes(addrs: &[String]) -> Result<Vec<String>, ConnectorError> {
    addrs
        .iter()
        .map(|raw| {
            let ip = parse_host_addr(raw)?;
            if let Some(reason) = unsafe_reason(&ip) {
                return Err(ConnectorError::UnsafeAddress(raw.clone(), reason));
            }
            match ip {
                IpAddr::V4(_) => Ok(format!("{ip}/32")),
                IpAddr::V6(_) => Ok(format!("{ip}/128")),
            }
        })
        .collect()
}

/// True when `current` answers the same host with a disjoint address set —
/// the classic DNS-rebinding shape. Callers should re-validate.
pub fn rebinding_detected(previous: &Resolution, current: &Resolution) -> bool {
    if normalise_host(&previous.host) != normalise_host(&current.host) {
        return false;
    }
    let old: HashSet<String> = previous
        .addrs
        .iter()
        .map(|a| a.trim().to_ascii_lowercase())
        .collect();
    let new: HashSet<String> = current
        .addrs
        .iter()
        .map(|a| a.trim().to_ascii_lowercase())
        .collect();
    !old.is_empty() && !new.is_empty() && old.is_disjoint(&new)
}

/// Convenience: previous resolutions keyed by normalised host.
pub fn index_resolutions(prior: &[Resolution]) -> HashMap<String, Resolution> {
    prior
        .iter()
        .map(|r| (normalise_host(&r.host), r.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> AppDef {
        AppDef {
            name: "db".into(),
            exact_hostnames: vec!["db.internal.example.com".into()],
            ports: vec![5432],
            protocols: vec!["tcp".into()],
        }
    }

    #[test]
    fn wildcards_rejected() {
        let mut bad = app();
        bad.exact_hostnames = vec!["*.example.com".into()];
        assert!(matches!(bad.validate(), Err(ConnectorError::Wildcard(_))));
    }

    #[test]
    fn single_label_and_bare_tld_rejected() {
        for host in [
            "dbserver",
            "localhost",
            "com",
            "example.123",
            "-bad.example.com",
        ] {
            let mut bad = app();
            bad.exact_hostnames = vec![host.into()];
            assert!(bad.validate().is_err(), "{host} should be rejected");
        }
        assert!(app().validate().is_ok());
    }

    #[test]
    fn overbroad_ports_rejected() {
        let mut bad = app();
        bad.ports = (1u16..=100).collect();
        assert!(matches!(
            bad.validate(),
            Err(ConnectorError::OverbroadPorts { .. })
        ));
    }

    #[test]
    fn metadata_and_prefixes_rejected() {
        let app = app();
        for addr in [
            "169.254.169.254",
            "100.100.100.200",
            "127.0.0.1",
            "::1",
            "224.0.0.5",
        ] {
            let res = Resolution {
                host: "db.internal.example.com".into(),
                addrs: vec![addr.into()],
            };
            assert!(
                res.validate_for_app(&app).is_err(),
                "{addr} should be rejected"
            );
        }
        let cidr = Resolution {
            host: "db.internal.example.com".into(),
            addrs: vec!["10.0.0.0/24".into()],
        };
        assert!(matches!(
            cidr.validate_for_app(&app),
            Err(ConnectorError::NonHostPrefix(_))
        ));
    }

    #[test]
    fn rebinding_detected_on_disjoint_answers() {
        let first = Resolution {
            host: "db.internal.example.com".into(),
            addrs: vec!["10.0.0.5".into()],
        };
        let rebound = Resolution {
            host: "db.internal.example.com".into(),
            addrs: vec!["10.0.0.99".into()],
        };
        let same = Resolution {
            host: "db.internal.example.com".into(),
            addrs: vec!["10.0.0.5".into(), "10.0.0.6".into()],
        };
        assert!(rebinding_detected(&first, &rebound));
        assert!(!rebinding_detected(&first, &same));
    }

    #[test]
    fn host_routes_render() {
        let routes = host_routes(&["10.0.0.5".to_owned(), "fd00::5".to_owned()]).unwrap();
        assert_eq!(routes, vec!["10.0.0.5/32", "fd00::5/128"]);
    }
}
