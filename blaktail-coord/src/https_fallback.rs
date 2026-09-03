//! HTTPS fallback transport ladder and endpoint approval (issue #48).
//!
//! Nodes climb direct -> UDP relay -> HTTPS relay only after sustained
//! failure (hysteresis), and HTTPS endpoints must be Australian HTTPS
//! origins. Only std + serde + thiserror + url.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Consecutive failures on the current transport before moving.
pub const LADDER_FAIL_THRESHOLD: u32 = 3;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FallbackError {
    #[error("endpoint '{0}' is not a valid URL")]
    BadUrl(String),
    #[error("endpoint '{0}' rejected: scheme must be https")]
    NonHttps(String),
    #[error("endpoint '{0}' rejected: host is not an approved AU origin")]
    NonAuHost(String),
    #[error("endpoint '{0}' rejected: URL must not embed credentials")]
    Credentials(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportLadder {
    Direct,
    UdpRelay,
    HttpsRelay,
}

/// Next transport with hysteresis: stay on `current` until it has failed
/// [`LADDER_FAIL_THRESHOLD`] times in a row, then pick the best transport
/// whose probe is healthy (direct preferred).
pub fn next_transport(
    current: TransportLadder,
    direct_ok: bool,
    udp_ok: bool,
    consecutive_failures: u32,
) -> TransportLadder {
    if consecutive_failures < LADDER_FAIL_THRESHOLD {
        return current;
    }
    if direct_ok {
        TransportLadder::Direct
    } else if udp_ok {
        TransportLadder::UdpRelay
    } else {
        TransportLadder::HttpsRelay
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub url: String,
    pub country: String,
}

/// Approve an HTTPS fallback endpoint URL. Non-HTTPS is rejected (except
/// loopback `localhost`/`127.0.0.1`, which tests use), and the host must be
/// an `.au` origin. URLs embedding credentials are rejected.
pub fn approved_endpoint(url: &str) -> Result<(), FallbackError> {
    let parsed = url::Url::parse(url).map_err(|_| FallbackError::BadUrl(url.to_owned()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| FallbackError::NonAuHost(url.to_owned()))?
        .to_ascii_lowercase();
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FallbackError::Credentials(url.to_owned()));
    }
    let loopback = host == "localhost" || host == "127.0.0.1";
    if parsed.scheme() != "https" && !(loopback && parsed.scheme() == "http") {
        return Err(FallbackError::NonHttps(url.to_owned()));
    }
    if loopback {
        return Ok(());
    }
    if host == "au" || host.ends_with(".au") {
        Ok(())
    } else {
        Err(FallbackError::NonAuHost(url.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hysteresis_stays_until_threshold() {
        assert_eq!(
            next_transport(TransportLadder::Direct, false, true, 0),
            TransportLadder::Direct
        );
        assert_eq!(
            next_transport(
                TransportLadder::Direct,
                false,
                true,
                LADDER_FAIL_THRESHOLD - 1
            ),
            TransportLadder::Direct
        );
        assert_eq!(
            next_transport(TransportLadder::Direct, false, true, LADDER_FAIL_THRESHOLD),
            TransportLadder::UdpRelay
        );
    }

    #[test]
    fn prefers_direct_when_healthy() {
        assert_eq!(
            next_transport(TransportLadder::HttpsRelay, true, true, 99),
            TransportLadder::Direct
        );
        assert_eq!(
            next_transport(TransportLadder::UdpRelay, false, false, 99),
            TransportLadder::HttpsRelay
        );
    }

    #[test]
    fn endpoint_policy() {
        assert!(approved_endpoint("https://relay-1.example.au").is_ok());
        assert!(approved_endpoint("https://deep.sub.domain.example.au:8443/path").is_ok());
        assert!(approved_endpoint("http://localhost:8080").is_ok());
        assert!(matches!(
            approved_endpoint("http://relay.example.au"),
            Err(FallbackError::NonHttps(_))
        ));
        assert!(matches!(
            approved_endpoint("https://relay.example.com"),
            Err(FallbackError::NonAuHost(_))
        ));
        assert!(matches!(
            approved_endpoint("https://user:pass@relay.example.au"),
            Err(FallbackError::Credentials(_))
        ));
    }
}
