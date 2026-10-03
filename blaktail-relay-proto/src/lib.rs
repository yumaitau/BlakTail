//! Sans-IO pieces of the BlakTail relay protocol.
//!
//! The same REGISTER/SEND/FORWARDED/PING/OBSERVED frames travel over UDP and,
//! as binary WebSocket messages, over the HTTPS fallback (ADR 0004). Nothing
//! here performs IO, so the desktop agent (tokio), the iOS Network Extension
//! (Swift sockets) and Android (Kotlin sockets) drive the same logic.

pub mod frame;
pub mod ladder;
pub mod mobile;
pub mod select;

pub use frame::*;

/// Approved Australian cloud regions (same list as `blaktail-config`).
/// Relays outside this list are never selected, whatever the coordinator
/// advertises.
pub fn is_australian_region(region: &str) -> bool {
    matches!(
        region.trim().to_ascii_lowercase().as_str(),
        "ap-southeast-2"
            | "australiaeast"
            | "australiasoutheast"
            | "australia-southeast1"
            | "australia-southeast2"
    )
}

/// Decodes lowercase or uppercase hex; `None` on odd length or bad digits.
pub fn hex_decode(input: &str) -> Option<Vec<u8>> {
    if !input.len().is_multiple_of(2) || !input.is_ascii() {
        return None;
    }
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip_and_rejects_garbage() {
        assert_eq!(hex_decode("00ff10"), Some(vec![0, 255, 16]));
        assert_eq!(hex_decode("0"), None);
        assert_eq!(hex_decode("zz"), None);
        assert_eq!(hex_decode("é1"), None);
    }

    #[test]
    fn only_australian_regions_pass() {
        assert!(is_australian_region(" AP-SOUTHEAST-2 "));
        assert!(is_australian_region("australiaeast"));
        assert!(!is_australian_region("ap-southeast-1"));
        assert!(!is_australian_region(""));
    }
}
