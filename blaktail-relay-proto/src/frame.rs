//! Wire format. Every frame starts with a one-byte type and a 16-byte node
//! id; payloads are opaque (normally WireGuard ciphertext).

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

pub const REGISTER: u8 = 1;
pub const SEND: u8 = 2;
pub const FORWARDED: u8 = 3;
/// Reflexive-address probe: [PING][id]; reply is [OBSERVED][id][sockaddr].
pub const PING: u8 = 4;
pub const OBSERVED: u8 = 5;
/// Peer-to-peer frames used by desktop hole punching; never sent to a relay.
pub const DIRECT: u8 = 6;
pub const PUNCH: u8 = 7;
pub const PUNCH_ACK: u8 = 8;

pub const ID_LEN: usize = 16;
pub const TOKEN_LEN: usize = 32;
pub const EXPIRY_LEN: usize = 8;
/// SEND/FORWARDED header: type + node id.
pub const HEADER: usize = 1 + ID_LEN;
/// REGISTER frame: type + node id + token expiry (unix seconds, BE) +
/// HMAC-SHA256 over (id || expiry).
pub const REGISTER_FRAME: usize = HEADER + EXPIRY_LEN + TOKEN_LEN;
/// OBSERVED reply: type + id + family(u8) + ip(16) + port(u16 BE).
pub const OBSERVED_FRAME: usize = HEADER + 1 + 16 + 2;
/// Encrypted WireGuard datagram ceiling; covers normal 1,500-byte underlays
/// while rejecting jumbo or amplification-oriented frames.
pub const MAX_PAYLOAD: usize = 2_048;
pub const MAX_SEND_FRAME: usize = HEADER + MAX_PAYLOAD;

pub type NodeId = [u8; ID_LEN];

pub fn register_frame(id: &NodeId, expires_at_unix: u64, token: &[u8; TOKEN_LEN]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(REGISTER_FRAME);
    frame.push(REGISTER);
    frame.extend_from_slice(id);
    frame.extend_from_slice(&expires_at_unix.to_be_bytes());
    frame.extend_from_slice(token);
    frame
}

pub fn ping_frame(id: &NodeId) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER);
    frame.push(PING);
    frame.extend_from_slice(id);
    frame
}

/// Wraps an encrypted datagram for `destination`; `None` when it would
/// exceed the relay's payload ceiling (the relay would drop it anyway).
pub fn send_frame(destination: &NodeId, payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD {
        return None;
    }
    let mut frame = Vec::with_capacity(HEADER + payload.len());
    frame.push(SEND);
    frame.extend_from_slice(destination);
    frame.extend_from_slice(payload);
    Some(frame)
}

/// Writes a SEND frame into `out`, returning its length. For callers that
/// must not allocate per packet (the mobile FFI).
pub fn write_send_frame(destination: &NodeId, payload: &[u8], out: &mut [u8]) -> Option<usize> {
    let len = HEADER + payload.len();
    if payload.len() > MAX_PAYLOAD || out.len() < len {
        return None;
    }
    out[0] = SEND;
    out[1..HEADER].copy_from_slice(destination);
    out[HEADER..len].copy_from_slice(payload);
    Some(len)
}

/// Splits a FORWARDED frame into (source node id, payload).
pub fn parse_forwarded(frame: &[u8]) -> Option<(NodeId, &[u8])> {
    if frame.len() < HEADER || frame.len() > MAX_SEND_FRAME || frame[0] != FORWARDED {
        return None;
    }
    let mut source = [0u8; ID_LEN];
    source.copy_from_slice(&frame[1..HEADER]);
    Some((source, &frame[HEADER..]))
}

/// Builds the OBSERVED reply the relay sends for a PING.
pub fn observed_frame(id: &NodeId, observed: SocketAddr) -> Vec<u8> {
    let mut frame = Vec::with_capacity(OBSERVED_FRAME);
    frame.push(OBSERVED);
    frame.extend_from_slice(id);
    match observed.ip() {
        IpAddr::V4(v4) => {
            frame.push(4);
            frame.extend_from_slice(&v4.to_ipv6_mapped().octets());
        }
        IpAddr::V6(v6) => {
            frame.push(6);
            frame.extend_from_slice(&v6.octets());
        }
    }
    frame.extend_from_slice(&observed.port().to_be_bytes());
    frame
}

/// Parses an OBSERVED reply addressed to `node_id`.
pub fn parse_observed(frame: &[u8], node_id: &NodeId) -> Option<SocketAddr> {
    if frame.len() != OBSERVED_FRAME || frame[0] != OBSERVED || frame[1..HEADER] != node_id[..] {
        return None;
    }
    let octets: [u8; 16] = frame[HEADER + 1..HEADER + 17].try_into().ok()?;
    let v6 = Ipv6Addr::from(octets);
    let ip = match frame[HEADER] {
        4 => IpAddr::V4(v6.to_ipv4_mapped()?),
        6 => IpAddr::V6(v6),
        _ => return None,
    };
    let port = u16::from_be_bytes(frame[HEADER + 17..OBSERVED_FRAME].try_into().ok()?);
    (port != 0).then(|| SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_have_documented_shapes() {
        let id = [7u8; ID_LEN];
        let register = register_frame(&id, 0x0102, &[9u8; TOKEN_LEN]);
        assert_eq!(register.len(), REGISTER_FRAME);
        assert_eq!(register[0], REGISTER);
        assert_eq!(
            &register[HEADER..HEADER + EXPIRY_LEN],
            &0x0102u64.to_be_bytes()
        );
        assert_eq!(ping_frame(&id), [&[PING][..], &id[..]].concat());
        assert!(send_frame(&id, &[0; MAX_PAYLOAD]).is_some());
        assert!(send_frame(&id, &[0; MAX_PAYLOAD + 1]).is_none());
        let mut out = [0u8; 64];
        assert_eq!(write_send_frame(&id, b"abc", &mut out), Some(HEADER + 3));
        assert_eq!(&out[..HEADER + 3], send_frame(&id, b"abc").unwrap());
        assert_eq!(write_send_frame(&id, &[0; 60], &mut out), None);
    }

    #[test]
    fn forwarded_parser_is_strict() {
        let id = [3u8; ID_LEN];
        let frame = [&[FORWARDED][..], &id[..], b"wg"].concat();
        assert_eq!(parse_forwarded(&frame), Some((id, &b"wg"[..])));
        assert_eq!(parse_forwarded(&frame[..HEADER - 1]), None);
        let mut send = frame.clone();
        send[0] = SEND;
        assert_eq!(parse_forwarded(&send), None);
        let huge = [&[FORWARDED][..], &id[..], &[0u8; MAX_PAYLOAD + 1][..]].concat();
        assert_eq!(parse_forwarded(&huge), None);
    }

    #[test]
    fn observed_round_trips_and_rejects_other_ids_and_zero_ports() {
        let id = [7u8; ID_LEN];
        for address in ["203.0.113.9:3478", "[2001:db8::1]:443"] {
            let address: SocketAddr = address.parse().unwrap();
            assert_eq!(
                parse_observed(&observed_frame(&id, address), &id),
                Some(address)
            );
        }
        let frame = observed_frame(&id, "203.0.113.9:3478".parse().unwrap());
        assert_eq!(parse_observed(&frame, &[8u8; ID_LEN]), None);
        let zero = observed_frame(&id, "203.0.113.9:0".parse().unwrap());
        assert_eq!(parse_observed(&zero, &id), None);
    }
}
