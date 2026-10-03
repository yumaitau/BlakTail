//! C ABI for the relay fallback. The platform keeps its sockets; Rust keeps
//! the relay protocol, AU-only relay choice, UDP -> WSS ladder and per-peer
//! direct/relay hysteresis (`blaktail_relay_proto::mobile`). No buffers are
//! retained between calls.

use crate::{BlakTailTunnel, TunnelInner};
use blaktail_relay_proto::{
    frame,
    ladder::Link,
    mobile::{format_node_id, parse_node_id, parse_relay_lines, MobileRelay},
    TOKEN_LEN,
};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;
use std::time::Instant;

pub const RELAY_ROUTE_DIRECT: i32 = 1;
pub const RELAY_ROUTE_UDP: i32 = 2;
pub const RELAY_ROUTE_WSS: i32 = 4;
const ERR: i32 = -1;

pub(crate) fn with_relay<T>(
    tunnel: *mut BlakTailTunnel,
    fallback: T,
    body: impl FnOnce(&mut TunnelInner) -> T,
) -> T {
    if tunnel.is_null() {
        return fallback;
    }
    // SAFETY: callers pass a live pointer from `blaktail_tunnel_create`.
    let tunnel = unsafe { &*tunnel };
    catch_unwind(AssertUnwindSafe(|| match tunnel.inner.lock() {
        Ok(mut inner) => Some(body(&mut inner)),
        Err(_) => None,
    }))
    .ok()
    .flatten()
    .unwrap_or(fallback)
}

unsafe fn c_str<'a>(value: *const c_char) -> Option<&'a str> {
    if value.is_null() {
        return None;
    }
    CStr::from_ptr(value).to_str().ok()
}

/// Safe core shared by the C ABI and JNI.
pub(crate) fn configure(
    inner: &mut TunnelInner,
    self_id: &str,
    token_hex: &str,
    expires_at_unix: u64,
    relays: &str,
    allow_wss: bool,
) -> bool {
    let Some(id) = parse_node_id(self_id) else {
        return false;
    };
    let Some(token) = blaktail_relay_proto::hex_decode(token_hex)
        .and_then(|raw| <[u8; TOKEN_LEN]>::try_from(raw).ok())
    else {
        // No capability yet: relay stays off, direct paths keep working.
        inner.relay = None;
        return true;
    };
    let relay = inner
        .relay
        .get_or_insert_with(|| MobileRelay::new(id, allow_wss));
    relay.configure(
        token,
        expires_at_unix,
        parse_relay_lines(relays),
        Instant::now(),
    );
    true
}

pub(crate) fn begin_peers(inner: &mut TunnelInner) {
    if let Some(relay) = inner.relay.as_mut() {
        relay.begin_peer_refresh();
    }
}

pub(crate) fn set_peer(
    inner: &mut TunnelInner,
    key: [u8; 32],
    node_id: &str,
    has_direct: bool,
) -> bool {
    let (Some(relay), Some(id)) = (inner.relay.as_mut(), parse_node_id(node_id)) else {
        return false;
    };
    relay.set_peer(key, id, has_direct);
    true
}

pub(crate) fn end_peers(inner: &mut TunnelInner) {
    if let Some(relay) = inner.relay.as_mut() {
        relay.end_peer_refresh();
    }
}

/// Route flags, and the SEND frame length written to `out` when relayed.
pub(crate) fn outbound(
    inner: &mut TunnelInner,
    key: &[u8; 32],
    datagram: &[u8],
    out: &mut [u8],
) -> (i32, usize) {
    let Some(relay) = inner.relay.as_mut() else {
        return (RELAY_ROUTE_DIRECT, 0);
    };
    let route = relay.outbound(key, Instant::now());
    let mut flags = if route.direct { RELAY_ROUTE_DIRECT } else { 0 };
    let mut written = 0;
    if let (Some(link), Some(id)) = (route.relay, relay.peer_id(key)) {
        if let Some(len) = frame::write_send_frame(&id, datagram, out) {
            written = len;
            flags |= match link {
                Link::Udp => RELAY_ROUTE_UDP,
                Link::Wss => RELAY_ROUTE_WSS,
            };
        }
    }
    if flags == 0 {
        // Never black-hole: without a usable relay frame try direct.
        flags = RELAY_ROUTE_DIRECT;
    }
    (flags, written)
}

/// Returns the peer key and payload length copied into `out`.
pub(crate) fn inbound(
    inner: &mut TunnelInner,
    data: &[u8],
    via_wss: bool,
    endpoint: &str,
    out: &mut [u8],
) -> Option<([u8; 32], usize)> {
    let relay = inner.relay.as_mut()?;
    let link = if via_wss { Link::Wss } else { Link::Udp };
    let (key, payload) = relay.inbound(data, link, endpoint, Instant::now())?;
    let target = out.get_mut(..payload.len())?;
    target.copy_from_slice(payload);
    Some((key, payload.len()))
}

pub(crate) fn direct_received(inner: &mut TunnelInner, key: &[u8; 32]) {
    if let Some(relay) = inner.relay.as_mut() {
        relay.direct_received(key);
    }
}

pub(crate) fn tick(inner: &mut TunnelInner) {
    if let Some(relay) = inner.relay.as_mut() {
        relay.tick(Instant::now());
    }
}

/// Next control frame: (route flag, endpoint, frame).
pub(crate) fn poll(inner: &mut TunnelInner) -> Option<(i32, String, Vec<u8>)> {
    let control = inner.relay.as_mut()?.poll()?;
    let kind = match control.link {
        Link::Udp => RELAY_ROUTE_UDP,
        Link::Wss => RELAY_ROUTE_WSS,
    };
    Some((kind, control.endpoint, control.frame))
}

/// Flow-report transport from the relay's actual state.
pub(crate) struct FlowTransport {
    /// Device-level label when every known peer is relayed.
    pub device: Option<&'static str>,
    pub relayed_peers: Vec<String>,
    pub relay_transport: &'static str,
}

pub(crate) fn flow_transport(inner: &TunnelInner) -> FlowTransport {
    let Some(relay) = inner.relay.as_ref() else {
        return FlowTransport {
            device: None,
            relayed_peers: Vec::new(),
            relay_transport: "udp_relay",
        };
    };
    let relay_transport = match relay.relay_link() {
        Some(Link::Wss) => "https_relay",
        _ => "udp_relay",
    };
    let relayed_peers: Vec<String> = relay
        .relayed_peer_ids()
        .iter()
        .map(format_node_id)
        .collect();
    let status = relay.status(Instant::now());
    FlowTransport {
        device: Some(if status.peers_relayed > 0 && status.peers_direct == 0 {
            relay_transport
        } else {
            "direct"
        }),
        relayed_peers,
        relay_transport,
    }
}

pub(crate) fn status_json(inner: &TunnelInner) -> String {
    let Some(relay) = inner.relay.as_ref() else {
        return r#"{"transport":"direct","relay":null,"link":null,"wss_url":null,"healthy":false,"peers_direct":0,"peers_relayed":0,"failovers":0}"#.to_owned();
    };
    let status = relay.status(Instant::now());
    format!(
        r#"{{"transport":"{}","relay":{},"link":{},"wss_url":{},"healthy":{},"peers_direct":{},"peers_relayed":{},"failovers":{}}}"#,
        status.transport,
        json_string(status.relay_endpoint.as_deref()),
        json_string(status.relay_link.map(|link| match link {
            Link::Udp => "udp",
            Link::Wss => "wss",
        })),
        json_string(status.wss_url.as_deref()),
        status.relay_healthy,
        status.peers_direct,
        status.peers_relayed,
        status.failovers,
    )
}

fn json_string(value: Option<&str>) -> String {
    let Some(value) = value else {
        return "null".to_owned();
    };
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

/// # Safety
/// `tunnel` must be live; `self_id`, `relay_token_hex` and `relays` are C
/// strings. `relays` lists one relay per line as `endpoint\tregion\twss`.
#[no_mangle]
pub unsafe extern "C" fn blaktail_relay_configure(
    tunnel: *mut BlakTailTunnel,
    self_id: *const c_char,
    relay_token_hex: *const c_char,
    expires_at_unix: u64,
    relays: *const c_char,
    allow_wss: u8,
) -> i32 {
    let (Some(id), Some(token), Some(relays)) =
        (c_str(self_id), c_str(relay_token_hex), c_str(relays))
    else {
        return ERR;
    };
    with_relay(tunnel, ERR, |inner| {
        if configure(inner, id, token, expires_at_unix, relays, allow_wss != 0) {
            0
        } else {
            ERR
        }
    })
}

/// # Safety
/// `tunnel` must be live.
#[no_mangle]
pub unsafe extern "C" fn blaktail_relay_begin_peers(tunnel: *mut BlakTailTunnel) {
    with_relay(tunnel, (), begin_peers);
}

/// # Safety
/// `public_key` points to 32 bytes; `node_id` is the peer's UUID C string.
#[no_mangle]
pub unsafe extern "C" fn blaktail_relay_set_peer(
    tunnel: *mut BlakTailTunnel,
    public_key: *const u8,
    node_id: *const c_char,
    has_direct: u8,
) -> i32 {
    let Some(node_id) = c_str(node_id) else {
        return ERR;
    };
    if public_key.is_null() {
        return ERR;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(slice::from_raw_parts(public_key, 32));
    with_relay(tunnel, ERR, |inner| {
        if set_peer(inner, key, node_id, has_direct != 0) {
            0
        } else {
            ERR
        }
    })
}

/// # Safety
/// `tunnel` must be live.
#[no_mangle]
pub unsafe extern "C" fn blaktail_relay_end_peers(tunnel: *mut BlakTailTunnel) {
    with_relay(tunnel, (), end_peers);
}

/// Routes one encrypted datagram for `peer_public`. Returns a bitmask:
/// `RELAY_ROUTE_DIRECT` (send `src` to the peer's endpoint), and/or
/// `RELAY_ROUTE_UDP`/`RELAY_ROUTE_WSS` (send `dst[..*dst_len]` to the relay).
///
/// # Safety
/// Pointers must be valid for the stated lengths.
#[no_mangle]
pub unsafe extern "C" fn blaktail_relay_outbound(
    tunnel: *mut BlakTailTunnel,
    peer_public: *const u8,
    src: *const u8,
    src_len: usize,
    dst: *mut u8,
    dst_cap: usize,
    dst_len: *mut usize,
) -> i32 {
    if peer_public.is_null() || src.is_null() || dst.is_null() || dst_len.is_null() {
        return ERR;
    }
    let key: [u8; 32] = slice::from_raw_parts(peer_public, 32)
        .try_into()
        .expect("32 bytes");
    let datagram = slice::from_raw_parts(src, src_len);
    let out = slice::from_raw_parts_mut(dst, dst_cap);
    *dst_len = 0;
    let (flags, written) = with_relay(tunnel, (ERR, 0), |inner| {
        outbound(inner, &key, datagram, out)
    });
    *dst_len = written;
    flags
}

/// Handles a frame received from a relay (`via_wss` 0 = UDP from
/// `endpoint`, 1 = the WebSocket). Returns 1 with WireGuard ciphertext in
/// `dst` and the sender in `peer_public_out`, 0 when the frame was a
/// control reply or not acceptable, -1 on bad arguments.
///
/// # Safety
/// Pointers must be valid for the stated lengths; `endpoint` is a C string.
#[no_mangle]
pub unsafe extern "C" fn blaktail_relay_inbound(
    tunnel: *mut BlakTailTunnel,
    src: *const u8,
    src_len: usize,
    via_wss: u8,
    endpoint: *const c_char,
    dst: *mut u8,
    dst_cap: usize,
    dst_len: *mut usize,
    peer_public_out: *mut u8,
) -> i32 {
    if src.is_null() || dst.is_null() || dst_len.is_null() || peer_public_out.is_null() {
        return ERR;
    }
    let endpoint = c_str(endpoint).unwrap_or_default();
    let data = slice::from_raw_parts(src, src_len);
    let out = slice::from_raw_parts_mut(dst, dst_cap);
    *dst_len = 0;
    match with_relay(tunnel, None, |inner| {
        inbound(inner, data, via_wss != 0, endpoint, out)
    }) {
        Some((key, len)) => {
            *dst_len = len;
            slice::from_raw_parts_mut(peer_public_out, 32).copy_from_slice(&key);
            1
        }
        None => 0,
    }
}

/// Call when a datagram from the peer's direct endpoint decrypted.
///
/// # Safety
/// `peer_public` points to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn blaktail_relay_direct_received(
    tunnel: *mut BlakTailTunnel,
    peer_public: *const u8,
) {
    if peer_public.is_null() {
        return;
    }
    let key: [u8; 32] = slice::from_raw_parts(peer_public, 32)
        .try_into()
        .expect("32 bytes");
    with_relay(tunnel, (), |inner| direct_received(inner, &key));
}

/// Advances relay timers; call about once a second, then drain
/// `blaktail_relay_poll`.
///
/// # Safety
/// `tunnel` must be live.
#[no_mangle]
pub unsafe extern "C" fn blaktail_relay_tick(tunnel: *mut BlakTailTunnel) {
    with_relay(tunnel, (), tick);
}

/// Next control frame to send. Returns 0 when none, `RELAY_ROUTE_UDP` (send
/// to the relay named in `endpoint_out`) or `RELAY_ROUTE_WSS`.
///
/// # Safety
/// Pointers must be valid for the stated lengths.
#[no_mangle]
pub unsafe extern "C" fn blaktail_relay_poll(
    tunnel: *mut BlakTailTunnel,
    dst: *mut u8,
    dst_cap: usize,
    dst_len: *mut usize,
    endpoint_out: *mut c_char,
    endpoint_cap: usize,
) -> i32 {
    if dst.is_null() || dst_len.is_null() || endpoint_out.is_null() || endpoint_cap == 0 {
        return ERR;
    }
    *dst_len = 0;
    let Some((kind, endpoint, frame)) = with_relay(tunnel, None, poll) else {
        return 0;
    };
    if frame.len() > dst_cap || endpoint.len() >= endpoint_cap {
        return ERR;
    }
    slice::from_raw_parts_mut(dst, frame.len()).copy_from_slice(&frame);
    *dst_len = frame.len();
    let name = slice::from_raw_parts_mut(endpoint_out.cast::<u8>(), endpoint.len() + 1);
    name[..endpoint.len()].copy_from_slice(endpoint.as_bytes());
    name[endpoint.len()] = 0;
    kind
}

/// Writes a NUL-terminated JSON status (transport, relay, link, wss_url,
/// healthy, peer counts, failovers). Returns its length, or -1 when `out`
/// is too small.
///
/// # Safety
/// `out` must be valid for `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn blaktail_relay_status(
    tunnel: *mut BlakTailTunnel,
    out: *mut c_char,
    cap: usize,
) -> isize {
    if out.is_null() {
        return -1;
    }
    let json = with_relay(tunnel, String::new(), |inner| status_json(inner));
    if json.is_empty() || json.len() >= cap {
        return -1;
    }
    let target = slice::from_raw_parts_mut(out.cast::<u8>(), json.len() + 1);
    target[..json.len()].copy_from_slice(json.as_bytes());
    target[json.len()] = 0;
    json.len() as isize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{blaktail_tunnel_create, blaktail_tunnel_free};
    use blaktail_relay_proto::{observed_frame, FORWARDED, HEADER, REGISTER, SEND};
    use std::ffi::CString;

    const SELF: &str = "00000000-0000-0000-0000-000000000001";
    const PEER: &str = "00000000-0000-0000-0000-000000000002";

    fn tunnel() -> *mut BlakTailTunnel {
        unsafe { blaktail_tunnel_create([7u8; 32].as_ptr()) }
    }

    fn configure(tunnel: *mut BlakTailTunnel) {
        let id = CString::new(SELF).unwrap();
        let token = CString::new("ab".repeat(32)).unwrap();
        let relays = CString::new(
            "relay-a.example.au:3478\tap-southeast-2\twss://relay-a.example.au/v1/relay\n\
             relay-x.example.com:3478\tus-east-1\t\n",
        )
        .unwrap();
        assert_eq!(
            unsafe {
                blaktail_relay_configure(
                    tunnel,
                    id.as_ptr(),
                    token.as_ptr(),
                    4_000_000_000,
                    relays.as_ptr(),
                    1,
                )
            },
            0
        );
    }

    fn poll_all(tunnel: *mut BlakTailTunnel) -> Vec<(i32, String, Vec<u8>)> {
        let mut out = Vec::new();
        loop {
            let mut frame = [0u8; 128];
            let mut len = 0usize;
            let mut endpoint = [0 as c_char; 256];
            let kind = unsafe {
                blaktail_relay_poll(
                    tunnel,
                    frame.as_mut_ptr(),
                    frame.len(),
                    &mut len,
                    endpoint.as_mut_ptr(),
                    endpoint.len(),
                )
            };
            if kind == 0 {
                return out;
            }
            let name = unsafe { CStr::from_ptr(endpoint.as_ptr()) }
                .to_str()
                .unwrap()
                .to_owned();
            out.push((kind, name, frame[..len].to_vec()));
        }
    }

    fn status(tunnel: *mut BlakTailTunnel) -> String {
        let mut out = [0 as c_char; 512];
        let len = unsafe { blaktail_relay_status(tunnel, out.as_mut_ptr(), out.len()) };
        assert!(len > 0);
        unsafe { CStr::from_ptr(out.as_ptr()) }
            .to_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn ffi_registers_wraps_and_unwraps_relay_frames() {
        let tunnel = tunnel();
        configure(tunnel);
        let control = poll_all(tunnel);
        assert_eq!(control.len(), 2);
        assert_eq!(control[0].0, RELAY_ROUTE_UDP);
        assert_eq!(control[0].1, "relay-a.example.au:3478");
        assert_eq!(control[0].2[0], REGISTER);

        let key = [9u8; 32];
        let peer = CString::new(PEER).unwrap();
        unsafe {
            blaktail_relay_begin_peers(tunnel);
            assert_eq!(
                blaktail_relay_set_peer(tunnel, key.as_ptr(), peer.as_ptr(), 0),
                0
            );
            blaktail_relay_end_peers(tunnel);
        }
        // No direct endpoint: the datagram must go via the relay over UDP.
        let datagram = b"wireguard-ciphertext";
        let mut out = [0u8; 2_100];
        let mut len = 0usize;
        let flags = unsafe {
            blaktail_relay_outbound(
                tunnel,
                key.as_ptr(),
                datagram.as_ptr(),
                datagram.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut len,
            )
        };
        assert_eq!(flags, RELAY_ROUTE_UDP);
        assert_eq!(out[0], SEND);
        assert_eq!(&out[HEADER..len], datagram);

        // A FORWARDED frame from the active relay comes back as ciphertext.
        let mut forwarded = vec![FORWARDED];
        forwarded.extend_from_slice(&parse_node_id(PEER).unwrap());
        forwarded.extend_from_slice(b"reply");
        let endpoint = CString::new("relay-a.example.au:3478").unwrap();
        let mut payload = [0u8; 2_048];
        let mut payload_len = 0usize;
        let mut sender = [0u8; 32];
        let result = unsafe {
            blaktail_relay_inbound(
                tunnel,
                forwarded.as_ptr(),
                forwarded.len(),
                0,
                endpoint.as_ptr(),
                payload.as_mut_ptr(),
                payload.len(),
                &mut payload_len,
                sender.as_mut_ptr(),
            )
        };
        assert_eq!(result, 1);
        assert_eq!(&payload[..payload_len], b"reply");
        assert_eq!(sender, key);

        // OBSERVED is consumed and marks the relay healthy.
        let observed = observed_frame(
            &parse_node_id(SELF).unwrap(),
            "203.0.113.4:5000".parse().unwrap(),
        );
        let result = unsafe {
            blaktail_relay_inbound(
                tunnel,
                observed.as_ptr(),
                observed.len(),
                0,
                endpoint.as_ptr(),
                payload.as_mut_ptr(),
                payload.len(),
                &mut payload_len,
                sender.as_mut_ptr(),
            )
        };
        assert_eq!(result, 0);
        let json = status(tunnel);
        assert!(json.contains(r#""transport":"relay""#), "{json}");
        assert!(
            json.contains(r#""relay":"relay-a.example.au:3478""#),
            "{json}"
        );
        assert!(json.contains(r#""healthy":true"#), "{json}");
        assert!(
            !json.contains("relay-x"),
            "offshore relay never selected: {json}"
        );
        unsafe { blaktail_tunnel_free(tunnel) };
    }

    #[test]
    fn ffi_without_relay_routes_direct_and_rejects_bad_arguments() {
        let tunnel = tunnel();
        let key = [1u8; 32];
        let mut out = [0u8; 64];
        let mut len = 0usize;
        assert_eq!(
            unsafe {
                blaktail_relay_outbound(
                    tunnel,
                    key.as_ptr(),
                    b"x".as_ptr(),
                    1,
                    out.as_mut_ptr(),
                    out.len(),
                    &mut len,
                )
            },
            RELAY_ROUTE_DIRECT
        );
        assert!(status(tunnel).contains(r#""transport":"direct""#));
        assert_eq!(
            unsafe {
                blaktail_relay_configure(
                    tunnel,
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                )
            },
            ERR
        );
        assert_eq!(
            unsafe {
                blaktail_relay_outbound(
                    std::ptr::null_mut(),
                    key.as_ptr(),
                    b"x".as_ptr(),
                    1,
                    out.as_mut_ptr(),
                    out.len(),
                    &mut len,
                )
            },
            ERR
        );
        let mut small = [0 as c_char; 8];
        assert_eq!(
            unsafe { blaktail_relay_status(tunnel, small.as_mut_ptr(), small.len()) },
            -1
        );
        unsafe { blaktail_tunnel_free(tunnel) };
    }

    #[test]
    fn json_strings_are_escaped() {
        assert_eq!(json_string(Some("a\"b\\c\n")), r#""a\"b\\c\u000a""#);
        assert_eq!(json_string(None), "null");
    }
}
