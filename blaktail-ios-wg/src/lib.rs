#[cfg(feature = "jni")]
mod android;

use boringtun::noise::{Tunn, TunnResult};
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;
use std::sync::Mutex;
use x25519_dalek::{PublicKey, StaticSecret};

const RESULT_DONE: i32 = 0;
const RESULT_WRITE_NETWORK: i32 = 1;
const RESULT_WRITE_TUNNEL: i32 = 2;
const RESULT_ERR: i32 = -1;

#[derive(Clone, Copy)]
enum Cidr {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl Cidr {
    fn parse(value: &str) -> Option<Self> {
        let (address, prefix) = value.split_once('/')?;
        let prefix: u8 = prefix.parse().ok()?;
        if address.contains(':') {
            let ip: Ipv6Addr = address.parse().ok()?;
            if prefix > 128 {
                return None;
            }
            let shift = 128u32.saturating_sub(u32::from(prefix));
            let network = if prefix == 0 {
                0
            } else {
                u128::from(ip) & (!0u128 << shift)
            };
            Some(Self::V6 { network, prefix })
        } else {
            let ip: Ipv4Addr = address.parse().ok()?;
            if prefix > 32 {
                return None;
            }
            let shift = 32u32.saturating_sub(u32::from(prefix));
            let network = if prefix == 0 {
                0
            } else {
                u32::from(ip) & (!0u32 << shift)
            };
            Some(Self::V4 { network, prefix })
        }
    }

    fn contains_v4(self, address: Ipv4Addr) -> bool {
        match self {
            Self::V4 { network, prefix } => {
                let shift = 32u32.saturating_sub(u32::from(prefix));
                let masked = if prefix == 0 {
                    0
                } else {
                    u32::from(address) & (!0u32 << shift)
                };
                masked == network
            }
            Self::V6 { .. } => false,
        }
    }

    fn contains_v6(self, address: Ipv6Addr) -> bool {
        match self {
            Self::V6 { network, prefix } => {
                let shift = 128u32.saturating_sub(u32::from(prefix));
                let masked = if prefix == 0 {
                    0
                } else {
                    u128::from(address) & (!0u128 << shift)
                };
                masked == network
            }
            Self::V4 { .. } => false,
        }
    }
}

struct PeerSlot {
    public_key: [u8; 32],
    tunn: Tunn,
    allowed: Vec<Cidr>,
    last_handshake_unix: u64,
}

pub struct BlakTailTunnel {
    inner: Mutex<TunnelInner>,
}

struct TunnelInner {
    private: StaticSecret,
    peers: BTreeMap<u32, PeerSlot>,
    next_index: u32,
}

impl TunnelInner {
    fn add_peer(&mut self, public_key: [u8; 32], allowed: Vec<Cidr>, keepalive: u16) -> bool {
        self.peers.retain(|_, peer| peer.public_key != public_key);
        let index = self.next_index;
        self.next_index = self.next_index.wrapping_add(1);
        let tunn = Tunn::new(
            self.private.clone(),
            PublicKey::from(public_key),
            None,
            if keepalive == 0 {
                None
            } else {
                Some(keepalive)
            },
            index,
            None,
        );
        self.peers.insert(
            index,
            PeerSlot {
                public_key,
                tunn,
                allowed,
                last_handshake_unix: 0,
            },
        );
        true
    }

    fn peer_for_packet(&mut self, packet: &[u8]) -> Option<&mut PeerSlot> {
        if packet.first().map(|byte| byte >> 4) == Some(4) && packet.len() >= 20 {
            let dest = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            return self
                .peers
                .values_mut()
                .find(|peer| peer.allowed.iter().any(|cidr| cidr.contains_v4(dest)));
        }
        if packet.first().map(|byte| byte >> 4) == Some(6) && packet.len() >= 40 {
            let dest = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
            return self
                .peers
                .values_mut()
                .find(|peer| peer.allowed.iter().any(|cidr| cidr.contains_v6(dest)));
        }
        None
    }
}

fn apply_result(
    result: TunnResult<'_>,
    dst_len: &mut usize,
    peer_public_out: &mut [u8; 32],
    peer_public: [u8; 32],
) -> i32 {
    match result {
        TunnResult::Done => RESULT_DONE,
        TunnResult::Err(_) => RESULT_ERR,
        TunnResult::WriteToNetwork(bytes) => {
            *dst_len = bytes.len();
            *peer_public_out = peer_public;
            RESULT_WRITE_NETWORK
        }
        TunnResult::WriteToTunnelV4(bytes, _) | TunnResult::WriteToTunnelV6(bytes, _) => {
            *dst_len = bytes.len();
            *peer_public_out = peer_public;
            RESULT_WRITE_TUNNEL
        }
    }
}

/// # Safety
/// `private_key` and `out` must each point at 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn blaktail_tunnel_public_key(private_key: *const u8, out: *mut u8) -> i32 {
    if private_key.is_null() || out.is_null() {
        return -1;
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(slice::from_raw_parts(private_key, 32));
    let public = PublicKey::from(&StaticSecret::from(raw));
    slice::from_raw_parts_mut(out, 32).copy_from_slice(public.as_bytes());
    0
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn parse_allowed(raw: &str) -> Vec<Cidr> {
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter_map(Cidr::parse)
        .collect()
}

/// # Safety
/// `private_key` must point to 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn blaktail_tunnel_create(private_key: *const u8) -> *mut BlakTailTunnel {
    if private_key.is_null() {
        return std::ptr::null_mut();
    }
    catch_unwind(AssertUnwindSafe(|| {
        let mut raw = [0u8; 32];
        raw.copy_from_slice(slice::from_raw_parts(private_key, 32));
        Box::into_raw(Box::new(BlakTailTunnel {
            inner: Mutex::new(TunnelInner {
                private: StaticSecret::from(raw),
                peers: BTreeMap::new(),
                next_index: 1,
            }),
        }))
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// # Safety
/// `tunnel` must be a pointer from `blaktail_tunnel_create` or null.
#[no_mangle]
pub unsafe extern "C" fn blaktail_tunnel_free(tunnel: *mut BlakTailTunnel) {
    if tunnel.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        drop(Box::from_raw(tunnel));
    }));
}

/// # Safety
/// `tunnel` and `public_key` must be valid. Writes the unix time of the last
/// decrypted transport packet for that peer, or zero when none has arrived.
#[no_mangle]
pub unsafe extern "C" fn blaktail_tunnel_last_handshake(
    tunnel: *mut BlakTailTunnel,
    public_key: *const u8,
) -> u64 {
    if tunnel.is_null() || public_key.is_null() {
        return 0;
    }
    let key = slice::from_raw_parts(public_key, 32);
    (*tunnel)
        .inner
        .lock()
        .ok()
        .and_then(|inner| {
            inner
                .peers
                .values()
                .find(|peer| peer.public_key.as_slice() == key)
                .map(|peer| peer.last_handshake_unix)
        })
        .unwrap_or(0)
}

/// # Safety
/// `tunnel` must be a live pointer from `blaktail_tunnel_create`.
#[no_mangle]
pub unsafe extern "C" fn blaktail_tunnel_clear_peers(tunnel: *mut BlakTailTunnel) {
    if tunnel.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Ok(mut inner) = (*tunnel).inner.lock() {
            inner.peers.clear();
        }
    }));
}

/// # Safety
/// Pointers must be valid for the stated lengths. `allowed_ips` is a C string.
#[no_mangle]
pub unsafe extern "C" fn blaktail_tunnel_add_peer(
    tunnel: *mut BlakTailTunnel,
    public_key: *const u8,
    allowed_ips: *const c_char,
    keepalive_seconds: u16,
) -> i32 {
    if tunnel.is_null() || public_key.is_null() || allowed_ips.is_null() {
        return RESULT_ERR;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let mut key = [0u8; 32];
        key.copy_from_slice(slice::from_raw_parts(public_key, 32));
        let allowed = match CStr::from_ptr(allowed_ips).to_str() {
            Ok(value) => parse_allowed(value),
            Err(_) => return RESULT_ERR,
        };
        let Ok(mut inner) = (*tunnel).inner.lock() else {
            return RESULT_ERR;
        };
        if inner.add_peer(key, allowed, keepalive_seconds) {
            RESULT_DONE
        } else {
            RESULT_ERR
        }
    }))
    .unwrap_or(RESULT_ERR)
}

/// # Safety
/// All pointers must be valid for the given lengths.
#[no_mangle]
pub unsafe extern "C" fn blaktail_tunnel_encapsulate(
    tunnel: *mut BlakTailTunnel,
    src: *const u8,
    src_len: usize,
    dst: *mut u8,
    dst_cap: usize,
    dst_len: *mut usize,
    peer_public_out: *mut u8,
) -> i32 {
    with_buffers(
        tunnel,
        src,
        src_len,
        dst,
        dst_cap,
        dst_len,
        peer_public_out,
        |inner, packet, output, length, peer_out| {
            let Some(peer) = inner.peer_for_packet(packet) else {
                return RESULT_ERR;
            };
            let public = peer.public_key;
            apply_result(
                peer.tunn.encapsulate(packet, output),
                length,
                peer_out,
                public,
            )
        },
    )
}

/// # Safety
/// All pointers must be valid for the given lengths.
#[no_mangle]
pub unsafe extern "C" fn blaktail_tunnel_decapsulate(
    tunnel: *mut BlakTailTunnel,
    src: *const u8,
    src_len: usize,
    dst: *mut u8,
    dst_cap: usize,
    dst_len: *mut usize,
    peer_public_out: *mut u8,
) -> i32 {
    with_buffers(
        tunnel,
        src,
        src_len,
        dst,
        dst_cap,
        dst_len,
        peer_public_out,
        |inner, packet, output, length, peer_out| {
            for peer in inner.peers.values_mut() {
                let public = peer.public_key;
                let result = peer.tunn.decapsulate(None, packet, output);
                if !matches!(result, TunnResult::Err(_)) {
                    if matches!(
                        result,
                        TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _)
                    ) {
                        peer.last_handshake_unix = unix_now();
                    }
                    return apply_result(result, length, peer_out, public);
                }
            }
            RESULT_ERR
        },
    )
}

/// # Safety
/// Destination pointers must be valid for the given lengths.
#[no_mangle]
pub unsafe extern "C" fn blaktail_tunnel_update_timers(
    tunnel: *mut BlakTailTunnel,
    dst: *mut u8,
    dst_cap: usize,
    dst_len: *mut usize,
    peer_public_out: *mut u8,
) -> i32 {
    if tunnel.is_null() || dst.is_null() || dst_len.is_null() || peer_public_out.is_null() {
        return RESULT_ERR;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let output = slice::from_raw_parts_mut(dst, dst_cap);
        let length = &mut *dst_len;
        *length = 0;
        let peer_out = &mut *(peer_public_out as *mut [u8; 32]);
        let Ok(mut inner) = (*tunnel).inner.lock() else {
            return RESULT_ERR;
        };
        for peer in inner.peers.values_mut() {
            let public = peer.public_key;
            let result = peer.tunn.update_timers(output);
            if matches!(result, TunnResult::WriteToNetwork(_)) {
                return apply_result(result, length, peer_out, public);
            }
        }
        RESULT_DONE
    }))
    .unwrap_or(RESULT_ERR)
}

#[allow(clippy::too_many_arguments)]
unsafe fn with_buffers(
    tunnel: *mut BlakTailTunnel,
    src: *const u8,
    src_len: usize,
    dst: *mut u8,
    dst_cap: usize,
    dst_len: *mut usize,
    peer_public_out: *mut u8,
    body: impl FnOnce(&mut TunnelInner, &[u8], &mut [u8], &mut usize, &mut [u8; 32]) -> i32,
) -> i32 {
    if tunnel.is_null() || dst.is_null() || dst_len.is_null() || peer_public_out.is_null() {
        return RESULT_ERR;
    }
    if src.is_null() && src_len != 0 {
        return RESULT_ERR;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let packet = if src.is_null() {
            &[]
        } else {
            slice::from_raw_parts(src, src_len)
        };
        let output = slice::from_raw_parts_mut(dst, dst_cap);
        let length = &mut *dst_len;
        *length = 0;
        let peer_out = &mut *(peer_public_out as *mut [u8; 32]);
        let Ok(mut inner) = (*tunnel).inner.lock() else {
            return RESULT_ERR;
        };
        body(&mut inner, packet, output, length, peer_out)
    }))
    .unwrap_or(RESULT_ERR)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet(dest: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2] = 0;
        packet[3] = 20;
        packet[16..20].copy_from_slice(&dest);
        packet
    }

    #[test]
    fn tunn_round_trip_without_ffi() {
        let alice_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let bob_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let mut alice = Tunn::new(
            alice_secret.clone(),
            PublicKey::from(&bob_secret),
            None,
            None,
            1,
            None,
        );
        let mut bob = Tunn::new(
            bob_secret,
            PublicKey::from(&alice_secret),
            None,
            None,
            2,
            None,
        );
        let ping = ipv4_packet([100, 64, 0, 2]);
        let mut buf_a = [0u8; 512];
        let mut buf_b = [0u8; 512];
        let TunnResult::WriteToNetwork(initiation) = alice.encapsulate(&ping, &mut buf_a) else {
            panic!("expected initiation");
        };
        let initiation = initiation.to_vec();
        let TunnResult::WriteToNetwork(response) = bob.decapsulate(None, &initiation, &mut buf_b)
        else {
            panic!("expected handshake response");
        };
        let response = response.to_vec();
        let TunnResult::WriteToNetwork(keepalive) = alice.decapsulate(None, &response, &mut buf_a)
        else {
            panic!("expected keepalive after handshake response");
        };
        let keepalive = keepalive.to_vec();
        assert!(matches!(
            bob.decapsulate(None, &keepalive, &mut buf_b),
            TunnResult::Done
        ));
        let TunnResult::WriteToNetwork(data) = alice.encapsulate(&ping, &mut buf_a) else {
            panic!("expected transport after handshake");
        };
        let data = data.to_vec();
        match bob.decapsulate(None, &data, &mut buf_b) {
            TunnResult::WriteToTunnelV4(inner, _) => assert_eq!(inner, ping.as_slice()),
            other => panic!("expected inner packet, got {other:?}"),
        }
    }

    #[test]
    fn handshake_and_transport_round_trip() {
        let alice_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let bob_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let alice_public = PublicKey::from(&alice_secret);
        let bob_public = PublicKey::from(&bob_secret);

        let alice = unsafe { blaktail_tunnel_create(alice_secret.to_bytes().as_ptr()) };
        let bob = unsafe { blaktail_tunnel_create(bob_secret.to_bytes().as_ptr()) };
        assert!(!alice.is_null());
        assert!(!bob.is_null());

        let alice_allowed = std::ffi::CString::new("100.64.0.2/32").unwrap();
        let bob_allowed = std::ffi::CString::new("100.64.0.1/32").unwrap();
        assert_eq!(
            unsafe {
                blaktail_tunnel_add_peer(
                    alice,
                    bob_public.as_bytes().as_ptr(),
                    alice_allowed.as_ptr(),
                    0,
                )
            },
            RESULT_DONE
        );
        assert_eq!(
            unsafe {
                blaktail_tunnel_add_peer(
                    bob,
                    alice_public.as_bytes().as_ptr(),
                    bob_allowed.as_ptr(),
                    0,
                )
            },
            RESULT_DONE
        );

        let ping = ipv4_packet([100, 64, 0, 2]);
        let mut peer = [0u8; 32];
        let mut initiation = vec![0u8; 512];
        let mut initiation_len = 0usize;
        assert_eq!(
            unsafe {
                blaktail_tunnel_encapsulate(
                    alice,
                    ping.as_ptr(),
                    ping.len(),
                    initiation.as_mut_ptr(),
                    initiation.len(),
                    &mut initiation_len,
                    peer.as_mut_ptr(),
                )
            },
            RESULT_WRITE_NETWORK
        );

        let mut response = vec![0u8; 512];
        let mut response_len = 0usize;
        assert_eq!(
            unsafe {
                blaktail_tunnel_decapsulate(
                    bob,
                    initiation.as_ptr(),
                    initiation_len,
                    response.as_mut_ptr(),
                    response.len(),
                    &mut response_len,
                    peer.as_mut_ptr(),
                )
            },
            RESULT_WRITE_NETWORK
        );

        let mut keepalive = vec![0u8; 512];
        let mut keepalive_len = 0usize;
        assert_eq!(
            unsafe {
                blaktail_tunnel_decapsulate(
                    alice,
                    response.as_ptr(),
                    response_len,
                    keepalive.as_mut_ptr(),
                    keepalive.len(),
                    &mut keepalive_len,
                    peer.as_mut_ptr(),
                )
            },
            RESULT_WRITE_NETWORK
        );
        let mut keepalive_ack = vec![0u8; 512];
        let mut keepalive_ack_len = 0usize;
        assert_eq!(
            unsafe {
                blaktail_tunnel_decapsulate(
                    bob,
                    keepalive.as_ptr(),
                    keepalive_len,
                    keepalive_ack.as_mut_ptr(),
                    keepalive_ack.len(),
                    &mut keepalive_ack_len,
                    peer.as_mut_ptr(),
                )
            },
            RESULT_DONE
        );

        let mut transport = vec![0u8; 512];
        let mut transport_len = 0usize;
        assert_eq!(
            unsafe {
                blaktail_tunnel_encapsulate(
                    alice,
                    ping.as_ptr(),
                    ping.len(),
                    transport.as_mut_ptr(),
                    transport.len(),
                    &mut transport_len,
                    peer.as_mut_ptr(),
                )
            },
            RESULT_WRITE_NETWORK
        );

        let mut inner = vec![0u8; 512];
        let mut inner_len = 0usize;
        assert_eq!(
            unsafe {
                blaktail_tunnel_decapsulate(
                    bob,
                    transport.as_ptr(),
                    transport_len,
                    inner.as_mut_ptr(),
                    inner.len(),
                    &mut inner_len,
                    peer.as_mut_ptr(),
                )
            },
            RESULT_WRITE_TUNNEL
        );
        assert_eq!(&inner[..inner_len], ping.as_slice());

        unsafe {
            blaktail_tunnel_free(alice);
            blaktail_tunnel_free(bob);
        }
    }
}
