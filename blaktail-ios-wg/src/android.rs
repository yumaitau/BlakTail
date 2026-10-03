//! JNI entry points for the Android VpnService. The packet pump stays in Kotlin.

use crate::relay::{self, with_relay};
use crate::BlakTailTunnel;
use crate::{
    blaktail_tunnel_add_peer, blaktail_tunnel_create, blaktail_tunnel_decapsulate,
    blaktail_tunnel_encapsulate, blaktail_tunnel_free, blaktail_tunnel_public_key,
    blaktail_tunnel_update_timers,
};
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring};
use jni::JNIEnv;
use std::ptr;

const WRITE_NETWORK: i32 = 1;
const WRITE_TUNNEL: i32 = 2;

#[no_mangle]
pub extern "system" fn Java_au_org_blaktail_NativeTunnel_publicKey<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    private_key: JByteArray<'local>,
) -> jbyteArray {
    let mut private = [0u8; 32];
    let mut public = [0u8; 32];
    if env
        .get_byte_array_region(private_key, 0, bytemut(&mut private))
        .is_err()
    {
        return ptr::null_mut();
    }
    let code = unsafe { blaktail_tunnel_public_key(private.as_ptr(), public.as_mut_ptr()) };
    if code != 0 {
        return ptr::null_mut();
    }
    env.byte_array_from_slice(&public)
        .ok()
        .map(|array| array.into_raw())
        .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_au_org_blaktail_NativeTunnel_create<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    private_key: JByteArray<'local>,
) -> jlong {
    let mut private = [0u8; 32];
    if env
        .get_byte_array_region(private_key, 0, bytemut(&mut private))
        .is_err()
    {
        return 0;
    }
    unsafe { blaktail_tunnel_create(private.as_ptr()) as jlong }
}

#[no_mangle]
pub extern "system" fn Java_au_org_blaktail_NativeTunnel_free(
    _env: JNIEnv,
    _class: JClass,
    tunnel: jlong,
) {
    if tunnel != 0 {
        unsafe { blaktail_tunnel_free(tunnel as *mut _) };
    }
}

#[no_mangle]
pub extern "system" fn Java_au_org_blaktail_NativeTunnel_addPeer<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    tunnel: jlong,
    public_key: JByteArray<'local>,
    allowed: JByteArray<'local>,
) -> jint {
    if tunnel == 0 {
        return -1;
    }
    let mut key = [0u8; 32];
    if env
        .get_byte_array_region(public_key, 0, bytemut(&mut key))
        .is_err()
    {
        return -1;
    }
    let Ok(allowed_bytes) = env.convert_byte_array(allowed) else {
        return -1;
    };
    let Ok(allowed) = std::ffi::CString::new(allowed_bytes) else {
        return -1;
    };
    unsafe { blaktail_tunnel_add_peer(tunnel as *mut _, key.as_ptr(), allowed.as_ptr(), 25) }
}

#[no_mangle]
pub extern "system" fn Java_au_org_blaktail_NativeTunnel_encapsulate<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    tunnel: jlong,
    packet: JByteArray<'local>,
) -> jbyteArray {
    transform(env, tunnel, packet, true)
}

#[no_mangle]
pub extern "system" fn Java_au_org_blaktail_NativeTunnel_decapsulate<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    tunnel: jlong,
    packet: JByteArray<'local>,
) -> jbyteArray {
    transform(env, tunnel, packet, false)
}

#[no_mangle]
pub extern "system" fn Java_au_org_blaktail_NativeTunnel_tick<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    tunnel: jlong,
) -> jbyteArray {
    if tunnel == 0 {
        return ptr::null_mut();
    }
    let mut output = vec![0u8; 2048];
    let mut length = 0usize;
    let mut peer = [0u8; 32];
    let code = unsafe {
        blaktail_tunnel_update_timers(
            tunnel as *mut _,
            output.as_mut_ptr(),
            output.len(),
            &mut length,
            peer.as_mut_ptr(),
        )
    };
    frame(&env, code, &peer, &output[..length])
}

fn transform<'local>(
    env: JNIEnv<'local>,
    tunnel: jlong,
    packet: JByteArray<'local>,
    encapsulate: bool,
) -> jbyteArray {
    if tunnel == 0 {
        return ptr::null_mut();
    }
    let Ok(input) = env.convert_byte_array(packet) else {
        return ptr::null_mut();
    };
    let mut output = vec![0u8; 2048];
    let mut length = 0usize;
    let mut peer = [0u8; 32];
    let code = unsafe {
        if encapsulate {
            blaktail_tunnel_encapsulate(
                tunnel as *mut _,
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut length,
                peer.as_mut_ptr(),
            )
        } else {
            blaktail_tunnel_decapsulate(
                tunnel as *mut _,
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut length,
                peer.as_mut_ptr(),
            )
        }
    };
    frame(&env, code, &peer, &output[..length])
}

fn frame(env: &JNIEnv, code: i32, peer: &[u8; 32], payload: &[u8]) -> jbyteArray {
    let kind = match code {
        WRITE_NETWORK => 1u8,
        WRITE_TUNNEL => 2u8,
        _ => return ptr::null_mut(),
    };
    let mut framed = Vec::with_capacity(1 + 32 + payload.len());
    framed.push(kind);
    framed.extend_from_slice(peer);
    framed.extend_from_slice(payload);
    env.byte_array_from_slice(&framed)
        .ok()
        .map(|array| array.into_raw())
        .unwrap_or(ptr::null_mut())
}

fn bytemut(bytes: &mut [u8]) -> &mut [i8] {
    unsafe { std::slice::from_raw_parts_mut(bytes.as_mut_ptr().cast(), bytes.len()) }
}

// Relay fallback. Android has no WebSocket transport in the platform SDK,
// so the core is configured with WSS disabled and stays on the UDP relay.

fn java_string(env: &mut JNIEnv, value: &JString) -> Option<String> {
    env.get_string(value).ok().map(Into::into)
}

fn public_key(env: &JNIEnv, key: &JByteArray) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    env.get_byte_array_region(key, 0, bytemut(&mut out))
        .ok()
        .map(|_| out)
}

fn bytes(env: &JNIEnv, data: &[u8]) -> jbyteArray {
    env.byte_array_from_slice(data)
        .ok()
        .map(|array| array.into_raw())
        .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_au_org_blaktail_NativeTunnel_relayConfigure<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    tunnel: jlong,
    self_id: JString<'local>,
    token_hex: JString<'local>,
    expires_at: jlong,
    relays: JString<'local>,
) -> jint {
    let (Some(id), Some(token), Some(relays)) = (
        java_string(&mut env, &self_id),
        java_string(&mut env, &token_hex),
        java_string(&mut env, &relays),
    ) else {
        return -1;
    };
    with_relay(tunnel as *mut BlakTailTunnel, -1, |inner| {
        if relay::configure(inner, &id, &token, expires_at.max(0) as u64, &relays, false) {
            0
        } else {
            -1
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_au_org_blaktail_NativeTunnel_relayBeginPeers(
    _env: JNIEnv,
    _class: JClass,
    tunnel: jlong,
) {
    with_relay(tunnel as *mut BlakTailTunnel, (), relay::begin_peers);
}

#[no_mangle]
pub extern "system" fn Java_au_org_blaktail_NativeTunnel_relaySetPeer<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    tunnel: jlong,
    key: JByteArray<'local>,
    node_id: JString<'local>,
    has_direct: jboolean,
) -> jint {
    let (Some(key), Some(node_id)) = (public_key(&env, &key), java_string(&mut env, &node_id))
    else {
        return -1;
    };
    with_relay(tunnel as *mut BlakTailTunnel, -1, |inner| {
        if relay::set_peer(inner, key, &node_id, has_direct != 0) {
            0
        } else {
            -1
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_au_org_blaktail_NativeTunnel_relayEndPeers(
    _env: JNIEnv,
    _class: JClass,
    tunnel: jlong,
) {
    with_relay(tunnel as *mut BlakTailTunnel, (), relay::end_peers);
}

/// Returns `[flags][SEND frame...]`; the frame is present only when a relay
/// flag is set.
#[no_mangle]
pub extern "system" fn Java_au_org_blaktail_NativeTunnel_relayOutbound<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    tunnel: jlong,
    key: JByteArray<'local>,
    datagram: JByteArray<'local>,
) -> jbyteArray {
    let (Some(key), Ok(datagram)) = (public_key(&env, &key), env.convert_byte_array(&datagram))
    else {
        return ptr::null_mut();
    };
    let mut out = vec![0u8; 1 + blaktail_relay_proto::MAX_SEND_FRAME];
    let (flags, written) = with_relay(tunnel as *mut BlakTailTunnel, (-1, 0), |inner| {
        relay::outbound(inner, &key, &datagram, &mut out[1..])
    });
    if flags < 0 {
        return ptr::null_mut();
    }
    out[0] = flags as u8;
    bytes(&env, &out[..1 + written])
}

/// Returns `[peer public key (32)][WireGuard ciphertext]`, or null when the
/// frame was a control reply or not acceptable.
#[no_mangle]
pub extern "system" fn Java_au_org_blaktail_NativeTunnel_relayInbound<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    tunnel: jlong,
    frame: JByteArray<'local>,
    endpoint: JString<'local>,
) -> jbyteArray {
    let (Ok(frame), Some(endpoint)) = (
        env.convert_byte_array(&frame),
        java_string(&mut env, &endpoint),
    ) else {
        return ptr::null_mut();
    };
    let mut out = vec![0u8; 32 + blaktail_relay_proto::MAX_PAYLOAD];
    let (head, payload) = out.split_at_mut(32);
    let Some((key, len)) = with_relay(tunnel as *mut BlakTailTunnel, None, |inner| {
        relay::inbound(inner, &frame, false, &endpoint, payload)
    }) else {
        return ptr::null_mut();
    };
    head.copy_from_slice(&key);
    bytes(&env, &out[..32 + len])
}

#[no_mangle]
pub extern "system" fn Java_au_org_blaktail_NativeTunnel_relayDirectReceived<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    tunnel: jlong,
    key: JByteArray<'local>,
) {
    if let Some(key) = public_key(&env, &key) {
        with_relay(tunnel as *mut BlakTailTunnel, (), |inner| {
            relay::direct_received(inner, &key)
        });
    }
}

#[no_mangle]
pub extern "system" fn Java_au_org_blaktail_NativeTunnel_relayTick(
    _env: JNIEnv,
    _class: JClass,
    tunnel: jlong,
) {
    with_relay(tunnel as *mut BlakTailTunnel, (), relay::tick);
}

/// Returns `[kind][endpoint length u16 BE][endpoint UTF-8][frame]` for the
/// next due control frame, or null.
#[no_mangle]
pub extern "system" fn Java_au_org_blaktail_NativeTunnel_relayPoll<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    tunnel: jlong,
) -> jbyteArray {
    let Some((kind, endpoint, frame)) =
        with_relay(tunnel as *mut BlakTailTunnel, None, relay::poll)
    else {
        return ptr::null_mut();
    };
    let name = endpoint.as_bytes();
    let Ok(name_len) = u16::try_from(name.len()) else {
        return ptr::null_mut();
    };
    let mut out = Vec::with_capacity(3 + name.len() + frame.len());
    out.push(kind as u8);
    out.extend_from_slice(&name_len.to_be_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&frame);
    bytes(&env, &out)
}

#[no_mangle]
pub extern "system" fn Java_au_org_blaktail_NativeTunnel_relayStatus<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    tunnel: jlong,
) -> jstring {
    let json = with_relay(tunnel as *mut BlakTailTunnel, String::new(), |inner| {
        relay::status_json(inner)
    });
    env.new_string(json)
        .map(|value| value.into_raw())
        .unwrap_or(ptr::null_mut())
}
