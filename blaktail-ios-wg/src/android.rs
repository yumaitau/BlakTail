//! JNI entry points for the Android VpnService. The packet pump stays in Kotlin.

use crate::{
    blaktail_tunnel_add_peer, blaktail_tunnel_create, blaktail_tunnel_decapsulate,
    blaktail_tunnel_encapsulate, blaktail_tunnel_free, blaktail_tunnel_public_key,
    blaktail_tunnel_update_timers,
};
use jni::objects::{JByteArray, JClass};
use jni::sys::{jbyteArray, jint, jlong};
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
    if env.get_byte_array_region(public_key, 0, bytemut(&mut key)).is_err() {
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
