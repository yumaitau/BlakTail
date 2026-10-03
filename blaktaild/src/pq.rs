//! Opt-in hybrid post-quantum pre-shared keys for WireGuard (ADR 0009).
//!
//! Two peers that both advertise [`CAPABILITY`] and whose organisation policy
//! is `prefer` or `require` run a small key exchange *inside* their existing
//! WireGuard tunnel, so the classical WireGuard session authenticates it. The
//! exchange combines a fresh ML-KEM-768 encapsulation (RustCrypto `ml-kem`)
//! with a fresh X25519 exchange; HKDF-SHA256 over both shared secrets and the
//! peers' static X25519 agreement (each side's WireGuard private key with the
//! other's WireGuard public key), keyed by a transcript hash that binds both
//! WireGuard public keys and an epoch counter, yields the 32-byte WireGuard
//! preshared key for that peer. The static agreement authenticates the
//! exchange end to end: a local process that squats the listener port, or
//! anything else without the WireGuard private key, cannot produce a valid
//! key confirmation. Nothing here is a new KEM or handshake; the PSK is only
//! mixed into WireGuard's own.
//!
//! Limits, stated plainly: WireGuard authentication stays classical
//! (Curve25519), the coordinator never sees or relays a PSK, and this layer
//! has not had an independent cryptographic review.

use crate::{Error, Peer};
use base64::{engine::general_purpose::STANDARD, Engine};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem},
    Ciphertext, EncapsulationKey, KeyExport, MlKem768,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
};
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Capability token both peers must advertise before an exchange is tried.
pub const CAPABILITY: &str = "pq-psk";
/// Algorithm string reported to the coordinator for display.
pub const ALGORITHM: &str = "ml-kem-768+x25519";
/// TCP port of the exchange listener, bound to the overlay address only.
pub const PORT: u16 = 51822;
/// Rotation interval (Rosenpass also rotates every two minutes).
pub const ROTATE_SECS: u64 = 120;
/// A PSK whose rotation keeps failing stays installed until this age, after
/// which the pair is reported degraded (or not established under `require`).
pub const PSK_LIFETIME_SECS: u64 = 600;
/// With a PSK installed and no WireGuard handshake for this long, the two
/// sides have probably diverged (one restarted, an Ack was lost): drop back
/// to no PSK so the tunnel can carry a fresh exchange.
pub const STALE_REVERT_SECS: u64 = 200;
/// Setting this to `1` makes the agent stop advertising [`CAPABILITY`].
pub const DISABLE_ENV: &str = "BLAKTAIL_DISABLE_PQ_PSK";
/// iptables chain holding per-peer blocks under `require`. It lives in the
/// mangle table, after connection tracking, so replies can be told apart
/// from new connections.
pub const BLOCK_CHAIN: &str = "BLAKTAIL-PQ";
const BLOCK_TABLE: &str = "mangle";

const VERSION: u8 = 2;
const LABEL: &[u8] = b"blaktail pq-psk v2";
const MAX_LINE: u64 = 8 * 1024;
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
const RETRY_SECS: u64 = 10;
const TICK: Duration = if cfg!(test) {
    Duration::from_millis(50)
} else {
    Duration::from_secs(3)
};
const STATE_FILE: &str = "pq-psk.json";
const X25519_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Policy as delivered in the peer map

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Off,
    Prefer,
    Require,
}

/// Per-peer policy from the coordinator: the pair's resolved mode, whether
/// that peer advertises [`CAPABILITY`], and whether traffic must be blocked
/// while a required PSK is not established. Never carries key material.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PeerPq {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub capable: bool,
    #[serde(default)]
    pub block: bool,
}

/// Whether this build and host can run the exchange.
pub fn locally_capable() -> bool {
    cfg!(any(target_os = "linux", target_os = "macos"))
        && std::env::var(DISABLE_ENV).map_or(true, |value| value.trim() != "1")
}

// ---------------------------------------------------------------------------
// Key material

/// A WireGuard preshared key. Zeroised on drop and never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct Psk(Zeroizing<[u8; 32]>);

impl Psk {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
    /// Base64 form for `wg`'s key-file input. The caller must not log it.
    pub fn to_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(STANDARD.encode(self.0.as_ref()))
    }
    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(self.0.iter().map(|b| format!("{b:02x}")).collect())
    }
}

impl std::fmt::Debug for Psk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Psk(<redacted>)")
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PqError {
    #[error("unexpected message")]
    Unexpected,
    #[error("unsupported protocol version")]
    Version,
    #[error("malformed field {0}")]
    Malformed(&'static str),
    #[error("wireguard keys in the exchange do not match this peer pair")]
    WrongPeer,
    #[error("only the peer with the lower WireGuard key initiates")]
    WrongRole,
    #[error("stale or replayed epoch {epoch} (last accepted {last})")]
    StaleEpoch { epoch: u64, last: u64 },
    #[error("key confirmation failed")]
    Confirmation,
    #[error("X25519 exchange was not contributory")]
    WeakDh,
    #[error("peer rejected the exchange: {reason}")]
    Rejected { reason: String, last_epoch: u64 },
    #[error("exchange I/O failed: {0}")]
    Io(String),
    #[error("exchange timed out")]
    Timeout,
}

impl From<std::io::Error> for PqError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.kind().to_string())
    }
}

fn decode_key(value: &str) -> Option<[u8; 32]> {
    STANDARD.decode(value.trim()).ok()?.try_into().ok()
}

fn decode_field(value: &str, len: usize, name: &'static str) -> Result<Vec<u8>, PqError> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| PqError::Malformed(name))?;
    if bytes.len() != len {
        return Err(PqError::Malformed(name));
    }
    Ok(bytes)
}

/// SHA-256 over every public value of one exchange, length-prefixed, plus
/// the protocol label, version, epoch and both WireGuard static keys in
/// initiator/responder order. Swapping any input changes the PSK.
#[allow(clippy::too_many_arguments)]
pub fn transcript(
    epoch: u64,
    initiator_wg: &[u8; 32],
    responder_wg: &[u8; 32],
    initiator_x25519: &[u8],
    mlkem_ek: &[u8],
    responder_x25519: &[u8],
    mlkem_ct: &[u8],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(LABEL);
    hash.update([VERSION]);
    hash.update(epoch.to_be_bytes());
    for part in [
        &initiator_wg[..],
        &responder_wg[..],
        initiator_x25519,
        mlkem_ek,
        responder_x25519,
        mlkem_ct,
    ] {
        hash.update((part.len() as u32).to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}

/// Reads the WireGuard private key file `ensure_private_key` maintains.
pub fn read_private_key(path: &Path) -> Option<StaticSecret> {
    let encoded = Zeroizing::new(std::fs::read_to_string(path).ok()?);
    let bytes = Zeroizing::new(STANDARD.decode(encoded.trim()).ok()?);
    let raw: [u8; 32] = bytes.as_slice().try_into().ok()?;
    Some(StaticSecret::from(raw))
}

/// X25519 of this node's WireGuard private key with the peer's WireGuard
/// public key. Both sides compute the same value; only holders of one of
/// the two private keys can.
pub fn static_agreement(
    own: &StaticSecret,
    peer: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, PqError> {
    let shared = own.diffie_hellman(&PublicKey::from(*peer));
    if !shared.was_contributory() {
        return Err(PqError::WeakDh);
    }
    Ok(Zeroizing::new(shared.to_bytes()))
}

/// HKDF-SHA256(salt = transcript, ikm = ML-KEM secret || X25519 secret ||
/// static agreement). Returns the WireGuard PSK and a separate
/// key-confirmation key.
pub fn derive(
    mlkem_secret: &[u8],
    x25519_secret: &[u8],
    static_secret: &[u8; 32],
    transcript: &[u8; 32],
) -> (Psk, Zeroizing<[u8; 32]>) {
    let mut ikm = Zeroizing::new(Vec::with_capacity(
        mlkem_secret.len() + x25519_secret.len() + static_secret.len(),
    ));
    ikm.extend_from_slice(mlkem_secret);
    ikm.extend_from_slice(x25519_secret);
    ikm.extend_from_slice(static_secret);
    let hkdf = Hkdf::<Sha256>::new(Some(transcript), &ikm);
    let mut psk = Zeroizing::new([0u8; 32]);
    let mut confirm = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"blaktail pq-psk v2 wireguard psk", psk.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 length");
    hkdf.expand(b"blaktail pq-psk v2 key confirmation", confirm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 length");
    (Psk(psk), confirm)
}

fn confirm_tag(key: &[u8; 32], role: &[u8], transcript: &[u8; 32]) -> Hmac<Sha256> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(role);
    mac.update(transcript);
    mac
}

// ---------------------------------------------------------------------------
// Messages

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    Init {
        v: u8,
        epoch: u64,
        initiator: String,
        responder: String,
        x25519: String,
        mlkem_ek: String,
    },
    Resp {
        v: u8,
        epoch: u64,
        x25519: String,
        mlkem_ct: String,
        confirm: String,
    },
    Confirm {
        v: u8,
        epoch: u64,
        confirm: String,
    },
    Ack {
        v: u8,
        epoch: u64,
    },
    Reject {
        v: u8,
        reason: String,
        last_epoch: u64,
    },
}

/// Initiator half of one exchange, holding only ephemeral secrets.
pub struct Initiator {
    epoch: u64,
    own: [u8; 32],
    peer: [u8; 32],
    static_secret: Zeroizing<[u8; 32]>,
    x25519: EphemeralSecret,
    x25519_public: [u8; 32],
    dk: <MlKem768 as Kem>::DecapsulationKey,
    ek: Vec<u8>,
}

/// Starts an exchange from `own` (the lower WireGuard key) to `peer`.
/// `static_secret` is [`static_agreement`] for the pair.
pub fn initiate(
    own: &[u8; 32],
    peer: &[u8; 32],
    static_secret: &[u8; 32],
    epoch: u64,
) -> Result<(Initiator, Message), PqError> {
    if own >= peer {
        return Err(PqError::WrongRole);
    }
    let x25519 = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let x25519_public = PublicKey::from(&x25519).to_bytes();
    let (dk, ek) = MlKem768::generate_keypair();
    let ek = ek.to_bytes().to_vec();
    let message = Message::Init {
        v: VERSION,
        epoch,
        initiator: STANDARD.encode(own),
        responder: STANDARD.encode(peer),
        x25519: STANDARD.encode(x25519_public),
        mlkem_ek: STANDARD.encode(&ek),
    };
    Ok((
        Initiator {
            epoch,
            own: *own,
            peer: *peer,
            static_secret: Zeroizing::new(*static_secret),
            x25519,
            x25519_public,
            dk,
            ek,
        },
        message,
    ))
}

impl Initiator {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Verifies the responder's key confirmation and returns the PSK plus
    /// the initiator's own confirmation message.
    pub fn finish(self, response: &Message) -> Result<(Psk, Message), PqError> {
        let (x25519, mlkem_ct, confirm) = match response {
            Message::Resp {
                v,
                epoch,
                x25519,
                mlkem_ct,
                confirm,
            } => {
                if *v != VERSION {
                    return Err(PqError::Version);
                }
                if *epoch != self.epoch {
                    return Err(PqError::StaleEpoch {
                        epoch: *epoch,
                        last: self.epoch,
                    });
                }
                (x25519, mlkem_ct, confirm)
            }
            Message::Reject {
                reason, last_epoch, ..
            } => {
                return Err(PqError::Rejected {
                    reason: reason.chars().take(64).collect(),
                    last_epoch: *last_epoch,
                })
            }
            _ => return Err(PqError::Unexpected),
        };
        let responder_x25519: [u8; 32] = decode_field(x25519, X25519_LEN, "x25519")?
            .try_into()
            .map_err(|_| PqError::Malformed("x25519"))?;
        let ct_bytes = decode_field(mlkem_ct, ct_len(), "mlkem_ct")?;
        let confirm = decode_field(confirm, 32, "confirm")?;
        let ct = Ciphertext::<MlKem768>::try_from(ct_bytes.as_slice())
            .map_err(|_| PqError::Malformed("mlkem_ct"))?;
        let kem_secret = Zeroizing::new(self.dk.decapsulate(&ct).to_vec());
        let dh = self
            .x25519
            .diffie_hellman(&PublicKey::from(responder_x25519));
        if !dh.was_contributory() {
            return Err(PqError::WeakDh);
        }
        let th = transcript(
            self.epoch,
            &self.own,
            &self.peer,
            &self.x25519_public,
            &self.ek,
            &responder_x25519,
            &ct_bytes,
        );
        let (psk, confirm_key) = derive(&kem_secret, dh.as_bytes(), &self.static_secret, &th);
        confirm_tag(&confirm_key, b"responder", &th)
            .verify_slice(&confirm)
            .map_err(|_| PqError::Confirmation)?;
        let own_tag = confirm_tag(&confirm_key, b"initiator", &th)
            .finalize()
            .into_bytes();
        Ok((
            psk,
            Message::Confirm {
                v: VERSION,
                epoch: self.epoch,
                confirm: STANDARD.encode(own_tag),
            },
        ))
    }
}

fn ct_len() -> usize {
    1088
}

fn ek_len() -> usize {
    1184
}

/// Responder half waiting for the initiator's key confirmation.
pub struct Responder {
    epoch: u64,
    psk: Psk,
    expected: Zeroizing<Vec<u8>>,
}

fn reject(reason: &str, last_epoch: u64) -> Message {
    Message::Reject {
        v: VERSION,
        reason: reason.into(),
        last_epoch,
    }
}

/// Answers an `Init` from `peer` (which must hold the lower key). `last_epoch`
/// is the newest epoch this side accepted for the pair; anything not newer is
/// a replay and is refused. `static_secret` is [`static_agreement`].
pub fn respond(
    own: &[u8; 32],
    peer: &[u8; 32],
    static_secret: &[u8; 32],
    last_epoch: u64,
    init: &Message,
) -> Result<(Responder, Message), PqError> {
    let Message::Init {
        v,
        epoch,
        initiator,
        responder,
        x25519,
        mlkem_ek,
    } = init
    else {
        return Err(PqError::Unexpected);
    };
    if *v != VERSION {
        return Err(PqError::Version);
    }
    if decode_key(initiator).as_ref() != Some(peer) || decode_key(responder).as_ref() != Some(own) {
        return Err(PqError::WrongPeer);
    }
    if peer >= own {
        return Err(PqError::WrongRole);
    }
    if *epoch <= last_epoch {
        return Err(PqError::StaleEpoch {
            epoch: *epoch,
            last: last_epoch,
        });
    }
    let initiator_x25519: [u8; 32] = decode_field(x25519, X25519_LEN, "x25519")?
        .try_into()
        .map_err(|_| PqError::Malformed("x25519"))?;
    let ek_bytes = decode_field(mlkem_ek, ek_len(), "mlkem_ek")?;
    let ek_array = ml_kem::Key::<EncapsulationKey<MlKem768>>::try_from(ek_bytes.as_slice())
        .map_err(|_| PqError::Malformed("mlkem_ek"))?;
    let ek =
        EncapsulationKey::<MlKem768>::new(&ek_array).map_err(|_| PqError::Malformed("mlkem_ek"))?;
    let (ct, kem_secret) = ek.encapsulate();
    let kem_secret = Zeroizing::new(kem_secret.to_vec());
    let ct_bytes = ct.to_vec();
    let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let responder_x25519 = PublicKey::from(&secret).to_bytes();
    let dh = secret.diffie_hellman(&PublicKey::from(initiator_x25519));
    if !dh.was_contributory() {
        return Err(PqError::WeakDh);
    }
    let th = transcript(
        *epoch,
        peer,
        own,
        &initiator_x25519,
        &ek_bytes,
        &responder_x25519,
        &ct_bytes,
    );
    let (psk, confirm_key) = derive(&kem_secret, dh.as_bytes(), static_secret, &th);
    let tag = confirm_tag(&confirm_key, b"responder", &th)
        .finalize()
        .into_bytes();
    let expected = Zeroizing::new(
        confirm_tag(&confirm_key, b"initiator", &th)
            .finalize()
            .into_bytes()
            .to_vec(),
    );
    Ok((
        Responder {
            epoch: *epoch,
            psk,
            expected,
        },
        Message::Resp {
            v: VERSION,
            epoch: *epoch,
            x25519: STANDARD.encode(responder_x25519),
            mlkem_ct: STANDARD.encode(&ct_bytes),
            confirm: STANDARD.encode(tag),
        },
    ))
}

impl Responder {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn finish(self, confirm: &Message) -> Result<Psk, PqError> {
        let Message::Confirm { v, epoch, confirm } = confirm else {
            return Err(PqError::Unexpected);
        };
        if *v != VERSION {
            return Err(PqError::Version);
        }
        if *epoch != self.epoch {
            return Err(PqError::StaleEpoch {
                epoch: *epoch,
                last: self.epoch,
            });
        }
        let tag = decode_field(confirm, 32, "confirm")?;
        if !constant_time_eq(&tag, &self.expected) {
            return Err(PqError::Confirmation);
        }
        Ok(self.psk)
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

// ---------------------------------------------------------------------------
// Wire transport: one JSON message per line over TCP inside the tunnel

async fn send<W: AsyncWrite + Unpin>(writer: &mut W, message: &Message) -> Result<(), PqError> {
    let mut line = serde_json::to_vec(message).map_err(|_| PqError::Malformed("encode"))?;
    line.push(b'\n');
    writer.write_all(&line).await?;
    writer.flush().await?;
    Ok(())
}

async fn recv<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Message, PqError> {
    let mut line = Vec::new();
    let read = (&mut *reader)
        .take(MAX_LINE)
        .read_until(b'\n', &mut line)
        .await?;
    if read == 0 || !line.ends_with(b"\n") {
        return Err(PqError::Malformed("frame"));
    }
    serde_json::from_slice(&line).map_err(|_| PqError::Malformed("frame"))
}

/// Runs the initiator side over `stream` and returns `(epoch, psk)` once the
/// responder has installed the same key (its `Ack`).
pub async fn run_initiator<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    own: &[u8; 32],
    peer: &[u8; 32],
    static_secret: &[u8; 32],
    epoch: u64,
) -> Result<(u64, Psk), PqError> {
    let (read, mut write) = tokio::io::split(stream);
    let mut read = tokio::io::BufReader::new(read);
    let (state, init) = initiate(own, peer, static_secret, epoch)?;
    send(&mut write, &init).await?;
    let response = recv(&mut read).await?;
    let (psk, confirm) = state.finish(&response)?;
    send(&mut write, &confirm).await?;
    match recv(&mut read).await? {
        Message::Ack { v, epoch: acked } if v == VERSION && acked == epoch => Ok((epoch, psk)),
        Message::Reject {
            reason, last_epoch, ..
        } => Err(PqError::Rejected {
            reason: reason.chars().take(64).collect(),
            last_epoch,
        }),
        _ => Err(PqError::Unexpected),
    }
}

/// What the responder needs to know about the connecting peer.
pub struct ResponderContext {
    pub own: [u8; 32],
    pub peer: [u8; 32],
    pub static_secret: Zeroizing<[u8; 32]>,
    pub last_epoch: u64,
}

/// Runs the responder side. `install` is called with the agreed key before
/// the `Ack` is sent, so the initiator never installs a key we lack.
pub async fn run_responder<S, F>(
    stream: S,
    context: ResponderContext,
    install: F,
) -> Result<(u64, Psk), PqError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(u64, &Psk) -> Result<(), String>,
{
    let (read, mut write) = tokio::io::split(stream);
    let mut read = tokio::io::BufReader::new(read);
    let init = recv(&mut read).await?;
    let (pending, response) = match respond(
        &context.own,
        &context.peer,
        &context.static_secret,
        context.last_epoch,
        &init,
    ) {
        Ok(ok) => ok,
        Err(error) => {
            let reason = match &error {
                PqError::StaleEpoch { .. } => "stale_epoch",
                PqError::WrongPeer => "wrong_peer",
                PqError::WrongRole => "wrong_role",
                PqError::Version => "version",
                _ => "invalid",
            };
            let _ = send(&mut write, &reject(reason, context.last_epoch)).await;
            return Err(error);
        }
    };
    send(&mut write, &response).await?;
    let confirm = recv(&mut read).await?;
    let epoch = pending.epoch();
    let psk = pending.finish(&confirm)?;
    if let Err(error) = install(epoch, &psk) {
        let _ = send(&mut write, &reject("install_failed", context.last_epoch)).await;
        return Err(PqError::Io(error));
    }
    send(&mut write, &Message::Ack { v: VERSION, epoch }).await?;
    Ok((epoch, psk))
}

// ---------------------------------------------------------------------------
// Per-peer state and the honest status reported to the coordinator

#[derive(Clone, Debug)]
pub struct Installed {
    pub epoch: u64,
    /// When the exchange that produced this key completed.
    pub at: u64,
    /// When the key was last written to the device (install, restart).
    pub applied_at: u64,
    pub psk: Psk,
}

#[derive(Clone, Debug, Default)]
pub struct Track {
    pub last_epoch: u64,
    pub installed: Option<Installed>,
    pub last_attempt_at: u64,
    pub last_error: Option<String>,
}

/// One peer as the PQ layer sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerPlan {
    pub id: Uuid,
    pub key: String,
    pub raw_key: [u8; 32],
    pub pq: PeerPq,
    /// Overlay host addresses (exchange endpoints).
    pub hosts: Vec<IpAddr>,
    /// Every route installed for the peer (what a block covers).
    pub routes: Vec<String>,
}

impl PeerPlan {
    pub fn from_peer(peer: &Peer) -> Option<Self> {
        let raw_key = decode_key(&peer.wg_public_key)?;
        Some(Self {
            id: peer.id,
            key: peer.wg_public_key.clone(),
            raw_key,
            pq: peer.pq.clone().unwrap_or_default(),
            hosts: crate::acl_filter::overlay_host_addrs(&peer.allowed_ips)
                .iter()
                .filter_map(|address| address.parse().ok())
                .collect(),
            routes: peer.allowed_ips.clone(),
        })
    }

    /// Both sides capable and policy asks for PQ.
    pub fn wants_exchange(&self, local_capable: bool) -> bool {
        self.pq.mode != Mode::Off && self.pq.capable && local_capable
    }
}

/// What an agent reports per peer. No key material, by construction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PeerReport {
    pub peer_id: Uuid,
    /// `classical`, `negotiating`, `established`, `degraded` or
    /// `required_not_established`.
    pub state: String,
    pub mode: Mode,
    /// [`ALGORITHM`] when a hybrid PSK is installed, empty otherwise.
    pub algorithm: String,
    pub epoch: u64,
    pub last_rotation_at: Option<u64>,
    /// True only when this agent actually drops the pair's traffic.
    pub blocked: bool,
    pub reason: String,
}

pub fn evaluate(
    plan: &PeerPlan,
    track: Option<&Track>,
    local_capable: bool,
    block_enforced: bool,
    now: u64,
) -> PeerReport {
    let installed = track.and_then(|track| track.installed.as_ref());
    let fresh = installed.filter(|installed| now.saturating_sub(installed.at) <= PSK_LIFETIME_SECS);
    let (state, reason) = match plan.pq.mode {
        Mode::Off => ("classical", "policy_off"),
        _ if !local_capable => match plan.pq.mode {
            Mode::Require => ("required_not_established", "local_not_capable"),
            _ => ("classical", "local_not_capable"),
        },
        _ if !plan.pq.capable => match plan.pq.mode {
            Mode::Require => ("required_not_established", "peer_not_capable"),
            _ => ("classical", "peer_not_capable"),
        },
        _ if fresh.is_some() => ("established", ""),
        Mode::Require if installed.is_some() => ("required_not_established", "rotation_failed"),
        Mode::Require => ("required_not_established", "not_yet_established"),
        _ if installed.is_some() => ("degraded", "rotation_failed"),
        _ => ("negotiating", "not_yet_established"),
    };
    let wants_block = state == "required_not_established" && plan.pq.block;
    let reason = if wants_block && !block_enforced {
        "block_not_supported_here"
    } else {
        reason
    };
    let shown = installed.filter(|_| state != "classical" && state != "negotiating");
    PeerReport {
        peer_id: plan.id,
        state: state.into(),
        mode: plan.pq.mode,
        algorithm: shown.map(|_| ALGORITHM.to_string()).unwrap_or_default(),
        epoch: shown.map_or(0, |installed| installed.epoch),
        last_rotation_at: shown.map(|installed| installed.at),
        blocked: wants_block && block_enforced,
        reason: reason.into(),
    }
}

// ---------------------------------------------------------------------------
// Platform hooks

/// Installs PSKs and pair blocks on the local WireGuard device.
pub trait PskDevice: Send + Sync {
    /// `None` clears the key (all-zero PSK, which WireGuard treats as none).
    fn set_psk(&self, peer_key_b64: &str, psk: Option<&Psk>) -> Result<(), Error>;
    /// Latest handshake per peer key in hex, as `Network::latest_handshakes`.
    fn latest_handshakes(&self) -> Result<HashMap<String, u64>, Error>;
    /// Blocks every route of each listed peer except the exchange port.
    /// Returns whether this platform enforces the block.
    fn set_blocked(&self, blocked: &[PeerPlan]) -> Result<bool, Error>;
    /// Whether [`PskDevice::set_blocked`] can enforce anything here.
    fn enforces_blocks(&self) -> bool;
    /// Interface to bind the exchange listener to, when supported.
    fn bind_device(&self) -> Option<String> {
        None
    }
}

/// Linux: kernel WireGuard (or the boringtun binary) through `wg(8)`. The key
/// travels on `wg`'s stdin (`preshared-key /dev/stdin`), never in argv or a
/// file on disk.
pub struct WgCommandDevice {
    pub interface: String,
}

impl WgCommandDevice {
    fn wg_set_psk(&self, peer: &str, encoded: &str) -> Result<(), Error> {
        use std::io::Write as _;
        let mut child = std::process::Command::new("wg")
            .args([
                "set",
                &self.interface,
                "peer",
                peer.trim(),
                "preshared-key",
                "/dev/stdin",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| Error::Message(format!("could not execute wg: {e}")))?;
        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| Error::Message("wg stdin unavailable".into()))?;
            stdin.write_all(encoded.as_bytes())?;
            stdin.write_all(b"\n")?;
        }
        let out = child.wait_with_output()?;
        if out.status.success() {
            Ok(())
        } else {
            Err(Error::Message(format!(
                "wg preshared-key update failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    }

    fn iptables(bin: &str, args: &[&str]) -> Result<(), Error> {
        let out = std::process::Command::new(bin)
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| Error::Message(format!("could not execute {bin}: {e}")))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(Error::Message(format!(
                "{bin} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    }

    pub fn clear_blocks() {
        for bin in ["iptables", "ip6tables"] {
            // `raw` held the chain in earlier releases; clear it there too.
            for table in ["raw", BLOCK_TABLE] {
                for hook in ["PREROUTING", "OUTPUT"] {
                    for _ in 0..4 {
                        let _ = Self::iptables(bin, &["-t", table, "-D", hook, "-j", BLOCK_CHAIN]);
                    }
                }
                let _ = Self::iptables(bin, &["-t", table, "-F", BLOCK_CHAIN]);
                let _ = Self::iptables(bin, &["-t", table, "-X", BLOCK_CHAIN]);
            }
        }
    }
}

impl PskDevice for WgCommandDevice {
    fn set_psk(&self, peer_key_b64: &str, psk: Option<&Psk>) -> Result<(), Error> {
        match psk {
            Some(psk) => self.wg_set_psk(peer_key_b64, &psk.to_base64()),
            None => self.wg_set_psk(peer_key_b64, &STANDARD.encode([0u8; 32])),
        }
    }

    fn latest_handshakes(&self) -> Result<HashMap<String, u64>, Error> {
        let out = std::process::Command::new("wg")
            .args(["show", &self.interface, "latest-handshakes"])
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| Error::Message(format!("could not execute wg: {e}")))?;
        if !out.status.success() {
            return Err(Error::Message("wg latest-handshakes failed".into()));
        }
        Ok(parse_handshakes(&String::from_utf8_lossy(&out.stdout)))
    }

    fn set_blocked(&self, blocked: &[PeerPlan]) -> Result<bool, Error> {
        Self::clear_blocks();
        if blocked.is_empty() {
            return Ok(true);
        }
        let plan = block_rules(blocked);
        for (bin, rules) in [("iptables", &plan.ipv4), ("ip6tables", &plan.ipv6)] {
            Self::iptables(bin, &["-t", BLOCK_TABLE, "-N", BLOCK_CHAIN])?;
            for rule in rules {
                let args: Vec<&str> = rule.iter().map(String::as_str).collect();
                Self::iptables(bin, &args)?;
            }
            for hook in ["PREROUTING", "OUTPUT"] {
                Self::iptables(
                    bin,
                    &["-t", BLOCK_TABLE, "-I", hook, "1", "-j", BLOCK_CHAIN],
                )?;
            }
        }
        Ok(true)
    }

    fn enforces_blocks(&self) -> bool {
        true
    }

    fn bind_device(&self) -> Option<String> {
        Some(self.interface.clone())
    }
}

pub fn parse_handshakes(text: &str) -> HashMap<String, u64> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let Some((key, stamp)) = line.split_once('\t') else {
            continue;
        };
        if let (Some(hex), Ok(secs)) = (crate::peer_key_hex(key), stamp.trim().parse::<u64>()) {
            map.insert(hex, secs);
        }
    }
    map
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct BlockPlan {
    pub ipv4: Vec<Vec<String>>,
    pub ipv6: Vec<Vec<String>>,
}

/// Per blocked peer, let only the exchange through and drop everything else
/// to or from its routes. Inbound, the peer may open a connection to our
/// listener port, and its packets from its listener port pass only as
/// replies (conntrack ESTABLISHED) to a connection we opened; outbound
/// mirrors that. A source or destination port of 51822 alone opens nothing.
/// Default routes are skipped (blocking `0.0.0.0/0` would cut the whole host
/// off); the exit node's own agent still blocks the pair from its side.
pub fn block_rules(blocked: &[PeerPlan]) -> BlockPlan {
    let mut plan = BlockPlan::default();
    let port = PORT.to_string();
    for peer in blocked {
        for route in &peer.routes {
            let Some((address, prefix)) = route.split_once('/') else {
                continue;
            };
            let Ok(parsed) = address.parse::<IpAddr>() else {
                continue;
            };
            if prefix == "0" {
                continue;
            }
            let host =
                (parsed.is_ipv4() && prefix == "32") || (parsed.is_ipv6() && prefix == "128");
            let rules = if parsed.is_ipv4() {
                &mut plan.ipv4
            } else {
                &mut plan.ipv6
            };
            let base = |direction: &str, rest: &[&str]| {
                let mut rule: Vec<String> =
                    ["-t", BLOCK_TABLE, "-A", BLOCK_CHAIN, direction, route]
                        .iter()
                        .map(|part| part.to_string())
                        .collect();
                rule.extend(rest.iter().map(|part| part.to_string()));
                rule
            };
            if host {
                for direction in ["-s", "-d"] {
                    rules.push(base(
                        direction,
                        &["-p", "tcp", "--dport", &port, "-j", "RETURN"],
                    ));
                    rules.push(base(
                        direction,
                        &[
                            "-p",
                            "tcp",
                            "--sport",
                            &port,
                            "-m",
                            "conntrack",
                            "--ctstate",
                            "ESTABLISHED",
                            "-j",
                            "RETURN",
                        ],
                    ));
                }
            }
            rules.push(base("-s", &["-j", "DROP"]));
            rules.push(base("-d", &["-j", "DROP"]));
        }
    }
    plan
}

/// macOS: boringtun's UAPI socket. The PSK map is shared with
/// `MacOsNetwork`, which rewrites every peer with `replace_peers=true` and
/// must re-send each key or it would silently fall back to no PSK.
pub struct UapiDevice {
    pub socket: PathBuf,
    pub keys: Arc<Mutex<HashMap<String, Psk>>>,
}

impl UapiDevice {
    fn request(&self, request: &str) -> Result<String, Error> {
        use std::io::{Read as _, Write as _};
        let mut stream = std::os::unix::net::UnixStream::connect(&self.socket).map_err(|e| {
            Error::Message(format!(
                "connect WireGuard UAPI {}: {e}",
                self.socket.display()
            ))
        })?;
        stream
            .write_all(request.as_bytes())
            .and_then(|_| stream.shutdown(std::net::Shutdown::Write))?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        if !response.contains("errno=0") {
            return Err(Error::Message("WireGuard UAPI rejected the request".into()));
        }
        Ok(response)
    }
}

impl PskDevice for UapiDevice {
    fn set_psk(&self, peer_key_b64: &str, psk: Option<&Psk>) -> Result<(), Error> {
        let hex = crate::peer_key_hex(peer_key_b64)
            .ok_or_else(|| Error::Message("peer key is not valid base64".into()))?;
        let value = match psk {
            Some(psk) => psk.to_hex(),
            None => Zeroizing::new("0".repeat(64)),
        };
        let request = Zeroizing::new(format!(
            "set=1\npublic_key={hex}\npreshared_key={}\n\n",
            value.as_str()
        ));
        self.request(&request)?;
        let mut keys = self.keys.lock().unwrap_or_else(|p| p.into_inner());
        match psk {
            Some(psk) => keys.insert(peer_key_b64.trim().to_string(), psk.clone()),
            None => keys.remove(peer_key_b64.trim()),
        };
        Ok(())
    }

    fn latest_handshakes(&self) -> Result<HashMap<String, u64>, Error> {
        let response = self.request("get=1\n\n")?;
        let mut map = HashMap::new();
        let mut current: Option<String> = None;
        for line in response.lines() {
            match line.split_once('=') {
                Some(("public_key", value)) => current = Some(value.trim().to_string()),
                Some(("last_handshake_time_sec", value)) => {
                    if let Some(key) = &current {
                        map.insert(key.clone(), value.trim().parse().unwrap_or(0));
                    }
                }
                _ => {}
            }
        }
        Ok(map)
    }

    fn set_blocked(&self, _blocked: &[PeerPlan]) -> Result<bool, Error> {
        Ok(false)
    }

    fn enforces_blocks(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Persistence: keys live beside the WireGuard private key (0600) so a daemon
// restart does not leave the pair mismatched until the stale timer fires.

#[derive(Default, Deserialize, Serialize)]
struct Persisted {
    #[serde(default)]
    peers: BTreeMap<String, PersistedPeer>,
}

#[derive(Deserialize, Serialize)]
struct PersistedPeer {
    last_epoch: u64,
    #[serde(default)]
    epoch: u64,
    #[serde(default)]
    at: u64,
    #[serde(default)]
    psk: Option<String>,
}

impl Drop for PersistedPeer {
    fn drop(&mut self) {
        if let Some(psk) = self.psk.as_mut() {
            zeroize::Zeroize::zeroize(psk);
        }
    }
}

fn load_tracks(dir: &Path, now: u64) -> HashMap<String, Track> {
    let Ok(bytes) = std::fs::read(dir.join(STATE_FILE)) else {
        return HashMap::new();
    };
    let bytes = Zeroizing::new(bytes);
    let Ok(persisted) = serde_json::from_slice::<Persisted>(&bytes) else {
        return HashMap::new();
    };
    persisted
        .peers
        .iter()
        .map(|(key, peer)| {
            let installed = peer
                .psk
                .as_deref()
                .and_then(decode_key)
                .filter(|_| now.saturating_sub(peer.at) <= PSK_LIFETIME_SECS)
                .map(|bytes| Installed {
                    epoch: peer.epoch,
                    at: peer.at,
                    applied_at: now,
                    psk: Psk::from_bytes(bytes),
                });
            (
                key.clone(),
                Track {
                    last_epoch: peer.last_epoch,
                    installed,
                    ..Track::default()
                },
            )
        })
        .collect()
}

fn save_tracks(dir: &Path, tracks: &HashMap<String, Track>) -> Result<(), Error> {
    let persisted = Persisted {
        peers: tracks
            .iter()
            .map(|(key, track)| {
                (
                    key.clone(),
                    PersistedPeer {
                        last_epoch: track.last_epoch,
                        epoch: track.installed.as_ref().map_or(0, |i| i.epoch),
                        at: track.installed.as_ref().map_or(0, |i| i.at),
                        psk: track
                            .installed
                            .as_ref()
                            .map(|i| i.psk.to_base64().as_str().to_owned()),
                    },
                )
            })
            .collect(),
    };
    let bytes = Zeroizing::new(serde_json::to_vec(&persisted)?);
    crate::write_secret(&dir.join(STATE_FILE), &bytes)
}

// ---------------------------------------------------------------------------
// Runtime

struct Shared {
    own: [u8; 32],
    /// This node's WireGuard private key, for [`static_agreement`].
    secret: Option<StaticSecret>,
    local_capable: bool,
    plans: BTreeMap<String, PeerPlan>,
    tracks: HashMap<String, Track>,
    dir: PathBuf,
    port: u16,
    block_enforced: bool,
    applied_blocks: Option<Vec<PeerPlan>>,
}

impl Shared {
    fn persist(&self) {
        if let Err(error) = save_tracks(&self.dir, &self.tracks) {
            tracing::warn!(%error, "could not persist post-quantum key state");
        }
    }

    /// Recomputes per-peer reports and (re)applies pair blocks when the
    /// blocked set changed. Called after every peer map and driver tick.
    fn refresh(&mut self, device: Option<&dyn PskDevice>, now: u64) -> Vec<PeerReport> {
        let reports: Vec<PeerReport> = self
            .plans
            .values()
            .map(|plan| {
                evaluate(
                    plan,
                    self.tracks.get(&plan.key),
                    self.local_capable,
                    self.block_enforced,
                    now,
                )
            })
            .collect();
        let blocked: Vec<PeerPlan> = self
            .plans
            .values()
            .zip(&reports)
            .filter(|(plan, report)| report.state == "required_not_established" && plan.pq.block)
            .map(|(plan, _)| plan.clone())
            .collect();
        if self.applied_blocks.as_ref() != Some(&blocked) {
            if let Some(device) = device {
                match device.set_blocked(&blocked) {
                    Ok(_) => self.applied_blocks = Some(blocked),
                    Err(error) => {
                        tracing::warn!(%error, "could not apply post-quantum pair blocks");
                    }
                }
            }
        }
        reports
    }
}

/// Runs the exchange listener and rotation driver and installs keys. The
/// sync loop calls [`PqRuntime::manage`] with every applied peer map.
pub struct PqRuntime {
    shared: Arc<Mutex<Shared>>,
    device: Option<Arc<dyn PskDevice>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    listen: Option<SocketAddr>,
    known_keys: BTreeSet<String>,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn lock(shared: &Mutex<Shared>) -> std::sync::MutexGuard<'_, Shared> {
    shared.lock().unwrap_or_else(|p| p.into_inner())
}

impl PqRuntime {
    /// `private_key` is this node's WireGuard private key; without it the
    /// node does not take part.
    pub fn new(
        private_key: Option<StaticSecret>,
        dir: &Path,
        device: Option<Arc<dyn PskDevice>>,
    ) -> Self {
        Self::with_options(private_key, dir, device, locally_capable(), PORT)
    }

    pub fn with_options(
        private_key: Option<StaticSecret>,
        dir: &Path,
        device: Option<Arc<dyn PskDevice>>,
        local_capable: bool,
        port: u16,
    ) -> Self {
        let tracks = load_tracks(dir, unix_now());
        Self {
            shared: Arc::new(Mutex::new(Shared {
                own: private_key
                    .as_ref()
                    .map_or([0; 32], |secret| PublicKey::from(secret).to_bytes()),
                local_capable: local_capable && device.is_some() && private_key.is_some(),
                secret: private_key,
                plans: BTreeMap::new(),
                tracks,
                dir: dir.to_path_buf(),
                port,
                block_enforced: device.as_ref().is_some_and(|d| d.enforces_blocks()),
                applied_blocks: None,
            })),
            device,
            tasks: Vec::new(),
            listen: None,
            known_keys: BTreeSet::new(),
        }
    }

    /// Whether to advertise [`CAPABILITY`].
    pub fn capable(&self) -> bool {
        lock(&self.shared).local_capable
    }

    /// Reconciles the peer set, (re)starts the listener on `listen_ip`,
    /// re-installs known keys for peers that reappeared, applies blocks and
    /// returns the per-peer report.
    pub fn manage(&mut self, peers: &[Peer], listen_ip: Option<IpAddr>) -> Vec<PeerReport> {
        let now = unix_now();
        let plans: BTreeMap<String, PeerPlan> = peers
            .iter()
            .filter_map(PeerPlan::from_peer)
            .map(|plan| (plan.key.clone(), plan))
            .collect();
        let (active, port) = {
            let mut shared = lock(&self.shared);
            let local_capable = shared.local_capable;
            // Policy turned off for a pair that had a key: clear it.
            let cleared: Vec<String> = shared
                .tracks
                .iter()
                .filter(|(key, track)| {
                    track.installed.is_some()
                        && !plans
                            .get(*key)
                            .is_some_and(|plan| plan.wants_exchange(local_capable))
                })
                .map(|(key, _)| key.clone())
                .collect();
            for key in &cleared {
                if let Some(track) = shared.tracks.get_mut(key) {
                    track.installed = None;
                }
                if plans.contains_key(key) {
                    if let Some(device) = &self.device {
                        let _ = device.set_psk(key, None);
                    }
                }
            }
            shared.tracks.retain(|key, _| plans.contains_key(key));
            shared.plans = plans.clone();
            if !cleared.is_empty() {
                shared.persist();
            }
            let active = plans
                .values()
                .any(|plan| plan.wants_exchange(local_capable));
            (active, shared.port)
        };
        // Peers newly (re)added to WireGuard lost any PSK: reinstall ours.
        if let Some(device) = &self.device {
            let mut shared = lock(&self.shared);
            for (key, track) in shared.tracks.iter_mut() {
                if self.known_keys.contains(key) {
                    continue;
                }
                if let Some(installed) = track.installed.as_mut() {
                    match device.set_psk(key, Some(&installed.psk)) {
                        Ok(()) => installed.applied_at = now,
                        Err(error) => {
                            tracing::warn!(%error, "could not reinstall post-quantum PSK")
                        }
                    }
                }
            }
        }
        self.known_keys = plans.keys().cloned().collect();
        let listen = listen_ip.map(|ip| SocketAddr::new(ip, port));
        if active && (self.tasks.is_empty() || self.listen != listen) {
            self.stop();
            if let Some(device) = &self.device {
                self.listen = listen;
                if let Some(listen) = listen {
                    self.tasks.push(tokio::spawn(serve(
                        self.shared.clone(),
                        device.clone(),
                        listen,
                    )));
                }
                self.tasks
                    .push(tokio::spawn(drive(self.shared.clone(), device.clone())));
            }
        } else if !active && !self.tasks.is_empty() {
            self.stop();
        }
        lock(&self.shared).refresh(self.device.as_deref(), now)
    }

    /// Current per-peer report (also re-applies blocks if they drifted).
    pub fn reports(&self) -> Vec<PeerReport> {
        lock(&self.shared).refresh(self.device.as_deref(), unix_now())
    }

    pub fn stop(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
        self.listen = None;
    }

    /// Removes blocks (for `down`/`pause` paths that keep the process).
    pub fn clear(&mut self) {
        self.stop();
        if let Some(device) = &self.device {
            let _ = device.set_blocked(&[]);
        }
        lock(&self.shared).applied_blocks = None;
    }

    /// Test hook: the installed key for a peer.
    pub fn installed(&self, peer_key: &str) -> Option<(u64, Psk)> {
        lock(&self.shared)
            .tracks
            .get(peer_key)
            .and_then(|track| track.installed.as_ref())
            .map(|installed| (installed.epoch, installed.psk.clone()))
    }
}

impl Drop for PqRuntime {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn bind_listener(
    addr: SocketAddr,
    device: Option<String>,
) -> std::io::Result<tokio::net::TcpListener> {
    let socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    #[cfg(target_os = "linux")]
    if let Some(device) = device {
        // Only connections that arrived through the WireGuard interface,
        // i.e. authenticated by a WireGuard session, reach the listener.
        socket.bind_device(Some(device.as_bytes()))?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = device;
    socket.bind(addr)?;
    socket.listen(16)
}

async fn serve(shared: Arc<Mutex<Shared>>, device: Arc<dyn PskDevice>, addr: SocketAddr) {
    let listener = loop {
        match bind_listener(addr, device.bind_device()).await {
            Ok(listener) => break listener,
            Err(error) => {
                tracing::warn!(%error, %addr, "post-quantum exchange listener unavailable; retrying");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };
    loop {
        let Ok((stream, from)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };
        let shared = shared.clone();
        let device = device.clone();
        tokio::spawn(async move {
            match tokio::time::timeout(EXCHANGE_TIMEOUT, accept_one(shared, device, stream, from))
                .await
            {
                Ok(Ok(epoch)) => tracing::info!(epoch, "post-quantum PSK installed (responder)"),
                Ok(Err(error)) => tracing::warn!(%error, %from, "post-quantum exchange refused"),
                Err(_) => tracing::warn!(%from, "post-quantum exchange timed out"),
            }
        });
    }
}

async fn accept_one(
    shared: Arc<Mutex<Shared>>,
    device: Arc<dyn PskDevice>,
    stream: tokio::net::TcpStream,
    from: SocketAddr,
) -> Result<u64, PqError> {
    let context = {
        let shared = lock(&shared);
        let plan = shared
            .plans
            .values()
            .find(|plan| plan.hosts.contains(&from.ip()))
            .filter(|plan| plan.wants_exchange(shared.local_capable))
            .ok_or(PqError::WrongPeer)?;
        ResponderContext {
            own: shared.own,
            peer: plan.raw_key,
            static_secret: static_agreement(
                shared.secret.as_ref().ok_or(PqError::WrongPeer)?,
                &plan.raw_key,
            )?,
            last_epoch: shared.tracks.get(&plan.key).map_or(0, |t| t.last_epoch),
        }
    };
    let peer_key = STANDARD.encode(context.peer);
    let install_shared = shared.clone();
    let install_key = peer_key.clone();
    let (epoch, _) = run_responder(stream, context, move |epoch, psk| {
        device
            .set_psk(&install_key, Some(psk))
            .map_err(|error| error.to_string())?;
        let mut shared = lock(&install_shared);
        let track = shared.tracks.entry(install_key.clone()).or_default();
        track.last_epoch = track.last_epoch.max(epoch);
        track.installed = Some(Installed {
            epoch,
            at: unix_now(),
            applied_at: unix_now(),
            psk: psk.clone(),
        });
        track.last_error = None;
        shared.persist();
        Ok(())
    })
    .await?;
    Ok(epoch)
}

/// Rotation driver: initiates for peers where this side holds the lower key,
/// and reverts to no PSK when a pair stops handshaking (diverged keys).
async fn drive(shared: Arc<Mutex<Shared>>, device: Arc<dyn PskDevice>) {
    loop {
        tokio::time::sleep(TICK).await;
        let now = unix_now();
        let handshakes = device.latest_handshakes().unwrap_or_default();
        let (jobs, own, port) = {
            let mut guard = lock(&shared);
            let shared = &mut *guard;
            let mut reverted = false;
            for (key, track) in shared.tracks.iter_mut() {
                let Some(installed) = &track.installed else {
                    continue;
                };
                let last = crate::peer_key_hex(key)
                    .and_then(|hex| handshakes.get(&hex).copied())
                    .unwrap_or(0);
                if now.saturating_sub(last.max(installed.applied_at)) > STALE_REVERT_SECS {
                    tracing::warn!(
                        "post-quantum pair stopped handshaking; clearing PSK to re-exchange"
                    );
                    let _ = device.set_psk(key, None);
                    track.installed = None;
                    reverted = true;
                }
            }
            if reverted {
                shared.persist();
            }
            let mut jobs = Vec::new();
            let local_capable = shared.local_capable;
            let own = shared.own;
            for plan in shared.plans.values() {
                if !plan.wants_exchange(local_capable) || own >= plan.raw_key {
                    continue;
                }
                let Some(host) = plan
                    .hosts
                    .iter()
                    .find(|ip| ip.is_ipv4())
                    .or(plan.hosts.first())
                else {
                    continue;
                };
                let track = shared.tracks.entry(plan.key.clone()).or_default();
                let due = track
                    .installed
                    .as_ref()
                    .is_none_or(|installed| now.saturating_sub(installed.at) >= ROTATE_SECS);
                if due && now.saturating_sub(track.last_attempt_at) >= RETRY_SECS {
                    track.last_attempt_at = now;
                    let Some(Ok(static_secret)) = shared
                        .secret
                        .as_ref()
                        .map(|secret| static_agreement(secret, &plan.raw_key))
                    else {
                        track.last_error = Some(PqError::WeakDh.to_string());
                        continue;
                    };
                    jobs.push((
                        plan.key.clone(),
                        plan.raw_key,
                        *host,
                        track.last_epoch + 1,
                        static_secret,
                    ));
                }
            }
            shared.refresh(Some(device.as_ref()), now);
            (jobs, own, shared.port)
        };
        for (key, peer, host, epoch, static_secret) in jobs {
            let shared = shared.clone();
            let device = device.clone();
            tokio::spawn(async move {
                let outcome = tokio::time::timeout(EXCHANGE_TIMEOUT, async {
                    let stream =
                        tokio::net::TcpStream::connect(SocketAddr::new(host, port)).await?;
                    run_initiator(stream, &own, &peer, &static_secret, epoch).await
                })
                .await
                .unwrap_or(Err(PqError::Timeout));
                record_initiator_outcome(&shared, device.as_ref(), &key, outcome);
            });
        }
    }
}

fn record_initiator_outcome(
    shared: &Mutex<Shared>,
    device: &dyn PskDevice,
    key: &str,
    outcome: Result<(u64, Psk), PqError>,
) {
    let mut shared = lock(shared);
    match outcome {
        Ok((epoch, psk)) => {
            if let Err(error) = device.set_psk(key, Some(&psk)) {
                tracing::warn!(%error, "could not install post-quantum PSK");
                return;
            }
            let track = shared.tracks.entry(key.to_string()).or_default();
            track.last_epoch = track.last_epoch.max(epoch);
            track.installed = Some(Installed {
                epoch,
                at: unix_now(),
                applied_at: unix_now(),
                psk,
            });
            track.last_error = None;
            shared.persist();
            tracing::info!(epoch, "post-quantum PSK installed (initiator)");
        }
        Err(error) => {
            let track = shared.tracks.entry(key.to_string()).or_default();
            if let PqError::Rejected { last_epoch, .. } = &error {
                // The responder remembers a newer epoch (we restarted without
                // state): move past it and retry on the next tick.
                track.last_epoch = track.last_epoch.max(*last_epoch);
                track.last_attempt_at = 0;
            }
            track.last_error = Some(error.to_string());
            tracing::warn!(%error, "post-quantum exchange failed; keeping the last good PSK");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stand-in static agreement for protocol tests on fixed keys.
    const STATIC: [u8; 32] = [5u8; 32];

    /// Two WireGuard key pairs, the lower public key first.
    fn ordered_secrets() -> (StaticSecret, StaticSecret) {
        let one = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let two = StaticSecret::random_from_rng(rand::rngs::OsRng);
        if PublicKey::from(&one).to_bytes() < PublicKey::from(&two).to_bytes() {
            (one, two)
        } else {
            (two, one)
        }
    }

    #[test]
    fn exchange_without_the_wireguard_private_key_fails() {
        let (low_secret, high_secret) = ordered_secrets();
        let low = PublicKey::from(&low_secret).to_bytes();
        let high = PublicKey::from(&high_secret).to_bytes();
        let ours = static_agreement(&low_secret, &high).unwrap();
        assert_eq!(*ours, *static_agreement(&high_secret, &low).unwrap());

        // A squatter on the responder's listener holds some other key: its
        // confirmation does not verify and the initiator installs nothing.
        let squatter = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let forged = static_agreement(&squatter, &low).unwrap();
        let (initiator, init) = initiate(&low, &high, &ours, 1).unwrap();
        let (_, resp) = respond(&high, &low, &forged, 0, &init).unwrap();
        assert_eq!(initiator.finish(&resp).err(), Some(PqError::Confirmation));

        // A squatting initiator is refused by the genuine responder.
        let (impostor, init) = initiate(&low, &high, &forged, 1).unwrap();
        let (responder, resp) = respond(&high, &low, &ours, 0, &init).unwrap();
        assert_eq!(impostor.finish(&resp).err(), Some(PqError::Confirmation));
        let (impostor, init) = initiate(&low, &high, &forged, 2).unwrap();
        let (genuine, _) = respond(&high, &low, &ours, 0, &init).unwrap();
        drop(responder);
        let forged_confirm = Message::Confirm {
            v: VERSION,
            epoch: 2,
            confirm: STANDARD.encode([0u8; 32]),
        };
        assert_eq!(
            genuine.finish(&forged_confirm).err(),
            Some(PqError::Confirmation)
        );
        drop(impostor);

        // The genuine keys agree.
        let (initiator, init) = initiate(&low, &high, &ours, 1).unwrap();
        let (responder, resp) = respond(&high, &low, &ours, 0, &init).unwrap();
        let (psk, confirm) = initiator.finish(&resp).unwrap();
        assert_eq!(responder.finish(&confirm).unwrap(), psk);
        // A low-order peer key gives no agreement at all.
        assert_eq!(
            static_agreement(&low_secret, &[0u8; 32]).err(),
            Some(PqError::WeakDh)
        );
    }

    fn key(byte: u8) -> [u8; 32] {
        let mut key = [byte; 32];
        key[0] = byte;
        key
    }

    #[test]
    fn transcript_binds_both_wireguard_keys_and_epoch() {
        let (a, b) = (key(1), key(2));
        let parts = (
            vec![3u8; 32],
            vec![4u8; 1184],
            vec![5u8; 32],
            vec![6u8; 1088],
        );
        let th = |epoch, i: &[u8; 32], r: &[u8; 32]| {
            transcript(epoch, i, r, &parts.0, &parts.1, &parts.2, &parts.3)
        };
        let (kem, dh, st) = ([7u8; 32], [8u8; 32], [6u8; 32]);
        let (psk, _) = derive(&kem, &dh, &st, &th(1, &a, &b));
        let (swapped, _) = derive(&kem, &dh, &st, &th(1, &b, &a));
        let (next_epoch, _) = derive(&kem, &dh, &st, &th(2, &a, &b));
        assert_ne!(psk, swapped, "swapping WireGuard keys must change the PSK");
        assert_ne!(psk, next_epoch, "the epoch must change the PSK");
        // Each shared secret contributes.
        assert_ne!(psk, derive(&[9u8; 32], &dh, &st, &th(1, &a, &b)).0);
        assert_ne!(psk, derive(&kem, &[9u8; 32], &st, &th(1, &a, &b)).0);
        assert_ne!(psk, derive(&kem, &dh, &[9u8; 32], &th(1, &a, &b)).0);
        assert!(!psk.is_zero());
        assert_eq!(format!("{psk:?}"), "Psk(<redacted>)");
    }

    #[test]
    fn both_sides_agree_and_confirm() {
        let (low, high) = (key(1), key(2));
        let (initiator, init) = initiate(&low, &high, &STATIC, 1).unwrap();
        let (responder, resp) = respond(&high, &low, &STATIC, 0, &init).unwrap();
        let (initiator_psk, confirm) = initiator.finish(&resp).unwrap();
        let responder_psk = responder.finish(&confirm).unwrap();
        assert_eq!(initiator_psk, responder_psk);
        assert!(!initiator_psk.is_zero());
    }

    #[test]
    fn replayed_or_old_epoch_init_is_rejected() {
        let (low, high) = (key(1), key(2));
        let (_, init) = initiate(&low, &high, &STATIC, 5).unwrap();
        assert!(matches!(
            respond(&high, &low, &STATIC, 5, &init),
            Err(PqError::StaleEpoch { epoch: 5, last: 5 })
        ));
        assert!(matches!(
            respond(&high, &low, &STATIC, 9, &init),
            Err(PqError::StaleEpoch { .. })
        ));
        assert!(respond(&high, &low, &STATIC, 4, &init).is_ok());
    }

    #[test]
    fn wrong_keys_role_and_tampering_are_refused() {
        let (low, high, other) = (key(1), key(2), key(3));
        assert_eq!(
            initiate(&high, &low, &STATIC, 1).err(),
            Some(PqError::WrongRole)
        );
        let (_, init) = initiate(&low, &high, &STATIC, 1).unwrap();
        // Init names `high` as responder; another node must refuse it.
        assert_eq!(
            respond(&other, &low, &STATIC, 0, &init).err(),
            Some(PqError::WrongPeer)
        );
        let (initiator, init) = initiate(&low, &high, &STATIC, 1).unwrap();
        let (_, resp) = respond(&high, &low, &STATIC, 0, &init).unwrap();
        let Message::Resp {
            v,
            epoch,
            x25519,
            mlkem_ct,
            ..
        } = resp
        else {
            panic!("expected resp");
        };
        let forged = Message::Resp {
            v,
            epoch,
            x25519,
            mlkem_ct,
            confirm: STANDARD.encode([0u8; 32]),
        };
        assert_eq!(initiator.finish(&forged).err(), Some(PqError::Confirmation));
    }

    fn plan(pq: PeerPq) -> PeerPlan {
        PeerPlan {
            id: Uuid::nil(),
            key: STANDARD.encode(key(2)),
            raw_key: key(2),
            pq,
            hosts: vec!["100.64.0.2".parse().unwrap()],
            routes: vec![
                "100.64.0.2/32".into(),
                "10.9.0.0/24".into(),
                "0.0.0.0/0".into(),
            ],
        }
    }

    #[test]
    fn downgrade_is_reported_and_blocked_never_silent() {
        let require = PeerPq {
            mode: Mode::Require,
            capable: false,
            block: true,
        };
        let report = evaluate(&plan(require.clone()), None, true, true, 1_000);
        assert_eq!(report.state, "required_not_established");
        assert_eq!(report.reason, "peer_not_capable");
        assert!(report.blocked);
        assert!(report.algorithm.is_empty());
        // Same pair, but this platform cannot enforce the block: say so.
        let report = evaluate(&plan(require.clone()), None, true, false, 1_000);
        assert!(!report.blocked);
        assert_eq!(report.reason, "block_not_supported_here");
        // Local side not capable under require is never shown as protected.
        let report = evaluate(
            &plan(PeerPq {
                capable: true,
                ..require
            }),
            None,
            false,
            true,
            1_000,
        );
        assert_eq!(report.state, "required_not_established");
        // Prefer with an incapable peer is plainly classical.
        let report = evaluate(
            &plan(PeerPq {
                mode: Mode::Prefer,
                capable: false,
                block: true,
            }),
            None,
            true,
            true,
            1_000,
        );
        assert_eq!(report.state, "classical");
        assert!(!report.blocked);
    }

    #[test]
    fn expired_key_degrades_and_fails_closed_under_require() {
        let installed = Track {
            last_epoch: 3,
            installed: Some(Installed {
                epoch: 3,
                at: 1_000,
                applied_at: 1_000,
                psk: Psk::from_bytes([1; 32]),
            }),
            ..Track::default()
        };
        let mut prefer = plan(PeerPq {
            mode: Mode::Prefer,
            capable: true,
            block: true,
        });
        let fresh = evaluate(&prefer, Some(&installed), true, true, 1_100);
        assert_eq!(fresh.state, "established");
        assert_eq!(fresh.algorithm, ALGORITHM);
        assert_eq!((fresh.epoch, fresh.last_rotation_at), (3, Some(1_000)));
        let stale = evaluate(
            &prefer,
            Some(&installed),
            true,
            true,
            1_000 + PSK_LIFETIME_SECS + 1,
        );
        assert_eq!(stale.state, "degraded");
        assert!(!stale.blocked);
        prefer.pq.mode = Mode::Require;
        let stale = evaluate(
            &prefer,
            Some(&installed),
            true,
            true,
            1_000 + PSK_LIFETIME_SECS + 1,
        );
        assert_eq!(stale.state, "required_not_established");
        assert_eq!(stale.reason, "rotation_failed");
        assert!(stale.blocked);
    }

    #[test]
    fn block_rules_keep_only_the_exchange_port_and_skip_default_routes() {
        let rules = block_rules(&[plan(PeerPq::default())]);
        let flat: Vec<String> = rules.ipv4.iter().map(|rule| rule.join(" ")).collect();
        let returns: Vec<&String> = flat
            .iter()
            .filter(|rule| rule.ends_with("RETURN"))
            .collect();
        // Inbound: new connections only to our listener; from the peer's
        // listener port only replies. Outbound mirrors it.
        assert_eq!(
            returns,
            [
                "-t mangle -A BLAKTAIL-PQ -s 100.64.0.2/32 -p tcp --dport 51822 -j RETURN",
                "-t mangle -A BLAKTAIL-PQ -s 100.64.0.2/32 -p tcp --sport 51822 -m conntrack --ctstate ESTABLISHED -j RETURN",
                "-t mangle -A BLAKTAIL-PQ -d 100.64.0.2/32 -p tcp --dport 51822 -j RETURN",
                "-t mangle -A BLAKTAIL-PQ -d 100.64.0.2/32 -p tcp --sport 51822 -m conntrack --ctstate ESTABLISHED -j RETURN",
            ]
        );
        // No rule lets a bare source or destination port through
        // regardless of state (e.g. sport 51822 to any local port).
        assert!(!flat
            .iter()
            .any(|rule| rule.contains("--sport") && !rule.contains("ESTABLISHED")));
        assert!(flat.contains(&"-t mangle -A BLAKTAIL-PQ -d 100.64.0.2/32 -j DROP".to_string()));
        assert!(flat.contains(&"-t mangle -A BLAKTAIL-PQ -s 10.9.0.0/24 -j DROP".to_string()));
        assert!(!flat.iter().any(|rule| rule.contains("0.0.0.0/0")));
        assert!(!flat
            .iter()
            .any(|rule| rule.contains("10.9.0.0/24") && rule.contains("RETURN")));
        assert!(rules.ipv6.is_empty());
    }

    #[derive(Default)]
    struct FakeDevice {
        keys: Mutex<HashMap<String, Psk>>,
        blocked: Mutex<Vec<Vec<Uuid>>>,
    }

    impl PskDevice for FakeDevice {
        fn set_psk(&self, peer: &str, psk: Option<&Psk>) -> Result<(), Error> {
            let mut keys = self.keys.lock().unwrap();
            match psk {
                Some(psk) => keys.insert(peer.to_string(), psk.clone()),
                None => keys.remove(peer),
            };
            Ok(())
        }
        fn latest_handshakes(&self) -> Result<HashMap<String, u64>, Error> {
            // Every pair is handshaking: never trip the stale revert.
            let keys = self.keys.lock().unwrap();
            Ok(keys
                .keys()
                .filter_map(|key| crate::peer_key_hex(key))
                .map(|hex| (hex, unix_now()))
                .collect())
        }
        fn set_blocked(&self, blocked: &[PeerPlan]) -> Result<bool, Error> {
            self.blocked
                .lock()
                .unwrap()
                .push(blocked.iter().map(|plan| plan.id).collect());
            Ok(true)
        }
        fn enforces_blocks(&self) -> bool {
            true
        }
    }

    fn overlay_peer(id: u128, raw: [u8; 32], pq: PeerPq) -> Peer {
        Peer {
            id: Uuid::from_u128(id),
            name: format!("peer-{id}"),
            wg_public_key: STANDARD.encode(raw),
            endpoint: None,
            allowed_ips: vec!["127.0.0.1/32".into()],
            dns_name: String::new(),
            tags: vec![],
            relay_endpoint: None,
            ingress: None,
            pq: Some(pq),
        }
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_agents_agree_on_a_psk_in_process() {
        let (low_secret, high_secret) = ordered_secrets();
        let low = PublicKey::from(&low_secret).to_bytes();
        let high = PublicKey::from(&high_secret).to_bytes();
        let port = free_port();
        let require = PeerPq {
            mode: Mode::Require,
            capable: true,
            block: true,
        };
        let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (dev_a, dev_b) = (
            Arc::new(FakeDevice::default()),
            Arc::new(FakeDevice::default()),
        );
        let mut a = PqRuntime::with_options(
            Some(low_secret),
            dir_a.path(),
            Some(dev_a.clone()),
            true,
            port,
        );
        let mut b = PqRuntime::with_options(
            Some(high_secret),
            dir_b.path(),
            Some(dev_b.clone()),
            true,
            port,
        );
        // B (higher key) listens; A (lower key) initiates. Both start
        // blocked: require, nothing established yet.
        let before_b = b.manage(
            &[overlay_peer(1, low, require.clone())],
            Some("127.0.0.1".parse().unwrap()),
        );
        let before_a = a.manage(&[overlay_peer(2, high, require.clone())], None);
        assert_eq!(before_a[0].state, "required_not_established");
        assert!(before_a[0].blocked && before_b[0].blocked);
        let a_key = STANDARD.encode(low);
        let b_key = STANDARD.encode(high);
        let mut agreed = None;
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if let (Some(on_a), Some(on_b)) = (a.installed(&b_key), b.installed(&a_key)) {
                agreed = Some((on_a, on_b));
                break;
            }
        }
        let ((epoch_a, psk_a), (epoch_b, psk_b)) = agreed.expect("exchange completed");
        assert_eq!((epoch_a, epoch_b), (1, 1));
        assert_eq!(psk_a, psk_b, "both sides derive the same PSK");
        assert!(!psk_a.is_zero());
        // What each fake WireGuard device received matches.
        assert_eq!(dev_a.keys.lock().unwrap().get(&b_key), Some(&psk_a));
        assert_eq!(dev_b.keys.lock().unwrap().get(&a_key), Some(&psk_b));
        let report = a.reports();
        assert_eq!(report[0].state, "established");
        assert_eq!(report[0].algorithm, ALGORITHM);
        assert!(!report[0].blocked);
        assert_eq!(
            dev_a.blocked.lock().unwrap().last().unwrap(),
            &Vec::<Uuid>::new()
        );
        // Persisted beside the private key with owner-only permissions.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir_a.path().join(STATE_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        // The peer turning the capability off downgrades loudly: A reports
        // not established and blocks B, and clears the key.
        let downgraded = a.manage(
            &[overlay_peer(
                2,
                high,
                PeerPq {
                    capable: false,
                    ..require
                },
            )],
            None,
        );
        assert_eq!(downgraded[0].state, "required_not_established");
        assert_eq!(downgraded[0].reason, "peer_not_capable");
        assert!(downgraded[0].blocked);
        assert_eq!(
            dev_a.blocked.lock().unwrap().last().unwrap(),
            &vec![Uuid::from_u128(2)]
        );
        assert!(dev_a.keys.lock().unwrap().get(&b_key).is_none());
    }

    #[tokio::test]
    async fn replayed_init_on_the_wire_gets_a_reject() {
        let (low, high) = (key(1), key(2));
        let (client, server) = tokio::io::duplex(16 * 1024);
        let responder = tokio::spawn(run_responder(
            server,
            ResponderContext {
                own: high,
                peer: low,
                static_secret: Zeroizing::new(STATIC),
                last_epoch: 0,
            },
            |_, _| Ok(()),
        ));
        let (epoch, psk) = run_initiator(client, &low, &high, &STATIC, 1)
            .await
            .unwrap();
        let (r_epoch, r_psk) = responder.await.unwrap().unwrap();
        assert_eq!((epoch, &psk), (r_epoch, &r_psk));
        // Replay epoch 1 (or older) against a responder that accepted it.
        let (state, init) = initiate(&low, &high, &STATIC, 1).unwrap();
        let (client, server) = tokio::io::duplex(16 * 1024);
        let responder = tokio::spawn(run_responder(
            server,
            ResponderContext {
                own: high,
                peer: low,
                static_secret: Zeroizing::new(STATIC),
                last_epoch: 1,
            },
            |_, _| panic!("a replay must never install a key"),
        ));
        let (read, mut write) = tokio::io::split(client);
        let mut read = tokio::io::BufReader::new(read);
        send(&mut write, &init).await.unwrap();
        let answer = recv(&mut read).await.unwrap();
        assert!(matches!(
            &answer,
            Message::Reject { reason, last_epoch: 1, .. } if reason == "stale_epoch"
        ));
        assert!(matches!(
            state.finish(&answer),
            Err(PqError::Rejected { last_epoch: 1, .. })
        ));
        assert!(matches!(
            responder.await.unwrap(),
            Err(PqError::StaleEpoch { epoch: 1, last: 1 })
        ));
    }

    #[test]
    fn reports_and_persisted_state_carry_no_key_material() {
        let report = PeerReport {
            peer_id: Uuid::nil(),
            state: "established".into(),
            mode: Mode::Require,
            algorithm: ALGORITHM.into(),
            epoch: 4,
            last_rotation_at: Some(1),
            blocked: false,
            reason: String::new(),
        };
        let json = serde_json::to_value(&report).unwrap();
        let keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            vec![
                "algorithm",
                "blocked",
                "epoch",
                "last_rotation_at",
                "mode",
                "peer_id",
                "reason",
                "state"
            ]
        );
    }

    #[test]
    fn handshake_parser_matches_wg_output() {
        let key = STANDARD.encode(key(2));
        let parsed = parse_handshakes(&format!("{key}\t1700000000\n"));
        assert_eq!(
            parsed.values().copied().collect::<Vec<_>>(),
            vec![1_700_000_000]
        );
    }
}
