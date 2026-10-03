//! SSH to the target over the overlay: pinned host key, certificate login.

use russh::{
    client,
    keys::{
        ssh_key::{self, private::Ed25519Keypair},
        Algorithm, Certificate, PrivateKey, PublicKey, PublicKeyOrCertificate,
    },
    Channel,
};
use std::{
    borrow::Cow,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SshError {
    /// The target presented a key other than the one its agent reported.
    #[error("the device's SSH host key does not match the key its agent reported")]
    HostKeyMismatch,
    #[error("could not reach the device: {0}")]
    Connect(String),
    #[error("the device refused the session certificate")]
    Auth,
    #[error("{0}")]
    Protocol(String),
}

/// A per-session key: generated in memory, never written anywhere.
pub struct SessionKey {
    pub private: Arc<PrivateKey>,
    pub public_openssh: String,
}

pub fn ephemeral_key() -> SessionKey {
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    let private = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
    seed.fill(0);
    let public_openssh = private
        .public_key()
        .to_openssh()
        .expect("encode Ed25519 public key");
    SessionKey {
        private: Arc::new(private),
        public_openssh,
    }
}

pub struct Verifier {
    expected: PublicKey,
    mismatch: Arc<AtomicBool>,
}

impl client::Handler for Verifier {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        presented: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let matches = presented.public_key().key_data() == self.expected.key_data();
        if !matches {
            self.mismatch.store(true, Ordering::SeqCst);
        }
        Ok(matches)
    }
}

pub struct Shell {
    pub handle: client::Handle<Verifier>,
    pub channel: Channel<client::Msg>,
}

pub struct Target<'a> {
    pub address: SocketAddr,
    /// OpenSSH Ed25519 public key reported by the target's agent.
    pub host_key: &'a str,
    pub user: &'a str,
}

/// Connects, proves the host key, logs in with the session certificate and
/// opens a PTY shell. Any host key other than the reported one fails closed
/// before authentication, so the certificate is never offered to it.
pub async fn open_shell(
    target: &Target<'_>,
    key: &SessionKey,
    certificate: &str,
    cols: u32,
    rows: u32,
) -> Result<Shell, SshError> {
    let expected = PublicKey::from_openssh(target.host_key)
        .map_err(|_| SshError::Protocol("the reported host key is malformed".into()))?;
    if expected.algorithm() != Algorithm::Ed25519 {
        return Err(SshError::Protocol(
            "the reported host key is not Ed25519".into(),
        ));
    }
    let certificate = Certificate::from_openssh(certificate)
        .map_err(|_| SshError::Protocol("the session certificate is malformed".into()))?;
    let mut config = client::Config {
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(30)),
        nodelay: true,
        ..Default::default()
    };
    // Only negotiate the algorithm we can pin, so a server with several host
    // keys cannot pick one the agent never reported.
    config.preferred.key = Cow::Owned(vec![Algorithm::Ed25519]);
    let mismatch = Arc::new(AtomicBool::new(false));
    let verifier = Verifier {
        expected,
        mismatch: mismatch.clone(),
    };
    let stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(target.address),
    )
    .await
    .map_err(|_| SshError::Connect("timed out".into()))?
    .map_err(|error| SshError::Connect(error.to_string()))?;
    let _ = stream.set_nodelay(true);
    let mut handle = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        client::connect_stream(Arc::new(config), stream, verifier),
    )
    .await
    {
        Ok(Ok(handle)) => handle,
        Ok(Err(error)) => {
            if mismatch.load(Ordering::SeqCst) {
                return Err(SshError::HostKeyMismatch);
            }
            return Err(SshError::Connect(error.to_string()));
        }
        Err(_) => return Err(SshError::Connect("SSH handshake timed out".into())),
    };
    if mismatch.load(Ordering::SeqCst) {
        return Err(SshError::HostKeyMismatch);
    }
    let auth = handle
        .authenticate_openssh_cert(target.user, key.private.clone(), certificate)
        .await
        .map_err(|error| SshError::Protocol(error.to_string()))?;
    if !auth.success() {
        return Err(SshError::Auth);
    }
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|error| SshError::Protocol(error.to_string()))?;
    channel
        .request_pty(false, "xterm-256color", cols, rows, 0, 0, &[])
        .await
        .map_err(|error| SshError::Protocol(error.to_string()))?;
    channel
        .request_shell(false)
        .await
        .map_err(|error| SshError::Protocol(error.to_string()))?;
    Ok(Shell { handle, channel })
}

/// Fingerprint for status messages; never the key material itself.
pub fn fingerprint(openssh: &str) -> Option<String> {
    ssh_key::PublicKey::from_openssh(openssh)
        .ok()
        .map(|key| key.fingerprint(ssh_key::HashAlg::Sha256).to_string())
}
