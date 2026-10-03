//! Private service serving (draft 10). When the operator opts a node in with
//! `--serve-services`, the agent fetches the services that target it,
//! generates each service key on this node, obtains 24-hour certificates by
//! CSR, and terminates TLS on the overlay address(es) only, proxying raw
//! bytes (HTTP/1.1 and WebSocket alike) to `127.0.0.1:<port>`. A source must
//! be on the coordinator-compiled allow list: unknown sources are dropped
//! before any TLS byte, and a known source asking for a service it may not
//! reach is dropped after reading SNI, before the handshake completes.
//! Service keys are written 0600 under the state directory and never logged.

use crate::{write_secret, Coordinator, Error, NodeState};
use rcgen::{CertificateParams, KeyPair};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    server::Acceptor,
    ServerConfig,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{watch, Semaphore},
    task::AbortHandle,
};
use tokio_rustls::LazyConfigAcceptor;
use uuid::Uuid;

pub const CAPABILITY: &str = "service-serving";
pub const DEFAULT_LISTEN_PORT: u16 = 443;
const SERVICES_DIR: &str = "services";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CONNECTIONS: usize = 256;

/// Coordinator-compiled sources that may reach one service (serving node only).
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServiceAccess {
    pub id: Uuid,
    pub fqdn: String,
    #[serde(default)]
    pub allowed_sources: Vec<String>,
}

/// A published service name this node's MagicDNS answers.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServiceRecord {
    pub name: String,
    #[serde(default)]
    pub addresses: Vec<String>,
}

/// One enabled service targeting this node, from `GET /v1/nodes/:id/services`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct AssignedService {
    pub id: Uuid,
    pub fqdn: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Deserialize)]
struct AssignedList {
    services: Vec<AssignedService>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct IssuedCertificate {
    pub certificate_pem: String,
    pub ca_pem: String,
    pub serial: String,
    pub not_after: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct HealthEntry {
    pub id: Uuid,
    pub listening: bool,
    pub healthy: bool,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServiceCa {
    pub namespace: String,
    pub cert_pem: String,
    pub fingerprint_sha256: String,
    pub not_after: i64,
}

/// What the serving runtime needs from the coordinator.
#[allow(async_fn_in_trait)]
pub trait ServiceApi {
    /// `Ok(None)` means the coordinator refused this node (revoked,
    /// suspended, expired): stop serving everything.
    async fn assigned_services(
        &self,
        state: &NodeState,
    ) -> Result<Option<Vec<AssignedService>>, Error>;
    async fn issue_certificate(
        &self,
        state: &NodeState,
        service: Uuid,
        csr_pem: &str,
    ) -> Result<IssuedCertificate, Error>;
    async fn report_service_health(
        &self,
        state: &NodeState,
        listen_port: u16,
        entries: &[HealthEntry],
    ) -> Result<(), Error>;
}

async fn api_error(response: reqwest::Response, what: &str) -> Error {
    let status = response.status();
    let message = response
        .json::<crate::ApiErrorResponse>()
        .await
        .map(|body| body.error)
        .unwrap_or_else(|_| format!("coordinator returned {status}"));
    Error::Message(format!("{what}: {message}"))
}

impl ServiceApi for Coordinator {
    async fn assigned_services(
        &self,
        state: &NodeState,
    ) -> Result<Option<Vec<AssignedService>>, Error> {
        let response = self
            .client
            .get(format!("{}/v1/nodes/{}/services", self.base, state.node_id))
            .bearer_auth(&state.node_token)
            .send()
            .await?;
        if matches!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
        ) {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(api_error(response, "service list rejected").await);
        }
        Ok(Some(response.json::<AssignedList>().await?.services))
    }

    async fn issue_certificate(
        &self,
        state: &NodeState,
        service: Uuid,
        csr_pem: &str,
    ) -> Result<IssuedCertificate, Error> {
        let response = self
            .client
            .post(format!(
                "{}/v1/nodes/{}/services/{service}/certificate",
                self.base, state.node_id
            ))
            .bearer_auth(&state.node_token)
            .json(&serde_json::json!({ "csr_pem": csr_pem }))
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(api_error(response, "certificate request rejected").await);
        }
        Ok(response.json().await?)
    }

    async fn report_service_health(
        &self,
        state: &NodeState,
        listen_port: u16,
        entries: &[HealthEntry],
    ) -> Result<(), Error> {
        let response = self
            .client
            .post(format!(
                "{}/v1/nodes/{}/services/health",
                self.base, state.node_id
            ))
            .bearer_auth(&state.node_token)
            .json(&serde_json::json!({ "listen_port": listen_port, "services": entries }))
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(api_error(response, "service health report rejected").await);
        }
        Ok(())
    }
}

impl Coordinator {
    /// The organisation's private service CA (public material only).
    pub async fn service_ca(&self, state: &NodeState) -> Result<ServiceCa, Error> {
        let response = self
            .client
            .get(format!(
                "{}/v1/nodes/{}/service-ca",
                self.base, state.node_id
            ))
            .bearer_auth(&state.node_token)
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(Error::Message(
                "this organisation has no private service CA yet (no service has been created)"
                    .into(),
            ));
        }
        if !response.status().is_success() {
            return Err(api_error(response, "service CA request rejected").await);
        }
        Ok(response.json().await?)
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// Renew once two thirds of the certificate's lifetime has passed.
pub fn renewal_due(issued_at: i64, not_after: i64, now: i64) -> bool {
    now >= issued_at + (not_after - issued_at).max(0) * 2 / 3
}

/// A fresh P-256 key generated on this node and a CSR naming only `fqdn`.
/// Returns (private key PEM, CSR PEM); only the CSR leaves the node.
pub fn new_key_and_csr(fqdn: &str) -> Result<(String, String), Error> {
    let key =
        KeyPair::generate().map_err(|_| Error::Message("service key generation failed".into()))?;
    let csr = CertificateParams::new(vec![fqdn.to_owned()])
        .and_then(|params| params.serialize_request(&key))
        .and_then(|request| request.pem())
        .map_err(|_| Error::Message(format!("could not build a CSR for {fqdn}")))?;
    Ok((key.serialize_pem(), csr))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredCertificate {
    fqdn: String,
    serial: String,
    issued_at: i64,
    not_after: i64,
}

/// A certificate this node holds for one service.
#[derive(Clone)]
struct Held {
    meta: StoredCertificate,
    certificate_pem: String,
    key_pem: String,
}

fn service_dir(state_dir: &Path) -> PathBuf {
    state_dir.join(SERVICES_DIR)
}

fn paths(state_dir: &Path, id: Uuid) -> (PathBuf, PathBuf, PathBuf) {
    let dir = service_dir(state_dir);
    (
        dir.join(format!("{id}.key")),
        dir.join(format!("{id}.crt")),
        dir.join(format!("{id}.json")),
    )
}

fn load_held(state_dir: &Path, id: Uuid) -> Option<Held> {
    let (key, cert, meta) = paths(state_dir, id);
    Some(Held {
        meta: serde_json::from_slice(&fs::read(meta).ok()?).ok()?,
        certificate_pem: fs::read_to_string(cert).ok()?,
        key_pem: fs::read_to_string(key).ok()?,
    })
}

fn save_held(state_dir: &Path, id: Uuid, held: &Held, ca_pem: &str) -> Result<(), Error> {
    let dir = service_dir(state_dir);
    fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    let (key, cert, meta) = paths(state_dir, id);
    write_secret(&key, held.key_pem.as_bytes())?;
    write_secret(&cert, held.certificate_pem.as_bytes())?;
    write_secret(&meta, &serde_json::to_vec(&held.meta)?)?;
    write_secret(&dir.join("ca.pem"), ca_pem.as_bytes())?;
    Ok(())
}

fn forget_held(state_dir: &Path, id: Uuid) {
    let (key, cert, meta) = paths(state_dir, id);
    for path in [key, cert, meta] {
        let _ = fs::remove_file(path);
    }
}

fn tls_config(held: &Held) -> Result<Arc<ServerConfig>, Error> {
    let chain = CertificateDer::pem_slice_iter(held.certificate_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::Message("issued certificate is not valid PEM".into()))?;
    let key = PrivateKeyDer::from_pem_slice(held.key_pem.as_bytes())
        .map_err(|_| Error::Message("stored service key is unreadable".into()))?;
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|error| Error::Message(format!("TLS setup failed: {error}")))?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(|error| {
                Error::Message(format!("certificate and key do not match: {error}"))
            })?;
    // Bytes are proxied unchanged, so offer only what a loopback HTTP/1.1
    // upstream speaks (WebSocket upgrades ride on it).
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Normalises IPv4-mapped IPv6 sources so allow-list matching is exact.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        other => other,
    }
}

struct Route {
    config: Arc<ServerConfig>,
    allowed: HashSet<IpAddr>,
    upstream: SocketAddr,
    not_after: i64,
    serial: String,
    /// Dropping the sender (route removed or replaced) ends live connections.
    closed: watch::Sender<()>,
}

type Table = Arc<RwLock<HashMap<String, Route>>>;

/// A route the current reconcile pass wants installed.
struct Desired {
    config: Arc<ServerConfig>,
    allowed: HashSet<IpAddr>,
    upstream: SocketAddr,
    not_after: i64,
    serial: String,
}

/// TLS listener bound to overlay addresses, routing by SNI.
pub struct ServiceListener {
    addrs: Vec<SocketAddr>,
    tasks: Vec<AbortHandle>,
}

impl ServiceListener {
    async fn bind(addrs: &[SocketAddr], table: Table) -> Result<Self, Error> {
        let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let mut tasks = Vec::new();
        let mut bound = Vec::new();
        for addr in addrs {
            let listener = match TcpListener::bind(addr).await {
                Ok(listener) => listener,
                Err(error) => {
                    for task in &tasks {
                        AbortHandle::abort(task);
                    }
                    return Err(Error::Message(format!(
                        "could not bind service listener on {addr}: {error}"
                    )));
                }
            };
            bound.push(listener.local_addr()?);
            let table = table.clone();
            let limit = limit.clone();
            tasks.push(
                tokio::spawn(async move {
                    loop {
                        let Ok((stream, peer)) = listener.accept().await else {
                            continue;
                        };
                        let source = canonical_ip(peer.ip());
                        // Unknown sources are dropped before any TLS byte.
                        let known = table
                            .read()
                            .map(|routes| {
                                routes.values().any(|route| route.allowed.contains(&source))
                            })
                            .unwrap_or(false);
                        if !known {
                            drop(stream);
                            continue;
                        }
                        let Ok(permit) = limit.clone().try_acquire_owned() else {
                            drop(stream);
                            continue;
                        };
                        let table = table.clone();
                        tokio::spawn(async move {
                            serve_connection(stream, source, table).await;
                            drop(permit);
                        });
                    }
                })
                .abort_handle(),
            );
        }
        Ok(Self {
            addrs: bound,
            tasks,
        })
    }

    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    fn stop(&self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Drop for ServiceListener {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn serve_connection(stream: TcpStream, source: IpAddr, table: Table) {
    let Ok(Ok(start)) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        LazyConfigAcceptor::new(Acceptor::default(), stream),
    )
    .await
    else {
        return;
    };
    let Some(sni) = start
        .client_hello()
        .server_name()
        .map(|name| name.trim_end_matches('.').to_ascii_lowercase())
    else {
        return; // No SNI (for example a raw-IP request): no service to pick.
    };
    let picked = table.read().ok().and_then(|routes| {
        let route = routes.get(&sni)?;
        (route.allowed.contains(&source) && route.not_after > unix_now()).then(|| {
            (
                route.config.clone(),
                route.upstream,
                route.closed.subscribe(),
            )
        })
    });
    let Some((config, upstream, mut closed)) = picked else {
        return; // Unknown name, expired certificate or source not allowed.
    };
    let Ok(Ok(mut tls)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, start.into_stream(config)).await
    else {
        return;
    };
    let Ok(mut upstream) = TcpStream::connect(upstream).await else {
        let _ = tls
            .write_all(
                b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            )
            .await;
        let _ = tls.shutdown().await;
        return;
    };
    tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream) => {}
        _ = closed.changed() => {}
    }
}

/// Bounded local-target check: TCP connect, and for HTTP an answer that
/// starts like an HTTP response. Returns (healthy, detail).
pub async fn probe_target(port: u16, protocol: &str, fqdn: &str) -> (bool, String) {
    if protocol != "http" {
        return (
            false,
            format!("{protocol} upstreams are not served by this agent; use a plain HTTP upstream on loopback"),
        );
    }
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let attempt = async {
        let mut stream = TcpStream::connect(target).await?;
        stream
            .write_all(
                format!("HEAD / HTTP/1.1\r\nHost: {fqdn}\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await?;
        let mut head = [0u8; 5];
        stream.read_exact(&mut head).await?;
        Ok::<bool, std::io::Error>(&head == b"HTTP/")
    };
    match tokio::time::timeout(PROBE_TIMEOUT, attempt).await {
        Ok(Ok(true)) => (true, String::new()),
        Ok(Ok(false)) => (false, format!("127.0.0.1:{port} did not answer HTTP")),
        Ok(Err(error)) => (false, format!("127.0.0.1:{port}: {}", error.kind())),
        Err(_) => (false, format!("127.0.0.1:{port} timed out")),
    }
}

/// Overlay host addresses this node owns, on `port`.
pub fn overlay_bind_addrs(state: &NodeState, port: u16) -> Vec<SocketAddr> {
    state
        .interface_addresses()
        .iter()
        .filter_map(|address| address.split('/').next()?.parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, port))
        .collect()
}

#[derive(Default)]
pub struct ServiceRuntime {
    table: Table,
    listener: Option<ServiceListener>,
    held: BTreeMap<Uuid, Held>,
    last_error: HashMap<Uuid, String>,
}

impl ServiceRuntime {
    /// Number of services the listener currently routes.
    pub fn routed(&self) -> usize {
        self.table.read().map(|routes| routes.len()).unwrap_or(0)
    }

    pub fn listen_addrs(&self) -> Vec<SocketAddr> {
        self.listener
            .as_ref()
            .map(|listener| listener.addrs().to_vec())
            .unwrap_or_default()
    }

    /// Drops every route (ending live connections) and the listener.
    pub fn stop(&mut self) {
        if let Ok(mut routes) = self.table.write() {
            routes.clear();
        }
        self.listener = None;
    }

    fn forget_all(&mut self, state_dir: &Path) {
        for id in std::mem::take(&mut self.held).into_keys() {
            forget_held(state_dir, id);
        }
        self.stop();
    }

    /// One reconcile pass; call after every control update.
    pub async fn manage(&mut self, api: &impl ServiceApi, state: &NodeState, state_dir: &Path) {
        if !state.serve_services {
            if !self.held.is_empty() || self.listener.is_some() {
                self.forget_all(state_dir);
            }
            return;
        }
        let assigned = match api.assigned_services(state).await {
            Ok(Some(assigned)) => assigned,
            Ok(None) => {
                tracing::warn!("coordinator refused this node's service list; stopped serving");
                self.forget_all(state_dir);
                return;
            }
            Err(error) => {
                tracing::warn!(%error, "could not fetch assigned services; keeping current listener");
                self.drop_expired();
                return;
            }
        };
        let wanted: HashSet<Uuid> = assigned.iter().map(|service| service.id).collect();
        for id in self.held.keys().copied().collect::<Vec<_>>() {
            if !wanted.contains(&id) {
                self.held.remove(&id);
                forget_held(state_dir, id);
            }
        }
        let now = unix_now();
        for service in &assigned {
            self.ensure_certificate(api, state, state_dir, service, now)
                .await;
        }
        let access: HashMap<Uuid, &crate::services::ServiceAccess> = state
            .service_access
            .iter()
            .map(|entry| (entry.id, entry))
            .collect();
        let mut desired: HashMap<String, Desired> = HashMap::new();
        for service in &assigned {
            let Some(held) = self.held.get(&service.id) else {
                continue;
            };
            if held.meta.not_after <= now || service.protocol != "http" {
                continue;
            }
            let allowed = access
                .get(&service.id)
                .filter(|entry| entry.fqdn.eq_ignore_ascii_case(&service.fqdn))
                .map(|entry| {
                    entry
                        .allowed_sources
                        .iter()
                        .filter_map(|source| source.parse::<IpAddr>().ok().map(canonical_ip))
                        .collect()
                })
                .unwrap_or_default();
            match tls_config(held) {
                Ok(config) => {
                    desired.insert(
                        service.fqdn.to_ascii_lowercase(),
                        Desired {
                            config,
                            allowed,
                            upstream: SocketAddr::from((Ipv4Addr::LOCALHOST, service.port)),
                            not_after: held.meta.not_after,
                            serial: held.meta.serial.clone(),
                        },
                    );
                }
                Err(error) => {
                    tracing::warn!(service = %service.fqdn, %error, "service certificate unusable");
                }
            }
        }
        self.apply_routes(desired);
        self.ensure_listener(state).await;
        let listening = self.listener.is_some();
        let mut entries = Vec::with_capacity(assigned.len());
        for service in &assigned {
            let routed = self.table.read().ok().and_then(|routes| {
                routes
                    .get(&service.fqdn.to_ascii_lowercase())
                    .map(|route| route.serial.clone())
            });
            let (healthy, mut detail) =
                probe_target(service.port, &service.protocol, &service.fqdn).await;
            if routed.is_none() {
                if let Some(error) = self.last_error.get(&service.id) {
                    detail = error.clone();
                }
            }
            entries.push(HealthEntry {
                id: service.id,
                listening: listening && routed.is_some(),
                healthy,
                detail,
                serial: routed,
            });
        }
        if !entries.is_empty() {
            if let Err(error) = api
                .report_service_health(state, listen_port(state), &entries)
                .await
            {
                tracing::warn!(%error, "could not report service health");
            }
        }
    }

    async fn ensure_certificate(
        &mut self,
        api: &impl ServiceApi,
        state: &NodeState,
        state_dir: &Path,
        service: &AssignedService,
        now: i64,
    ) {
        if let std::collections::btree_map::Entry::Vacant(slot) = self.held.entry(service.id) {
            if let Some(held) = load_held(state_dir, service.id) {
                slot.insert(held);
            }
        }
        let due = match self.held.get(&service.id) {
            Some(held) => {
                !held.meta.fqdn.eq_ignore_ascii_case(&service.fqdn)
                    || renewal_due(held.meta.issued_at, held.meta.not_after, now)
            }
            None => true,
        };
        if !due {
            return;
        }
        let (key_pem, csr_pem) = match new_key_and_csr(&service.fqdn) {
            Ok(pair) => pair,
            Err(error) => {
                self.last_error.insert(service.id, error.to_string());
                return;
            }
        };
        match api.issue_certificate(state, service.id, &csr_pem).await {
            Ok(issued) => {
                let held = Held {
                    meta: StoredCertificate {
                        fqdn: service.fqdn.clone(),
                        serial: issued.serial.clone(),
                        issued_at: now,
                        not_after: issued.not_after,
                    },
                    certificate_pem: issued.certificate_pem,
                    key_pem,
                };
                if let Err(error) = save_held(state_dir, service.id, &held, &issued.ca_pem) {
                    tracing::warn!(service = %service.fqdn, %error, "could not store service certificate");
                }
                tracing::info!(service = %service.fqdn, serial = %held.meta.serial, not_after = held.meta.not_after, "service certificate issued");
                self.last_error.remove(&service.id);
                self.held.insert(service.id, held);
            }
            Err(error) => {
                tracing::warn!(service = %service.fqdn, %error, "service certificate request failed");
                self.last_error.insert(service.id, error.to_string());
            }
        }
    }

    fn apply_routes(&mut self, mut desired: HashMap<String, Desired>) {
        let Ok(mut routes) = self.table.write() else {
            return;
        };
        routes.retain(|fqdn, route| {
            desired.get(fqdn).is_some_and(|wanted| {
                route.serial == wanted.serial
                    && route.allowed == wanted.allowed
                    && route.upstream == wanted.upstream
            })
        });
        for (fqdn, wanted) in desired.drain() {
            if routes.contains_key(&fqdn) {
                continue;
            }
            let (closed, _) = watch::channel(());
            routes.insert(
                fqdn,
                Route {
                    config: wanted.config,
                    allowed: wanted.allowed,
                    upstream: wanted.upstream,
                    not_after: wanted.not_after,
                    serial: wanted.serial,
                    closed,
                },
            );
        }
    }

    fn drop_expired(&mut self) {
        let now = unix_now();
        if let Ok(mut routes) = self.table.write() {
            routes.retain(|_, route| route.not_after > now);
        }
        if self.routed() == 0 {
            self.listener = None;
        }
    }

    async fn ensure_listener(&mut self, state: &NodeState) {
        if self.routed() == 0 {
            self.listener = None;
            return;
        }
        let addrs = overlay_bind_addrs(state, listen_port(state));
        if self
            .listener
            .as_ref()
            .is_some_and(|listener| listener.addrs() == addrs.as_slice())
        {
            return;
        }
        self.listener = None;
        match ServiceListener::bind(&addrs, self.table.clone()).await {
            Ok(listener) => {
                tracing::info!(addresses = ?listener.addrs(), "private service listener active on overlay addresses");
                self.listener = Some(listener);
            }
            Err(error) => tracing::warn!(%error, "private service listener not started"),
        }
    }
}

pub fn listen_port(state: &NodeState) -> u16 {
    state
        .service_listen_port
        .filter(|port| *port != 0)
        .unwrap_or(DEFAULT_LISTEN_PORT)
}

/// SHA-256 fingerprint (lowercase hex) of the first certificate in `pem`.
pub fn pem_fingerprint(pem: &str) -> Result<String, Error> {
    use sha2::{Digest, Sha256};
    let der = CertificateDer::from_pem_slice(pem.as_bytes())
        .map_err(|_| Error::Message("service CA is not a PEM certificate".into()))?;
    Ok(Sha256::digest(der.as_ref())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
mod tests;
