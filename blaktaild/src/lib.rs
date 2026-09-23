use base64::{engine::general_purpose::STANDARD, Engine};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};
use thiserror::Error;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

pub mod acl_filter;
pub mod dns;
pub mod relay_client;
pub mod share;
pub use dns::{
    configure_system_dns, dns_domain, organisation_dns_managed, organisation_resolver_suffixes,
    published_resolver_suffixes, remove_system_dns, MagicDns,
};
pub use relay_client::RelayMesh;
#[cfg(target_os = "windows")]
mod windows;
pub use share::{
    disable_share, enable_share, load_shares, overlay_ipv4, put_share_file, save_shares,
    LocalShare, PublishedShare, ShareServer, DEFAULT_SHARE_PORT,
};
#[cfg(target_os = "windows")]
pub use windows::WindowsNetwork;

pub const DEFAULT_STATE_DIR: &str = "/var/lib/blaktail";
pub const DEFAULT_INTERFACE: &str = "blaktail0";
pub const TUNNEL_MTU: &str = "1280";
pub const TUNNEL_MTU_BYTES: usize = 1_280;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("coordinator request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("invalid state: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Peer {
    pub id: Uuid,
    pub name: String,
    pub wg_public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub dns_name: String,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Reflexive UDP address of the peer's relay-client socket. A nonce exchange
    /// proves reachability before opaque WireGuard ciphertext uses this path.
    #[serde(default)]
    pub relay_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress: Option<PeerIngress>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PeerIngress {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub all: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tcp: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub udp: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub icmp: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_tcp: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_udp: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deny_icmp: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_users: Vec<String>,
}

impl Peer {
    pub fn ingress_summary(&self) -> String {
        match &self.ingress {
            None => "legacy".into(),
            Some(ingress)
                if ingress.all
                    && ingress.deny_tcp.is_empty()
                    && ingress.deny_udp.is_empty()
                    && !ingress.deny_icmp =>
            {
                if ingress.ssh_users.is_empty() {
                    "all".into()
                } else {
                    format!("all ssh:{}", ingress.ssh_users.join(","))
                }
            }
            Some(ingress) => {
                let mut parts = Vec::new();
                if ingress.all {
                    parts.push("all".into());
                }
                if !ingress.tcp.is_empty() {
                    parts.push(format!("tcp:{}", ingress.tcp.join(",")));
                }
                if !ingress.udp.is_empty() {
                    parts.push(format!("udp:{}", ingress.udp.join(",")));
                }
                if ingress.icmp {
                    parts.push("icmp".into());
                }
                if !ingress.deny_tcp.is_empty() {
                    parts.push(format!("deny-tcp:{}", ingress.deny_tcp.join(",")));
                }
                if !ingress.ssh_users.is_empty() {
                    parts.push(format!("ssh:{}", ingress.ssh_users.join(",")));
                }
                if parts.is_empty() {
                    "deny".into()
                } else {
                    parts.join(" ")
                }
            }
        }
    }
}
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerChange {
    Remove(String),
    Upsert(Peer),
}

pub fn peer_diff(current: &[Peer], desired: &[Peer]) -> Vec<PeerChange> {
    let old: BTreeMap<_, _> = current.iter().map(|p| (&p.wg_public_key, p)).collect();
    let new: BTreeMap<_, _> = desired.iter().map(|p| (&p.wg_public_key, p)).collect();
    let mut changes = vec![];
    for key in old.keys() {
        if !new.contains_key(key) {
            changes.push(PeerChange::Remove((*key).clone()));
        }
    }
    for (key, peer) in new {
        if old.get(key).copied() != Some(peer) {
            changes.push(PeerChange::Upsert(peer.clone()));
        }
    }
    changes
}

/// Kernel WireGuard routes each AllowedIP to exactly one peer. When the
/// coordinator exports a rotated key beside its predecessor, keep the key
/// already on the interface until the overlap row disappears. Policy fields
/// such as ingress still come from the desired row for that key.
pub fn installable_wireguard_peers(current: &[Peer], desired: &[Peer]) -> Vec<Peer> {
    let desired_by_key = desired
        .iter()
        .map(|peer| (peer.wg_public_key.as_str(), peer))
        .collect::<BTreeMap<_, _>>();
    let mut claimed = BTreeSet::new();
    let mut installed = Vec::new();
    let mut seen = BTreeSet::new();
    for peer in current {
        let Some(fresh) = desired_by_key.get(peer.wg_public_key.as_str()) else {
            continue;
        };
        if fresh
            .allowed_ips
            .iter()
            .any(|route| claimed.contains(route.as_str()))
        {
            continue;
        }
        for route in &fresh.allowed_ips {
            claimed.insert(route.clone());
        }
        seen.insert(fresh.wg_public_key.as_str());
        installed.push((*fresh).clone());
    }
    for peer in desired {
        if !seen.insert(peer.wg_public_key.as_str()) {
            continue;
        }
        if peer
            .allowed_ips
            .iter()
            .any(|route| claimed.contains(route.as_str()))
        {
            continue;
        }
        for route in &peer.allowed_ips {
            claimed.insert(route.clone());
        }
        installed.push(peer.clone());
    }
    installed
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NodeState {
    pub node_id: Uuid,
    pub node_token: String,
    pub coord: String,
    pub interface: String,
    pub assigned_ip: String,
    #[serde(default)]
    pub assigned_ips: Vec<String>,
    #[serde(default)]
    pub dns_name: String,
    #[serde(default)]
    pub credential_expires_at: i64,
    #[serde(default)]
    pub advertised_routes: Vec<String>,
    #[serde(default)]
    pub exit_node: Option<String>,
    #[serde(default)]
    pub exit_node_active: bool,
    #[serde(default)]
    pub router_previous_ipv4_forward: Option<bool>,
    #[serde(default)]
    pub peers: Vec<Peer>,
    /// Advertised relay endpoints (host:port UDP) and our capability token.
    #[serde(default)]
    pub relays: Vec<String>,
    #[serde(default)]
    pub relay_token: String,
    #[serde(default)]
    pub relay_expires_at: u64,
    #[serde(default)]
    pub relay_endpoint: Option<String>,
    #[serde(default)]
    pub relay_endpoint_reported_at: u64,
    #[serde(default)]
    pub dns_mode: Option<String>,
    #[serde(default)]
    pub org_dns: Option<OrgDnsSnapshot>,
    #[serde(default)]
    pub dns_degraded: Option<String>,
    #[serde(default)]
    pub control_revision: i64,
    #[serde(default)]
    pub published_shares: Vec<crate::PublishedShare>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct OrgDnsSnapshot {
    #[serde(default)]
    pub revision: i64,
    #[serde(default)]
    pub managed: bool,
    #[serde(default)]
    pub records: Vec<OrgDnsRecord>,
    #[serde(default)]
    pub search_domains: Vec<String>,
    #[serde(default)]
    pub split: Vec<OrgDnsSplit>,
    #[serde(default)]
    pub global_resolvers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OrgDnsSplit {
    pub suffix: String,
    #[serde(default)]
    pub resolvers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OrgDnsRecord {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub value: String,
}

impl NodeState {
    pub fn interface_addresses(&self) -> Vec<String> {
        let mut addresses = self.assigned_ips.clone();
        if !addresses.contains(&self.assigned_ip) {
            addresses.insert(0, self.assigned_ip.clone());
        }
        addresses.retain(|address| !address.trim().is_empty());
        addresses
    }

    pub fn ipv6_address(&self) -> Option<&str> {
        self.assigned_ips
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(self.assigned_ip.as_str()))
            .find(|address| address.contains(':'))
    }
}
#[derive(Serialize)]
struct RegisterRequest<'a> {
    join_key: &'a str,
    name: &'a str,
    wg_public_key: &'a str,
    endpoint: Option<&'a str>,
    allowed_ips: Vec<String>,
    advertised_routes: &'a [String],
    os: &'a str,
    os_version: &'a str,
    agent_version: &'a str,
    hostname: &'a str,
    capabilities: Vec<String>,
    ephemeral: bool,
}
pub struct Registration<'a> {
    pub join_key: &'a str,
    pub name: &'a str,
    pub public_key: &'a str,
    pub endpoint: Option<&'a str>,
    pub interface: &'a str,
    pub advertised_routes: &'a [String],
    pub exit_node: Option<String>,
    pub ephemeral: bool,
}
#[derive(Serialize)]
struct DeviceAuthorizationRequest<'a> {
    name: &'a str,
    wg_public_key: &'a str,
}
#[derive(Debug, Deserialize)]
pub struct DeviceAuthorization {
    pub device_code: String,
    pub user_code: String,
    pub verification_url: String,
    pub expires_at: i64,
    pub interval_seconds: u64,
}
#[derive(Deserialize)]
struct DeviceAuthorizationStatus {
    status: String,
}
#[derive(Deserialize)]
struct RegisterResponse {
    id: Uuid,
    node_token: String,
    assigned_ip: String,
    #[serde(default)]
    assigned_ips: Vec<String>,
    #[serde(default)]
    dns_name: String,
    #[serde(default)]
    credential_expires_at: i64,
    #[serde(default)]
    relays: Vec<String>,
    #[serde(default)]
    relay_token: String,
    #[serde(default)]
    relay_expires_at: u64,
}
#[derive(Deserialize)]
struct PeersResponse {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    peers: Vec<Peer>,
    #[serde(default)]
    added: Vec<Peer>,
    #[serde(default)]
    removed: Vec<Uuid>,
    #[serde(default)]
    assigned_ips: Vec<String>,
    #[serde(default)]
    dns_name: String,
    #[serde(default)]
    credential_expires_at: i64,
    #[serde(default)]
    exit_node_active: bool,
    #[serde(default)]
    relays: Vec<String>,
    #[serde(default)]
    relay_token: String,
    #[serde(default)]
    relay_expires_at: u64,
    #[serde(default)]
    dns: Option<OrgDnsSnapshot>,
    #[serde(default)]
    revision: Option<i64>,
    #[serde(default)]
    shares: Vec<crate::PublishedShare>,
}

#[derive(Serialize)]
struct ReauthRequest<'a> {
    join_key: &'a str,
}

#[derive(Serialize)]
struct AdvertisedRoutesRequest<'a> {
    advertised_routes: &'a [String],
}

#[derive(Deserialize)]
struct ReauthResponse {
    node_token: String,
    credential_expires_at: i64,
}

#[derive(Deserialize)]
struct ApiErrorResponse {
    error: String,
}

#[derive(Clone)]
pub struct Coordinator {
    base: String,
    client: reqwest::Client,
}
impl Coordinator {
    pub fn new(base: &str) -> Result<Self, Error> {
        Self::with_ca(base, None)
    }

    pub fn with_ca(base: &str, ca_pem: Option<&[u8]>) -> Result<Self, Error> {
        let base = base.trim_end_matches('/').to_owned();
        if !(base.starts_with("https://")
            || base.starts_with("http://127.0.0.1")
            || base.starts_with("http://localhost"))
        {
            return Err(Error::Message(
                "coordinator must use HTTPS (HTTP is allowed only for localhost)".into(),
            ));
        }
        let mut builder = reqwest::Client::builder();
        if let Some(pem) = ca_pem {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(pem)
                    .map_err(|error| Error::Message(format!("invalid coordinator CA: {error}")))?,
            );
        }
        Ok(Self {
            base,
            client: builder.build()?,
        })
    }
    pub async fn begin_device_authorization(
        &self,
        name: &str,
        public_key: &str,
    ) -> Result<DeviceAuthorization, Error> {
        let response = self
            .client
            .post(format!("{}/v1/device-authorizations", self.base))
            .json(&DeviceAuthorizationRequest {
                name,
                wg_public_key: public_key,
            })
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let message = response
                .json::<ApiErrorResponse>()
                .await
                .map(|body| body.error)
                .unwrap_or_else(|_| format!("coordinator returned {status}"));
            return Err(Error::Message(format!(
                "could not start browser enrollment: {message}"
            )));
        }
        Ok(response.json().await?)
    }
    pub async fn device_authorization_approved(&self, device_code: &str) -> Result<bool, Error> {
        let response = self
            .client
            .get(format!(
                "{}/v1/device-authorizations/{device_code}",
                self.base
            ))
            .send()
            .await?;
        let status = response.status();
        if status == reqwest::StatusCode::GONE || status == reqwest::StatusCode::UNAUTHORIZED {
            let message = response
                .json::<ApiErrorResponse>()
                .await
                .map(|body| body.error)
                .unwrap_or_else(|_| "device authorization expired or was rejected".into());
            return Err(Error::Message(message));
        }
        if status != reqwest::StatusCode::OK && status != reqwest::StatusCode::ACCEPTED {
            return Err(Error::Message(format!(
                "device authorization polling failed ({status})"
            )));
        }
        let body: DeviceAuthorizationStatus = response.json().await?;
        match (status, body.status.as_str()) {
            (reqwest::StatusCode::OK, "approved") => Ok(true),
            (reqwest::StatusCode::ACCEPTED, "pending") => Ok(false),
            _ => Err(Error::Message(
                "coordinator returned an invalid device authorization state".into(),
            )),
        }
    }
    pub async fn register(&self, registration: Registration<'_>) -> Result<NodeState, Error> {
        let response = self
            .client
            .post(format!("{}/v1/nodes/register", self.base))
            .json(&RegisterRequest {
                join_key: registration.join_key,
                name: registration.name,
                wg_public_key: registration.public_key,
                endpoint: registration.endpoint,
                allowed_ips: vec![],
                advertised_routes: registration.advertised_routes,
                os: std::env::consts::OS,
                os_version: std::env::consts::ARCH,
                agent_version: env!("CARGO_PKG_VERSION"),
                hostname: registration.name,
                capabilities: vec!["wireguard".into(), "magicdns".into()],
                ephemeral: registration.ephemeral,
            })
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(Error::Message(format!(
                "join rejected by coordinator ({})",
                response.status()
            )));
        }
        let r: RegisterResponse = response.json().await?;
        let assigned_ips = if r.assigned_ips.is_empty() {
            vec![r.assigned_ip.clone()]
        } else {
            r.assigned_ips
        };
        Ok(NodeState {
            node_id: r.id,
            node_token: r.node_token,
            coord: self.base.clone(),
            interface: registration.interface.into(),
            assigned_ip: r.assigned_ip,
            assigned_ips,
            dns_name: r.dns_name,
            credential_expires_at: r.credential_expires_at,
            advertised_routes: registration.advertised_routes.to_vec(),
            exit_node: registration.exit_node,
            exit_node_active: false,
            router_previous_ipv4_forward: None,
            peers: vec![],
            relays: r.relays,
            relay_token: r.relay_token,
            relay_expires_at: r.relay_expires_at,
            relay_endpoint: None,
            relay_endpoint_reported_at: 0,
            dns_mode: None,
            org_dns: None,
            dns_degraded: None,
            control_revision: 0,
            published_shares: vec![],
        })
    }
    pub async fn peers(&self, state: &mut NodeState) -> Result<Vec<Peer>, Error> {
        let mut request = self
            .client
            .get(format!("{}/v1/nodes/{}/peers", self.base, state.node_id))
            .bearer_auth(&state.node_token);
        request = request.query(&[("ipv6", "true")]);
        if let Some(revision) = state.org_dns.as_ref().map(|dns| dns.revision) {
            request = request.query(&[("dns_revision", revision.to_string())]);
        }
        if let Some(exit_node) = state.exit_node.as_deref() {
            request = request.query(&[("exit_node", exit_node)]);
        }
        let response = request.send().await?;
        Self::read_peers_response(state, response).await
    }

    pub async fn wait_for_control_update(
        &self,
        state: &mut NodeState,
        wait: u64,
    ) -> Result<Option<Vec<Peer>>, Error> {
        let wait = wait.min(25);
        let mut request = self
            .client
            .get(format!("{}/v1/nodes/{}/updates", self.base, state.node_id))
            .bearer_auth(&state.node_token)
            .timeout(Duration::from_secs(wait + 10));
        request = request.query(&[
            ("since", state.control_revision.to_string()),
            ("wait", wait.to_string()),
            ("ipv6", "true".into()),
            ("version", "2".into()),
        ]);
        if let Some(revision) = state.org_dns.as_ref().map(|dns| dns.revision) {
            request = request.query(&[("dns_revision", revision.to_string())]);
        }
        if let Some(exit_node) = state.exit_node.as_deref() {
            request = request.query(&[("exit_node", exit_node)]);
        }
        let response = request.send().await?;
        if response.status() == reqwest::StatusCode::NO_CONTENT {
            return Ok(None);
        }
        Ok(Some(Self::read_peers_response(state, response).await?))
    }

    async fn read_peers_response(
        state: &mut NodeState,
        response: reqwest::Response,
    ) -> Result<Vec<Peer>, Error> {
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            let message = response
                .json::<ApiErrorResponse>()
                .await
                .map(|body| body.error)
                .unwrap_or_else(|_| "node authentication rejected".into());
            return Err(Error::Message(message));
        }
        let body: PeersResponse = response.error_for_status()?.json().await?;
        let peers = Self::apply_control_peers(&state.peers, &body);
        if let Some(revision) = body.revision {
            state.control_revision = revision;
        }
        if !body.assigned_ips.is_empty() {
            state.assigned_ips = body.assigned_ips;
        }
        state.dns_name = body.dns_name;
        state.credential_expires_at = body.credential_expires_at;
        state.exit_node_active = body.exit_node_active;
        state.relays = body.relays;
        state.relay_token = body.relay_token;
        state.relay_expires_at = body.relay_expires_at;
        apply_org_dns_snapshot(state, body.dns);
        state.published_shares = body.shares;
        Ok(peers)
    }

    pub async fn publish_shares(
        &self,
        state: &NodeState,
        shares: &[crate::LocalShare],
    ) -> Result<(), Error> {
        let response = self
            .client
            .put(format!("{}/v1/nodes/{}/shares", self.base, state.node_id))
            .bearer_auth(&state.node_token)
            .json(&serde_json::json!({ "shares": shares }))
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let message = response
                .json::<ApiErrorResponse>()
                .await
                .map(|body| body.error)
                .unwrap_or_else(|_| format!("coordinator returned {status}"));
            return Err(Error::Message(format!("share publish rejected: {message}")));
        }
        Ok(())
    }

    fn apply_control_peers(current: &[Peer], body: &PeersResponse) -> Vec<Peer> {
        if body.kind.as_deref() == Some("delta") {
            let removed = body.removed.iter().copied().collect::<HashSet<_>>();
            let mut by_id = current
                .iter()
                .filter(|peer| !removed.contains(&peer.id))
                .map(|peer| (peer.id, peer.clone()))
                .collect::<BTreeMap<_, _>>();
            for peer in &body.added {
                by_id.insert(peer.id, peer.clone());
            }
            return by_id.into_values().collect();
        }
        body.peers.clone()
    }
    pub async fn update_advertised_routes(
        &self,
        state: &NodeState,
        routes: &[String],
    ) -> Result<(), Error> {
        let response = self
            .client
            .put(format!("{}/v1/nodes/{}/routes", self.base, state.node_id))
            .bearer_auth(&state.node_token)
            .json(&AdvertisedRoutesRequest {
                advertised_routes: routes,
            })
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let message = response
                .json::<ApiErrorResponse>()
                .await
                .map(|body| body.error)
                .unwrap_or_else(|_| format!("coordinator returned {status}"));
            return Err(Error::Message(format!(
                "route advertisement rejected: {message}"
            )));
        }
        Ok(())
    }
    pub async fn reauth(&self, state: &mut NodeState, join_key: &str) -> Result<(), Error> {
        let response = self
            .client
            .post(format!("{}/v1/nodes/{}/reauth", self.base, state.node_id))
            .bearer_auth(&state.node_token)
            .json(&ReauthRequest { join_key })
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(Error::Message(format!(
                "re-authentication rejected by coordinator ({})",
                response.status()
            )));
        }
        let renewed: ReauthResponse = response.json().await?;
        state.node_token = renewed.node_token;
        state.credential_expires_at = renewed.credential_expires_at;
        Ok(())
    }
    pub async fn revoke(&self, state: &NodeState) -> Result<(), Error> {
        self.client
            .delete(format!("{}/v1/nodes/{}", self.base, state.node_id))
            .bearer_auth(&state.node_token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
    pub async fn report_relay_endpoint(
        &self,
        state: &NodeState,
        endpoint: std::net::SocketAddr,
    ) -> Result<(), Error> {
        self.client
            .put(format!(
                "{}/v1/nodes/{}/relay-endpoint",
                self.base, state.node_id
            ))
            .bearer_auth(&state.node_token)
            .json(&serde_json::json!({"endpoint": endpoint.to_string()}))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

pub fn ensure_private_key(dir: &Path) -> Result<(PathBuf, String), Error> {
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    let path = dir.join("private.key");
    if !path.exists() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let mut encoded = STANDARD.encode(secret.to_bytes());
        write_secret(&path, encoded.as_bytes())?;
        encoded.zeroize();
    }
    let mode = fs::metadata(&path)?.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(Error::Message(format!(
            "{} must have mode 0600 (found {mode:04o})",
            path.display()
        )));
    }
    let mut encoded = fs::read_to_string(&path)?;
    let bytes = STANDARD
        .decode(encoded.trim())
        .map_err(|_| Error::Message("private key file is not valid base64".into()))?;
    encoded.zeroize();
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Message("private key must contain 32 bytes".into()))?;
    let public = STANDARD.encode(PublicKey::from(&StaticSecret::from(raw)).as_bytes());
    Ok((path, public))
}
pub fn write_state(dir: &Path, state: &NodeState) -> Result<(), Error> {
    write_secret(&dir.join("state.json"), &serde_json::to_vec_pretty(state)?)
}
fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let tmp = path.with_extension("tmp");
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(tmp, path)?;
    Ok(())
}
pub fn read_state(dir: &Path) -> Result<NodeState, Error> {
    Ok(serde_json::from_slice(&fs::read(dir.join("state.json"))?)?)
}

pub trait Network {
    fn setup(&mut self, interface: &str, key: &Path, addresses: &[String]) -> Result<(), Error>;
    fn set_addresses(&mut self, interface: &str, addresses: &[String]) -> Result<(), Error>;
    fn apply(&mut self, interface: &str, changes: &[PeerChange]) -> Result<(), Error>;
    fn down(&mut self, interface: &str) -> Result<(), Error>;
    /// Repoints one peer's transport endpoint without touching its other
    /// settings. Used to switch a peer between direct and relay paths.
    fn set_peer_endpoint(
        &mut self,
        interface: &str,
        peer_key_b64: &str,
        endpoint: &str,
    ) -> Result<(), Error>;
    /// Unix timestamps of the latest handshake per peer key (base64), if known.
    fn latest_handshakes(&mut self, interface: &str) -> Result<HashMap<String, u64>, Error>;
    /// The WireGuard listen endpoint on this machine (loopback IP + port).
    fn listen_endpoint(&mut self, interface: &str) -> Result<Option<std::net::SocketAddr>, Error>;
    /// Reconciles forwarding/NAT for a subnet or exit-node advertisement and
    /// returns the original IPv4-forwarding setting for safe restoration.
    /// IPv6 routes (including `::/0`) are handled symmetrically via
    /// `ip6tables` inside the Linux implementation; see its docs for details.
    fn configure_router(
        &mut self,
        _interface: &str,
        _previous_routes: &[String],
        desired_routes: &[String],
        _original_ipv4_forward: Option<bool>,
    ) -> Result<Option<bool>, Error> {
        if desired_routes.is_empty() {
            Ok(None)
        } else {
            Err(Error::Message(
                "subnet and exit-node advertisement is supported on Linux only".into(),
            ))
        }
    }
    fn apply_ingress(&mut self, _interface: &str, _peers: &[Peer]) -> Result<(), Error> {
        Ok(())
    }
}

fn parse_cidr(value: &str) -> Result<(std::net::IpAddr, u8), Error> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| Error::Message(format!("address {value} must use CIDR notation")))?;
    let address: std::net::IpAddr = address
        .parse()
        .map_err(|_| Error::Message(format!("address {value} is invalid")))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| Error::Message(format!("address {value} has an invalid prefix")))?;
    if (address.is_ipv4() && prefix > 32) || (address.is_ipv6() && prefix > 128) {
        return Err(Error::Message(format!(
            "address {value} has an invalid prefix"
        )));
    }
    Ok((address, prefix))
}

fn iproute_family(value: &str) -> Result<&'static str, Error> {
    Ok(if parse_cidr(value)?.0.is_ipv4() {
        "-4"
    } else {
        "-6"
    })
}

/// Classifies a route string as IPv6 when it contains a colon. This covers
/// `::/0` (exit-node default), ULA advertisements such as `fd00::/8`, and
/// any other v6 CIDR; everything else is treated as IPv4.
fn is_ipv6_route(route: &str) -> bool {
    route.contains(':')
}
/// Normalises a base64 WireGuard public key to the hex form used by the
/// userspace UAPI, so path-management bookkeeping is uniform per platform.
pub fn peer_key_hex(peer_key_b64: &str) -> Option<String> {
    let raw = STANDARD.decode(peer_key_b64.trim()).ok()?;
    Some(raw.iter().map(|b| format!("{b:02x}")).collect())
}
/// Decides when a peer's direct path is considered dead (no handshake within
/// this window after first observation) and how long we keep re-trying it.
pub const DIRECT_GRACE_SECS: u64 = 30;
pub const HANDSHAKE_FRESH_SECS: u64 = 180;
pub const DIRECT_RETRY_SECS: u64 = 300;
const EXIT_ROUTE_TABLE: &str = "51820";
const EXIT_MAIN_RULE_PRIORITY: &str = "13000";
const EXIT_TUNNEL_RULE_PRIORITY: &str = "13001";

#[derive(Default)]
pub struct LinuxNetwork {
    peer_routes: HashMap<String, Vec<String>>,
    installed_routes: HashSet<String>,
    exit_routing: bool,
}
impl LinuxNetwork {
    fn run(program: &str, args: &[&str]) -> Result<(), Error> {
        let out = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| Error::Message(format!("could not execute {program}: {e}")))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(Error::Message(format!(
                "{program} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    }

    fn run_ignore(program: &str, args: &[&str]) {
        let _ = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    fn replace_addresses(interface: &str, addresses: &[String]) -> Result<(), Error> {
        if addresses.is_empty() {
            return Err(Error::Message(
                "coordinator returned no tunnel addresses".into(),
            ));
        }
        for address in addresses {
            let (parsed, prefix) = parse_cidr(address)?;
            if (parsed.is_ipv4() && prefix != 32) || (parsed.is_ipv6() && prefix != 128) {
                return Err(Error::Message(format!(
                    "tunnel address {address} must be a host route"
                )));
            }
            Self::run(
                "ip",
                &[
                    iproute_family(address)?,
                    "address",
                    "replace",
                    address,
                    "dev",
                    interface,
                ],
            )?;
        }
        Ok(())
    }

    fn reconcile_routes(&mut self, interface: &str) -> Result<(), Error> {
        let desired: HashSet<String> = self
            .peer_routes
            .values()
            .flatten()
            .filter(|route| route.as_str() != "0.0.0.0/0")
            .cloned()
            .collect();
        let additions: Vec<_> = desired
            .difference(&self.installed_routes)
            .cloned()
            .collect();
        for route in additions {
            Self::run(
                "ip",
                &[
                    iproute_family(&route)?,
                    "route",
                    "add",
                    &route,
                    "dev",
                    interface,
                ],
            )?;
            self.installed_routes.insert(route);
        }
        let removals: Vec<_> = self
            .installed_routes
            .difference(&desired)
            .cloned()
            .collect();
        for route in removals {
            Self::run(
                "ip",
                &[
                    iproute_family(&route)?,
                    "route",
                    "del",
                    &route,
                    "dev",
                    interface,
                ],
            )?;
            self.installed_routes.remove(&route);
        }

        let wants_exit = self
            .peer_routes
            .values()
            .flatten()
            .any(|route| route == "0.0.0.0/0");
        if wants_exit && !self.exit_routing {
            self.enable_exit_routing(interface)?;
        } else if !wants_exit && self.exit_routing {
            self.disable_exit_routing(interface);
        }
        Ok(())
    }

    fn clear_exit_rules() {
        Self::run_ignore(
            "ip",
            &[
                "-4",
                "rule",
                "del",
                "priority",
                EXIT_MAIN_RULE_PRIORITY,
                "table",
                "main",
                "suppress_prefixlength",
                "0",
            ],
        );
        Self::run_ignore(
            "ip",
            &[
                "-4",
                "rule",
                "del",
                "priority",
                EXIT_TUNNEL_RULE_PRIORITY,
                "not",
                "fwmark",
                EXIT_ROUTE_TABLE,
                "table",
                EXIT_ROUTE_TABLE,
            ],
        );
        Self::run_ignore(
            "ip",
            &["-4", "route", "del", "default", "table", EXIT_ROUTE_TABLE],
        );
    }

    fn enable_exit_routing(&mut self, interface: &str) -> Result<(), Error> {
        Self::clear_exit_rules();
        Self::run("wg", &["set", interface, "fwmark", EXIT_ROUTE_TABLE])?;
        let configured = (|| {
            Self::run(
                "ip",
                &[
                    "-4",
                    "route",
                    "add",
                    "default",
                    "dev",
                    interface,
                    "table",
                    EXIT_ROUTE_TABLE,
                ],
            )?;
            Self::run(
                "ip",
                &[
                    "-4",
                    "rule",
                    "add",
                    "priority",
                    EXIT_MAIN_RULE_PRIORITY,
                    "table",
                    "main",
                    "suppress_prefixlength",
                    "0",
                ],
            )?;
            Self::run(
                "ip",
                &[
                    "-4",
                    "rule",
                    "add",
                    "priority",
                    EXIT_TUNNEL_RULE_PRIORITY,
                    "not",
                    "fwmark",
                    EXIT_ROUTE_TABLE,
                    "table",
                    EXIT_ROUTE_TABLE,
                ],
            )
        })();
        if let Err(error) = configured {
            Self::clear_exit_rules();
            Self::run_ignore("wg", &["set", interface, "fwmark", "off"]);
            return Err(error);
        }
        self.exit_routing = true;
        Ok(())
    }

    fn disable_exit_routing(&mut self, interface: &str) {
        Self::clear_exit_rules();
        Self::run_ignore("wg", &["set", interface, "fwmark", "off"]);
        self.exit_routing = false;
    }

    fn ipv4_forwarding() -> Result<bool, Error> {
        let output = Command::new("sysctl")
            .args(["-n", "net.ipv4.ip_forward"])
            .stdin(Stdio::null())
            .output()
            .map_err(|error| Error::Message(format!("could not execute sysctl: {error}")))?;
        if !output.status.success() {
            return Err(Error::Message(format!(
                "could not read net.ipv4.ip_forward: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        match String::from_utf8_lossy(&output.stdout).trim() {
            "0" => Ok(false),
            "1" => Ok(true),
            value => Err(Error::Message(format!(
                "unexpected net.ipv4.ip_forward value {value}"
            ))),
        }
    }

    fn ipv6_forwarding() -> Result<bool, Error> {
        let output = Command::new("sysctl")
            .args(["-n", "net.ipv6.conf.all.forwarding"])
            .stdin(Stdio::null())
            .output()
            .map_err(|error| Error::Message(format!("could not execute sysctl: {error}")))?;
        if !output.status.success() {
            return Err(Error::Message(format!(
                "could not read net.ipv6.conf.all.forwarding: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        match String::from_utf8_lossy(&output.stdout).trim() {
            "0" => Ok(false),
            "1" => Ok(true),
            value => Err(Error::Message(format!(
                "unexpected net.ipv6.conf.all.forwarding value {value}"
            ))),
        }
    }

    fn remove_router_rules(interface: &str, routes: &[String]) {
        for route in routes {
            let bin = if is_ipv6_route(route) {
                "ip6tables"
            } else {
                "iptables"
            };
            Self::run_ignore(
                bin,
                &[
                    "-D",
                    "FORWARD",
                    "-i",
                    interface,
                    "-d",
                    route,
                    "-m",
                    "comment",
                    "--comment",
                    "blaktail-router",
                    "-j",
                    "ACCEPT",
                ],
            );
        }
        for bin in ["iptables", "ip6tables"] {
            Self::run_ignore(
                bin,
                &[
                    "-D",
                    "FORWARD",
                    "-o",
                    interface,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "RELATED,ESTABLISHED",
                    "-m",
                    "comment",
                    "--comment",
                    "blaktail-router",
                    "-j",
                    "ACCEPT",
                ],
            );
        }
        Self::run_ignore(
            "iptables",
            &[
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                "100.64.0.0/10",
                "!",
                "-o",
                interface,
                "-m",
                "comment",
                "--comment",
                "blaktail-router",
                "-j",
                "MASQUERADE",
            ],
        );
        Self::run_ignore(
            "ip6tables",
            &[
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                "fd00::/8",
                "!",
                "-o",
                interface,
                "-m",
                "comment",
                "--comment",
                "blaktail-router",
                "-j",
                "MASQUERADE",
            ],
        );
    }

    fn clear_acl_filter(interface: &str) {
        for bin in ["iptables", "ip6tables"] {
            for _ in 0..4 {
                Self::run_ignore(
                    bin,
                    &["-D", "INPUT", "-i", interface, "-j", acl_filter::ACL_CHAIN],
                );
            }
            Self::run_ignore(bin, &["-F", acl_filter::ACL_CHAIN]);
            Self::run_ignore(bin, &["-X", acl_filter::ACL_CHAIN]);
        }
    }

    fn install_acl_chain(bin: &str, interface: &str, rules: &[Vec<String>]) -> Result<(), Error> {
        Self::run_ignore(bin, &["-N", acl_filter::ACL_CHAIN]);
        Self::run(bin, &["-F", acl_filter::ACL_CHAIN])?;
        if Self::run(
            bin,
            &["-C", "INPUT", "-i", interface, "-j", acl_filter::ACL_CHAIN],
        )
        .is_err()
        {
            Self::run(
                bin,
                &[
                    "-I",
                    "INPUT",
                    "1",
                    "-i",
                    interface,
                    "-j",
                    acl_filter::ACL_CHAIN,
                ],
            )?;
        }
        for rule in rules {
            let args: Vec<&str> = rule.iter().map(String::as_str).collect();
            Self::run(bin, &args)?;
        }
        Ok(())
    }
}
impl Network for LinuxNetwork {
    fn setup(&mut self, interface: &str, key: &Path, addresses: &[String]) -> Result<(), Error> {
        Self::clear_exit_rules();
        Self::clear_acl_filter(interface);
        self.peer_routes.clear();
        self.installed_routes.clear();
        self.exit_routing = false;
        let _ = Command::new("ip")
            .args(["link", "delete", "dev", interface])
            .output();
        if Self::run(
            "ip",
            &["link", "add", "dev", interface, "type", "wireguard"],
        )
        .is_err()
        {
            Self::run("boringtun", &[interface]).map_err(|_| {
                Error::Message(
                    "kernel WireGuard is unavailable and boringtun could not be started".into(),
                )
            })?;
        }
        let key = key
            .to_str()
            .ok_or_else(|| Error::Message("private key path is not UTF-8".into()))?;
        Self::run("wg", &["set", interface, "private-key", key])?;
        Self::replace_addresses(interface, addresses)?;
        Self::run("ip", &["link", "set", "dev", interface, "mtu", TUNNEL_MTU])?;
        Self::run("ip", &["link", "set", "up", "dev", interface])
    }
    fn set_addresses(&mut self, interface: &str, addresses: &[String]) -> Result<(), Error> {
        Self::replace_addresses(interface, addresses)
    }
    fn apply(&mut self, interface: &str, changes: &[PeerChange]) -> Result<(), Error> {
        for change in changes {
            match change {
                PeerChange::Remove(key) => {
                    Self::run("wg", &["set", interface, "peer", key, "remove"])?;
                    self.peer_routes.remove(key);
                }
                PeerChange::Upsert(peer) => {
                    let ips = peer.allowed_ips.join(",");
                    let mut args = vec![
                        "set",
                        interface,
                        "peer",
                        peer.wg_public_key.as_str(),
                        "allowed-ips",
                        ips.as_str(),
                    ];
                    if let Some(endpoint) = &peer.endpoint {
                        args.extend(["endpoint", endpoint.as_str(), "persistent-keepalive", "25"]);
                    }
                    Self::run("wg", &args)?;
                    self.peer_routes
                        .insert(peer.wg_public_key.clone(), peer.allowed_ips.clone());
                }
            }
        }
        self.reconcile_routes(interface)
    }
    fn apply_ingress(&mut self, interface: &str, peers: &[Peer]) -> Result<(), Error> {
        Self::clear_acl_filter(interface);
        let plan = acl_filter::plan_overlay_filter(peers);
        if !plan.enforce {
            return Ok(());
        }
        if let Err(error) = Self::install_acl_chain("iptables", interface, &plan.ipv4) {
            Self::clear_acl_filter(interface);
            return Err(error);
        }
        if let Err(error) = Self::install_acl_chain("ip6tables", interface, &plan.ipv6) {
            Self::clear_acl_filter(interface);
            return Err(error);
        }
        Ok(())
    }
    fn down(&mut self, interface: &str) -> Result<(), Error> {
        self.disable_exit_routing(interface);
        Self::clear_acl_filter(interface);
        Self::run("ip", &["link", "delete", "dev", interface])
    }
    fn set_peer_endpoint(
        &mut self,
        interface: &str,
        peer_key_b64: &str,
        endpoint: &str,
    ) -> Result<(), Error> {
        Self::run(
            "wg",
            &[
                "set",
                interface,
                "peer",
                peer_key_b64.trim(),
                "endpoint",
                endpoint,
            ],
        )
    }
    fn latest_handshakes(&mut self, interface: &str) -> Result<HashMap<String, u64>, Error> {
        let out = Command::new("wg")
            .args(["show", interface, "latest-handshakes"])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| Error::Message(format!("could not execute wg: {e}")))?;
        if !out.status.success() {
            return Err(Error::Message("wg latest-handshakes failed".into()));
        }
        let mut map = HashMap::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let Some((key, stamp)) = line.split_once('\t') else {
                continue;
            };
            if let (Some(hex), Ok(secs)) = (peer_key_hex(key), stamp.trim().parse::<u64>()) {
                map.insert(hex, secs);
            }
        }
        Ok(map)
    }
    fn listen_endpoint(&mut self, interface: &str) -> Result<Option<std::net::SocketAddr>, Error> {
        let out = Command::new("wg")
            .args(["show", interface, "listen-port"])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| Error::Message(format!("could not execute wg: {e}")))?;
        if !out.status.success() {
            return Ok(None);
        }
        let port: u16 = String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .map_err(|_| Error::Message("wg listen-port is not numeric".into()))?;
        Ok((port != 0).then(|| std::net::SocketAddr::from(([127, 0, 0, 1], port))))
    }
    /// Reconciles forwarding/NAT for subnet and exit-node advertisements.
    ///
    /// IPv4 routes (including the `0.0.0.0/0` exit-node default) are
    /// installed via `iptables` with MASQUERADE from `100.64.0.0/10`, while
    /// IPv6 routes (including `::/0`) go via `ip6tables` with MASQUERADE
    /// from `fd00::/8`. Each family's filter/NAT rules and sysctl
    /// (`net.ipv4.ip_forward` / `net.ipv6.conf.all.forwarding`) are only
    /// touched when that family has advertised routes.
    ///
    /// The return value preserves the original IPv4-forwarding setting for
    /// safe restoration (`None` once no routes remain); IPv6 forwarding is
    /// managed symmetrically inside but its original value is not returned,
    /// to keep this signature stable for existing callers. On teardown the
    /// IPv6 flag is restored to `0` only when the stored IPv4 original is
    /// `Some(false)`, i.e. this node enabled forwarding.
    fn configure_router(
        &mut self,
        interface: &str,
        previous_routes: &[String],
        desired_routes: &[String],
        original_ipv4_forward: Option<bool>,
    ) -> Result<Option<bool>, Error> {
        let known_routes: HashSet<_> = previous_routes
            .iter()
            .chain(desired_routes)
            .cloned()
            .collect();
        Self::remove_router_rules(interface, &known_routes.into_iter().collect::<Vec<_>>());
        if desired_routes.is_empty() {
            if original_ipv4_forward == Some(false) && Self::ipv4_forwarding()? {
                Self::run("sysctl", &["-w", "net.ipv4.ip_forward=0"])?;
            }
            // Symmetric best-effort v6 restore, gated on the same stored
            // original so a no-op teardown (None) never touches sysctl.
            if original_ipv4_forward == Some(false) {
                if let Ok(enabled) = Self::ipv6_forwarding() {
                    if enabled {
                        Self::run("sysctl", &["-w", "net.ipv6.conf.all.forwarding=0"])?;
                    }
                }
            }
            return Ok(None);
        }

        let has_v4 = desired_routes.iter().any(|route| !is_ipv6_route(route));
        let has_v6 = desired_routes.iter().any(|route| is_ipv6_route(route));

        let installed = (|| {
            for route in desired_routes {
                let bin = if is_ipv6_route(route) {
                    "ip6tables"
                } else {
                    "iptables"
                };
                Self::run(
                    bin,
                    &[
                        "-I",
                        "FORWARD",
                        "1",
                        "-i",
                        interface,
                        "-d",
                        route,
                        "-m",
                        "comment",
                        "--comment",
                        "blaktail-router",
                        "-j",
                        "ACCEPT",
                    ],
                )?;
            }
            for bin in ["iptables", "ip6tables"] {
                let wanted = (bin == "iptables" && has_v4) || (bin == "ip6tables" && has_v6);
                if !wanted {
                    continue;
                }
                Self::run(
                    bin,
                    &[
                        "-I",
                        "FORWARD",
                        "1",
                        "-o",
                        interface,
                        "-m",
                        "conntrack",
                        "--ctstate",
                        "RELATED,ESTABLISHED",
                        "-m",
                        "comment",
                        "--comment",
                        "blaktail-router",
                        "-j",
                        "ACCEPT",
                    ],
                )?;
            }
            if has_v4 {
                Self::run(
                    "iptables",
                    &[
                        "-t",
                        "nat",
                        "-A",
                        "POSTROUTING",
                        "-s",
                        "100.64.0.0/10",
                        "!",
                        "-o",
                        interface,
                        "-m",
                        "comment",
                        "--comment",
                        "blaktail-router",
                        "-j",
                        "MASQUERADE",
                    ],
                )?;
            }
            if has_v6 {
                Self::run(
                    "ip6tables",
                    &[
                        "-t",
                        "nat",
                        "-A",
                        "POSTROUTING",
                        "-s",
                        "fd00::/8",
                        "!",
                        "-o",
                        interface,
                        "-m",
                        "comment",
                        "--comment",
                        "blaktail-router",
                        "-j",
                        "MASQUERADE",
                    ],
                )?;
            }
            Ok::<(), Error>(())
        })();
        if let Err(error) = installed {
            Self::remove_router_rules(interface, desired_routes);
            return Err(error);
        }
        let original = if has_v4 {
            let current = match Self::ipv4_forwarding() {
                Ok(current) => current,
                Err(error) => {
                    Self::remove_router_rules(interface, desired_routes);
                    return Err(error);
                }
            };
            let original = original_ipv4_forward.unwrap_or(current);
            if !current {
                if let Err(error) = Self::run("sysctl", &["-w", "net.ipv4.ip_forward=1"]) {
                    Self::remove_router_rules(interface, desired_routes);
                    return Err(error);
                }
            }
            Some(original)
        } else {
            original_ipv4_forward
        };
        if has_v6 {
            let current = match Self::ipv6_forwarding() {
                Ok(current) => current,
                Err(error) => {
                    Self::remove_router_rules(interface, desired_routes);
                    return Err(error);
                }
            };
            if !current {
                if let Err(error) = Self::run("sysctl", &["-w", "net.ipv6.conf.all.forwarding=1"]) {
                    Self::remove_router_rules(interface, desired_routes);
                    return Err(error);
                }
            }
        }
        Ok(original)
    }
}

/// Userspace WireGuard backend for macOS. Opens a kernel `utun` device through
/// boringtun and drives it over the local UAPI socket, so no Network Extension
/// or kernel module is required.
#[cfg(target_os = "macos")]
pub struct MacOsNetwork {
    device: Option<boringtun::device::DeviceHandle>,
    name: Option<String>,
    private_hex: String,
    peers: Vec<Peer>,
    installed_routes: HashSet<String>,
}

#[cfg(target_os = "macos")]
impl MacOsNetwork {
    pub fn new() -> Self {
        Self {
            device: None,
            name: None,
            private_hex: String::new(),
            peers: vec![],
            installed_routes: HashSet::new(),
        }
    }

    fn utun_name(&self) -> Result<&str, Error> {
        self.name
            .as_deref()
            .ok_or_else(|| Error::Message("utun device is not open".into()))
    }

    fn read_private_hex(key: &Path) -> Result<String, Error> {
        let encoded = fs::read_to_string(key)?;
        let bytes = STANDARD
            .decode(encoded.trim())
            .map_err(|_| Error::Message("private key file is not valid base64".into()))?;
        Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }

    fn uapi(&self, request: &str) -> Result<(), Error> {
        let name = self.utun_name()?;
        let path = format!("/var/run/wireguard/{name}.sock");
        let mut stream = std::os::unix::net::UnixStream::connect(path.clone())
            .map_err(|e| Error::Message(format!("connect WireGuard UAPI {path}: {e}")))?;
        use std::io::{Read as _, Write as _};
        stream
            .write_all(request.as_bytes())
            .and_then(|_| stream.shutdown(std::net::Shutdown::Write))
            .map_err(|e| Error::Message(format!("write WireGuard UAPI {path}: {e}")))?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        if !response.contains("errno=0") {
            return Err(Error::Message(
                "WireGuard UAPI rejected the peer configuration".into(),
            ));
        }
        Ok(())
    }

    fn run(program: &str, args: &[&str]) -> Result<(), Error> {
        let out = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| Error::Message(format!("could not execute {program}: {e}")))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(Error::Message(format!(
                "{program} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    }

    fn run_ignore(program: &str, args: &[&str]) {
        let _ = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    fn replace_addresses(name: &str, addresses: &[String]) -> Result<(), Error> {
        if addresses.is_empty() {
            return Err(Error::Message(
                "coordinator returned no tunnel addresses".into(),
            ));
        }
        for address in addresses {
            let (parsed, prefix) = parse_cidr(address)?;
            if parsed.is_ipv4() && prefix == 32 {
                let address = parsed.to_string();
                Self::run("/sbin/ifconfig", &[name, "inet", &address, &address, "up"])?;
            } else if parsed.is_ipv6() && prefix == 128 {
                Self::run_ignore("/sbin/ifconfig", &[name, "inet6", address, "delete"]);
                Self::run("/sbin/ifconfig", &[name, "inet6", address, "alias"])?;
            } else {
                return Err(Error::Message(format!(
                    "tunnel address {address} must be a host route"
                )));
            }
        }
        Ok(())
    }

    fn route_target(route: &str) -> Result<(&'static str, &'static str, &str), Error> {
        let (address, prefix) = parse_cidr(route)?;
        let family = if address.is_ipv4() { "-inet" } else { "-inet6" };
        let host_prefix = if address.is_ipv4() { 32 } else { 128 };
        if prefix == host_prefix {
            Ok((family, "-host", route.split('/').next().unwrap_or(route)))
        } else {
            Ok((family, "-net", route))
        }
    }

    fn remove_route(name: &str, route: &str) -> Result<(), Error> {
        let (family, kind, target) = Self::route_target(route)?;
        Self::run(
            "/sbin/route",
            &["-n", "delete", family, kind, target, "-interface", name],
        )
    }

    /// Applies the full desired peer set with `replace_peers=true`, then pins
    /// each host or subnet route to the utun device.
    fn push_config_and_routes(&mut self) -> Result<(), Error> {
        let desired: HashSet<String> = self
            .peers
            .iter()
            .flat_map(|peer| peer.allowed_ips.iter())
            .cloned()
            .collect();
        if desired.contains("0.0.0.0/0") {
            return Err(Error::Message(
                "exit-node routing is supported on Linux only".into(),
            ));
        }
        let mut request = format!(
            "set=1\nprivate_key={}\nreplace_peers=true\n",
            self.private_hex
        );
        for peer in &self.peers {
            request.push_str(&format!(
                "public_key={}\nreplace_allowed_ips=true\npersistent_keepalive_interval=25\n",
                peer.wg_public_key
            ));
            if let Some(endpoint) = &peer.endpoint {
                request.push_str(&format!("endpoint={endpoint}\n"));
            }
            for ip in &peer.allowed_ips {
                request.push_str(&format!("allowed_ip={ip}\n"));
            }
        }
        request.push('\n');
        self.uapi(&request)?;
        let name = self.utun_name()?.to_owned();
        let additions: Vec<_> = desired
            .difference(&self.installed_routes)
            .cloned()
            .collect();
        for route in additions {
            let (family, kind, target) = Self::route_target(&route)?;
            Self::run(
                "/sbin/route",
                &["-n", "add", family, kind, target, "-interface", &name],
            )?;
            self.installed_routes.insert(route);
        }
        let removals: Vec<_> = self
            .installed_routes
            .difference(&desired)
            .cloned()
            .collect();
        for route in removals {
            Self::remove_route(&name, &route)?;
            self.installed_routes.remove(&route);
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl Default for MacOsNetwork {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
impl Network for MacOsNetwork {
    fn setup(&mut self, _interface: &str, key: &Path, addresses: &[String]) -> Result<(), Error> {
        self.device = None;
        self.name = None;
        self.private_hex = Self::read_private_hex(key)?;
        let name_file = tempfile::Builder::new()
            .prefix("blaktail-utun-")
            .tempfile()?
            .into_temp_path();
        // boringtun reports the allocated utun index through this file.
        std::env::set_var("WG_TUN_NAME_FILE", &name_file);
        let device = boringtun::device::DeviceHandle::new("utun", Default::default())
            .map_err(|e| Error::Message(format!("open userspace utun (run as root): {e}")))?;
        std::env::remove_var("WG_TUN_NAME_FILE");
        let mut name = String::new();
        for _ in 0..50 {
            if let Ok(reported) = fs::read_to_string(&name_file) {
                name = reported.trim().to_owned();
                if !name.is_empty() {
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        if name.is_empty() {
            return Err(Error::Message("utun name was not reported".into()));
        }
        Self::run("/sbin/ifconfig", &[&name, "mtu", TUNNEL_MTU])?;
        Self::replace_addresses(&name, addresses)?;
        self.device = Some(device);
        self.name = Some(name);
        self.peers.clear();
        self.installed_routes.clear();
        Ok(())
    }
    fn set_addresses(&mut self, _interface: &str, addresses: &[String]) -> Result<(), Error> {
        Self::replace_addresses(self.utun_name()?, addresses)
    }
    fn apply(&mut self, _interface: &str, changes: &[PeerChange]) -> Result<(), Error> {
        if self.name.is_none() {
            return Err(Error::Message(
                "utun device is not open; run setup first".into(),
            ));
        }
        for change in changes {
            match change {
                PeerChange::Remove(key) => self.peers.retain(|p| &p.wg_public_key != key),
                PeerChange::Upsert(peer) => match self
                    .peers
                    .iter_mut()
                    .find(|p| p.wg_public_key == peer.wg_public_key)
                {
                    Some(existing) => *existing = peer.clone(),
                    None => self.peers.push(peer.clone()),
                },
            }
        }
        self.push_config_and_routes()
    }
    fn down(&mut self, _interface: &str) -> Result<(), Error> {
        if let Some(name) = &self.name {
            for route in &self.installed_routes {
                let _ = Self::remove_route(name, route);
            }
        }
        self.device = None;
        self.name = None;
        self.peers.clear();
        self.installed_routes.clear();
        Ok(())
    }
    fn set_peer_endpoint(
        &mut self,
        _interface: &str,
        peer_key_b64: &str,
        endpoint: &str,
    ) -> Result<(), Error> {
        let Some(hex) = peer_key_hex(peer_key_b64) else {
            return Err(Error::Message("peer key is not valid base64".into()));
        };
        let request = format!("set=1\npublic_key={hex}\nendpoint={endpoint}\n\n");
        self.uapi(&request)
    }
    fn latest_handshakes(&mut self, _interface: &str) -> Result<HashMap<String, u64>, Error> {
        let mut map = HashMap::new();
        let mut current_key: Option<String> = None;
        for (key, value) in self.uapi_pairs()? {
            match key.as_str() {
                "public_key" => current_key = Some(value.trim().to_owned()),
                "last_handshake_time_sec" => {
                    if let Some(hex_key) = &current_key {
                        map.insert(hex_key.clone(), value.trim().parse::<u64>().unwrap_or(0));
                    }
                }
                _ => {}
            }
        }
        Ok(map)
    }
    fn listen_endpoint(&mut self, _interface: &str) -> Result<Option<std::net::SocketAddr>, Error> {
        let port = self
            .uapi_pairs()?
            .into_iter()
            .find(|(k, _)| k == "listen_port")
            .and_then(|(_, v)| v.parse::<u16>().ok());
        match port {
            Some(port) if port != 0 => Ok(Some(std::net::SocketAddr::from(([127, 0, 0, 1], port)))),
            _ => Ok(None),
        }
    }
}

#[cfg(target_os = "macos")]
impl MacOsNetwork {
    /// UAPI `get=1` dump as ordered key/value pairs: per-peer blocks carry
    /// `public_key=<hex>` followed by `last_handshake_time_sec=<n>` (absent or
    /// zero when never handshaken). Keys repeat across peer blocks.
    fn uapi_pairs(&self) -> Result<Vec<(String, String)>, Error> {
        let name = self.utun_name()?;
        let path = format!("/var/run/wireguard/{name}.sock");
        let mut stream = std::os::unix::net::UnixStream::connect(path.clone())
            .map_err(|e| Error::Message(format!("connect WireGuard UAPI {path}: {e}")))?;
        use std::io::{Read as _, Write as _};
        stream
            .write_all(b"get=1\n\n")
            .and_then(|_| stream.shutdown(std::net::Shutdown::Write))
            .map_err(|e| Error::Message(format!("write WireGuard UAPI {path}: {e}")))?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        if !response.contains("errno=0") {
            return Err(Error::Message("WireGuard UAPI get failed".into()));
        }
        Ok(response
            .lines()
            .filter_map(|l| l.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
            .collect())
    }
}
pub async fn sync_once(
    coord: &Coordinator,
    network: &mut dyn Network,
    state: &mut NodeState,
    dir: &Path,
) -> Result<usize, Error> {
    let previous_assigned_ips = state.assigned_ips.clone();
    let previous_addresses = state.interface_addresses();
    let desired = match coord.wait_for_control_update(state, 0).await {
        Ok(Some(peers)) => peers,
        Ok(None) => return Ok(0),
        Err(error) => {
            tracing::warn!(
                %error,
                "control update snapshot failed; using peers recovery"
            );
            coord.peers(state).await?
        }
    };
    apply_peer_map(
        network,
        state,
        dir,
        desired,
        previous_assigned_ips,
        previous_addresses,
    )
}

pub fn apply_peer_map(
    network: &mut dyn Network,
    state: &mut NodeState,
    dir: &Path,
    desired: Vec<Peer>,
    previous_assigned_ips: Vec<String>,
    previous_addresses: Vec<String>,
) -> Result<usize, Error> {
    let desired_addresses = state.interface_addresses();
    if desired_addresses != previous_addresses {
        if let Err(error) = network.set_addresses(&state.interface, &desired_addresses) {
            state.assigned_ips = previous_assigned_ips;
            return Err(error);
        }
    }
    let installed = installable_wireguard_peers(&state.peers, &desired);
    let changes = peer_diff(&state.peers, &installed);
    network.apply(&state.interface, &changes)?;
    apply_peer_filter(network, dir, &state.interface, &installed)?;
    state.peers = installed;
    write_state(dir, state)?;
    Ok(changes.len())
}

fn apply_peer_filter(
    network: &mut dyn Network,
    dir: &Path,
    interface: &str,
    peers: &[Peer],
) -> Result<(), Error> {
    network.apply_ingress(interface, peers)?;
    write_secret(
        &dir.join("sshd_blaktail.conf"),
        acl_filter::sshd_policy_config(peers).as_bytes(),
    )
}

/// Reinstalls the persisted peer set after a platform backend recreates its
/// WireGuard interface. This keeps the last known mesh usable during a
/// coordinator outage and makes daemon restarts deterministic.
pub fn restore_peers(
    network: &mut dyn Network,
    state: &NodeState,
    dir: &Path,
) -> Result<usize, Error> {
    let changes: Vec<_> = state
        .peers
        .iter()
        .cloned()
        .map(PeerChange::Upsert)
        .collect();
    network.apply(&state.interface, &changes)?;
    apply_peer_filter(network, dir, &state.interface, &state.peers)?;
    Ok(changes.len())
}

pub fn validate_advertised_routes(routes: &[String]) -> Result<Vec<String>, Error> {
    if routes.len() > 32 {
        return Err(Error::Message("at most 32 routes may be advertised".into()));
    }
    let mut canonical = routes
        .iter()
        .map(|route| canonical_ipv4_route(route))
        .collect::<Result<Vec<_>, _>>()?;
    canonical.sort();
    canonical.dedup();
    for (index, route) in canonical.iter().enumerate() {
        if route != "0.0.0.0/0"
            && !["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
                .iter()
                .any(|private| ipv4_route_is_within(route, private))
        {
            return Err(Error::Message(format!(
                "route {route} must be an RFC1918 private subnet or 0.0.0.0/0"
            )));
        }
        if route != "0.0.0.0/0" && ipv4_routes_overlap(route, "100.64.0.0/10") {
            return Err(Error::Message(format!(
                "route {route} overlaps the BlakTail address pool"
            )));
        }
        if route != "0.0.0.0/0"
            && canonical[index + 1..]
                .iter()
                .any(|other| other != "0.0.0.0/0" && ipv4_routes_overlap(route, other))
        {
            return Err(Error::Message(format!(
                "route {route} overlaps another advertised route"
            )));
        }
    }
    Ok(canonical)
}

fn canonical_ipv4_route(route: &str) -> Result<String, Error> {
    let route = route.trim();
    let (address, prefix) = route
        .split_once('/')
        .ok_or_else(|| Error::Message(format!("route {route} must use CIDR notation")))?;
    let address: std::net::Ipv4Addr = address
        .parse()
        .map_err(|_| Error::Message(format!("route {route} must be IPv4 CIDR")))?;
    let prefix: u8 = prefix
        .parse()
        .ok()
        .filter(|prefix| *prefix <= 32)
        .ok_or_else(|| Error::Message(format!("route {route} has an invalid prefix")))?;
    let mask = ipv4_mask(prefix);
    let raw = u32::from(address);
    if raw & !mask != 0 {
        return Err(Error::Message(format!(
            "route {route} is not a network address"
        )));
    }
    if prefix != 0
        && (address.is_loopback()
            || address.is_link_local()
            || address.is_multicast()
            || address.is_broadcast())
    {
        return Err(Error::Message(format!(
            "route {route} is not a routable network"
        )));
    }
    Ok(format!("{address}/{prefix}"))
}

fn ipv4_routes_overlap(left: &str, right: &str) -> bool {
    let parse = |route: &str| {
        let (address, prefix) = route.split_once('/').expect("validated CIDR");
        (
            u32::from(
                address
                    .parse::<std::net::Ipv4Addr>()
                    .expect("validated IPv4"),
            ),
            prefix.parse::<u8>().expect("validated prefix"),
        )
    };
    let (left_address, left_prefix) = parse(left);
    let (right_address, right_prefix) = parse(right);
    let mask = ipv4_mask(left_prefix.min(right_prefix));
    left_address & mask == right_address & mask
}

fn ipv4_route_is_within(route: &str, container: &str) -> bool {
    let parse = |cidr: &str| {
        let (address, prefix) = cidr.split_once('/').expect("validated CIDR");
        (
            u32::from(
                address
                    .parse::<std::net::Ipv4Addr>()
                    .expect("validated IPv4"),
            ),
            prefix.parse::<u8>().expect("validated prefix"),
        )
    };
    let (address, prefix) = parse(route);
    let (container_address, container_prefix) = parse(container);
    prefix >= container_prefix
        && address & ipv4_mask(container_prefix) == container_address & ipv4_mask(container_prefix)
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

pub fn validate_interface(name: &str) -> Result<(), Error> {
    if name.is_empty()
        || name.len() > 15
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(Error::Message(
            "interface must be 1-15 ASCII letters, digits, '_' or '-'".into(),
        ));
    }
    Ok(())
}

fn apply_org_dns_snapshot(state: &mut NodeState, incoming: Option<OrgDnsSnapshot>) {
    dns::adopt_org_dns_snapshot(state, incoming);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingNetwork {
        applied: Vec<PeerChange>,
    }

    impl Network for RecordingNetwork {
        fn setup(
            &mut self,
            _interface: &str,
            _key: &Path,
            _addresses: &[String],
        ) -> Result<(), Error> {
            Ok(())
        }
        fn set_addresses(&mut self, _interface: &str, _addresses: &[String]) -> Result<(), Error> {
            Ok(())
        }
        fn apply(&mut self, _interface: &str, changes: &[PeerChange]) -> Result<(), Error> {
            self.applied.extend_from_slice(changes);
            Ok(())
        }
        fn down(&mut self, _interface: &str) -> Result<(), Error> {
            Ok(())
        }
        fn set_peer_endpoint(
            &mut self,
            _interface: &str,
            _peer_key_b64: &str,
            _endpoint: &str,
        ) -> Result<(), Error> {
            Ok(())
        }
        fn latest_handshakes(&mut self, _interface: &str) -> Result<HashMap<String, u64>, Error> {
            Ok(HashMap::new())
        }
        fn listen_endpoint(
            &mut self,
            _interface: &str,
        ) -> Result<Option<std::net::SocketAddr>, Error> {
            Ok(None)
        }
    }

    fn peer(key: &str, endpoint: Option<&str>) -> Peer {
        Peer {
            id: Uuid::nil(),
            name: key.into(),
            wg_public_key: key.into(),
            endpoint: endpoint.map(str::to_owned),
            allowed_ips: vec!["100.64.0.1/32".into()],
            dns_name: format!("{key}.tail.blaktail"),
            tags: vec![],
            relay_endpoint: None,
            ingress: None,
        }
    }
    #[test]
    fn overlapping_allowed_ips_keep_the_installed_key() {
        let mut old = peer("old", Some("192.0.2.10:51820"));
        old.allowed_ips = vec!["10.8.0.2/32".into()];
        let mut new = peer("new", Some("192.0.2.10:51820"));
        new.allowed_ips = vec!["10.8.0.2/32".into()];
        let installed = installable_wireguard_peers(&[old.clone()], &[new.clone(), old.clone()]);
        assert_eq!(
            installed
                .iter()
                .map(|peer| peer.wg_public_key.as_str())
                .collect::<Vec<_>>(),
            vec!["old"]
        );
        let after = installable_wireguard_peers(&[old.clone()], &[new.clone()]);
        assert_eq!(
            after
                .iter()
                .map(|peer| peer.wg_public_key.as_str())
                .collect::<Vec<_>>(),
            vec!["new"]
        );
    }

    #[test]
    fn same_key_adopts_desired_ingress() {
        let mut current = peer("vanilla", Some("192.0.2.10:51820"));
        current.allowed_ips = vec!["10.8.0.2/32".into()];
        current.ingress = Some(PeerIngress {
            all: true,
            ..PeerIngress::default()
        });
        let mut desired = current.clone();
        desired.ingress = Some(PeerIngress {
            tcp: vec!["8080".into()],
            ..PeerIngress::default()
        });
        let installed = installable_wireguard_peers(&[current], &[desired.clone()]);
        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0].wg_public_key, "vanilla");
        assert_eq!(installed[0].ingress, desired.ingress);
    }

    #[test]
    fn diff_removes_adds_and_updates() {
        assert_eq!(
            peer_diff(
                &[peer("gone", None), peer("changed", None)],
                &[peer("new", None), peer("changed", Some("192.0.2.1:51820"))]
            ),
            vec![
                PeerChange::Remove("gone".into()),
                PeerChange::Upsert(peer("changed", Some("192.0.2.1:51820"))),
                PeerChange::Upsert(peer("new", None))
            ]
        );
    }

    #[test]
    fn advertised_routes_are_canonical_and_non_overlapping() {
        assert_eq!(
            validate_advertised_routes(&[
                "10.20.0.0/16".into(),
                "0.0.0.0/0".into(),
                "10.20.0.0/16".into(),
            ])
            .unwrap(),
            vec!["0.0.0.0/0", "10.20.0.0/16"]
        );
        for invalid in [
            "10.20.0.1/16",
            "10.20.0.0/33",
            "100.64.1.0/24",
            "128.0.0.0/1",
            "192.0.2.0/24",
            "127.0.0.0/8",
            "10.20.0.0",
            "fd00::/8",
        ] {
            assert!(validate_advertised_routes(&[invalid.into()]).is_err());
        }
        assert!(
            validate_advertised_routes(&["10.20.0.0/16".into(), "10.20.1.0/24".into(),]).is_err()
        );
    }

    #[test]
    fn dual_stack_addresses_select_the_correct_kernel_family() {
        assert_eq!(iproute_family("100.64.0.1/32").unwrap(), "-4");
        assert_eq!(iproute_family("fd12:3456::1/128").unwrap(), "-6");
        assert!(parse_cidr("fd12:3456::1/129").is_err());
    }

    #[test]
    fn ipv6_route_helper_classifies_by_colon() {
        assert!(!is_ipv6_route("10.20.0.0/16"));
        assert!(!is_ipv6_route("0.0.0.0/0"));
        assert!(!is_ipv6_route("192.168.1.0/24"));
        assert!(is_ipv6_route("fd00::/8"));
        assert!(is_ipv6_route("::/0"));
        assert!(is_ipv6_route("2001:db8::/32"));
        assert!(is_ipv6_route("fd12:3456::1/128"));
    }

    #[test]
    fn empty_router_routes_short_circuit_without_touching_sysctl() {
        // With no stored original, teardown must not read sysctl at all, so
        // this passes without root or Linux networking tools present.
        let mut network = LinuxNetwork::default();
        assert_eq!(
            network
                .configure_router("blaktail0", &[], &[], None)
                .unwrap(),
            None
        );
        // Best-effort cleanup of stale rules (run_ignore) must not fail.
        let previous = vec!["10.20.0.0/16".to_string(), "fd00::/8".to_string()];
        assert_eq!(
            network
                .configure_router("blaktail0", &previous, &[], None)
                .unwrap(),
            None
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_routes_distinguish_ipv4_and_ipv6_hosts() {
        assert_eq!(
            MacOsNetwork::route_target("100.64.0.1/32").unwrap(),
            ("-inet", "-host", "100.64.0.1")
        );
        assert_eq!(
            MacOsNetwork::route_target("fd12:3456::1/128").unwrap(),
            ("-inet6", "-host", "fd12:3456::1")
        );
    }

    #[test]
    fn persisted_peers_are_reinstalled_after_interface_recreation() {
        let expected = peer("restored", Some("192.0.2.1:51820"));
        let state = NodeState {
            node_id: Uuid::nil(),
            node_token: "secret".into(),
            coord: "https://coord.example".into(),
            interface: "blaktail0".into(),
            assigned_ip: "100.64.0.1/32".into(),
            assigned_ips: vec!["100.64.0.1/32".into()],
            dns_name: "self.12345678.blaktail".into(),
            credential_expires_at: 1,
            advertised_routes: vec![],
            exit_node: None,
            exit_node_active: false,
            router_previous_ipv4_forward: None,
            peers: vec![expected.clone()],
            relays: vec![],
            relay_token: String::new(),
            relay_expires_at: 0,
            relay_endpoint: None,
            relay_endpoint_reported_at: 0,
            dns_mode: None,
            org_dns: None,
            dns_degraded: None,
            control_revision: 0,
            published_shares: vec![],
        };
        let mut network = RecordingNetwork::default();
        let dir =
            std::env::temp_dir().join(format!("blaktail-restore-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(restore_peers(&mut network, &state, &dir).unwrap(), 1);
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(network.applied, vec![PeerChange::Upsert(expected)]);
    }
    #[test]
    fn key_file_is_created_with_0600() {
        let dir = std::env::temp_dir().join(format!("blaktail-key-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let (path, public) = ensure_private_key(&dir).unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!public.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn insecure_existing_key_fails_closed() {
        let dir = std::env::temp_dir().join(format!("blaktail-mode-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        ensure_private_key(&dir).unwrap();
        fs::set_permissions(dir.join("private.key"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ensure_private_key(&dir).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn poll_without_dns_keeps_last_known_good_snapshot() {
        let mut state = NodeState {
            node_id: Uuid::from_u128(1),
            node_token: "secret".into(),
            coord: "http://localhost:3000".into(),
            interface: "blaktail0".into(),
            assigned_ip: "100.64.0.1/32".into(),
            assigned_ips: vec!["100.64.0.1/32".into()],
            dns_name: "self.12345678.blaktail".into(),
            credential_expires_at: 1,
            advertised_routes: vec![],
            exit_node: None,
            exit_node_active: false,
            router_previous_ipv4_forward: None,
            peers: vec![],
            relays: vec![],
            relay_token: String::new(),
            relay_expires_at: 0,
            relay_endpoint: None,
            relay_endpoint_reported_at: 0,
            dns_mode: None,
            org_dns: Some(OrgDnsSnapshot {
                revision: 4,
                managed: true,
                search_domains: vec!["internal.example".into()],
                ..OrgDnsSnapshot::default()
            }),
            dns_degraded: None,
            control_revision: 3,
            published_shares: vec![],
        };
        apply_org_dns_snapshot(&mut state, None);
        assert_eq!(state.org_dns.as_ref().map(|dns| dns.revision), Some(4));
        apply_org_dns_snapshot(
            &mut state,
            Some(OrgDnsSnapshot {
                revision: 5,
                managed: true,
                ..OrgDnsSnapshot::default()
            }),
        );
        assert_eq!(state.org_dns.as_ref().map(|dns| dns.revision), Some(5));
        assert!(state.org_dns.as_ref().unwrap().search_domains.is_empty());
    }

    #[test]
    fn control_update_snapshot_deserializes_revision() {
        let body: PeersResponse = serde_json::from_value(serde_json::json!({
            "kind": "snapshot",
            "revision": 8,
            "peers": [],
            "assigned_ips": ["100.64.0.1/32"],
            "dns_name": "self.12345678.blaktail"
        }))
        .unwrap();
        assert_eq!(body.revision, Some(8));
        assert!(body.peers.is_empty());
        let peers: PeersResponse = serde_json::from_value(serde_json::json!({
            "peers": [],
            "assigned_ips": [],
            "dns_name": "self.12345678.blaktail"
        }))
        .unwrap();
        assert_eq!(peers.revision, None);
    }

    #[test]
    fn control_update_delta_merges_added_and_removed_peers() {
        let kept = Uuid::from_u128(1);
        let gone = Uuid::from_u128(2);
        let added = Uuid::from_u128(3);
        let current = vec![
            Peer {
                id: kept,
                name: "kept".into(),
                wg_public_key: "kept-key".into(),
                endpoint: None,
                allowed_ips: vec!["100.64.0.2/32".into()],
                dns_name: "kept.blaktail".into(),
                tags: vec![],
                relay_endpoint: None,
                ingress: None,
            },
            Peer {
                id: gone,
                name: "gone".into(),
                wg_public_key: "gone-key".into(),
                endpoint: None,
                allowed_ips: vec!["100.64.0.3/32".into()],
                dns_name: "gone.blaktail".into(),
                tags: vec![],
                relay_endpoint: None,
                ingress: None,
            },
        ];
        let body = PeersResponse {
            kind: Some("delta".into()),
            peers: vec![],
            added: vec![Peer {
                id: added,
                name: "added".into(),
                wg_public_key: "added-key".into(),
                endpoint: None,
                allowed_ips: vec!["100.64.0.4/32".into()],
                dns_name: "added.blaktail".into(),
                tags: vec![],
                relay_endpoint: None,
                ingress: None,
            }],
            removed: vec![gone],
            assigned_ips: vec![],
            dns_name: String::new(),
            credential_expires_at: 0,
            exit_node_active: false,
            relays: vec![],
            relay_token: String::new(),
            relay_expires_at: 0,
            dns: None,
            revision: Some(9),
            shares: vec![],
        };
        let merged = Coordinator::apply_control_peers(&current, &body);
        assert_eq!(
            merged.iter().map(|peer| peer.id).collect::<Vec<_>>(),
            vec![kept, added]
        );
    }
}
