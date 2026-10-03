//! Optional MDM/EDR posture integrations (draft 08, ADR 0005).
//!
//! An organisation owner may connect read-only device inventories from
//! Microsoft Intune, CrowdStrike Falcon, SentinelOne, FleetDM or Huntress.
//! The coordinator polls each provider, keeps only the fields in
//! `DeviceSignal`, and matches records to its own devices inside the same
//! organisation. A posture check's `integration` requirement then reads the
//! matched signal. Credentials are sealed at rest and never returned,
//! audited or logged; provider errors are reduced to fixed categories.

use crate::{
    append_audit, bump_control_revision, console_session, now,
    permissions::{require, Permission},
    posture::{load_checks, MissingData},
    ApiError, AppState, Session, Store,
};
use axum::{
    extract::{Path as UrlPath, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post, put},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::{Rng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    time::Duration,
};
use tracing::warn;
use url::Url;
use uuid::Uuid;

const SEALED_PREFIX: &str = "btpi1.";
const MAX_INTEGRATIONS_PER_ORG: i64 = 8;
const DEFAULT_INTERVAL_SECS: i64 = 15 * 60;
const MIN_INTERVAL_SECS: i64 = 5 * 60;
const MAX_INTERVAL_SECS: i64 = 24 * 60 * 60;
const DEFAULT_MAX_AGE_SECS: i64 = 60 * 60;
const MIN_AGE_SECS: i64 = 60;
const MAX_AGE_SECS: i64 = 30 * 24 * 60 * 60;
/// Background reconciles running at once across all organisations.
const MAX_CONCURRENT_SYNCS: usize = 4;
const LOOP_TICK: Duration = Duration::from_secs(30);
const LEASE_SECS: i64 = 5 * 60;
const SYNC_TIMEOUT: Duration = Duration::from_secs(4 * 60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
const MAX_DEVICES: usize = 50_000;
const MAX_PAGES: usize = 500;
/// A 429 whose Retry-After fits inside this wait is retried in place.
const MAX_INLINE_RETRY_SECS: u64 = 30;
const MAX_RATE_RETRIES: usize = 3;
const MAX_BACKOFF_SECS: i64 = 6 * 60 * 60;

pub(crate) const PROVIDER_SOURCE: &str = "provider_reported";
pub(crate) const RESIDENCY_NOTICE: &str = "Provider calls leave this deployment. Device records are pulled from the vendor's cloud (or, for FleetDM, wherever its server runs), which may be outside Australia. BlakTail stores only the fields listed for each provider, in this coordinator's database, and does not verify where the vendor hosts your tenant.";

// ---------------------------------------------------------------------------
// Providers

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Kind {
    Intune,
    CrowdStrike,
    SentinelOne,
    FleetDm,
    Huntress,
}

impl Kind {
    const ALL: [Kind; 5] = [
        Kind::Intune,
        Kind::CrowdStrike,
        Kind::SentinelOne,
        Kind::FleetDm,
        Kind::Huntress,
    ];

    pub(crate) fn id(self) -> &'static str {
        match self {
            Kind::Intune => "intune",
            Kind::CrowdStrike => "crowdstrike",
            Kind::SentinelOne => "sentinelone",
            Kind::FleetDm => "fleetdm",
            Kind::Huntress => "huntress",
        }
    }

    fn parse(value: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|kind| kind.id() == value)
    }

    fn label(self) -> &'static str {
        match self {
            Kind::Intune => "Microsoft Intune",
            Kind::CrowdStrike => "CrowdStrike Falcon",
            Kind::SentinelOne => "SentinelOne",
            Kind::FleetDm => "FleetDM",
            Kind::Huntress => "Huntress",
        }
    }
}

const CROWDSTRIKE_REGIONS: &[(&str, &str)] = &[
    ("us-1", "https://api.crowdstrike.com"),
    ("us-2", "https://api.us-2.crowdstrike.com"),
    ("eu-1", "https://api.eu-1.crowdstrike.com"),
    ("us-gov-1", "https://api.laggar.gcw.crowdstrike.com"),
];

#[derive(Serialize)]
struct FieldInfo {
    name: &'static str,
    label: &'static str,
    help: &'static str,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    options: &'static [&'static str],
}

#[derive(Serialize)]
struct ProviderInfo {
    kind: &'static str,
    label: &'static str,
    fields: Vec<FieldInfo>,
    secret_label: &'static str,
    /// Least-privilege credential the operator must create.
    access: &'static str,
    data_collected: &'static str,
    compliance_rule: &'static str,
    residency: &'static str,
}

fn provider_info(kind: Kind) -> ProviderInfo {
    let field = |name, label, help| FieldInfo {
        name,
        label,
        help,
        options: &[],
    };
    match kind {
        Kind::Intune => ProviderInfo {
            kind: kind.id(),
            label: kind.label(),
            fields: vec![
                field("tenant_id", "Directory (tenant) ID", "Microsoft Entra tenant GUID or primary domain."),
                field("client_id", "Application (client) ID", "App registration used only for this integration."),
            ],
            secret_label: "Client secret",
            access: "Microsoft Entra app registration with the application permission DeviceManagementManagedDevices.Read.All (admin consent), OAuth 2.0 client credentials. No write permissions.",
            data_collected: "Managed device ID, device name, serial number, Wi-Fi and Ethernet MAC addresses, compliance state and last sync time from GET /v1.0/deviceManagement/managedDevices.",
            compliance_rule: "complianceState must be \"compliant\". In grace period, non-compliant, conflict, error, unknown and Configuration Manager states do not pass.",
            residency: "Microsoft Graph global endpoint (graph.microsoft.com). Your Intune tenant's data location was chosen when the tenant was created; BlakTail does not verify it.",
        },
        Kind::CrowdStrike => ProviderInfo {
            kind: kind.id(),
            label: kind.label(),
            fields: vec![
                FieldInfo {
                    name: "region",
                    label: "Falcon cloud",
                    help: "The Falcon cloud your tenant lives in.",
                    options: &["us-1", "us-2", "eu-1", "us-gov-1"],
                },
                field("client_id", "API client ID", "Falcon API client created for this integration."),
            ],
            secret_label: "API client secret",
            access: "Falcon API client with only the Hosts: Read scope. OAuth 2.0 client credentials.",
            data_collected: "Host ID, hostname, serial number, MAC address, sensor status (normal or contained), reduced-functionality mode and last-seen time from the Hosts API.",
            compliance_rule: "Sensor status must be \"normal\" (not contained or containment pending) and not in reduced functionality mode. Use the rule's last-seen limit to require a recently active sensor.",
            residency: "The Falcon clouds this integration supports (US-1, US-2, EU-1, US-GOV-1) are hosted outside Australia.",
        },
        Kind::SentinelOne => ProviderInfo {
            kind: kind.id(),
            label: kind.label(),
            fields: vec![field(
                "console_url",
                "Management console URL",
                "For example https://your-tenant.sentinelone.net",
            )],
            secret_label: "API token",
            access: "Service user API token with the Viewer role, scoped to the account or site whose endpoints should count.",
            data_collected: "Agent ID, computer name, serial number, physical MAC addresses, infected, active and up-to-date flags and last-active time from GET /web/api/v2.1/agents.",
            compliance_rule: "Agent must be active, not infected and up to date.",
            residency: "SentinelOne hosts each console in a vendor-chosen region; check your console's region with SentinelOne. BlakTail does not verify it.",
        },
        Kind::FleetDm => ProviderInfo {
            kind: kind.id(),
            label: kind.label(),
            fields: vec![field(
                "server_url",
                "Fleet server URL",
                "Public HTTPS address of your Fleet server.",
            )],
            secret_label: "API token",
            access: "API-only user with the Observer role (global or the relevant team). Fleet must be reachable over public HTTPS from the coordinator.",
            data_collected: "Host ID, hostname, hardware serial, primary MAC address, failing-policy count and last-seen time from GET /api/v1/fleet/hosts.",
            compliance_rule: "The host must have zero failing policies.",
            residency: "Depends on where your Fleet server runs. Self-hosted Fleet in Australia keeps device data onshore; Fleet-managed cloud may not.",
        },
        Kind::Huntress => ProviderInfo {
            kind: kind.id(),
            label: kind.label(),
            fields: vec![field("api_key", "API key", "Public half of the Huntress API key pair.")],
            secret_label: "API secret key",
            access: "Huntress API key pair. Huntress keys are account-wide; BlakTail only calls GET /v1/agents.",
            data_collected: "Agent ID, hostname, serial number, MAC addresses and last callback time from GET /v1/agents.",
            compliance_rule: "The Huntress agent must be installed. Set the rule's last-seen limit to require a recent callback.",
            residency: "Huntress's API is hosted outside Australia (api.huntress.io).",
        },
    }
}

/// Non-secret provider settings. Each provider accepts only its own fields.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    console_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    server_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    api_key: Option<String>,
    /// Also match on hostname when no serial or MAC matches. Hostnames are
    /// chosen by users, so this is weaker and off by default.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    match_hostname: bool,
    /// Test builds only: send every provider call to a local mock server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    api_base_override: Option<String>,
}

#[derive(Clone, Debug)]
struct Endpoints {
    token_url: Option<String>,
    api_base: String,
}

fn token_like(value: &Option<String>, label: &str) -> Result<String, ApiError> {
    let value = value.as_deref().map(str::trim).unwrap_or_default();
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(ApiError::BadRequest(format!(
            "{label} must be 1-128 letters, digits, '-', '_' or '.'"
        )));
    }
    Ok(value.to_owned())
}

fn https_origin(raw: &str, label: &str) -> Result<Url, ApiError> {
    let url = crate::webhooks::validate_destination_url(raw.trim(), cfg!(test))
        .map_err(|_| ApiError::BadRequest(format!("{label} must be a public https URL")))?;
    if url.query().is_some() || url.fragment().is_some() || !matches!(url.path(), "" | "/") {
        return Err(ApiError::BadRequest(format!(
            "{label} must be just the server address, without a path"
        )));
    }
    Ok(url)
}

fn origin(url: &Url) -> String {
    url.as_str().trim_end_matches('/').to_owned()
}

fn validate_config(kind: Kind, config: &ProviderConfig) -> Result<Endpoints, ApiError> {
    let allowed: &[&str] = match kind {
        Kind::Intune => &["tenant_id", "client_id"],
        Kind::CrowdStrike => &["region", "client_id"],
        Kind::SentinelOne => &["console_url"],
        Kind::FleetDm => &["server_url"],
        Kind::Huntress => &["api_key"],
    };
    let present = [
        ("tenant_id", config.tenant_id.is_some()),
        ("client_id", config.client_id.is_some()),
        ("region", config.region.is_some()),
        ("console_url", config.console_url.is_some()),
        ("server_url", config.server_url.is_some()),
        ("api_key", config.api_key.is_some()),
    ];
    if let Some((name, _)) = present
        .iter()
        .find(|(name, set)| *set && !allowed.contains(name))
    {
        return Err(ApiError::BadRequest(format!(
            "{} does not use {name}",
            kind.label()
        )));
    }
    let override_base = match &config.api_base_override {
        Some(_) if !cfg!(test) => {
            return Err(ApiError::BadRequest(
                "api_base_override is only available in test builds".into(),
            ))
        }
        Some(raw) => Some(origin(&https_origin(raw, "api_base_override")?)),
        None => None,
    };
    let endpoints = match kind {
        Kind::Intune => {
            let tenant = token_like(&config.tenant_id, "tenant_id")?;
            token_like(&config.client_id, "client_id")?;
            let (login, graph) = match &override_base {
                Some(base) => (base.clone(), base.clone()),
                None => (
                    "https://login.microsoftonline.com".to_owned(),
                    "https://graph.microsoft.com".to_owned(),
                ),
            };
            Endpoints {
                token_url: Some(format!("{login}/{tenant}/oauth2/v2.0/token")),
                api_base: format!("{graph}/v1.0"),
            }
        }
        Kind::CrowdStrike => {
            token_like(&config.client_id, "client_id")?;
            let region = config.region.as_deref().unwrap_or_default();
            let base = CROWDSTRIKE_REGIONS
                .iter()
                .find(|(id, _)| *id == region)
                .map(|(_, base)| (*base).to_owned())
                .ok_or_else(|| {
                    ApiError::BadRequest("region must be us-1, us-2, eu-1 or us-gov-1".into())
                })?;
            let base = override_base.unwrap_or(base);
            Endpoints {
                token_url: Some(format!("{base}/oauth2/token")),
                api_base: base,
            }
        }
        Kind::SentinelOne => {
            let url = https_origin(
                config.console_url.as_deref().unwrap_or_default(),
                "console_url",
            )?;
            let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
            if url.scheme() != "https" || !host.ends_with(".sentinelone.net") {
                return Err(ApiError::BadRequest(
                    "console_url must be an https://<tenant>.sentinelone.net address".into(),
                ));
            }
            Endpoints {
                token_url: None,
                api_base: override_base.unwrap_or_else(|| origin(&url)),
            }
        }
        Kind::FleetDm => {
            let url = https_origin(
                config.server_url.as_deref().unwrap_or_default(),
                "server_url",
            )?;
            Endpoints {
                token_url: None,
                api_base: override_base.unwrap_or_else(|| origin(&url)),
            }
        }
        Kind::Huntress => {
            token_like(&config.api_key, "api_key")?;
            Endpoints {
                token_url: None,
                api_base: override_base.unwrap_or_else(|| "https://api.huntress.io".into()),
            }
        }
    };
    Ok(endpoints)
}

// ---------------------------------------------------------------------------
// Sealed credentials

/// A provider credential. `Debug` never prints the value.
struct Secret(String);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

fn seal_cipher(master: &[u8]) -> Result<ChaCha20Poly1305, ApiError> {
    // Same construction as webhook signing secrets, with its own key domain.
    let key = Sha256::new()
        .chain_update(b"blaktail-posture-integration-v1")
        .chain_update(master)
        .finalize();
    ChaCha20Poly1305::new_from_slice(&key).map_err(|_| ApiError::CorruptData)
}

fn seal_secret(master: &[u8], plaintext: &str) -> Result<String, ApiError> {
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ciphertext = seal_cipher(master)?
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
        .map_err(|_| ApiError::CorruptData)?;
    let mut packed = nonce.to_vec();
    packed.extend(ciphertext);
    Ok(format!("{SEALED_PREFIX}{}", STANDARD.encode(packed)))
}

fn open_secret(master: &[u8], sealed: &str) -> Result<Secret, ApiError> {
    let raw = STANDARD
        .decode(
            sealed
                .strip_prefix(SEALED_PREFIX)
                .ok_or(ApiError::CorruptData)?,
        )
        .map_err(|_| ApiError::CorruptData)?;
    if raw.len() <= 12 {
        return Err(ApiError::CorruptData);
    }
    let (nonce, ciphertext) = raw.split_at(12);
    let plaintext = seal_cipher(master)?
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| ApiError::CorruptData)?;
    String::from_utf8(plaintext)
        .map(Secret)
        .map_err(|_| ApiError::CorruptData)
}

/// Lets the console show that a secret changed without revealing any of it.
fn secret_fingerprint(plaintext: &str) -> String {
    let digest = Sha256::new()
        .chain_update(b"blaktail-posture-integration-fingerprint")
        .chain_update(plaintext.as_bytes())
        .finalize();
    format!(
        "sha256:{}",
        digest[..4]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

fn validate_secret(value: &str) -> Result<&str, ApiError> {
    let value = value.trim();
    if value.len() < 8 || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "secret must be 8-4096 printable characters".into(),
        ));
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// HTTP with bounded retries; errors carry categories, never provider text.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdapterError {
    /// 401/403 or a refused token request: wrong credential or scope.
    Auth,
    /// 429 that did not clear within the inline retries.
    RateLimited(u64),
    Status(u16),
    Unreachable,
    /// The provider host failed the outbound address policy.
    Blocked,
    BadResponse,
    TooLarge,
}

impl AdapterError {
    fn code(self) -> &'static str {
        match self {
            AdapterError::Auth => "auth_failed",
            AdapterError::RateLimited(_) => "rate_limited",
            AdapterError::Status(_) => "provider_error",
            AdapterError::Unreachable => "unreachable",
            AdapterError::Blocked => "blocked_address",
            AdapterError::BadResponse => "bad_response",
            AdapterError::TooLarge => "too_large",
        }
    }

    fn message(self) -> String {
        match self {
            AdapterError::Auth => "The provider rejected the credential. Check the secret, client ID and that the read-only scope is granted.".into(),
            AdapterError::RateLimited(secs) => format!("The provider rate-limited requests; retrying after at least {secs} seconds."),
            AdapterError::Status(code) => format!("The provider returned HTTP {code}."),
            AdapterError::Unreachable => "The provider could not be reached or timed out.".into(),
            AdapterError::Blocked => "The provider address resolves to a private or blocked network address.".into(),
            AdapterError::BadResponse => "The provider response was not in the documented format.".into(),
            AdapterError::TooLarge => format!("The provider returned more than {MAX_DEVICES} devices or an oversized page."),
        }
    }
}

pub(crate) struct Http {
    client: reqwest::Client,
}

impl Http {
    /// Builds a client that connects only to the checked addresses of the
    /// given URLs and never follows redirects.
    async fn for_urls(urls: &[&str]) -> Result<Http, AdapterError> {
        let mut builder = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("blaktail-coord/", env!("CARGO_PKG_VERSION")));
        for raw in urls {
            let url = crate::webhooks::validate_destination_url(raw, cfg!(test))
                .map_err(|_| AdapterError::Blocked)?;
            let pinned = crate::webhooks::revalidate_resolved_ips(&url)
                .await
                .map_err(|_| AdapterError::Blocked)?;
            if let (Some(host), Some(addr)) = (url.host_str(), pinned) {
                builder = builder.resolve(host, addr);
            }
        }
        Ok(Http {
            client: builder.build().map_err(|_| AdapterError::Unreachable)?,
        })
    }

    async fn send(
        &self,
        request: impl Fn(&reqwest::Client) -> reqwest::RequestBuilder,
    ) -> Result<Vec<u8>, AdapterError> {
        let mut attempt = 0;
        loop {
            let response = request(&self.client)
                .send()
                .await
                .map_err(|_| AdapterError::Unreachable)?;
            let status = response.status().as_u16();
            if status == 429 {
                let wait = retry_after(response.headers()).unwrap_or(5);
                if attempt < MAX_RATE_RETRIES && wait <= MAX_INLINE_RETRY_SECS {
                    attempt += 1;
                    tokio::time::sleep(Duration::from_secs(wait.max(1))).await;
                    continue;
                }
                return Err(AdapterError::RateLimited(wait.max(1)));
            }
            if matches!(status, 400 | 401 | 403) {
                // Token endpoints answer a bad client secret with 400/401.
                return Err(AdapterError::Auth);
            }
            if !(200..300).contains(&status) {
                return Err(AdapterError::Status(status));
            }
            if response
                .content_length()
                .is_some_and(|len| len as usize > MAX_BODY_BYTES)
            {
                return Err(AdapterError::TooLarge);
            }
            let body = response
                .bytes()
                .await
                .map_err(|_| AdapterError::Unreachable)?;
            if body.len() > MAX_BODY_BYTES {
                return Err(AdapterError::TooLarge);
            }
            return Ok(body.to_vec());
        }
    }

    async fn json<T: DeserializeOwned>(
        &self,
        request: impl Fn(&reqwest::Client) -> reqwest::RequestBuilder,
    ) -> Result<T, AdapterError> {
        serde_json::from_slice(&self.send(request).await?).map_err(|_| AdapterError::BadResponse)
    }

    /// OAuth 2.0 client-credentials grant; returns the bearer token.
    async fn client_credentials(
        &self,
        token_url: &str,
        client_id: &str,
        secret: &Secret,
        scope: Option<&str>,
    ) -> Result<String, AdapterError> {
        #[derive(Deserialize)]
        struct Token {
            access_token: String,
        }
        let mut form = vec![
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", secret.0.as_str()),
        ];
        if let Some(scope) = scope {
            form.push(("scope", scope));
        }
        let token: Token = self
            .json(|client| client.post(token_url).form(&form))
            .await
            .map_err(|error| match error {
                AdapterError::Status(_) | AdapterError::BadResponse => AdapterError::Auth,
                other => other,
            })?;
        if token.access_token.is_empty() {
            return Err(AdapterError::Auth);
        }
        Ok(token.access_token)
    }
}

fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    let text = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    if let Some(secs) = text("retry-after").and_then(|v| v.trim().parse::<u64>().ok()) {
        return Some(secs.min(3600));
    }
    // CrowdStrike sends the epoch second at which the window reopens.
    text("x-ratelimit-retryafter")
        .and_then(|v| v.trim().parse::<i64>().ok())
        .map(|at| (at - now()).clamp(1, 3600) as u64)
}

fn parse_time(value: Option<&str>) -> Option<i64> {
    let at = chrono::DateTime::parse_from_rfc3339(value?.trim())
        .ok()?
        .timestamp();
    // Graph reports "never" as 0001-01-01.
    (at > 946_684_800).then_some(at)
}

// ---------------------------------------------------------------------------
// Adapter contract (ADR 0005)

/// One provider record, reduced to the fields BlakTail keeps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeviceSignal {
    pub(crate) external_id: String,
    pub(crate) hostname: Option<String>,
    pub(crate) serial_number: Option<String>,
    pub(crate) mac_addresses: Vec<String>,
    /// `None` when the provider gives no usable verdict.
    pub(crate) compliant: Option<bool>,
    /// Short provider status label shown to administrators.
    pub(crate) status: String,
    /// The provider's last contact with the device, not BlakTail's sync time.
    pub(crate) last_seen_at: Option<i64>,
}

trait PostureAdapter {
    fn kind(&self) -> Kind;
    /// Pulls the provider's current view of the organisation's devices.
    async fn reconcile(
        &self,
        http: &Http,
        secret: &Secret,
    ) -> Result<Vec<DeviceSignal>, AdapterError>;
}

fn push_signal(out: &mut Vec<DeviceSignal>, signal: DeviceSignal) -> Result<(), AdapterError> {
    if out.len() >= MAX_DEVICES {
        return Err(AdapterError::TooLarge);
    }
    if signal.external_id.is_empty() || signal.external_id.len() > 128 {
        return Err(AdapterError::BadResponse);
    }
    out.push(signal);
    Ok(())
}

fn short(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().chars().take(128).collect::<String>())
        .filter(|v| !v.is_empty())
}

struct Intune<'a> {
    endpoints: &'a Endpoints,
    client_id: &'a str,
}

impl PostureAdapter for Intune<'_> {
    fn kind(&self) -> Kind {
        Kind::Intune
    }

    async fn reconcile(
        &self,
        http: &Http,
        secret: &Secret,
    ) -> Result<Vec<DeviceSignal>, AdapterError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Device {
            id: String,
            device_name: Option<String>,
            serial_number: Option<String>,
            wi_fi_mac_address: Option<String>,
            ethernet_mac_address: Option<String>,
            compliance_state: Option<String>,
            last_sync_date_time: Option<String>,
        }
        #[derive(Deserialize)]
        struct Page {
            value: Vec<Device>,
            #[serde(rename = "@odata.nextLink")]
            next_link: Option<String>,
        }
        let token = http
            .client_credentials(
                self.endpoints.token_url.as_deref().unwrap_or_default(),
                self.client_id,
                secret,
                Some("https://graph.microsoft.com/.default"),
            )
            .await?;
        let base = &self.endpoints.api_base;
        let mut next = Some(format!(
            "{base}/deviceManagement/managedDevices?$select=id,deviceName,serialNumber,wiFiMacAddress,ethernetMacAddress,complianceState,lastSyncDateTime"
        ));
        let mut out = Vec::new();
        for _ in 0..MAX_PAGES {
            let Some(url) = next.take() else {
                return Ok(out);
            };
            let page: Page = http.json(|c| c.get(&url).bearer_auth(&token)).await?;
            for device in page.value {
                let state = device.compliance_state.unwrap_or_default();
                push_signal(
                    &mut out,
                    DeviceSignal {
                        external_id: device.id,
                        hostname: short(device.device_name),
                        serial_number: short(device.serial_number),
                        mac_addresses: [device.wi_fi_mac_address, device.ethernet_mac_address]
                            .into_iter()
                            .flatten()
                            .collect(),
                        compliant: match state.as_str() {
                            "compliant" => Some(true),
                            "" | "unknown" => None,
                            _ => Some(false),
                        },
                        status: if state.is_empty() {
                            "unknown".into()
                        } else {
                            state.chars().take(32).collect()
                        },
                        last_seen_at: parse_time(device.last_sync_date_time.as_deref()),
                    },
                )?;
            }
            // Follow only links back to the same Graph endpoint.
            if let Some(link) = page.next_link {
                if !link.starts_with(&format!("{base}/")) {
                    return Err(AdapterError::BadResponse);
                }
                next = Some(link);
            }
        }
        Err(AdapterError::TooLarge)
    }
}

struct CrowdStrike<'a> {
    endpoints: &'a Endpoints,
    client_id: &'a str,
}

const CROWDSTRIKE_PAGE: usize = 5000;

impl PostureAdapter for CrowdStrike<'_> {
    fn kind(&self) -> Kind {
        Kind::CrowdStrike
    }

    async fn reconcile(
        &self,
        http: &Http,
        secret: &Secret,
    ) -> Result<Vec<DeviceSignal>, AdapterError> {
        #[derive(Deserialize, Default)]
        struct Pagination {
            #[serde(default)]
            offset: Option<String>,
            #[serde(default)]
            total: Option<u64>,
        }
        #[derive(Deserialize, Default)]
        struct Meta {
            #[serde(default)]
            pagination: Pagination,
        }
        #[derive(Deserialize)]
        struct Ids {
            #[serde(default)]
            meta: Meta,
            #[serde(default)]
            resources: Vec<String>,
        }
        #[derive(Deserialize)]
        struct Host {
            device_id: String,
            hostname: Option<String>,
            serial_number: Option<String>,
            mac_address: Option<String>,
            last_seen: Option<String>,
            status: Option<String>,
            reduced_functionality_mode: Option<String>,
        }
        #[derive(Deserialize)]
        struct Hosts {
            #[serde(default)]
            resources: Vec<Host>,
        }
        let token = http
            .client_credentials(
                self.endpoints.token_url.as_deref().unwrap_or_default(),
                self.client_id,
                secret,
                None,
            )
            .await?;
        let base = &self.endpoints.api_base;
        let mut ids: Vec<String> = Vec::new();
        let mut offset: Option<String> = None;
        for page in 0.. {
            if page >= MAX_PAGES {
                return Err(AdapterError::TooLarge);
            }
            let mut url =
                format!("{base}/devices/queries/devices-scroll/v1?limit={CROWDSTRIKE_PAGE}");
            if let Some(token) = &offset {
                url.push_str("&offset=");
                url.push_str(&urlencode(token));
            }
            let batch: Ids = http.json(|c| c.get(&url).bearer_auth(&token)).await?;
            let count = batch.resources.len();
            ids.extend(batch.resources);
            if ids.len() > MAX_DEVICES {
                return Err(AdapterError::TooLarge);
            }
            let total = batch.meta.pagination.total.unwrap_or(0) as usize;
            offset = batch.meta.pagination.offset.filter(|o| !o.is_empty());
            if count == 0 || offset.is_none() || ids.len() >= total {
                break;
            }
        }
        let mut out = Vec::new();
        for chunk in ids.chunks(CROWDSTRIKE_PAGE) {
            let body = serde_json::json!({ "ids": chunk });
            let hosts: Hosts = http
                .json(|c| {
                    c.post(format!("{base}/devices/entities/devices/v2"))
                        .bearer_auth(&token)
                        .json(&body)
                })
                .await?;
            for host in hosts.resources {
                let status = host.status.unwrap_or_else(|| "unknown".into());
                let reduced = host
                    .reduced_functionality_mode
                    .is_some_and(|mode| mode.eq_ignore_ascii_case("yes"));
                push_signal(
                    &mut out,
                    DeviceSignal {
                        external_id: host.device_id,
                        hostname: short(host.hostname),
                        serial_number: short(host.serial_number),
                        mac_addresses: host.mac_address.into_iter().collect(),
                        compliant: Some(status == "normal" && !reduced),
                        status: if reduced {
                            format!("{status}, reduced functionality")
                        } else {
                            status.chars().take(32).collect()
                        },
                        last_seen_at: parse_time(host.last_seen.as_deref()),
                    },
                )?;
            }
        }
        Ok(out)
    }
}

fn urlencode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

struct SentinelOne<'a> {
    endpoints: &'a Endpoints,
}

impl PostureAdapter for SentinelOne<'_> {
    fn kind(&self) -> Kind {
        Kind::SentinelOne
    }

    async fn reconcile(
        &self,
        http: &Http,
        secret: &Secret,
    ) -> Result<Vec<DeviceSignal>, AdapterError> {
        #[derive(Deserialize)]
        struct Interface {
            physical: Option<String>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Agent {
            id: String,
            computer_name: Option<String>,
            serial_number: Option<String>,
            #[serde(default)]
            network_interfaces: Vec<Interface>,
            infected: Option<bool>,
            is_active: Option<bool>,
            is_up_to_date: Option<bool>,
            last_active_date: Option<String>,
        }
        #[derive(Deserialize, Default)]
        #[serde(rename_all = "camelCase")]
        struct Pagination {
            next_cursor: Option<String>,
        }
        #[derive(Deserialize)]
        struct Page {
            #[serde(default)]
            data: Vec<Agent>,
            #[serde(default)]
            pagination: Pagination,
        }
        let base = &self.endpoints.api_base;
        let auth = format!("ApiToken {}", secret.0);
        let mut cursor: Option<String> = None;
        let mut out = Vec::new();
        for _ in 0..MAX_PAGES {
            let mut url = format!("{base}/web/api/v2.1/agents?limit=1000");
            if let Some(cursor) = &cursor {
                url.push_str("&cursor=");
                url.push_str(&urlencode(cursor));
            }
            let page: Page = http
                .json(|c| c.get(&url).header("authorization", &auth))
                .await?;
            for agent in page.data {
                let infected = agent.infected.unwrap_or(true);
                let active = agent.is_active.unwrap_or(false);
                let current = agent.is_up_to_date.unwrap_or(false);
                push_signal(
                    &mut out,
                    DeviceSignal {
                        external_id: agent.id,
                        hostname: short(agent.computer_name),
                        serial_number: short(agent.serial_number),
                        mac_addresses: agent
                            .network_interfaces
                            .into_iter()
                            .filter_map(|i| i.physical)
                            .collect(),
                        compliant: Some(!infected && active && current),
                        status: if infected {
                            "infected"
                        } else if !active {
                            "inactive"
                        } else if !current {
                            "agent out of date"
                        } else {
                            "healthy"
                        }
                        .into(),
                        last_seen_at: parse_time(agent.last_active_date.as_deref()),
                    },
                )?;
            }
            cursor = page.pagination.next_cursor.filter(|c| !c.is_empty());
            if cursor.is_none() {
                return Ok(out);
            }
        }
        Err(AdapterError::TooLarge)
    }
}

struct FleetDm<'a> {
    endpoints: &'a Endpoints,
}

const FLEET_PAGE: usize = 500;

impl PostureAdapter for FleetDm<'_> {
    fn kind(&self) -> Kind {
        Kind::FleetDm
    }

    async fn reconcile(
        &self,
        http: &Http,
        secret: &Secret,
    ) -> Result<Vec<DeviceSignal>, AdapterError> {
        #[derive(Deserialize, Default)]
        struct Issues {
            failing_policies_count: Option<u64>,
        }
        #[derive(Deserialize)]
        struct Host {
            id: u64,
            hostname: Option<String>,
            hardware_serial: Option<String>,
            primary_mac: Option<String>,
            seen_time: Option<String>,
            #[serde(default)]
            issues: Option<Issues>,
        }
        #[derive(Deserialize)]
        struct Page {
            #[serde(default)]
            hosts: Vec<Host>,
        }
        let base = &self.endpoints.api_base;
        let mut out = Vec::new();
        for page_number in 0..MAX_PAGES {
            let url = format!(
                "{base}/api/v1/fleet/hosts?page={page_number}&per_page={FLEET_PAGE}&order_key=id"
            );
            let page: Page = http.json(|c| c.get(&url).bearer_auth(&secret.0)).await?;
            let count = page.hosts.len();
            for host in page.hosts {
                let failing = host.issues.and_then(|issues| issues.failing_policies_count);
                push_signal(
                    &mut out,
                    DeviceSignal {
                        external_id: host.id.to_string(),
                        hostname: short(host.hostname),
                        serial_number: short(host.hardware_serial),
                        mac_addresses: host.primary_mac.into_iter().collect(),
                        compliant: failing.map(|count| count == 0),
                        status: match failing {
                            Some(0) => "all policies passing".into(),
                            Some(count) => format!("{count} failing policies"),
                            None => "policy results unavailable".into(),
                        },
                        last_seen_at: parse_time(host.seen_time.as_deref()),
                    },
                )?;
            }
            if count < FLEET_PAGE {
                return Ok(out);
            }
        }
        Err(AdapterError::TooLarge)
    }
}

struct Huntress<'a> {
    endpoints: &'a Endpoints,
    api_key: &'a str,
}

impl PostureAdapter for Huntress<'_> {
    fn kind(&self) -> Kind {
        Kind::Huntress
    }

    async fn reconcile(
        &self,
        http: &Http,
        secret: &Secret,
    ) -> Result<Vec<DeviceSignal>, AdapterError> {
        #[derive(Deserialize)]
        struct Agent {
            id: u64,
            hostname: Option<String>,
            serial_number: Option<String>,
            #[serde(default)]
            mac_addresses: Vec<String>,
            last_callback_at: Option<String>,
        }
        #[derive(Deserialize, Default)]
        struct Pagination {
            next_page_token: Option<String>,
        }
        #[derive(Deserialize)]
        struct Page {
            #[serde(default)]
            agents: Vec<Agent>,
            #[serde(default)]
            pagination: Pagination,
        }
        let base = &self.endpoints.api_base;
        let auth = format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", self.api_key, secret.0))
        );
        let mut token: Option<String> = None;
        let mut out = Vec::new();
        for _ in 0..MAX_PAGES {
            let mut url = format!("{base}/v1/agents?limit=500");
            if let Some(token) = &token {
                url.push_str("&page_token=");
                url.push_str(&urlencode(token));
            }
            let page: Page = http
                .json(|c| c.get(&url).header("authorization", &auth))
                .await?;
            for agent in page.agents {
                push_signal(
                    &mut out,
                    DeviceSignal {
                        external_id: agent.id.to_string(),
                        hostname: short(agent.hostname),
                        serial_number: short(agent.serial_number),
                        mac_addresses: agent.mac_addresses,
                        compliant: Some(true),
                        status: "agent installed".into(),
                        last_seen_at: parse_time(agent.last_callback_at.as_deref()),
                    },
                )?;
            }
            token = page.pagination.next_page_token.filter(|t| !t.is_empty());
            if token.is_none() {
                return Ok(out);
            }
        }
        Err(AdapterError::TooLarge)
    }
}

async fn reconcile_with(
    adapter: impl PostureAdapter,
    http: &Http,
    secret: &Secret,
) -> Result<Vec<DeviceSignal>, AdapterError> {
    let result = adapter.reconcile(http, secret).await;
    if let Err(error) = &result {
        tracing::debug!(
            provider = adapter.kind().id(),
            error = error.code(),
            "provider reconcile failed"
        );
    }
    result
}

async fn run_adapter(
    kind: Kind,
    config: &ProviderConfig,
    endpoints: &Endpoints,
    secret: &Secret,
) -> Result<Vec<DeviceSignal>, AdapterError> {
    let mut hosts = vec![endpoints.api_base.as_str()];
    hosts.extend(endpoints.token_url.as_deref());
    let http = Http::for_urls(&hosts).await?;
    let client_id = config.client_id.as_deref().unwrap_or_default();
    let signals = match kind {
        Kind::Intune => {
            reconcile_with(
                Intune {
                    endpoints,
                    client_id,
                },
                &http,
                secret,
            )
            .await
        }
        Kind::CrowdStrike => {
            reconcile_with(
                CrowdStrike {
                    endpoints,
                    client_id,
                },
                &http,
                secret,
            )
            .await
        }
        Kind::SentinelOne => reconcile_with(SentinelOne { endpoints }, &http, secret).await,
        Kind::FleetDm => reconcile_with(FleetDm { endpoints }, &http, secret).await,
        Kind::Huntress => {
            reconcile_with(
                Huntress {
                    endpoints,
                    api_key: config.api_key.as_deref().unwrap_or_default(),
                },
                &http,
                secret,
            )
            .await
        }
    }?;
    // Providers may repeat a record across pages; keep the last one.
    let unique: BTreeMap<String, DeviceSignal> = signals
        .into_iter()
        .map(|signal| (signal.external_id.clone(), signal))
        .collect();
    Ok(unique.into_values().collect())
}

// ---------------------------------------------------------------------------
// Matching

/// Normalised serial, or `None` for blanks and common firmware placeholders.
pub(crate) fn normalise_serial(value: &str) -> Option<String> {
    let serial: String = value
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    const PLACEHOLDERS: &[&str] = &[
        "TOBEFILLEDBYO.E.M.",
        "DEFAULTSTRING",
        "SYSTEMSERIALNUMBER",
        "CHASSISSERIALNUMBER",
        "NOTSPECIFIED",
        "NOTAPPLICABLE",
        "N/A",
        "NONE",
        "UNKNOWN",
        "INVALID",
        "0123456789",
        "123456789",
    ];
    let first = serial.chars().next()?;
    if serial.len() < 4
        || serial.len() > 64
        || serial.chars().all(|c| c == first)
        || serial.chars().any(|c| c.is_control())
        || PLACEHOLDERS.contains(&serial.as_str())
    {
        return None;
    }
    Some(serial)
}

/// `aa:bb:cc:dd:ee:ff` for a globally unique unicast MAC. Randomised
/// (locally administered), multicast and all-zero addresses never match.
pub(crate) fn normalise_mac(value: &str) -> Option<String> {
    let hex: String = value
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.' | ' '))
        .collect::<String>()
        .to_ascii_lowercase();
    if hex.len() != 12 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let first = u8::from_str_radix(&hex[..2], 16).ok()?;
    if first & 0x03 != 0 || hex.chars().all(|c| c == '0') {
        return None;
    }
    Some(
        hex.as_bytes()
            .chunks(2)
            .map(|pair| String::from_utf8_lossy(pair).into_owned())
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn normalise_hostname(value: &str) -> Option<String> {
    let host = value.trim().split('.').next()?.to_ascii_lowercase();
    (!host.is_empty() && host.len() <= 63).then_some(host)
}

#[derive(Clone, Debug)]
pub(crate) struct NodeKeys {
    pub(crate) id: Uuid,
    pub(crate) hostname: Option<String>,
    pub(crate) serial: Option<String>,
    pub(crate) macs: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct StoredSignal {
    pub(crate) external_id: String,
    pub(crate) hostname: Option<String>,
    pub(crate) serial: Option<String>,
    pub(crate) macs: Vec<String>,
    pub(crate) compliant: Option<bool>,
    pub(crate) status: String,
    pub(crate) last_seen_at: Option<i64>,
    pub(crate) synced_at: i64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum DeviceMatch {
    /// The provider has no record with this device's identifiers.
    Unmatched,
    /// More than one record matched, or the record also matches another
    /// device. Ambiguous matches never pass.
    Ambiguous { candidates: usize },
    Matched {
        external_id: String,
        matched_by: &'static str,
        compliant: Option<bool>,
        status: String,
        last_seen_at: Option<i64>,
        synced_at: i64,
    },
}

/// Matches provider records to devices of ONE organisation. Serial wins
/// over MAC, MAC over (opt-in) hostname; a device matches only when exactly
/// one record matches at its strongest key and no other device claims it.
pub(crate) fn match_devices(
    nodes: &[NodeKeys],
    signals: &[StoredSignal],
    match_hostname: bool,
) -> HashMap<Uuid, DeviceMatch> {
    let mut by_serial: HashMap<&str, BTreeSet<usize>> = HashMap::new();
    let mut by_mac: HashMap<&str, BTreeSet<usize>> = HashMap::new();
    let mut by_host: HashMap<String, BTreeSet<usize>> = HashMap::new();
    for (index, signal) in signals.iter().enumerate() {
        if let Some(serial) = &signal.serial {
            by_serial.entry(serial).or_default().insert(index);
        }
        for mac in &signal.macs {
            by_mac.entry(mac).or_default().insert(index);
        }
        if let Some(host) = signal.hostname.as_deref().and_then(normalise_hostname) {
            by_host.entry(host).or_default().insert(index);
        }
    }
    let candidates: Vec<(Option<&'static str>, BTreeSet<usize>)> = nodes
        .iter()
        .map(|node| {
            if let Some(found) = node.serial.as_deref().and_then(|s| by_serial.get(s)) {
                return (Some("serial_number"), found.clone());
            }
            let macs: BTreeSet<usize> = node
                .macs
                .iter()
                .filter_map(|mac| by_mac.get(mac.as_str()))
                .flatten()
                .copied()
                .collect();
            if !macs.is_empty() {
                return (Some("mac_address"), macs);
            }
            if match_hostname {
                if let Some(found) = node
                    .hostname
                    .as_deref()
                    .and_then(normalise_hostname)
                    .and_then(|host| by_host.get(&host))
                {
                    return (Some("hostname"), found.clone());
                }
            }
            (None, BTreeSet::new())
        })
        .collect();
    let mut claims: HashMap<usize, usize> = HashMap::new();
    for (_, set) in &candidates {
        for index in set {
            *claims.entry(*index).or_default() += 1;
        }
    }
    nodes
        .iter()
        .zip(candidates)
        .map(|(node, (key, set))| {
            let result = match (key, set.len()) {
                (_, 0) => DeviceMatch::Unmatched,
                (Some(key), 1) => {
                    let index = *set.iter().next().expect("one candidate");
                    let claimed = claims.get(&index).copied().unwrap_or(0);
                    if claimed > 1 {
                        DeviceMatch::Ambiguous {
                            candidates: claimed,
                        }
                    } else {
                        let signal = &signals[index];
                        DeviceMatch::Matched {
                            external_id: signal.external_id.clone(),
                            matched_by: key,
                            compliant: signal.compliant,
                            status: signal.status.clone(),
                            last_seen_at: signal.last_seen_at,
                            synced_at: signal.synced_at,
                        }
                    }
                }
                (_, many) => DeviceMatch::Ambiguous { candidates: many },
            };
            (node.id, result)
        })
        .collect()
}

/// One integration's view of one device, attached to posture facts.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct IntegrationFact {
    pub(crate) integration_id: String,
    pub(crate) kind: &'static str,
    pub(crate) provider: &'static str,
    pub(crate) name: String,
    pub(crate) enabled: bool,
    pub(crate) last_success_at: Option<i64>,
    pub(crate) outage_since: Option<i64>,
    #[serde(rename = "match")]
    pub(crate) matched: DeviceMatch,
    pub(crate) source: &'static str,
}

struct IntegrationRow {
    id: String,
    kind: Kind,
    name: String,
    config: ProviderConfig,
    enabled: bool,
    last_success_at: Option<i64>,
    outage_since: Option<i64>,
}

async fn load_integration_rows(
    pool: &sqlx::AnyPool,
    org_id: &str,
) -> Result<Vec<IntegrationRow>, ApiError> {
    sqlx::query(
        "SELECT id,kind,name,config_json,enabled,last_success_at,outage_since FROM posture_integrations WHERE org_id=$1 ORDER BY name",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|row| {
        Ok(IntegrationRow {
            id: row.try_get(0)?,
            kind: Kind::parse(&row.try_get::<String, _>(1)?).ok_or(ApiError::CorruptData)?,
            name: row.try_get(2)?,
            config: serde_json::from_str(&row.try_get::<String, _>(3)?)
                .map_err(|_| ApiError::CorruptData)?,
            enabled: row.try_get::<i64, _>(4)? != 0,
            last_success_at: row.try_get(5)?,
            outage_since: row.try_get(6)?,
        })
    })
    .collect()
}

async fn load_node_keys(pool: &sqlx::AnyPool, org_id: &str) -> Result<Vec<NodeKeys>, ApiError> {
    sqlx::query(
        "SELECT id,COALESCE(hostname,name),serial_number,mac_addresses_json FROM nodes WHERE org_id=$1 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|row| {
        Ok(NodeKeys {
            id: Uuid::parse_str(&row.try_get::<String, _>(0)?).map_err(|_| ApiError::CorruptData)?,
            hostname: row.try_get(1)?,
            serial: row
                .try_get::<Option<String>, _>(2)?
                .as_deref()
                .and_then(normalise_serial),
            macs: row
                .try_get::<Option<String>, _>(3)?
                .and_then(|json| serde_json::from_str::<Vec<String>>(&json).ok())
                .unwrap_or_default(),
        })
    })
    .collect()
}

/// Stored signals per integration, only for integrations in `org_id`.
async fn load_signals(
    pool: &sqlx::AnyPool,
    org_id: &str,
) -> Result<HashMap<String, Vec<StoredSignal>>, ApiError> {
    let rows = sqlx::query(
        "SELECT d.integration_id,d.external_id,d.hostname,d.serial_number,d.mac_addresses_json,d.compliant,d.status,d.last_seen_at,d.synced_at FROM posture_integration_devices d JOIN posture_integrations i ON i.id=d.integration_id AND i.org_id=d.org_id WHERE d.org_id=$1",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;
    let mut out: HashMap<String, Vec<StoredSignal>> = HashMap::new();
    for row in rows {
        out.entry(row.try_get(0)?).or_default().push(StoredSignal {
            external_id: row.try_get(1)?,
            hostname: row.try_get(2)?,
            serial: row.try_get(3)?,
            macs: serde_json::from_str(&row.try_get::<String, _>(4)?).unwrap_or_default(),
            compliant: row.try_get::<Option<i64>, _>(5)?.map(|v| v != 0),
            status: row.try_get(6)?,
            last_seen_at: row.try_get(7)?,
            synced_at: row.try_get(8)?,
        });
    }
    Ok(out)
}

/// Fills each device's integration facts from this organisation's
/// integrations only. Matching always considers every active device of the
/// organisation, so a record two devices claim is ambiguous for both.
pub(crate) async fn attach(
    pool: &sqlx::AnyPool,
    org_id: &str,
    facts: &mut [crate::posture::NodeFacts],
) -> Result<(), ApiError> {
    let integrations = load_integration_rows(pool, org_id).await?;
    if integrations.is_empty() || facts.is_empty() {
        return Ok(());
    }
    let nodes = load_node_keys(pool, org_id).await?;
    let signals = load_signals(pool, org_id).await?;
    for integration in &integrations {
        let matches = match_devices(
            &nodes,
            signals
                .get(&integration.id)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            integration.config.match_hostname,
        );
        for fact in facts.iter_mut() {
            fact.integrations.insert(
                integration.id.clone(),
                IntegrationFact {
                    integration_id: integration.id.clone(),
                    kind: integration.kind.id(),
                    provider: integration.kind.label(),
                    name: integration.name.clone(),
                    enabled: integration.enabled,
                    last_success_at: integration.last_success_at,
                    outage_since: integration.outage_since,
                    matched: matches
                        .get(&fact.id)
                        .cloned()
                        .unwrap_or(DeviceMatch::Unmatched),
                    source: PROVIDER_SOURCE,
                },
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Posture requirement

fn default_max_age() -> i64 {
    DEFAULT_MAX_AGE_SECS
}

/// `integration` requirement of a posture check.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct IntegrationRequirement {
    pub(crate) integration_id: Uuid,
    /// How old BlakTail's last successful confirmation of the device's
    /// provider record may be.
    #[serde(default = "default_max_age")]
    pub(crate) max_age_secs: i64,
    /// Optional: how long ago the provider itself may last have seen the
    /// device (sensor check-in, MDM sync).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_last_seen_secs: Option<i64>,
    /// While the provider is in outage and data is stale: `fail` (default)
    /// or `pass` for devices whose last known state was passing.
    #[serde(default)]
    pub(crate) on_outage: MissingData,
}

impl IntegrationRequirement {
    pub(crate) fn validate(&self) -> Result<(), ApiError> {
        for age in std::iter::once(self.max_age_secs).chain(self.max_last_seen_secs) {
            if !(MIN_AGE_SECS..=MAX_AGE_SECS).contains(&age) {
                return Err(ApiError::BadRequest(
                    "integration ages must be 60-2592000 seconds".into(),
                ));
            }
        }
        Ok(())
    }
}

pub(crate) struct Outcome {
    pub(crate) passed: bool,
    pub(crate) reason: String,
    /// When a passing result lapses without new provider data.
    pub(crate) lapse: Option<i64>,
}

fn fail(reason: String) -> Outcome {
    Outcome {
        passed: false,
        reason,
        lapse: None,
    }
}

pub(crate) fn assess(
    requirement: &IntegrationRequirement,
    fact: Option<&IntegrationFact>,
    now: i64,
) -> Outcome {
    let Some(fact) = fact else {
        return fail("integration is not configured in this organisation".into());
    };
    let provider = fact.provider;
    if !fact.enabled {
        return fail(format!("{provider} integration {} is disabled", fact.name));
    }
    let (compliant, status, last_seen_at, synced_at, matched_by) = match &fact.matched {
        DeviceMatch::Unmatched => {
            return fail(format!(
                "{provider} has no record matching this device's serial number or MAC address"
            ))
        }
        DeviceMatch::Ambiguous { candidates } => {
            return fail(format!(
                "{provider} match is ambiguous ({candidates} candidates); ambiguous matches fail"
            ))
        }
        DeviceMatch::Matched {
            compliant,
            status,
            last_seen_at,
            synced_at,
            matched_by,
            ..
        } => (*compliant, status, *last_seen_at, *synced_at, *matched_by),
    };
    if compliant != Some(true) {
        return fail(format!(
            "{provider} reports {status} (matched by {matched_by})"
        ));
    }
    let age = now.saturating_sub(synced_at);
    if age > requirement.max_age_secs {
        return match (fact.outage_since, requirement.on_outage) {
            (Some(since), MissingData::Pass) => Outcome {
                passed: true,
                reason: format!(
                    "{provider} unreachable since {since}; last known state {status} is {age}s old and this check fails open during outages"
                ),
                lapse: None,
            },
            (Some(since), MissingData::Fail) => fail(format!(
                "{provider} unreachable since {since}; data is {age}s old (limit {}s) and this check fails closed",
                requirement.max_age_secs
            )),
            (None, _) => fail(format!(
                "{provider} data is {age}s old (limit {}s)",
                requirement.max_age_secs
            )),
        };
    }
    let mut lapse = synced_at + requirement.max_age_secs;
    if let Some(max) = requirement.max_last_seen_secs {
        match last_seen_at {
            Some(seen) if now.saturating_sub(seen) <= max => lapse = lapse.min(seen + max),
            Some(seen) => {
                return fail(format!(
                    "{provider} last saw this device {}s ago (limit {max}s)",
                    now.saturating_sub(seen)
                ))
            }
            None => return fail(format!("{provider} has no last-seen time for this device")),
        }
    }
    Outcome {
        passed: true,
        reason: format!("{provider} reports {status} (matched by {matched_by}, {age}s old)"),
        lapse: Some(lapse),
    }
}

/// A posture check may reference only its own organisation's integration.
pub(crate) async fn ensure_in_org(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: Uuid,
    integration_id: Uuid,
) -> Result<(), ApiError> {
    let found: Option<String> =
        sqlx::query_scalar("SELECT id FROM posture_integrations WHERE id=$1 AND org_id=$2")
            .bind(integration_id.to_string())
            .bind(org_id.to_string())
            .fetch_optional(&mut **tx)
            .await?;
    found.map(|_| ()).ok_or_else(|| {
        ApiError::BadRequest("integration_id is not an integration in this organisation".into())
    })
}

// ---------------------------------------------------------------------------
// Agent-reported hardware identifiers

/// Records the serial number and MAC addresses the node reports. They are
/// self-reported by the node token holder; a copied serial makes the match
/// ambiguous for both devices rather than transferring a passing signal.
pub(crate) async fn record_hardware(
    store: &Store,
    org_id: &str,
    node_id: Uuid,
    serial: Option<&str>,
    macs: Option<&str>,
) -> Result<(), ApiError> {
    if serial.is_none() && macs.is_none() {
        return Ok(());
    }
    let row =
        sqlx::query("SELECT serial_number,mac_addresses_json FROM nodes WHERE id=$1 AND org_id=$2")
            .bind(node_id.to_string())
            .bind(org_id)
            .fetch_optional(&store.pool)
            .await?
            .ok_or(ApiError::Unauthorized)?;
    let current_serial: Option<String> = row.try_get(0)?;
    let current_macs: Option<String> = row.try_get(1)?;
    let next_serial = match serial {
        Some(value) => normalise_serial(value),
        None => current_serial.clone(),
    };
    let next_macs = match macs {
        Some(value) => {
            let list: BTreeSet<String> = value
                .split(',')
                .filter_map(normalise_mac)
                .take(16)
                .collect();
            Some(serde_json::to_string(&list).map_err(|_| ApiError::CorruptData)?)
        }
        None => current_macs.clone(),
    };
    if next_serial == current_serial && next_macs == current_macs {
        return Ok(());
    }
    let mut tx = store.pool.begin().await?;
    sqlx::query(
        "UPDATE nodes SET serial_number=$1,mac_addresses_json=$2 WHERE id=$3 AND org_id=$4",
    )
    .bind(&next_serial)
    .bind(&next_macs)
    .bind(node_id.to_string())
    .bind(org_id)
    .execute(&mut *tx)
    .await?;
    bump_control_revision(&mut tx, org_id).await?;
    tx.commit().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Reconcile and outage state

#[derive(Debug, Serialize)]
pub(crate) struct SyncReport {
    ok: bool,
    devices: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    next_sync_at: i64,
}

fn jitter(secs: i64, percent: i64) -> i64 {
    let spread = (secs * percent / 100).max(1);
    secs + rand::thread_rng().gen_range(-spread..=spread)
}

fn backoff_secs(failures: i64, interval: i64, retry_after: Option<u64>) -> i64 {
    let exponent = (failures - 1).clamp(0, 10) as u32;
    let base = (60_i64 << exponent)
        .min(interval.max(3600))
        .min(MAX_BACKOFF_SECS);
    jitter(base, 20)
        .max(retry_after.unwrap_or(0) as i64)
        .max(30)
}

/// Digest of the stored fields that can change a posture decision.
fn signal_line(
    external_id: &str,
    hostname: &Option<String>,
    serial: &Option<String>,
    macs_json: &str,
    compliant: Option<bool>,
    status: &str,
) -> String {
    format!("{external_id:?}|{hostname:?}|{serial:?}|{macs_json}|{compliant:?}|{status:?}\n")
}

async fn stored_digest(pool: &sqlx::AnyPool, integration_id: &str) -> Result<String, ApiError> {
    let rows = sqlx::query(
        "SELECT external_id,hostname,serial_number,mac_addresses_json,compliant,status FROM posture_integration_devices WHERE integration_id=$1 ORDER BY external_id",
    )
    .bind(integration_id)
    .fetch_all(pool)
    .await?;
    let mut hasher = Sha256::new();
    for row in rows {
        hasher.update(signal_line(
            &row.try_get::<String, _>(0)?,
            &row.try_get(1)?,
            &row.try_get(2)?,
            &row.try_get::<String, _>(3)?,
            row.try_get::<Option<i64>, _>(4)?.map(|v| v != 0),
            &row.try_get::<String, _>(5)?,
        ));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Runs one reconcile for an integration and records success or outage.
/// Provider errors never change stored signals.
pub(crate) async fn sync_integration(
    state: &AppState,
    org_id: &str,
    integration_id: &str,
) -> Result<SyncReport, ApiError> {
    let row = sqlx::query(
        "SELECT kind,config_json,sealed_secret,interval_secs,consecutive_failures,outage_since FROM posture_integrations WHERE id=$1 AND org_id=$2",
    )
    .bind(integration_id)
    .bind(org_id)
    .fetch_optional(&state.store.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let kind = Kind::parse(&row.try_get::<String, _>(0)?).ok_or(ApiError::CorruptData)?;
    let config: ProviderConfig =
        serde_json::from_str(&row.try_get::<String, _>(1)?).map_err(|_| ApiError::CorruptData)?;
    let secret = open_secret(&state.auth_hmac_secret, &row.try_get::<String, _>(2)?)?;
    let interval: i64 = row.try_get(3)?;
    let failures: i64 = row.try_get(4)?;
    let was_outage = row.try_get::<Option<i64>, _>(5)?.is_some();
    let result = match validate_config(kind, &config) {
        Ok(endpoints) => tokio::time::timeout(
            SYNC_TIMEOUT,
            run_adapter(kind, &config, &endpoints, &secret),
        )
        .await
        .unwrap_or(Err(AdapterError::Unreachable)),
        Err(_) => Err(AdapterError::Blocked),
    };
    drop(secret);
    let at = now();
    match result {
        Ok(signals) => {
            // Normalise once: stored identifiers are what matching compares.
            let synced: Vec<(DeviceSignal, String)> = signals
                .into_iter()
                .map(|mut signal| {
                    let macs: BTreeSet<String> = signal
                        .mac_addresses
                        .iter()
                        .filter_map(|mac| normalise_mac(mac))
                        .collect();
                    signal.serial_number =
                        signal.serial_number.as_deref().and_then(normalise_serial);
                    let macs_json = serde_json::to_string(&macs).unwrap_or_else(|_| "[]".into());
                    (signal, macs_json)
                })
                .collect();
            let mut hasher = Sha256::new();
            for (signal, macs_json) in &synced {
                hasher.update(signal_line(
                    &signal.external_id,
                    &signal.hostname,
                    &signal.serial_number,
                    macs_json,
                    signal.compliant,
                    &signal.status,
                ));
            }
            let digest = format!("{:x}", hasher.finalize());
            let changed = digest != stored_digest(&state.store.pool, integration_id).await?;
            let next = at + jitter(interval, 10);
            let mut tx = state.store.pool.begin().await?;
            sqlx::query("DELETE FROM posture_integration_devices WHERE integration_id=$1")
                .bind(integration_id)
                .execute(&mut *tx)
                .await?;
            for (signal, macs_json) in &synced {
                sqlx::query("INSERT INTO posture_integration_devices(integration_id,org_id,external_id,hostname,serial_number,mac_addresses_json,compliant,status,last_seen_at,synced_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
                    .bind(integration_id)
                    .bind(org_id)
                    .bind(&signal.external_id)
                    .bind(&signal.hostname)
                    .bind(&signal.serial_number)
                    .bind(macs_json)
                    .bind(signal.compliant.map(i64::from))
                    .bind(&signal.status)
                    .bind(signal.last_seen_at)
                    .bind(at)
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query("UPDATE posture_integrations SET last_attempt_at=$1,last_success_at=$1,consecutive_failures=0,outage_since=NULL,last_error=NULL,device_count=$2,next_sync_at=$3,lease_until=NULL WHERE id=$4 AND org_id=$5")
                .bind(at)
                .bind(synced.len() as i64)
                .bind(next)
                .bind(integration_id)
                .bind(org_id)
                .execute(&mut *tx)
                .await?;
            // Recovery bumps once so fail-open/closed decisions re-evaluate.
            if changed || was_outage {
                bump_control_revision(&mut tx, org_id).await?;
            }
            tx.commit().await?;
            Ok(SyncReport {
                ok: true,
                devices: synced.len(),
                error_code: None,
                error: None,
                next_sync_at: next,
            })
        }
        Err(error) => {
            let retry = match error {
                AdapterError::RateLimited(secs) => Some(secs),
                _ => None,
            };
            let next = at + backoff_secs(failures + 1, interval, retry);
            let mut tx = state.store.pool.begin().await?;
            sqlx::query("UPDATE posture_integrations SET last_attempt_at=$1,consecutive_failures=consecutive_failures+1,outage_since=COALESCE(outage_since,$1),last_error=$2,next_sync_at=$3,lease_until=NULL WHERE id=$4 AND org_id=$5")
                .bind(at)
                .bind(error.message())
                .bind(next)
                .bind(integration_id)
                .bind(org_id)
                .execute(&mut *tx)
                .await?;
            if !was_outage {
                bump_control_revision(&mut tx, org_id).await?;
            }
            tx.commit().await?;
            warn!(
                integration = integration_id,
                provider = kind.id(),
                error = error.code(),
                failures = failures + 1,
                "posture integration reconcile failed"
            );
            Ok(SyncReport {
                ok: false,
                devices: 0,
                error_code: Some(error.code()),
                error: Some(error.message()),
                next_sync_at: next,
            })
        }
    }
}

/// Claims due integrations with a lease so replicas never run the same one.
pub(crate) async fn claim_due(
    pool: &sqlx::AnyPool,
    limit: usize,
) -> Result<Vec<(String, String)>, ApiError> {
    let at = now();
    let rows = sqlx::query(
        "SELECT id,org_id FROM posture_integrations WHERE enabled=1 AND next_sync_at<=$1 AND (lease_until IS NULL OR lease_until<$1) ORDER BY next_sync_at LIMIT $2",
    )
    .bind(at)
    .bind(limit as i64)
    .fetch_all(pool)
    .await?;
    let mut claimed = Vec::new();
    for row in rows {
        let id: String = row.try_get(0)?;
        let won = sqlx::query(
            "UPDATE posture_integrations SET lease_until=$1 WHERE id=$2 AND (lease_until IS NULL OR lease_until<$3)",
        )
        .bind(at + LEASE_SECS)
        .bind(&id)
        .bind(at)
        .execute(pool)
        .await?
        .rows_affected();
        if won == 1 {
            claimed.push((id, row.try_get(1)?));
        }
    }
    Ok(claimed)
}

/// Runs due reconciles with bounded concurrency. Returns how many ran.
pub(crate) async fn run_due(state: &AppState) -> Result<usize, ApiError> {
    let due = claim_due(&state.store.pool, MAX_CONCURRENT_SYNCS * 8).await?;
    let count = due.len();
    let mut tasks = tokio::task::JoinSet::new();
    for (id, org_id) in due {
        while tasks.len() >= MAX_CONCURRENT_SYNCS {
            tasks.join_next().await;
        }
        let state = state.clone();
        tasks.spawn(async move {
            if let Err(error) = sync_integration(&state, &org_id, &id).await {
                warn!(integration = %id, %error, "posture integration reconcile could not be recorded");
            }
        });
    }
    while tasks.join_next().await.is_some() {}
    Ok(count)
}

pub(crate) async fn sync_loop(state: AppState) {
    // Tests drive `run_due` and `sync_integration` directly.
    if cfg!(test) {
        return;
    }
    loop {
        if let Err(error) = run_due(&state).await {
            warn!(%error, "posture integration poll failed");
        }
        tokio::time::sleep(LOOP_TICK).await;
    }
}

// ---------------------------------------------------------------------------
// Console API

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/orgs/:org_id/posture-integrations",
            get(list_integrations).post(create_integration),
        )
        .route(
            "/v1/orgs/:org_id/posture-integrations/:integration_id",
            put(update_integration).delete(delete_integration),
        )
        .route(
            "/v1/orgs/:org_id/posture-integrations/:integration_id/sync",
            post(sync_now),
        )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateIntegration {
    kind: String,
    name: String,
    #[serde(default)]
    config: ProviderConfig,
    secret: String,
    #[serde(default)]
    interval_secs: Option<i64>,
    /// The owner read the provider's data notice before the first call.
    #[serde(default)]
    privacy_acknowledged: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateIntegration {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    config: Option<ProviderConfig>,
    /// Replaces the stored secret. Required whenever `config` changes, so a
    /// stored credential is never redirected to a new endpoint.
    #[serde(default)]
    secret: Option<String>,
    #[serde(default)]
    interval_secs: Option<i64>,
    #[serde(default)]
    enabled: Option<bool>,
}

#[derive(Serialize)]
struct IntegrationView {
    id: String,
    kind: &'static str,
    provider: &'static str,
    name: String,
    config: ProviderConfig,
    secret_fingerprint: String,
    interval_secs: i64,
    enabled: bool,
    privacy_acknowledged_at: i64,
    privacy_acknowledged_by: String,
    created_at: i64,
    updated_at: i64,
    next_sync_at: i64,
    last_attempt_at: Option<i64>,
    last_success_at: Option<i64>,
    consecutive_failures: i64,
    outage_since: Option<i64>,
    last_error: Option<String>,
    provider_devices: i64,
    /// BlakTail devices matched to exactly one provider record.
    matched_devices: usize,
    ambiguous_devices: usize,
    /// BlakTail devices with no provider record.
    unmatched_devices: usize,
    /// Provider records that match no BlakTail device.
    unmatched_records: usize,
    referenced_by: Vec<String>,
}

#[derive(Serialize)]
struct IntegrationList {
    residency_notice: &'static str,
    providers: Vec<ProviderInfo>,
    integrations: Vec<IntegrationView>,
}

fn validate_name(name: &str) -> Result<String, ApiError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "integration name must be 1-64 printable characters".into(),
        ));
    }
    Ok(name.to_owned())
}

fn validate_interval(value: Option<i64>) -> Result<i64, ApiError> {
    let interval = value.unwrap_or(DEFAULT_INTERVAL_SECS);
    if !(MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&interval) {
        return Err(ApiError::BadRequest(
            "interval_secs must be 300-86400 seconds".into(),
        ));
    }
    Ok(interval)
}

async fn referencing_checks(
    pool: &sqlx::AnyPool,
    org_id: Uuid,
) -> Result<HashMap<String, Vec<String>>, ApiError> {
    let mut refs: HashMap<String, Vec<String>> = HashMap::new();
    for (name, check) in load_checks(pool, &org_id.to_string()).await? {
        if let Some(requirement) = &check.definition.integration {
            refs.entry(requirement.integration_id.to_string())
                .or_default()
                .push(name);
        }
    }
    Ok(refs)
}

async fn list_integrations(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<IntegrationList>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewNetwork)?;
    let pool = &s.store.pool;
    let org = org_id.to_string();
    let rows = sqlx::query(
        "SELECT id,kind,name,config_json,secret_hint,interval_secs,enabled,privacy_ack_at,privacy_ack_by,created_at,updated_at,next_sync_at,last_attempt_at,last_success_at,consecutive_failures,outage_since,last_error,device_count FROM posture_integrations WHERE org_id=$1 ORDER BY name",
    )
    .bind(&org)
    .fetch_all(pool)
    .await?;
    let nodes = load_node_keys(pool, &org).await?;
    let signals = load_signals(pool, &org).await?;
    let refs = referencing_checks(pool, org_id).await?;
    let mut integrations = Vec::new();
    for row in rows {
        let id: String = row.try_get(0)?;
        let kind = Kind::parse(&row.try_get::<String, _>(1)?).ok_or(ApiError::CorruptData)?;
        let mut config: ProviderConfig = serde_json::from_str(&row.try_get::<String, _>(3)?)
            .map_err(|_| ApiError::CorruptData)?;
        config.api_base_override = None;
        let stored = signals.get(&id).map(Vec::as_slice).unwrap_or_default();
        let matches = match_devices(&nodes, stored, config.match_hostname);
        let claimed: BTreeSet<&str> = matches
            .values()
            .filter_map(|m| match m {
                DeviceMatch::Matched { external_id, .. } => Some(external_id.as_str()),
                _ => None,
            })
            .collect();
        let count = |pred: fn(&DeviceMatch) -> bool| matches.values().filter(|m| pred(m)).count();
        integrations.push(IntegrationView {
            kind: kind.id(),
            provider: kind.label(),
            name: row.try_get(2)?,
            config,
            secret_fingerprint: row.try_get(4)?,
            interval_secs: row.try_get(5)?,
            enabled: row.try_get::<i64, _>(6)? != 0,
            privacy_acknowledged_at: row.try_get(7)?,
            privacy_acknowledged_by: row.try_get(8)?,
            created_at: row.try_get(9)?,
            updated_at: row.try_get(10)?,
            next_sync_at: row.try_get(11)?,
            last_attempt_at: row.try_get(12)?,
            last_success_at: row.try_get(13)?,
            consecutive_failures: row.try_get(14)?,
            outage_since: row.try_get(15)?,
            last_error: row.try_get(16)?,
            provider_devices: row.try_get(17)?,
            matched_devices: count(|m| matches!(m, DeviceMatch::Matched { .. })),
            ambiguous_devices: count(|m| matches!(m, DeviceMatch::Ambiguous { .. })),
            unmatched_devices: count(|m| matches!(m, DeviceMatch::Unmatched)),
            unmatched_records: stored
                .iter()
                .filter(|signal| !claimed.contains(signal.external_id.as_str()))
                .count(),
            referenced_by: refs.get(&id).cloned().unwrap_or_default(),
            id,
        });
    }
    Ok(Json(IntegrationList {
        residency_notice: RESIDENCY_NOTICE,
        providers: Kind::ALL.into_iter().map(provider_info).collect(),
        integrations,
    }))
}

/// Audit details never include the secret or its fingerprint.
fn audit_config(config: &ProviderConfig) -> serde_json::Value {
    let mut config = config.clone();
    config.api_base_override = None;
    serde_json::to_value(config).unwrap_or_default()
}

async fn create_integration(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<CreateIntegration>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageSecurity)?;
    let kind = Kind::parse(&input.kind).ok_or_else(|| {
        ApiError::BadRequest(
            "kind must be intune, crowdstrike, sentinelone, fleetdm or huntress".into(),
        )
    })?;
    if !input.privacy_acknowledged {
        return Err(ApiError::BadRequest(
            "acknowledge the provider's data notice before connecting it".into(),
        ));
    }
    let name = validate_name(&input.name)?;
    let interval = validate_interval(input.interval_secs)?;
    validate_config(kind, &input.config)?;
    let secret = validate_secret(&input.secret)?;
    let sealed = seal_secret(&s.auth_hmac_secret, secret)?;
    let id = Uuid::new_v4().to_string();
    let at = now();
    let mut tx = s.store.pool.begin().await?;
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM posture_integrations WHERE org_id=$1")
            .bind(org_id.to_string())
            .fetch_one(&mut *tx)
            .await?;
    if count >= MAX_INTEGRATIONS_PER_ORG {
        return Err(ApiError::BadRequest(
            "organisations are limited to 8 posture integrations".into(),
        ));
    }
    sqlx::query("INSERT INTO posture_integrations(id,org_id,kind,name,config_json,sealed_secret,secret_hint,interval_secs,enabled,privacy_ack_at,privacy_ack_by,created_at,updated_at,next_sync_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,1,$9,$10,$9,$9,$9)")
        .bind(&id)
        .bind(org_id.to_string())
        .bind(kind.id())
        .bind(&name)
        .bind(serde_json::to_string(&input.config).map_err(|_| ApiError::CorruptData)?)
        .bind(&sealed)
        .bind(secret_fingerprint(secret))
        .bind(interval)
        .bind(at)
        .bind(&session.user_id)
        .execute(&mut *tx)
        .await
        .map_err(crate::conflict("an integration with that name already exists"))?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "posture_integration.created",
        "posture_integration",
        Some(&id),
        &serde_json::json!({
            "name": name,
            "kind": kind.id(),
            "config": audit_config(&input.config),
            "interval_secs": interval,
            "privacy_acknowledged": true,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({"id": id, "kind": kind.id(), "name": name})),
    ))
}

async fn update_integration(
    State(s): State<AppState>,
    UrlPath((org_id, integration_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<UpdateIntegration>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageSecurity)?;
    let mut tx = s.store.pool.begin().await?;
    let row = sqlx::query(
        "SELECT kind,name,config_json,interval_secs,enabled FROM posture_integrations WHERE id=$1 AND org_id=$2",
    )
    .bind(integration_id.to_string())
    .bind(org_id.to_string())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let kind = Kind::parse(&row.try_get::<String, _>(0)?).ok_or(ApiError::CorruptData)?;
    let current_config: ProviderConfig =
        serde_json::from_str(&row.try_get::<String, _>(2)?).map_err(|_| ApiError::CorruptData)?;
    let name = match &input.name {
        Some(name) => validate_name(name)?,
        None => row.try_get(1)?,
    };
    let interval = match input.interval_secs {
        Some(value) => validate_interval(Some(value))?,
        None => row.try_get(3)?,
    };
    let enabled = input.enabled.unwrap_or(row.try_get::<i64, _>(4)? != 0);
    let config = input.config.clone().unwrap_or(current_config.clone());
    let config_changed = config != current_config;
    if config_changed && input.secret.is_none() {
        return Err(ApiError::BadRequest(
            "re-enter the secret when changing provider settings".into(),
        ));
    }
    validate_config(kind, &config)?;
    let secret = input.secret.as_deref().map(validate_secret).transpose()?;
    let sealed = secret
        .map(|value| seal_secret(&s.auth_hmac_secret, value))
        .transpose()?;
    let at = now();
    sqlx::query("UPDATE posture_integrations SET name=$1,config_json=$2,interval_secs=$3,enabled=$4,sealed_secret=COALESCE($5,sealed_secret),secret_hint=COALESCE($6,secret_hint),updated_at=$7,next_sync_at=CASE WHEN $8=1 THEN $7 ELSE next_sync_at END WHERE id=$9 AND org_id=$10")
        .bind(&name)
        .bind(serde_json::to_string(&config).map_err(|_| ApiError::CorruptData)?)
        .bind(interval)
        .bind(i64::from(enabled))
        .bind(&sealed)
        .bind(secret.map(secret_fingerprint))
        .bind(at)
        .bind(i64::from(config_changed || secret.is_some()))
        .bind(integration_id.to_string())
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(crate::conflict("an integration with that name already exists"))?;
    if config_changed {
        // Records pulled with the old settings no longer apply.
        sqlx::query(
            "DELETE FROM posture_integration_devices WHERE integration_id=$1 AND org_id=$2",
        )
        .bind(integration_id.to_string())
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await?;
    }
    bump_control_revision(&mut tx, org_id.to_string()).await?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "posture_integration.updated",
        "posture_integration",
        Some(&integration_id.to_string()),
        &serde_json::json!({
            "name": name,
            "kind": kind.id(),
            "config": audit_config(&config),
            "interval_secs": interval,
            "enabled": enabled,
            "secret_rotated": secret.is_some(),
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        serde_json::json!({"id": integration_id, "name": name, "enabled": enabled}),
    ))
}

async fn delete_integration(
    State(s): State<AppState>,
    UrlPath((org_id, integration_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageSecurity)?;
    let id = integration_id.to_string();
    if let Some(checks) = referencing_checks(&s.store.pool, org_id).await?.get(&id) {
        return Err(ApiError::Conflict(format!(
            "integration is referenced by posture checks {}; remove the requirement first",
            checks.join(", ")
        )));
    }
    let mut tx = s.store.pool.begin().await?;
    let row = sqlx::query("SELECT name,kind FROM posture_integrations WHERE id=$1 AND org_id=$2")
        .bind(&id)
        .bind(org_id.to_string())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    let name: String = row.try_get(0)?;
    let kind: String = row.try_get(1)?;
    sqlx::query("DELETE FROM posture_integration_devices WHERE integration_id=$1 AND org_id=$2")
        .bind(&id)
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM posture_integrations WHERE id=$1 AND org_id=$2")
        .bind(&id)
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await?;
    bump_control_revision(&mut tx, org_id.to_string()).await?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "posture_integration.deleted",
        "posture_integration",
        Some(&id),
        &serde_json::json!({"name": name, "kind": kind}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Test connection: reconciles now and reports the outcome category.
async fn sync_now(
    State(s): State<AppState>,
    UrlPath((org_id, integration_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<SyncReport>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageSecurity)?;
    sync_as(&s, org_id, &session, integration_id).await
}

async fn sync_as(
    s: &AppState,
    org_id: Uuid,
    session: &Session,
    integration_id: Uuid,
) -> Result<Json<SyncReport>, ApiError> {
    let id = integration_id.to_string();
    let report = sync_integration(s, &org_id.to_string(), &id).await?;
    let mut tx = s.store.pool.begin().await?;
    append_audit(
        &mut tx,
        org_id,
        session,
        "posture_integration.tested",
        "posture_integration",
        Some(&id),
        &serde_json::json!({"ok": report.ok, "devices": report.devices, "error_code": report.error_code}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(report))
}

#[cfg(test)]
pub(crate) mod tests;
