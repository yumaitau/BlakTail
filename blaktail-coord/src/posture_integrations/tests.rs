//! Adapter tests against local mock servers that replicate each vendor's
//! documented response shapes, pagination, auth failures and 429s. No live
//! vendor tenant is used.

use super::*;
use axum::{
    extract::{Form, Query, State as AxState},
    http::HeaderMap as AxHeaders,
    response::{IntoResponse, Response},
    routing::{get as ax_get, post as ax_post},
    Json as AxJson, Router as AxRouter,
};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

/// Shared switches for a mock provider.
#[derive(Default)]
pub(crate) struct Mock {
    pub(crate) calls: AtomicUsize,
    /// Answer the next request with 429 and `Retry-After: 1`.
    pub(crate) rate_limit_once: AtomicBool,
    /// Answer every request with 503.
    pub(crate) down: AtomicBool,
    /// FleetDM: give the first host this many failing policies.
    pub(crate) failing: AtomicUsize,
}

pub(crate) type MockState = (Arc<Mock>, String);

/// Common front gate: counts calls, then simulates outage or rate limiting.
fn gate(mock: &Mock) -> Option<Response> {
    mock.calls.fetch_add(1, Ordering::SeqCst);
    if mock.down.load(Ordering::SeqCst) {
        return Some(StatusCode::SERVICE_UNAVAILABLE.into_response());
    }
    if mock.rate_limit_once.swap(false, Ordering::SeqCst) {
        return Some(
            (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", "1")],
                "slow down",
            )
                .into_response(),
        );
    }
    None
}

fn unauthorised() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        AxJson(serde_json::json!({"error": "invalid_client"})),
    )
        .into_response()
}

fn header<'a>(headers: &'a AxHeaders, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
}

/// Starts `router(base)` on an ephemeral loopback port; returns the base URL.
pub(crate) async fn serve(mock: Arc<Mock>, router: fn() -> AxRouter<MockState>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = router().with_state((mock, base.clone()));
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    base
}

// --- Microsoft Intune (Graph) ---------------------------------------------

pub(crate) const INTUNE_SECRET: &str = "intune-client-secret-value";

pub(crate) fn intune_router() -> AxRouter<MockState> {
    async fn token(
        AxState((mock, _)): AxState<MockState>,
        Form(form): Form<HashMap<String, String>>,
    ) -> Response {
        if let Some(response) = gate(&mock) {
            return response;
        }
        if form.get("grant_type").map(String::as_str) != Some("client_credentials")
            || form.get("client_secret").map(String::as_str) != Some(INTUNE_SECRET)
            || form.get("scope").map(String::as_str) != Some("https://graph.microsoft.com/.default")
        {
            return unauthorised();
        }
        AxJson(serde_json::json!({"token_type":"Bearer","expires_in":3599,"access_token":"graph-token"}))
            .into_response()
    }
    async fn devices(
        AxState((mock, base)): AxState<MockState>,
        headers: AxHeaders,
        Query(query): Query<HashMap<String, String>>,
    ) -> Response {
        if let Some(response) = gate(&mock) {
            return response;
        }
        if header(&headers, "authorization") != "Bearer graph-token" {
            return unauthorised();
        }
        if query.get("$skiptoken").map(String::as_str) == Some("2") {
            return AxJson(serde_json::json!({"value":[{
                "id":"intune-2","deviceName":"ranger-tablet","serialNumber":"F9GZ12345",
                "wiFiMacAddress":"","ethernetMacAddress":null,"complianceState":"inGracePeriod",
                "lastSyncDateTime":"2026-10-02T23:58:46.7156189-08:00"}]}))
            .into_response();
        }
        AxJson(serde_json::json!({
            "@odata.nextLink": format!("{base}/v1.0/deviceManagement/managedDevices?$skiptoken=2"),
            "value":[{
                "@odata.type":"#microsoft.graph.managedDevice",
                "id":"intune-1","deviceName":"Field-Laptop","serialNumber":"C02XK1ABCD",
                "wiFiMacAddress":"3C22FB112233","ethernetMacAddress":"","complianceState":"compliant",
                "lastSyncDateTime":"2026-10-03T00:02:49.3205976Z"}]
        }))
        .into_response()
    }
    AxRouter::new()
        .route("/:tenant/oauth2/v2.0/token", ax_post(token))
        .route("/v1.0/deviceManagement/managedDevices", ax_get(devices))
}

// --- CrowdStrike Falcon -----------------------------------------------------

pub(crate) const CROWDSTRIKE_SECRET: &str = "falcon-client-secret-value";

pub(crate) fn crowdstrike_router() -> AxRouter<MockState> {
    async fn token(
        AxState((mock, _)): AxState<MockState>,
        Form(form): Form<HashMap<String, String>>,
    ) -> Response {
        if let Some(response) = gate(&mock) {
            return response;
        }
        if form.get("client_secret").map(String::as_str) != Some(CROWDSTRIKE_SECRET) {
            return unauthorised();
        }
        (
            StatusCode::CREATED,
            AxJson(serde_json::json!({"access_token":"falcon-token","token_type":"bearer","expires_in":1799})),
        )
            .into_response()
    }
    async fn scroll(
        AxState((mock, _)): AxState<MockState>,
        headers: AxHeaders,
        Query(query): Query<HashMap<String, String>>,
    ) -> Response {
        if let Some(response) = gate(&mock) {
            return response;
        }
        if header(&headers, "authorization") != "Bearer falcon-token" {
            return unauthorised();
        }
        let page = match query.get("offset").map(String::as_str) {
            None => {
                serde_json::json!({"meta":{"pagination":{"offset":"scroll-2","expires_at":1,"total":3}},"resources":["aid-1","aid-2"],"errors":[]})
            }
            Some("scroll-2") => {
                serde_json::json!({"meta":{"pagination":{"offset":"","expires_at":1,"total":3}},"resources":["aid-3"],"errors":[]})
            }
            Some(_) => return StatusCode::BAD_GATEWAY.into_response(),
        };
        AxJson(page).into_response()
    }
    async fn details(
        AxState((mock, _)): AxState<MockState>,
        headers: AxHeaders,
        AxJson(body): AxJson<serde_json::Value>,
    ) -> Response {
        if let Some(response) = gate(&mock) {
            return response;
        }
        if header(&headers, "authorization") != "Bearer falcon-token" {
            return unauthorised();
        }
        let all = [
            serde_json::json!({"device_id":"aid-1","hostname":"field-laptop","serial_number":"C02XK1ABCD","mac_address":"3c-22-fb-11-22-33","last_seen":"2026-10-03T00:00:00Z","status":"normal","reduced_functionality_mode":"no"}),
            serde_json::json!({"device_id":"aid-2","hostname":"office-pc","serial_number":"PF3ABCDE","mac_address":"00-1a-2b-3c-4d-5e","last_seen":"2026-10-03T00:00:00Z","status":"contained","reduced_functionality_mode":"no"}),
            serde_json::json!({"device_id":"aid-3","hostname":"old-mac","serial_number":"C02OLD999","mac_address":"00-1a-2b-3c-4d-5f","last_seen":"2026-09-01T00:00:00Z","status":"normal","reduced_functionality_mode":"yes"}),
        ];
        let wanted: Vec<String> = serde_json::from_value(body["ids"].clone()).unwrap_or_default();
        let resources: Vec<_> = all
            .into_iter()
            .filter(|host| wanted.iter().any(|id| host["device_id"] == id.as_str()))
            .collect();
        AxJson(serde_json::json!({"meta":{},"resources":resources,"errors":[]})).into_response()
    }
    AxRouter::new()
        .route("/oauth2/token", ax_post(token))
        .route("/devices/queries/devices-scroll/v1", ax_get(scroll))
        .route("/devices/entities/devices/v2", ax_post(details))
}

// --- SentinelOne ------------------------------------------------------------

pub(crate) const SENTINELONE_TOKEN: &str = "s1-api-token-value";

pub(crate) fn sentinelone_router() -> AxRouter<MockState> {
    async fn agents(
        AxState((mock, _)): AxState<MockState>,
        headers: AxHeaders,
        Query(query): Query<HashMap<String, String>>,
    ) -> Response {
        if let Some(response) = gate(&mock) {
            return response;
        }
        if header(&headers, "authorization") != format!("ApiToken {SENTINELONE_TOKEN}") {
            return unauthorised();
        }
        let page = match query.get("cursor").map(String::as_str) {
            None => serde_json::json!({
                "data":[{"id":"1001","computerName":"field-laptop","serialNumber":"C02XK1ABCD",
                    "networkInterfaces":[{"name":"en0","physical":"3c:22:fb:11:22:33","inet":["10.0.0.5"]}],
                    "infected":false,"isActive":true,"isUpToDate":true,"lastActiveDate":"2026-10-03T00:00:00.000000Z"}],
                "pagination":{"totalItems":2,"nextCursor":"cursor-2"}}),
            Some("cursor-2") => serde_json::json!({
                "data":[{"id":"1002","computerName":"office-pc","serialNumber":"PF3ABCDE",
                    "networkInterfaces":[],"infected":true,"isActive":true,"isUpToDate":true,
                    "lastActiveDate":"2026-10-03T00:00:00Z"}],
                "pagination":{"totalItems":2,"nextCursor":null}}),
            Some(_) => return StatusCode::BAD_REQUEST.into_response(),
        };
        AxJson(page).into_response()
    }
    AxRouter::new().route("/web/api/v2.1/agents", ax_get(agents))
}

// --- FleetDM ----------------------------------------------------------------

pub(crate) const FLEET_TOKEN: &str = "fleet-api-token-value";

pub(crate) fn fleet_router() -> AxRouter<MockState> {
    async fn hosts(
        AxState((mock, _)): AxState<MockState>,
        headers: AxHeaders,
        Query(query): Query<HashMap<String, String>>,
    ) -> Response {
        if let Some(response) = gate(&mock) {
            return response;
        }
        if header(&headers, "authorization") != format!("Bearer {FLEET_TOKEN}") {
            return unauthorised();
        }
        let per_page: usize = query
            .get("per_page")
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);
        let page: usize = query.get("page").and_then(|v| v.parse().ok()).unwrap_or(0);
        let failing = mock.failing.load(Ordering::SeqCst);
        // 500 filler hosts on page 0 force a second page, as Fleet's
        // page/per_page pagination has no "next" marker.
        let total = per_page + 1;
        let hosts: Vec<_> = (page * per_page..((page + 1) * per_page).min(total))
            .map(|index| match index {
                0 => serde_json::json!({"id":1,"hostname":"field-laptop.local","hardware_serial":"C02XK1ABCD","primary_mac":"3c:22:fb:11:22:33","seen_time":"2026-10-03T00:00:00Z","status":"online","issues":{"failing_policies_count":failing,"total_issues_count":failing}}),
                1 => serde_json::json!({"id":2,"hostname":"office-pc","hardware_serial":"PF3ABCDE","primary_mac":"","seen_time":"2026-10-03T00:00:00Z","status":"online","issues":{"failing_policies_count":0,"total_issues_count":0}}),
                n => serde_json::json!({"id":n+1,"hostname":format!("filler-{n}"),"hardware_serial":format!("FILL{n:05}"),"primary_mac":"","seen_time":"2026-10-01T00:00:00Z","status":"offline","issues":{"failing_policies_count":0,"total_issues_count":0}}),
            })
            .collect();
        AxJson(serde_json::json!({"hosts": hosts})).into_response()
    }
    AxRouter::new().route("/api/v1/fleet/hosts", ax_get(hosts))
}

// --- Huntress ---------------------------------------------------------------

pub(crate) const HUNTRESS_KEY: &str = "hk_public_key";
pub(crate) const HUNTRESS_SECRET: &str = "huntress-secret-value";

pub(crate) fn huntress_router() -> AxRouter<MockState> {
    async fn agents(
        AxState((mock, _)): AxState<MockState>,
        headers: AxHeaders,
        Query(query): Query<HashMap<String, String>>,
    ) -> Response {
        if let Some(response) = gate(&mock) {
            return response;
        }
        let expected = format!(
            "Basic {}",
            STANDARD.encode(format!("{HUNTRESS_KEY}:{HUNTRESS_SECRET}"))
        );
        if header(&headers, "authorization") != expected {
            return unauthorised();
        }
        let page = match query.get("page_token").map(String::as_str) {
            None => serde_json::json!({
                "agents":[{"id":1,"account_id":5,"hostname":"field-laptop","serial_number":"C02XK1ABCD",
                    "mac_addresses":["3c:22:fb:11:22:33"],"last_callback_at":"2026-10-03T00:00:00Z",
                    "platform":"darwin","defender_status":"Healthy"}],
                "pagination":{"current_page":1,"limit":500,"next_page_token":"MjAyMi0wMy0wMQ","next_page_url":"https://api.huntress.io/v1/agents?page_token=MjAyMi0wMy0wMQ&limit=500"}}),
            Some("MjAyMi0wMy0wMQ") => serde_json::json!({
                "agents":[{"id":2,"hostname":"office-pc","serial_number":"PF3ABCDE","mac_addresses":[],
                    "last_callback_at":"2026-09-01T00:00:00Z","platform":"windows"}],
                "pagination":{"current_page":2,"limit":500}}),
            Some(_) => return StatusCode::BAD_REQUEST.into_response(),
        };
        AxJson(page).into_response()
    }
    AxRouter::new().route("/v1/agents", ax_get(agents))
}

// --- Harness ----------------------------------------------------------------

fn config_for(kind: Kind, base: &str) -> ProviderConfig {
    let mut config = ProviderConfig {
        api_base_override: Some(base.into()),
        ..ProviderConfig::default()
    };
    match kind {
        Kind::Intune => {
            config.tenant_id = Some("contoso.onmicrosoft.com".into());
            config.client_id = Some("11111111-2222-3333-4444-555555555555".into());
        }
        Kind::CrowdStrike => {
            config.region = Some("us-1".into());
            config.client_id = Some("falconclient".into());
        }
        Kind::SentinelOne => config.console_url = Some("https://tenant.sentinelone.net".into()),
        Kind::FleetDm => config.server_url = Some("https://fleet.example.com".into()),
        Kind::Huntress => config.api_key = Some(HUNTRESS_KEY.into()),
    }
    config
}

pub(crate) fn mock_config_json(kind: &str, base: &str) -> serde_json::Value {
    serde_json::to_value(config_for(Kind::parse(kind).unwrap(), base)).unwrap()
}

fn secret_for(kind: Kind) -> &'static str {
    match kind {
        Kind::Intune => INTUNE_SECRET,
        Kind::CrowdStrike => CROWDSTRIKE_SECRET,
        Kind::SentinelOne => SENTINELONE_TOKEN,
        Kind::FleetDm => FLEET_TOKEN,
        Kind::Huntress => HUNTRESS_SECRET,
    }
}

fn router_for(kind: Kind) -> fn() -> AxRouter<MockState> {
    match kind {
        Kind::Intune => intune_router,
        Kind::CrowdStrike => crowdstrike_router,
        Kind::SentinelOne => sentinelone_router,
        Kind::FleetDm => fleet_router,
        Kind::Huntress => huntress_router,
    }
}

async fn reconcile(
    kind: Kind,
    base: &str,
    secret: &str,
) -> Result<Vec<DeviceSignal>, AdapterError> {
    let config = config_for(kind, base);
    let endpoints = validate_config(kind, &config).unwrap();
    run_adapter(kind, &config, &endpoints, &Secret(secret.into())).await
}

fn by_id(signals: &[DeviceSignal], id: &str) -> DeviceSignal {
    signals
        .iter()
        .find(|signal| signal.external_id == id)
        .cloned()
        .unwrap_or_else(|| panic!("signal {id}"))
}

#[tokio::test]
async fn intune_follows_next_link_and_maps_compliance_state() {
    let mock = Arc::new(Mock::default());
    let base = serve(mock.clone(), intune_router).await;
    let signals = reconcile(Kind::Intune, &base, INTUNE_SECRET).await.unwrap();
    assert_eq!(signals.len(), 2);
    let laptop = by_id(&signals, "intune-1");
    assert_eq!(laptop.compliant, Some(true));
    assert_eq!(laptop.serial_number.as_deref(), Some("C02XK1ABCD"));
    assert!(laptop.mac_addresses.contains(&"3C22FB112233".to_string()));
    assert!(laptop.last_seen_at.is_some());
    // Grace period is not compliance.
    let tablet = by_id(&signals, "intune-2");
    assert_eq!(tablet.compliant, Some(false));
    assert_eq!(tablet.status, "inGracePeriod");
    // Token + two pages.
    assert_eq!(mock.calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn crowdstrike_scrolls_ids_then_fetches_details() {
    let mock = Arc::new(Mock::default());
    let base = serve(mock.clone(), crowdstrike_router).await;
    let signals = reconcile(Kind::CrowdStrike, &base, CROWDSTRIKE_SECRET)
        .await
        .unwrap();
    assert_eq!(signals.len(), 3);
    assert_eq!(by_id(&signals, "aid-1").compliant, Some(true));
    let contained = by_id(&signals, "aid-2");
    assert_eq!(
        (contained.compliant, contained.status.as_str()),
        (Some(false), "contained")
    );
    let reduced = by_id(&signals, "aid-3");
    assert_eq!(reduced.compliant, Some(false));
    assert!(reduced.status.contains("reduced functionality"));
}

#[tokio::test]
async fn sentinelone_follows_cursor_and_flags_infected_agents() {
    let mock = Arc::new(Mock::default());
    let base = serve(mock.clone(), sentinelone_router).await;
    let signals = reconcile(Kind::SentinelOne, &base, SENTINELONE_TOKEN)
        .await
        .unwrap();
    assert_eq!(signals.len(), 2);
    let healthy = by_id(&signals, "1001");
    assert_eq!(
        (healthy.compliant, healthy.status.as_str()),
        (Some(true), "healthy")
    );
    assert_eq!(healthy.mac_addresses, vec!["3c:22:fb:11:22:33"]);
    let infected = by_id(&signals, "1002");
    assert_eq!(
        (infected.compliant, infected.status.as_str()),
        (Some(false), "infected")
    );
}

#[tokio::test]
async fn fleet_pages_until_a_short_page_and_counts_failing_policies() {
    let mock = Arc::new(Mock::default());
    mock.failing.store(2, Ordering::SeqCst);
    let base = serve(mock.clone(), fleet_router).await;
    let signals = reconcile(Kind::FleetDm, &base, FLEET_TOKEN).await.unwrap();
    assert_eq!(signals.len(), FLEET_PAGE + 1);
    assert_eq!(mock.calls.load(Ordering::SeqCst), 2);
    let laptop = by_id(&signals, "1");
    assert_eq!(
        (laptop.compliant, laptop.status.as_str()),
        (Some(false), "2 failing policies")
    );
    assert_eq!(by_id(&signals, "2").compliant, Some(true));
}

#[tokio::test]
async fn huntress_uses_basic_auth_and_page_tokens() {
    let mock = Arc::new(Mock::default());
    let base = serve(mock.clone(), huntress_router).await;
    let signals = reconcile(Kind::Huntress, &base, HUNTRESS_SECRET)
        .await
        .unwrap();
    assert_eq!(signals.len(), 2);
    let laptop = by_id(&signals, "1");
    assert_eq!(laptop.compliant, Some(true));
    assert!(laptop.last_seen_at.is_some());
}

#[tokio::test]
async fn every_adapter_reports_auth_failure_as_a_category() {
    for kind in Kind::ALL {
        let mock = Arc::new(Mock::default());
        let base = serve(mock, router_for(kind)).await;
        let error = reconcile(kind, &base, "wrong-secret-value")
            .await
            .unwrap_err();
        assert_eq!(error, AdapterError::Auth, "{kind:?}");
        // The message never echoes the credential or the provider body.
        assert!(!error.message().contains("wrong-secret-value"));
        assert!(!error.message().contains("invalid_client"));
    }
}

#[tokio::test]
async fn every_adapter_honours_retry_after_on_429() {
    for kind in Kind::ALL {
        let mock = Arc::new(Mock::default());
        mock.rate_limit_once.store(true, Ordering::SeqCst);
        let base = serve(mock.clone(), router_for(kind)).await;
        let started = std::time::Instant::now();
        let signals = reconcile(kind, &base, secret_for(kind)).await.unwrap();
        assert!(!signals.is_empty(), "{kind:?}");
        assert!(
            started.elapsed() >= Duration::from_millis(900),
            "{kind:?} waited"
        );
    }
}

#[tokio::test]
async fn long_retry_after_and_outage_become_errors() {
    async fn always_limited() -> Response {
        (StatusCode::TOO_MANY_REQUESTS, [("retry-after", "900")]).into_response()
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(
            listener,
            AxRouter::new().route("/api/v1/fleet/hosts", ax_get(always_limited)),
        )
        .await
        .unwrap();
    });
    assert_eq!(
        reconcile(Kind::FleetDm, &base, FLEET_TOKEN)
            .await
            .unwrap_err(),
        AdapterError::RateLimited(900)
    );
    let mock = Arc::new(Mock::default());
    mock.down.store(true, Ordering::SeqCst);
    let base = serve(mock, fleet_router).await;
    assert_eq!(
        reconcile(Kind::FleetDm, &base, FLEET_TOKEN)
            .await
            .unwrap_err(),
        AdapterError::Status(503)
    );
}

#[tokio::test]
async fn graph_next_link_to_another_host_is_rejected() {
    async fn token() -> AxJson<serde_json::Value> {
        AxJson(serde_json::json!({"access_token":"graph-token"}))
    }
    async fn devices() -> AxJson<serde_json::Value> {
        AxJson(
            serde_json::json!({"value":[],"@odata.nextLink":"http://169.254.169.254/latest/meta-data"}),
        )
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(
            listener,
            AxRouter::new()
                .route("/:tenant/oauth2/v2.0/token", ax_post(token))
                .route("/v1.0/deviceManagement/managedDevices", ax_get(devices)),
        )
        .await
        .unwrap();
    });
    assert_eq!(
        reconcile(Kind::Intune, &base, INTUNE_SECRET)
            .await
            .unwrap_err(),
        AdapterError::BadResponse
    );
}

#[test]
fn config_accepts_only_each_providers_fields_and_safe_endpoints() {
    let fleet = |url: &str| ProviderConfig {
        server_url: Some(url.into()),
        ..ProviderConfig::default()
    };
    assert!(validate_config(Kind::FleetDm, &fleet("https://fleet.example.com")).is_ok());
    assert!(validate_config(Kind::FleetDm, &fleet("https://169.254.169.254")).is_err());
    assert!(validate_config(Kind::FleetDm, &fleet("https://fleet.example.com/api?x=1")).is_err());
    let s1 = ProviderConfig {
        console_url: Some("https://attacker.example.com".into()),
        ..ProviderConfig::default()
    };
    assert!(validate_config(Kind::SentinelOne, &s1).is_err());
    let mixed = ProviderConfig {
        api_key: Some("key".into()),
        server_url: Some("https://fleet.example.com".into()),
        ..ProviderConfig::default()
    };
    assert!(validate_config(Kind::Huntress, &mixed).is_err());
    let tenant = ProviderConfig {
        tenant_id: Some("../../evil".into()),
        client_id: Some("abc".into()),
        ..ProviderConfig::default()
    };
    assert!(validate_config(Kind::Intune, &tenant).is_err());
    let region = ProviderConfig {
        region: Some("au-1".into()),
        client_id: Some("abc".into()),
        ..ProviderConfig::default()
    };
    assert!(validate_config(Kind::CrowdStrike, &region).is_err());
}

#[test]
fn sealed_secrets_round_trip_and_never_print() {
    let master = b"test-master-secret-at-least-32-bytes!";
    let sealed = seal_secret(master, "provider-secret").unwrap();
    assert!(sealed.starts_with(SEALED_PREFIX) && !sealed.contains("provider-secret"));
    let opened = open_secret(master, &sealed).unwrap();
    assert_eq!(opened.0, "provider-secret");
    assert!(!format!("{opened:?}").contains("provider-secret"));
    assert!(open_secret(b"another-master-secret-of-32-bytes!!", &sealed).is_err());
    assert!(!secret_fingerprint("provider-secret").contains("provider"));
}

// --- Matching and assessment -------------------------------------------------

fn node(n: u128, serial: Option<&str>, macs: &[&str], host: &str) -> NodeKeys {
    NodeKeys {
        id: Uuid::from_u128(n),
        hostname: Some(host.into()),
        serial: serial.and_then(normalise_serial),
        macs: macs.iter().filter_map(|m| normalise_mac(m)).collect(),
        pinned_at: None,
        pending: false,
    }
}

fn pinned(mut keys: NodeKeys, at: i64) -> NodeKeys {
    keys.pinned_at = Some(at);
    keys
}

fn signal(id: &str, serial: Option<&str>, macs: &[&str], host: &str) -> StoredSignal {
    StoredSignal {
        external_id: id.into(),
        hostname: Some(host.into()),
        serial: serial.and_then(normalise_serial),
        macs: macs.iter().filter_map(|m| normalise_mac(m)).collect(),
        compliant: Some(true),
        status: "healthy".into(),
        last_seen_at: Some(1_000),
        synced_at: 1_000,
    }
}

#[test]
fn identifiers_normalise_and_reject_placeholders() {
    assert_eq!(normalise_serial(" c02xk1 abcd "), Some("C02XK1ABCD".into()));
    for junk in [
        "",
        "0",
        "To Be Filled By O.E.M.",
        "Default string",
        "00000000",
        "N/A",
    ] {
        assert_eq!(normalise_serial(junk), None, "{junk}");
    }
    assert_eq!(
        normalise_mac("3C22FB112233"),
        Some("3c:22:fb:11:22:33".into())
    );
    assert_eq!(
        normalise_mac("3c-22-fb-11-22-33"),
        Some("3c:22:fb:11:22:33".into())
    );
    // Randomised (locally administered), multicast and zero MACs never match.
    assert_eq!(normalise_mac("02:42:ac:11:00:02"), None);
    assert_eq!(normalise_mac("01:00:5e:00:00:01"), None);
    assert_eq!(normalise_mac("00:00:00:00:00:00"), None);
}

#[test]
fn matching_prefers_serial_then_mac_and_hostname_is_opt_in() {
    let nodes = [
        node(1, Some("C02XK1ABCD"), &[], "laptop"),
        node(2, None, &["3c:22:fb:44:55:66"], "desk"),
        node(3, None, &[], "kiosk"),
    ];
    let signals = [
        signal("a", Some("C02XK1ABCD"), &[], "other-name"),
        signal("b", None, &["3C22FB445566"], "desk"),
        signal("c", None, &[], "kiosk.corp.example"),
    ];
    let result = match_devices(&nodes, &signals, false);
    assert!(
        matches!(&result[&Uuid::from_u128(1)], DeviceMatch::Matched { external_id, matched_by: "serial_number", .. } if external_id == "a")
    );
    assert!(matches!(
        &result[&Uuid::from_u128(2)],
        DeviceMatch::Matched {
            matched_by: "mac_address",
            ..
        }
    ));
    assert_eq!(result[&Uuid::from_u128(3)], DeviceMatch::Unmatched);
    let with_host = match_devices(&nodes, &signals, true);
    assert!(matches!(
        &with_host[&Uuid::from_u128(3)],
        DeviceMatch::Matched {
            matched_by: "hostname",
            ..
        }
    ));
}

#[test]
fn ambiguous_matches_fail_for_every_claimant() {
    // Two provider records share a serial.
    let nodes = [node(1, Some("C02XK1ABCD"), &[], "laptop")];
    let signals = [
        signal("a", Some("C02XK1ABCD"), &[], "laptop"),
        signal("b", Some("C02XK1ABCD"), &[], "laptop-old"),
    ];
    assert_eq!(
        match_devices(&nodes, &signals, false)[&Uuid::from_u128(1)],
        DeviceMatch::Ambiguous { candidates: 2 }
    );
    // A second device copies the serial and neither has a pin time: neither
    // inherits the signal.
    let nodes = [
        node(1, Some("C02XK1ABCD"), &[], "laptop"),
        node(2, Some("C02XK1ABCD"), &[], "impostor"),
    ];
    let signals = [signal("a", Some("C02XK1ABCD"), &[], "laptop")];
    let result = match_devices(&nodes, &signals, false);
    assert!(result
        .values()
        .all(|m| *m == DeviceMatch::Ambiguous { candidates: 2 }));
}

#[test]
fn first_device_to_pin_identifiers_keeps_a_contested_record() {
    let signals = [signal("a", Some("C02XK1ABCD"), &[], "laptop")];
    // The impostor copied the serial after the owner pinned it.
    let nodes = [
        pinned(node(1, Some("C02XK1ABCD"), &[], "laptop"), 100),
        pinned(node(2, Some("C02XK1ABCD"), &[], "impostor"), 200),
    ];
    let result = match_devices(&nodes, &signals, false);
    assert!(matches!(
        &result[&Uuid::from_u128(1)],
        DeviceMatch::Matched { external_id, .. } if external_id == "a"
    ));
    assert_eq!(result[&Uuid::from_u128(2)], DeviceMatch::Contested);
    // A claim by MAC against a record already held by serial loses too, and
    // a device that never pinned ranks after one that did.
    let signals = [signal(
        "a",
        Some("C02XK1ABCD"),
        &["3c:22:fb:11:22:33"],
        "laptop",
    )];
    let nodes = [
        node(2, None, &["3c:22:fb:11:22:33"], "impostor"),
        pinned(node(1, Some("C02XK1ABCD"), &[], "laptop"), 300),
    ];
    let result = match_devices(&nodes, &signals, false);
    assert!(matches!(
        &result[&Uuid::from_u128(1)],
        DeviceMatch::Matched { .. }
    ));
    assert_eq!(result[&Uuid::from_u128(2)], DeviceMatch::Contested);
    // Equal pin times have no first reporter: both stay ambiguous.
    let nodes = [
        pinned(node(1, Some("C02XK1ABCD"), &[], "laptop"), 100),
        pinned(node(2, Some("C02XK1ABCD"), &[], "impostor"), 100),
    ];
    assert!(match_devices(&nodes, &signals, false)
        .values()
        .all(|m| *m == DeviceMatch::Ambiguous { candidates: 2 }));
}

fn fact(matched: DeviceMatch, outage_since: Option<i64>) -> IntegrationFact {
    IntegrationFact {
        integration_id: "i".into(),
        kind: "fleetdm",
        provider: "FleetDM",
        name: "fleet".into(),
        enabled: true,
        last_success_at: Some(1_000),
        outage_since,
        matched,
        source: PROVIDER_SOURCE,
    }
}

fn matched(compliant: bool, synced_at: i64, last_seen: Option<i64>) -> DeviceMatch {
    DeviceMatch::Matched {
        external_id: "a".into(),
        matched_by: "serial_number",
        compliant: Some(compliant),
        status: if compliant { "healthy" } else { "infected" }.into(),
        last_seen_at: last_seen,
        synced_at,
    }
}

fn requirement(value: serde_json::Value) -> IntegrationRequirement {
    let mut value = value;
    value["integration_id"] = serde_json::json!(Uuid::nil());
    let requirement: IntegrationRequirement = serde_json::from_value(value).unwrap();
    requirement.validate().unwrap();
    requirement
}

#[test]
fn assessment_is_closed_by_default_and_open_only_when_configured() {
    let strict = requirement(serde_json::json!({"max_age_secs": 600}));
    let fresh = assess(
        &strict,
        Some(&fact(matched(true, 1_000, None), None)),
        1_100,
    );
    assert!(fresh.passed);
    assert_eq!(fresh.lapse, Some(1_600));
    assert!(
        !assess(
            &strict,
            Some(&fact(matched(false, 1_000, None), None)),
            1_100
        )
        .passed
    );
    assert!(!assess(&strict, Some(&fact(DeviceMatch::Unmatched, None)), 1_100).passed);
    assert!(
        !assess(
            &strict,
            Some(&fact(DeviceMatch::Ambiguous { candidates: 2 }, None)),
            1_100
        )
        .passed
    );
    assert!(!assess(&strict, None, 1_100).passed);
    let changed = assess(
        &strict,
        Some(&fact(DeviceMatch::IdentityChanged, None)),
        1_100,
    );
    assert!(!changed.passed && changed.reason.contains("approves"));
    assert!(!assess(&strict, Some(&fact(DeviceMatch::Contested, None)), 1_100).passed);
    // Stale data during an outage fails closed by default.
    let outage = fact(matched(true, 1_000, None), Some(1_200));
    let closed = assess(&strict, Some(&outage), 5_000);
    assert!(!closed.passed && closed.reason.contains("fails closed"));
    // Fail-open keeps a device whose last known state passed...
    let lenient = requirement(serde_json::json!({"max_age_secs": 600, "on_outage": "pass"}));
    assert!(assess(&lenient, Some(&outage), 5_000).passed);
    // ...but never one that was failing, and never without an outage.
    let failing = fact(matched(false, 1_000, None), Some(1_200));
    assert!(!assess(&lenient, Some(&failing), 5_000).passed);
    let stale = fact(matched(true, 1_000, None), None);
    assert!(!assess(&lenient, Some(&stale), 5_000).passed);
    let mut disabled = fact(matched(true, 1_000, None), None);
    disabled.enabled = false;
    assert!(!assess(&strict, Some(&disabled), 1_100).passed);
}

#[test]
fn last_seen_limit_fails_old_sensors_and_sets_the_deadline() {
    let rule = requirement(serde_json::json!({"max_age_secs": 3600, "max_last_seen_secs": 300}));
    let recent = assess(
        &rule,
        Some(&fact(matched(true, 1_000, Some(1_000)), None)),
        1_100,
    );
    assert!(recent.passed);
    assert_eq!(recent.lapse, Some(1_300));
    assert!(
        !assess(
            &rule,
            Some(&fact(matched(true, 1_000, Some(500)), None)),
            1_100
        )
        .passed
    );
    assert!(!assess(&rule, Some(&fact(matched(true, 1_000, None), None)), 1_100).passed);
    assert!(serde_json::from_value::<IntegrationRequirement>(
        serde_json::json!({"integration_id": Uuid::nil(), "max_age_secs": 10})
    )
    .unwrap()
    .validate()
    .is_err());
}

#[test]
fn backoff_grows_respects_retry_after_and_stays_bounded() {
    assert!(backoff_secs(1, 900, None) <= 72);
    assert!(backoff_secs(4, 900, None) >= 380);
    assert!(backoff_secs(30, 900, None) <= 3600 * 6 / 5);
    assert!(backoff_secs(1, 900, Some(600)) >= 600);
}
