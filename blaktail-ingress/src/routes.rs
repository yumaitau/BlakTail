//! The live route table. Routes come only from the coordinator; each one
//! names exactly one target socket, and the table goes dark when the
//! coordinator has not confirmed it within the stale bound.

use crate::limits::RateLimiter;
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};
use tokio::sync::{watch, Semaphore};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct RouteConfig {
    pub id: Uuid,
    pub fqdn: String,
    pub target_address: String,
    pub target_port: u16,
    pub tls_mode: String,
    pub auth_mode: String,
    #[serde(default)]
    pub allowed_email_domains: Vec<String>,
    /// Client networks allowed to use the route; empty means any.
    #[serde(default)]
    pub allowed_source_cidrs: Vec<String>,
    pub rate_limit_per_minute: i64,
    pub max_body_bytes: i64,
    pub max_connections: i64,
    pub log_retention_days: i64,
    pub revision: i64,
}

#[derive(Debug, Deserialize)]
pub struct IngressConfig {
    pub revision: i64,
    pub stale_after_secs: u64,
    pub routes: Vec<RouteConfig>,
}

/// Which target addresses the proxy may ever dial. Defaults to the BlakTail
/// overlay (100.64.0.0/10); a coordinator cannot point a route at metadata
/// services, loopback or the ingress host's LAN.
#[derive(Clone, Debug)]
pub struct TargetPolicy {
    allowed: Vec<(IpAddr, u8)>,
}

impl Default for TargetPolicy {
    fn default() -> Self {
        Self {
            allowed: vec![(IpAddr::from([100, 64, 0, 0]), 10)],
        }
    }
}

impl TargetPolicy {
    pub fn new(cidrs: &[String]) -> Result<Self, String> {
        if cidrs.is_empty() {
            return Ok(Self::default());
        }
        let allowed = cidrs
            .iter()
            .map(|cidr| parse_cidr(cidr).ok_or_else(|| format!("invalid CIDR {cidr:?}")))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { allowed })
    }

    pub fn permits(&self, ip: IpAddr) -> bool {
        self.allowed
            .iter()
            .any(|(network, prefix)| cidr_contains(*network, *prefix, ip))
    }
}

pub fn parse_cidr(cidr: &str) -> Option<(IpAddr, u8)> {
    let (address, prefix) = cidr.split_once('/')?;
    let address: IpAddr = address.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    let max = if address.is_ipv4() { 32 } else { 128 };
    (prefix <= max).then_some((address, prefix))
}

pub fn cidr_contains(network: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (network, ip) {
        (IpAddr::V4(network), IpAddr::V4(ip)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            u32::from(network) & mask == u32::from(ip) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(ip)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            u128::from(network) & mask == u128::from(ip) & mask
        }
        _ => false,
    }
}

/// One route as served: its config plus the limiters that outlive a single
/// request. Dropping it from the table closes upgraded tunnels.
pub struct LiveRoute {
    pub config: RouteConfig,
    pub target: SocketAddr,
    sources: Vec<(IpAddr, u8)>,
    pub limiter: Mutex<RateLimiter>,
    pub connections: Arc<Semaphore>,
    revoked: watch::Sender<bool>,
}

impl LiveRoute {
    fn new(config: RouteConfig, target: SocketAddr, sources: Vec<(IpAddr, u8)>) -> Self {
        let rate = u32::try_from(config.rate_limit_per_minute.clamp(1, 60_000)).unwrap_or(600);
        let connections = usize::try_from(config.max_connections.clamp(1, 4096)).unwrap_or(256);
        Self {
            limiter: Mutex::new(RateLimiter::per_minute(rate)),
            connections: Arc::new(Semaphore::new(connections)),
            revoked: watch::channel(false).0,
            config,
            target,
            sources,
        }
    }

    /// Whether `client` may use this route (IPv4-mapped IPv6 counts as IPv4).
    pub fn source_allowed(&self, client: IpAddr) -> bool {
        let client = client.to_canonical();
        self.sources.is_empty()
            || self
                .sources
                .iter()
                .any(|(network, prefix)| cidr_contains(*network, *prefix, client))
    }

    pub fn max_body(&self) -> u64 {
        u64::try_from(self.config.max_body_bytes).unwrap_or(0)
    }

    pub fn oidc(&self) -> bool {
        self.config.auth_mode == "oidc"
    }

    /// Resolves when this route is withdrawn or changed.
    pub fn revoked(&self) -> watch::Receiver<bool> {
        self.revoked.subscribe()
    }
}

#[derive(Default)]
struct Snapshot {
    routes: HashMap<String, Arc<LiveRoute>>,
    fresh_until: Option<Instant>,
    revision: i64,
}

#[derive(Default)]
pub struct RouteTable {
    inner: RwLock<Snapshot>,
    policy: TargetPolicy,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ApplyOutcome {
    pub served: Vec<String>,
    /// Routes refused locally (for example a target outside the overlay).
    pub refused: Vec<(Uuid, String)>,
}

impl RouteTable {
    pub fn new(policy: TargetPolicy) -> Self {
        Self {
            inner: RwLock::default(),
            policy,
        }
    }

    /// Replaces the table with `config`. Unchanged routes keep their
    /// limiters; removed or changed ones are revoked so open tunnels close.
    pub fn apply(&self, config: &IngressConfig) -> ApplyOutcome {
        let mut outcome = ApplyOutcome::default();
        let mut next = HashMap::new();
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        for route in &config.routes {
            let fqdn = route.fqdn.to_ascii_lowercase();
            let target = match route.target_address.parse::<IpAddr>() {
                Ok(ip) if self.policy.permits(ip) && route.target_port != 0 => {
                    SocketAddr::new(ip, route.target_port)
                }
                _ => {
                    outcome.refused.push((
                        route.id,
                        "target is outside the overlay address range this ingress may dial".into(),
                    ));
                    continue;
                }
            };
            let Some(sources) = route
                .allowed_source_cidrs
                .iter()
                .map(|cidr| parse_cidr(cidr))
                .collect::<Option<Vec<_>>>()
            else {
                outcome.refused.push((
                    route.id,
                    "route has an invalid allowed client network".into(),
                ));
                continue;
            };
            let live = match inner.routes.get(&fqdn) {
                Some(existing) if existing.config == *route && existing.target == target => {
                    existing.clone()
                }
                _ => Arc::new(LiveRoute::new(route.clone(), target, sources)),
            };
            outcome.served.push(fqdn.clone());
            next.insert(fqdn, live);
        }
        for (fqdn, old) in &inner.routes {
            if !next.get(fqdn).is_some_and(|new| Arc::ptr_eq(new, old)) {
                let _ = old.revoked.send(true);
            }
        }
        inner.routes = next;
        inner.revision = config.revision;
        inner.fresh_until =
            Some(Instant::now() + Duration::from_secs(config.stale_after_secs.min(30)));
        outcome.served.sort();
        outcome
    }

    /// The coordinator confirmed nothing changed (long-poll 204).
    pub fn confirm(&self, stale_after: Duration) {
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        inner.fresh_until = Some(Instant::now() + stale_after.min(Duration::from_secs(30)));
    }

    /// Withdraws everything (credential refused, node suspended).
    pub fn clear(&self) {
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        for route in inner.routes.values() {
            let _ = route.revoked.send(true);
        }
        inner.routes.clear();
        inner.fresh_until = None;
    }

    pub fn revision(&self) -> i64 {
        self.inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .revision
    }

    /// A live route for `host`, or `None` when unknown or when the table is
    /// stale (the coordinator has not confirmed it within the bound).
    pub fn get(&self, host: &str) -> Option<Arc<LiveRoute>> {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        if inner
            .fresh_until
            .is_none_or(|until| Instant::now() >= until)
        {
            return None;
        }
        inner.routes.get(&host.to_ascii_lowercase()).cloned()
    }

    pub fn is_fresh(&self) -> bool {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        inner
            .fresh_until
            .is_some_and(|until| Instant::now() < until)
    }

    /// Every route in the table, fresh or not (for certificates and logs).
    pub fn all(&self) -> Vec<Arc<LiveRoute>> {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        inner.routes.values().cloned().collect()
    }

    #[cfg(test)]
    pub(crate) fn expire_now(&self) {
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        inner.fresh_until = Some(Instant::now());
    }
}

#[cfg(test)]
pub(crate) fn test_route(fqdn: &str, target: SocketAddr) -> RouteConfig {
    RouteConfig {
        id: Uuid::new_v4(),
        fqdn: fqdn.into(),
        target_address: target.ip().to_string(),
        target_port: target.port(),
        tls_mode: "operator_files".into(),
        auth_mode: "none".into(),
        allowed_email_domains: Vec::new(),
        allowed_source_cidrs: Vec::new(),
        rate_limit_per_minute: 6000,
        max_body_bytes: 1024,
        max_connections: 64,
        log_retention_days: 7,
        revision: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(routes: Vec<RouteConfig>) -> IngressConfig {
        IngressConfig {
            revision: 7,
            stale_after_secs: 30,
            routes,
        }
    }

    #[test]
    fn targets_outside_the_overlay_are_refused() {
        let table = RouteTable::new(TargetPolicy::default());
        let mut metadata = test_route("a.example.org.au", "169.254.169.254:80".parse().unwrap());
        metadata.id = Uuid::from_u128(1);
        let loopback = test_route("b.example.org.au", "127.0.0.1:22".parse().unwrap());
        let good = test_route("c.example.org.au", "100.64.0.9:8080".parse().unwrap());
        let outcome = table.apply(&config(vec![metadata, loopback, good]));
        assert_eq!(outcome.served, vec!["c.example.org.au"]);
        assert_eq!(outcome.refused.len(), 2);
        assert!(table.get("a.example.org.au").is_none());
        assert!(table.get("C.Example.org.au").is_some());
    }

    #[test]
    fn stale_tables_serve_nothing_and_removal_revokes() {
        let table = RouteTable::new(TargetPolicy::default());
        let route = test_route("a.example.org.au", "100.64.0.9:8080".parse().unwrap());
        table.apply(&config(vec![route.clone()]));
        let live = table.get("a.example.org.au").unwrap();
        let revoked = live.revoked();
        // Same config keeps the same limiter state.
        table.apply(&config(vec![route]));
        assert!(Arc::ptr_eq(&live, &table.get("a.example.org.au").unwrap()));
        assert!(!*revoked.borrow());
        table.expire_now();
        assert!(table.get("a.example.org.au").is_none());
        table.apply(&config(vec![]));
        assert!(*revoked.borrow());
    }

    #[test]
    fn source_networks_gate_clients_and_bad_ones_refuse_the_route() {
        let table = RouteTable::new(TargetPolicy::default());
        let mut limited = test_route("a.example.org.au", "100.64.0.9:80".parse().unwrap());
        limited.allowed_source_cidrs = vec!["203.0.113.0/24".into()];
        let mut broken = test_route("b.example.org.au", "100.64.0.9:80".parse().unwrap());
        broken.allowed_source_cidrs = vec!["nonsense".into()];
        let outcome = table.apply(&config(vec![limited, broken]));
        assert_eq!(outcome.served, vec!["a.example.org.au"]);
        let route = table.get("a.example.org.au").unwrap();
        assert!(route.source_allowed("203.0.113.5".parse().unwrap()));
        assert!(route.source_allowed("::ffff:203.0.113.5".parse().unwrap()));
        assert!(!route.source_allowed("198.51.100.5".parse().unwrap()));
    }

    #[test]
    fn cidr_matching() {
        let (net, prefix) = parse_cidr("100.64.0.0/10").unwrap();
        assert!(cidr_contains(net, prefix, "100.127.255.1".parse().unwrap()));
        assert!(!cidr_contains(net, prefix, "100.128.0.1".parse().unwrap()));
        assert!(!cidr_contains(net, prefix, "::1".parse().unwrap()));
        assert!(parse_cidr("10.0.0.0/33").is_none());
    }
}
