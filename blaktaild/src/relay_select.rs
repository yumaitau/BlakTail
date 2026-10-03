//! Deterministic, Australia-only relay selection with bounded failover.
//!
//! Relays keep registrations in memory, so two peers can only relay to each
//! other through the same relay. Every agent therefore walks the
//! coordinator's list in the same order and uses the first relay that is not
//! cooling down after a failure. A failed relay backs off exponentially
//! (30 s doubling to 10 min). Once a higher-priority relay's back-off has
//! elapsed, an authenticated probe must succeed before the agent fails back,
//! so all agents converge on the same healthy relay without flapping.

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

const BASE_COOLDOWN: Duration = Duration::from_secs(30);
const MAX_COOLDOWN: Duration = Duration::from_secs(600);
/// Re-resolve relay names at most this often while a relay is in use.
const RESOLVE_TTL: Duration = Duration::from_secs(300);

/// One coordinator-advertised relay and its declared Australian region.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayEndpoint {
    pub endpoint: String,
    pub region: String,
}

/// Relay names in coordinator priority order, keeping only those declared in
/// an approved Australian region. Coordinators that predate declared regions
/// send only `relays`; those are used as-is because that coordinator already
/// validated `coordinator.region`.
pub fn eligible_relays(relays: &[String], declared: &[RelayEndpoint]) -> Vec<String> {
    if declared.is_empty() {
        return relays.to_vec();
    }
    declared
        .iter()
        .filter(|relay| blaktail_config::is_australian_region(&relay.region))
        .map(|relay| relay.endpoint.clone())
        .collect()
}

#[derive(Clone, Copy, Debug)]
struct Failure {
    strikes: u32,
    retry_at: Instant,
}

#[derive(Default)]
pub struct RelaySelector {
    failures: HashMap<SocketAddr, Failure>,
    resolved_for: Vec<String>,
    resolved: Vec<SocketAddr>,
    resolved_at: Option<Instant>,
    failovers: u64,
    failbacks: u64,
}

impl RelaySelector {
    /// Resolved candidate addresses in priority order, cached for five
    /// minutes or until the advertised list changes.
    pub async fn candidates(&mut self, relays: &[String]) -> Vec<SocketAddr> {
        let fresh = self
            .resolved_at
            .is_some_and(|at| at.elapsed() < RESOLVE_TTL);
        if !fresh || self.resolved_for != relays || self.resolved.is_empty() {
            let mut resolved = Vec::new();
            for relay in relays {
                if let Ok(addresses) = tokio::net::lookup_host(relay).await {
                    for address in addresses {
                        if !resolved.contains(&address) {
                            resolved.push(address);
                        }
                    }
                }
            }
            self.resolved_for = relays.to_vec();
            self.resolved = resolved;
            self.resolved_at = Some(Instant::now());
        }
        self.resolved.clone()
    }

    fn cooling(&self, address: SocketAddr, now: Instant) -> bool {
        self.failures
            .get(&address)
            .is_some_and(|failure| failure.retry_at > now)
    }

    /// First candidate not cooling down. When every candidate is cooling,
    /// the one whose back-off ends first, so an agent never gives up on
    /// relaying while at least one relay is configured.
    pub fn choose(&self, candidates: &[SocketAddr], now: Instant) -> Option<SocketAddr> {
        candidates
            .iter()
            .copied()
            .find(|address| !self.cooling(*address, now))
            .or_else(|| {
                candidates
                    .iter()
                    .copied()
                    .min_by_key(|address| self.failures.get(address).map(|f| f.retry_at))
            })
    }

    pub fn record_failure(&mut self, address: SocketAddr, now: Instant) -> Duration {
        let strikes = self
            .failures
            .get(&address)
            .map_or(1, |failure| failure.strikes.saturating_add(1));
        let cooldown = BASE_COOLDOWN
            .saturating_mul(1u32 << (strikes - 1).min(10))
            .min(MAX_COOLDOWN);
        self.failures.insert(
            address,
            Failure {
                strikes,
                retry_at: now + cooldown,
            },
        );
        cooldown
    }

    pub fn record_healthy(&mut self, address: SocketAddr) {
        self.failures.remove(&address);
    }

    /// A higher-priority relay whose back-off has ended, if any. The caller
    /// must prove it with an authenticated probe before switching.
    pub fn failback_target(
        &self,
        active: SocketAddr,
        candidates: &[SocketAddr],
        now: Instant,
    ) -> Option<SocketAddr> {
        candidates
            .iter()
            .copied()
            .take_while(|address| *address != active)
            .find(|address| !self.cooling(*address, now))
    }

    pub fn note_failover(&mut self) {
        self.failovers += 1;
    }

    pub fn note_failback(&mut self) {
        self.failbacks += 1;
    }

    pub fn failovers(&self) -> u64 {
        self.failovers
    }

    pub fn failbacks(&self) -> u64 {
        self.failbacks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addresses() -> [SocketAddr; 3] {
        [
            "192.0.2.1:3478".parse().unwrap(),
            "192.0.2.2:3478".parse().unwrap(),
            "192.0.2.3:3478".parse().unwrap(),
        ]
    }

    #[test]
    fn only_declared_australian_relays_are_eligible_in_coordinator_order() {
        let declared = vec![
            RelayEndpoint {
                endpoint: "relay-b:3478".into(),
                region: "australia-southeast1".into(),
            },
            RelayEndpoint {
                endpoint: "relay-x:3478".into(),
                region: "ap-southeast-1".into(),
            },
            RelayEndpoint {
                endpoint: "relay-a:3478".into(),
                region: "ap-southeast-2".into(),
            },
        ];
        assert_eq!(
            eligible_relays(&["ignored:3478".into()], &declared),
            vec!["relay-b:3478", "relay-a:3478"]
        );
        assert_eq!(
            eligible_relays(&["legacy:3478".into()], &[]),
            vec!["legacy:3478"]
        );
        let offshore_only = &declared[1..2];
        assert!(eligible_relays(&["relay-x:3478".into()], offshore_only).is_empty());
    }

    #[test]
    fn every_agent_picks_the_same_first_healthy_relay() {
        let [a, b, c] = addresses();
        let now = Instant::now();
        let first = RelaySelector::default();
        let second = RelaySelector::default();
        assert_eq!(first.choose(&[a, b, c], now), Some(a));
        assert_eq!(second.choose(&[a, b, c], now), Some(a));
        assert_eq!(first.choose(&[], now), None);
    }

    #[test]
    fn failover_skips_cooling_relays_and_is_bounded_when_all_fail() {
        let [a, b, c] = addresses();
        let now = Instant::now();
        let mut selector = RelaySelector::default();
        selector.record_failure(a, now);
        assert_eq!(selector.choose(&[a, b, c], now), Some(b));
        selector.record_failure(b, now + Duration::from_secs(1));
        assert_eq!(selector.choose(&[a, b, c], now), Some(c));
        selector.record_failure(c, now + Duration::from_secs(2));
        // All cooling: retry the one whose back-off ends first, never none.
        assert_eq!(selector.choose(&[a, b, c], now), Some(a));
        // After a's back-off it is preferred again.
        assert_eq!(
            selector.choose(&[a, b, c], now + Duration::from_secs(31)),
            Some(a)
        );
    }

    #[test]
    fn back_off_doubles_and_caps_then_resets_on_health() {
        let [a, ..] = addresses();
        let now = Instant::now();
        let mut selector = RelaySelector::default();
        let cooldowns: Vec<u64> = (0..7)
            .map(|_| selector.record_failure(a, now).as_secs())
            .collect();
        assert_eq!(cooldowns, vec![30, 60, 120, 240, 480, 600, 600]);
        selector.record_healthy(a);
        assert_eq!(selector.record_failure(a, now).as_secs(), 30);
    }

    #[test]
    fn failback_waits_for_back_off_and_only_targets_higher_priority() {
        let [a, b, c] = addresses();
        let now = Instant::now();
        let mut selector = RelaySelector::default();
        selector.record_failure(a, now);
        assert_eq!(selector.failback_target(b, &[a, b, c], now), None);
        assert_eq!(
            selector.failback_target(b, &[a, b, c], now + Duration::from_secs(30)),
            Some(a)
        );
        assert_eq!(selector.failback_target(a, &[a, b, c], now), None);
        // A failed probe extends the back-off rather than flapping.
        selector.record_failure(a, now + Duration::from_secs(30));
        assert_eq!(
            selector.failback_target(b, &[a, b, c], now + Duration::from_secs(60)),
            None
        );
    }

    #[tokio::test]
    async fn candidates_resolve_in_order_without_duplicates() {
        let mut selector = RelaySelector::default();
        let relays = vec![
            "127.0.0.1:3478".to_owned(),
            "127.0.0.1:3478".to_owned(),
            "127.0.0.2:3478".to_owned(),
        ];
        assert_eq!(
            selector.candidates(&relays).await,
            vec![
                "127.0.0.1:3478".parse::<SocketAddr>().unwrap(),
                "127.0.0.2:3478".parse().unwrap()
            ]
        );
    }
}
