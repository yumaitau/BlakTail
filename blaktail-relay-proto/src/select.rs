//! Deterministic relay choice with exponential back-off.
//!
//! Relays keep registrations in memory, so two peers can only relay to each
//! other through the same relay process. Every client therefore walks the
//! coordinator's (already Australia-filtered) list in the same order and uses
//! the first relay that is not cooling down after a failure. A failed relay
//! backs off exponentially (30 s doubling to 10 min). Fail-back to a
//! higher-priority relay happens only after the caller proves it with an
//! authenticated probe, so clients converge without flapping.

use std::{
    collections::HashMap,
    hash::Hash,
    time::{Duration, Instant},
};

pub const BASE_COOLDOWN: Duration = Duration::from_secs(30);
pub const MAX_COOLDOWN: Duration = Duration::from_secs(600);

#[derive(Clone, Copy, Debug)]
struct Failure {
    strikes: u32,
    retry_at: Instant,
}

/// Selection state keyed by whatever identifies a relay for the caller: a
/// resolved `SocketAddr` on desktop, the advertised `host:port` on mobile.
#[derive(Debug)]
pub struct Selector<K> {
    failures: HashMap<K, Failure>,
    failovers: u64,
    failbacks: u64,
}

impl<K> Default for Selector<K> {
    fn default() -> Self {
        Self {
            failures: HashMap::new(),
            failovers: 0,
            failbacks: 0,
        }
    }
}

impl<K: Clone + Eq + Hash> Selector<K> {
    fn cooling(&self, relay: &K, now: Instant) -> bool {
        self.failures
            .get(relay)
            .is_some_and(|failure| failure.retry_at > now)
    }

    /// First candidate not cooling down. When every candidate is cooling,
    /// the one whose back-off ends first, so a client never gives up on
    /// relaying while at least one relay is configured.
    pub fn choose(&self, candidates: &[K], now: Instant) -> Option<K> {
        candidates
            .iter()
            .find(|relay| !self.cooling(relay, now))
            .or_else(|| {
                candidates
                    .iter()
                    .min_by_key(|relay| self.failures.get(*relay).map(|f| f.retry_at))
            })
            .cloned()
    }

    pub fn record_failure(&mut self, relay: K, now: Instant) -> Duration {
        let strikes = self
            .failures
            .get(&relay)
            .map_or(1, |failure| failure.strikes.saturating_add(1));
        let cooldown = BASE_COOLDOWN
            .saturating_mul(1u32 << (strikes - 1).min(10))
            .min(MAX_COOLDOWN);
        self.failures.insert(
            relay,
            Failure {
                strikes,
                retry_at: now + cooldown,
            },
        );
        cooldown
    }

    pub fn record_healthy(&mut self, relay: &K) {
        self.failures.remove(relay);
    }

    /// A higher-priority relay whose back-off has ended, if any. The caller
    /// must prove it with an authenticated probe before switching.
    pub fn failback_target(&self, active: &K, candidates: &[K], now: Instant) -> Option<K> {
        candidates
            .iter()
            .take_while(|relay| *relay != active)
            .find(|relay| !self.cooling(relay, now))
            .cloned()
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

    const RELAYS: [&str; 3] = ["a:3478", "b:3478", "c:3478"];

    #[test]
    fn every_client_picks_the_same_first_healthy_relay() {
        let now = Instant::now();
        let first = Selector::<&str>::default();
        let second = Selector::<&str>::default();
        assert_eq!(first.choose(&RELAYS, now), Some("a:3478"));
        assert_eq!(second.choose(&RELAYS, now), Some("a:3478"));
        assert_eq!(first.choose(&[], now), None);
    }

    #[test]
    fn failover_skips_cooling_relays_and_is_bounded_when_all_fail() {
        let [a, b, c] = RELAYS;
        let now = Instant::now();
        let mut selector = Selector::default();
        selector.record_failure(a, now);
        assert_eq!(selector.choose(&RELAYS, now), Some(b));
        selector.record_failure(b, now + Duration::from_secs(1));
        assert_eq!(selector.choose(&RELAYS, now), Some(c));
        selector.record_failure(c, now + Duration::from_secs(2));
        assert_eq!(selector.choose(&RELAYS, now), Some(a));
        assert_eq!(
            selector.choose(&RELAYS, now + Duration::from_secs(31)),
            Some(a)
        );
    }

    #[test]
    fn back_off_doubles_caps_and_resets() {
        let now = Instant::now();
        let mut selector = Selector::default();
        let cooldowns: Vec<u64> = (0..7)
            .map(|_| selector.record_failure("a", now).as_secs())
            .collect();
        assert_eq!(cooldowns, vec![30, 60, 120, 240, 480, 600, 600]);
        selector.record_healthy(&"a");
        assert_eq!(selector.record_failure("a", now).as_secs(), 30);
    }

    #[test]
    fn failback_only_targets_higher_priority_after_back_off() {
        let [a, b, _] = RELAYS;
        let now = Instant::now();
        let mut selector = Selector::default();
        selector.record_failure(a, now);
        assert_eq!(selector.failback_target(&b, &RELAYS, now), None);
        assert_eq!(
            selector.failback_target(&b, &RELAYS, now + Duration::from_secs(30)),
            Some(a)
        );
        assert_eq!(selector.failback_target(&a, &RELAYS, now), None);
    }
}
