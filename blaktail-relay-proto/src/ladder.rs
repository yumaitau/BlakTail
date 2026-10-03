//! Hysteresis for the two decisions a client makes about its relay path:
//! which link carries relay frames (UDP or the WSS fallback), and whether a
//! given peer is reached directly or through the relay.

use std::time::{Duration, Instant};

/// Consecutive unanswered UDP probe rounds before falling back to WSS.
pub const WSS_AFTER_UDP_MISSES: u32 = 3;
/// Consecutive answered UDP probe rounds before promoting back to UDP.
pub const UDP_AFTER_HITS: u32 = 3;
/// Probe cadence while UDP has not (yet) been proven or just missed.
pub const FAST_ROUND: Duration = Duration::from_secs(5);
/// Probe/keepalive cadence on a healthy link; below the relay's 120 s idle
/// reap and the 60 s ALB idle timeout.
pub const STEADY_ROUND: Duration = Duration::from_secs(25);
/// No authenticated OBSERVED reply over any link for this long means the
/// relay is gone and the client fails over. Two steady rounds: one missed
/// probe switches to fast rounds, so a single lost datagram does not trip it.
pub const RELAY_HEALTH: Duration = Duration::from_secs(50);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Link {
    Udp,
    Wss,
}

impl Link {
    /// Transport label reported in status output and to the coordinator.
    pub fn transport_label(self) -> &'static str {
        match self {
            Self::Udp => "relay",
            Self::Wss => "relay-wss",
        }
    }
}

/// Chooses the relay link. UDP is always preferred; WSS is used only after
/// [`WSS_AFTER_UDP_MISSES`] consecutive silent UDP rounds, and UDP must then
/// answer [`UDP_AFTER_HITS`] rounds in a row before it is trusted again. UDP
/// probes keep running while on WSS so promotion can happen.
#[derive(Clone, Debug)]
pub struct LinkLadder {
    link: Link,
    wss_available: bool,
    answered: bool,
    misses: u32,
    hits: u32,
}

impl LinkLadder {
    pub fn new(wss_available: bool) -> Self {
        Self {
            link: Link::Udp,
            wss_available,
            answered: false,
            misses: 0,
            hits: 0,
        }
    }

    pub fn link(&self) -> Link {
        self.link
    }

    pub fn set_wss_available(&mut self, available: bool) {
        self.wss_available = available;
        if !available {
            self.link = Link::Udp;
        }
    }

    /// An authenticated OBSERVED reply arrived over UDP.
    pub fn udp_answered(&mut self) {
        self.answered = true;
    }

    /// Closes a probe round; returns the link to use for the next one.
    pub fn end_round(&mut self) -> Link {
        if std::mem::take(&mut self.answered) {
            self.misses = 0;
            self.hits = self.hits.saturating_add(1);
        } else {
            self.hits = 0;
            self.misses = self.misses.saturating_add(1);
        }
        match self.link {
            Link::Udp if self.wss_available && self.misses >= WSS_AFTER_UDP_MISSES => {
                self.link = Link::Wss;
            }
            Link::Wss if self.hits >= UDP_AFTER_HITS => {
                self.link = Link::Udp;
            }
            _ => {}
        }
        self.link
    }

    /// When the next probe round should end.
    /// Whether the last closed round got a UDP answer. While on WSS, clients
    /// re-register over the WebSocket only when this is false: the relay
    /// keeps one address per node, so a WSS REGISTER racing a working UDP
    /// probe would steal the registration and the probe's reply.
    pub fn udp_proven(&self) -> bool {
        self.hits > 0
    }

    pub fn round_length(&self) -> Duration {
        match self.link {
            Link::Udp if self.hits > 0 => STEADY_ROUND,
            Link::Udp => FAST_ROUND,
            Link::Wss => STEADY_ROUND,
        }
    }
}

/// Outbound datagrams after this long with nothing received directly mean
/// the direct path is dead (WireGuard persistent keepalive is 25 s).
pub const DIRECT_SILENCE: Duration = Duration::from_secs(15);
/// While relayed, retry the direct path this often...
pub const DIRECT_RETRY_EVERY: Duration = Duration::from_secs(30);
/// ...by duplicating outbound ciphertext to it for this long.
pub const DIRECT_PROBE_WINDOW: Duration = Duration::from_secs(10);
/// Direct receipts needed during probing before leaving the relay.
pub const DIRECT_PROMOTE_HITS: u32 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathMode {
    Direct,
    Relay,
}

/// Where one outbound datagram should go.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Route {
    pub direct: bool,
    pub relay: bool,
}

/// Per-peer direct/relay hysteresis for clients whose WireGuard engine and
/// sockets live in the platform (mobile). Demotion needs sustained silence;
/// promotion needs repeated proof, so a lossy path does not flap.
#[derive(Clone, Debug)]
pub struct PeerPath {
    mode: PathMode,
    has_direct: bool,
    unanswered_since: Option<Instant>,
    probe_until: Option<Instant>,
    next_probe: Option<Instant>,
    hits: u32,
}

impl PeerPath {
    pub fn new(has_direct: bool) -> Self {
        Self {
            mode: if has_direct {
                PathMode::Direct
            } else {
                PathMode::Relay
            },
            has_direct,
            unanswered_since: None,
            probe_until: None,
            next_probe: None,
            hits: 0,
        }
    }

    pub fn mode(&self) -> PathMode {
        self.mode
    }

    pub fn set_has_direct(&mut self, has_direct: bool) {
        self.has_direct = has_direct;
        if !has_direct {
            self.mode = PathMode::Relay;
        }
    }

    /// Decides where an outbound datagram goes. `relay_ready` is false when
    /// no relay is registered, in which case direct is the only option.
    pub fn route(&mut self, now: Instant, relay_ready: bool) -> Route {
        if !relay_ready {
            return Route {
                direct: self.has_direct,
                relay: false,
            };
        }
        match self.mode {
            PathMode::Direct => {
                let since = *self.unanswered_since.get_or_insert(now);
                if now.duration_since(since) < DIRECT_SILENCE {
                    return Route {
                        direct: true,
                        relay: false,
                    };
                }
                self.mode = PathMode::Relay;
                self.hits = 0;
                self.probe_until = None;
                self.next_probe = Some(now + DIRECT_RETRY_EVERY);
                Route {
                    direct: false,
                    relay: true,
                }
            }
            PathMode::Relay => {
                if !self.has_direct {
                    return Route {
                        direct: false,
                        relay: true,
                    };
                }
                let probing = match self.probe_until {
                    Some(until) if now < until => true,
                    _ => {
                        let due = self.next_probe.is_none_or(|at| now >= at);
                        if due {
                            self.probe_until = Some(now + DIRECT_PROBE_WINDOW);
                            self.next_probe = Some(now + DIRECT_RETRY_EVERY);
                            self.hits = 0;
                        }
                        due
                    }
                };
                Route {
                    direct: probing,
                    relay: true,
                }
            }
        }
    }

    /// A datagram from the peer's direct endpoint decrypted successfully.
    pub fn direct_received(&mut self) {
        self.unanswered_since = None;
        if self.mode == PathMode::Relay && self.has_direct {
            self.hits = self.hits.saturating_add(1);
            if self.hits >= DIRECT_PROMOTE_HITS {
                self.mode = PathMode::Direct;
                self.hits = 0;
                self.probe_until = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_falls_back_after_three_silent_rounds_and_promotes_after_three_answers() {
        let mut ladder = LinkLadder::new(true);
        assert_eq!(ladder.round_length(), FAST_ROUND);
        assert_eq!(ladder.end_round(), Link::Udp);
        assert_eq!(ladder.end_round(), Link::Udp);
        assert_eq!(ladder.end_round(), Link::Wss);
        // One answer is not enough to leave WSS, and a miss resets progress.
        ladder.udp_answered();
        assert_eq!(ladder.end_round(), Link::Wss);
        assert_eq!(ladder.end_round(), Link::Wss);
        for expected in [Link::Wss, Link::Wss, Link::Udp] {
            ladder.udp_answered();
            assert_eq!(ladder.end_round(), expected);
        }
        assert_eq!(ladder.round_length(), STEADY_ROUND);
    }

    #[test]
    fn health_window_covers_two_steady_rounds_and_the_fast_retries() {
        assert!(RELAY_HEALTH >= STEADY_ROUND * 2);
        // After a missed steady round, fast rounds still fit before failover.
        assert!(STEADY_ROUND + FAST_ROUND * 2 < RELAY_HEALTH);
    }

    #[test]
    fn link_stays_on_udp_without_an_approved_wss_endpoint() {
        let mut ladder = LinkLadder::new(false);
        for _ in 0..10 {
            assert_eq!(ladder.end_round(), Link::Udp);
        }
        ladder.set_wss_available(true);
        assert_eq!(ladder.end_round(), Link::Wss);
        ladder.set_wss_available(false);
        assert_eq!(ladder.link(), Link::Udp);
    }

    #[test]
    fn healthy_udp_link_keeps_steady_cadence() {
        let mut ladder = LinkLadder::new(true);
        for _ in 0..5 {
            ladder.udp_answered();
            assert_eq!(ladder.end_round(), Link::Udp);
        }
        assert_eq!(ladder.round_length(), STEADY_ROUND);
        assert_eq!(ladder.end_round(), Link::Udp);
        assert_eq!(ladder.round_length(), FAST_ROUND);
    }

    #[test]
    fn peer_demotes_after_silence_and_promotes_only_after_repeated_proof() {
        let start = Instant::now();
        let mut path = PeerPath::new(true);
        let direct_only = Route {
            direct: true,
            relay: false,
        };
        assert_eq!(path.route(start, true), direct_only);
        assert_eq!(
            path.route(start + Duration::from_secs(14), true),
            direct_only
        );
        // Something came back directly: the silence clock restarts.
        path.direct_received();
        assert_eq!(
            path.route(start + Duration::from_secs(20), true),
            direct_only
        );
        let demoted = start + Duration::from_secs(36);
        assert_eq!(
            path.route(demoted, true),
            Route {
                direct: false,
                relay: true
            }
        );
        assert_eq!(path.mode(), PathMode::Relay);
        // No probing until the retry interval; then duplicate for the window.
        assert!(!path.route(demoted + Duration::from_secs(5), true).direct);
        let probe = demoted + DIRECT_RETRY_EVERY;
        assert_eq!(
            path.route(probe, true),
            Route {
                direct: true,
                relay: true
            }
        );
        assert!(path.route(probe + Duration::from_secs(9), true).direct);
        assert!(!path.route(probe + Duration::from_secs(11), true).direct);
        path.direct_received();
        assert_eq!(path.mode(), PathMode::Relay);
        path.direct_received();
        assert_eq!(path.mode(), PathMode::Direct);
    }

    #[test]
    fn peer_without_direct_endpoint_always_relays_and_without_relay_always_direct() {
        let now = Instant::now();
        let mut relayed = PeerPath::new(false);
        assert_eq!(
            relayed.route(now, true),
            Route {
                direct: false,
                relay: true
            }
        );
        relayed.direct_received();
        relayed.direct_received();
        assert_eq!(relayed.mode(), PathMode::Relay);
        let mut direct = PeerPath::new(true);
        assert_eq!(
            direct.route(now + Duration::from_secs(100), false),
            Route {
                direct: true,
                relay: false
            }
        );
    }
}
