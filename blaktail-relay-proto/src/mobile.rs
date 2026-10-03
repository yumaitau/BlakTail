//! Relay session for clients whose sockets live outside Rust (the iOS
//! Network Extension and the Android `VpnService`). The platform owns one UDP
//! socket per relay endpoint and, when told to, one WebSocket; this type only
//! decides what to send where. State is a few hundred bytes per peer and no
//! buffers are retained, which keeps the Network Extension well inside its
//! memory limit.

use crate::{
    frame::{self, NodeId, ID_LEN, TOKEN_LEN},
    is_australian_region,
    ladder::{Link, LinkLadder, PathMode, PeerPath, Route},
    select::Selector,
};
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

pub use crate::ladder::RELAY_HEALTH;
/// A fresh relay gets this long to answer, covering the UDP -> WSS ladder.
pub const RELAY_GRACE: Duration = Duration::from_secs(35);
/// How long a fail-back candidate gets to answer its probes.
const FAILBACK_PROBE: Duration = Duration::from_secs(10);
const MAX_PEERS: usize = 4_096;
const MAX_RELAYS: usize = 16;
const MAX_QUEUED_CONTROL: usize = 16;

pub type PublicKey = [u8; 32];

/// One coordinator-advertised relay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayOption {
    /// UDP `host:port`.
    pub endpoint: String,
    pub region: String,
    /// Coordinator-approved `wss://` URL served by the same relay process.
    pub wss: Option<String>,
}

/// Parses the FFI relay list: one relay per line, `endpoint\tregion\twss`
/// (the WSS URL may be empty). Offshore and malformed lines are dropped.
pub fn parse_relay_lines(lines: &str) -> Vec<RelayOption> {
    lines
        .lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let endpoint = fields.next()?.trim();
            let region = fields.next()?.trim();
            let wss = fields.next().map(str::trim).filter(|url| !url.is_empty());
            if endpoint.is_empty() || !is_australian_region(region) {
                return None;
            }
            Some(RelayOption {
                endpoint: endpoint.to_owned(),
                region: region.to_owned(),
                wss: wss
                    .filter(|url| url.starts_with("wss://") && !url.contains('@'))
                    .map(str::to_owned),
            })
        })
        .take(MAX_RELAYS)
        .collect()
}

/// A control frame the platform must send.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Control {
    pub link: Link,
    /// UDP destination (`host:port`); ignored for WSS, which goes to
    /// [`Status::wss_url`].
    pub endpoint: String,
    pub frame: Vec<u8>,
}

/// Where a wrapped outbound datagram should go.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Outbound {
    /// Send the raw ciphertext to the peer's direct endpoint.
    pub direct: bool,
    /// Send the SEND frame to the active relay over this link.
    pub relay: Option<Link>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Status {
    /// `direct`, `relay`, `relay-wss`, or `none` when no peer has traffic.
    pub transport: &'static str,
    pub relay_endpoint: Option<String>,
    pub relay_link: Option<Link>,
    pub wss_url: Option<String>,
    pub relay_healthy: bool,
    pub peers_direct: usize,
    pub peers_relayed: usize,
    pub failovers: u64,
}

struct Peer {
    id: NodeId,
    path: PeerPath,
    active: bool,
}

struct Active {
    endpoint: String,
    wss: Option<String>,
    ladder: LinkLadder,
    started: Instant,
    last_seen: Option<Instant>,
    round_ends: Instant,
}

struct Failback {
    endpoint: String,
    until: Instant,
}

pub struct MobileRelay {
    self_id: NodeId,
    token: [u8; TOKEN_LEN],
    expires_at_unix: u64,
    allow_wss: bool,
    relays: Vec<RelayOption>,
    selector: Selector<String>,
    active: Option<Active>,
    failback: Option<Failback>,
    peers: HashMap<PublicKey, Peer>,
    control: VecDeque<Control>,
}

impl MobileRelay {
    /// `allow_wss` is false on platforms without a WebSocket transport, so
    /// the ladder never strands them on a link they cannot open.
    pub fn new(self_id: NodeId, allow_wss: bool) -> Self {
        Self {
            self_id,
            token: [0; TOKEN_LEN],
            expires_at_unix: 0,
            allow_wss,
            relays: Vec::new(),
            selector: Selector::default(),
            active: None,
            failback: None,
            peers: HashMap::new(),
            control: VecDeque::new(),
        }
    }

    /// Installs (or refreshes) the coordinator's relay capability and list.
    /// Keeps the active relay when it is still advertised.
    pub fn configure(
        &mut self,
        token: [u8; TOKEN_LEN],
        expires_at_unix: u64,
        relays: Vec<RelayOption>,
        now: Instant,
    ) {
        let token_changed = token != self.token || expires_at_unix != self.expires_at_unix;
        self.token = token;
        self.expires_at_unix = expires_at_unix;
        self.relays = relays;
        let still_listed = self.active.as_ref().and_then(|active| {
            self.relays
                .iter()
                .find(|relay| relay.endpoint == active.endpoint)
                .cloned()
        });
        match (self.active.as_mut(), still_listed) {
            (Some(active), Some(relay)) => {
                active.wss = relay.wss.filter(|_| self.allow_wss);
                active.ladder.set_wss_available(active.wss.is_some());
                if token_changed {
                    self.queue_registration();
                }
            }
            _ => {
                self.active = None;
                self.activate_choice(now);
            }
        }
    }

    /// Maps a WireGuard public key to its coordinator node id.
    pub fn set_peer(&mut self, public_key: PublicKey, id: NodeId, has_direct: bool) {
        if let Some(peer) = self.peers.get_mut(&public_key) {
            peer.id = id;
            peer.path.set_has_direct(has_direct);
            peer.active = true;
            return;
        }
        if self.peers.len() >= MAX_PEERS {
            return;
        }
        self.peers.insert(
            public_key,
            Peer {
                id,
                path: PeerPath::new(has_direct),
                active: true,
            },
        );
    }

    /// Marks every peer stale before a coordinator refresh re-adds them.
    pub fn begin_peer_refresh(&mut self) {
        for peer in self.peers.values_mut() {
            peer.active = false;
        }
    }

    pub fn end_peer_refresh(&mut self) {
        self.peers.retain(|_, peer| peer.active);
    }

    fn relay_ready(&self) -> bool {
        self.active.is_some() && self.expires_at_unix > 0
    }

    fn active_link(&self) -> Option<Link> {
        self.active.as_ref().map(|active| active.ladder.link())
    }

    /// Routes one encrypted datagram for `peer`. When `relay` is set the
    /// caller wraps it with [`frame::write_send_frame`] using [`Self::peer_id`].
    pub fn outbound(&mut self, peer: &PublicKey, now: Instant) -> Outbound {
        let relay_ready = self.relay_ready();
        let link = self.active_link();
        let Some(state) = self.peers.get_mut(peer) else {
            return Outbound {
                direct: true,
                relay: None,
            };
        };
        let Route { direct, relay } = state.path.route(now, relay_ready);
        Outbound {
            direct,
            relay: if relay { link } else { None },
        }
    }

    pub fn peer_id(&self, peer: &PublicKey) -> Option<NodeId> {
        self.peers.get(peer).map(|state| state.id)
    }

    /// A datagram from `peer`'s direct endpoint decrypted successfully.
    pub fn direct_received(&mut self, peer: &PublicKey) {
        if let Some(state) = self.peers.get_mut(peer) {
            state.path.direct_received();
        }
    }

    /// Handles a frame from a relay. Returns the sending peer and the
    /// encrypted payload for FORWARDED frames; control replies are consumed.
    /// `endpoint` is the UDP relay it came from (ignored for WSS).
    pub fn inbound<'a>(
        &mut self,
        data: &'a [u8],
        link: Link,
        endpoint: &str,
        now: Instant,
    ) -> Option<(PublicKey, &'a [u8])> {
        if frame::parse_observed(data, &self.self_id).is_some() {
            self.observed(link, endpoint, now);
            return None;
        }
        let (source, payload) = frame::parse_forwarded(data)?;
        // Only the active relay may deliver traffic.
        let from_active = self.active.as_ref().is_some_and(|active| match link {
            Link::Udp => active.endpoint == endpoint,
            Link::Wss => active.ladder.link() == Link::Wss,
        });
        if !from_active {
            return None;
        }
        self.peers
            .iter()
            .find(|(_, peer)| peer.id == source)
            .map(|(key, _)| (*key, payload))
    }

    fn observed(&mut self, link: Link, endpoint: &str, now: Instant) {
        if link == Link::Udp {
            if let Some(failback) = &self.failback {
                if failback.endpoint == endpoint && now < failback.until {
                    let endpoint = failback.endpoint.clone();
                    self.failback = None;
                    self.selector.record_healthy(&endpoint);
                    self.selector.note_failback();
                    self.activate(endpoint, now);
                    return;
                }
            }
        }
        let Some(active) = self.active.as_mut() else {
            return;
        };
        let matches = match link {
            Link::Udp => active.endpoint == endpoint,
            Link::Wss => active.wss.is_some(),
        };
        if !matches {
            return;
        }
        active.last_seen = Some(now);
        if link == Link::Udp {
            active.ladder.udp_answered();
        }
        let endpoint = active.endpoint.clone();
        self.selector.record_healthy(&endpoint);
    }

    /// Advances timers. Call about once a second, then drain [`Self::poll`].
    pub fn tick(&mut self, now: Instant) {
        if self.relays.is_empty() || self.expires_at_unix == 0 {
            self.active = None;
            return;
        }
        if self.active.is_none() {
            self.activate_choice(now);
        }
        let Some(active) = self.active.as_mut() else {
            return;
        };
        let healthy = active
            .last_seen
            .map_or(now.duration_since(active.started) < RELAY_GRACE, |seen| {
                now.duration_since(seen) < RELAY_HEALTH
            });
        if !healthy {
            let failed = active.endpoint.clone();
            self.selector.record_failure(failed.clone(), now);
            self.selector.note_failover();
            self.active = None;
            self.activate_choice(now);
            return;
        }
        if now >= active.round_ends {
            active.ladder.end_round();
            active.round_ends = now + active.ladder.round_length();
            self.queue_registration();
        }
        if let Some(failback) = &self.failback {
            if now >= failback.until {
                let endpoint = failback.endpoint.clone();
                self.failback = None;
                self.selector.record_failure(endpoint, now);
            }
        } else if let Some(active) = &self.active {
            let candidates = self.candidates();
            if let Some(target) = self
                .selector
                .failback_target(&active.endpoint, &candidates, now)
            {
                self.failback = Some(Failback {
                    endpoint: target.clone(),
                    until: now + FAILBACK_PROBE,
                });
                self.push_probe(Link::Udp, target);
            }
        }
    }

    /// Next control frame to send, if any.
    pub fn poll(&mut self) -> Option<Control> {
        self.control.pop_front()
    }

    pub fn status(&self, now: Instant) -> Status {
        let relay_ready = self.relay_ready();
        let (mut direct, mut relayed) = (0, 0);
        for peer in self.peers.values() {
            match peer.path.mode() {
                PathMode::Relay if relay_ready => relayed += 1,
                _ => direct += 1,
            }
        }
        let link = self.active_link();
        Status {
            transport: match (relayed, link) {
                (0, _) if direct == 0 => "none",
                (0, _) => "direct",
                (_, Some(link)) => link.transport_label(),
                (_, None) => "direct",
            },
            relay_endpoint: self.active.as_ref().map(|active| active.endpoint.clone()),
            relay_link: link,
            wss_url: self
                .active
                .as_ref()
                .filter(|active| active.ladder.link() == Link::Wss)
                .and_then(|active| active.wss.clone()),
            relay_healthy: self.active.as_ref().is_some_and(|active| {
                active
                    .last_seen
                    .is_some_and(|seen| now.duration_since(seen) < RELAY_HEALTH)
            }),
            peers_direct: direct,
            peers_relayed: relayed,
            failovers: self.selector.failovers(),
        }
    }

    fn candidates(&self) -> Vec<String> {
        self.relays
            .iter()
            .map(|relay| relay.endpoint.clone())
            .collect()
    }

    fn activate_choice(&mut self, now: Instant) {
        let candidates = self.candidates();
        if let Some(endpoint) = self.selector.choose(&candidates, now) {
            self.activate(endpoint, now);
        }
    }

    fn activate(&mut self, endpoint: String, now: Instant) {
        let wss = self
            .relays
            .iter()
            .find(|relay| relay.endpoint == endpoint)
            .and_then(|relay| relay.wss.clone())
            .filter(|_| self.allow_wss);
        let ladder = LinkLadder::new(wss.is_some());
        self.active = Some(Active {
            round_ends: now + ladder.round_length(),
            endpoint,
            wss,
            ladder,
            started: now,
            last_seen: None,
        });
        self.queue_registration();
    }

    /// REGISTER + PING to the active relay: always over UDP (that is the
    /// probe that lets the ladder promote back), and also over WSS while the
    /// fallback carries traffic.
    fn queue_registration(&mut self) {
        let Some(active) = &self.active else {
            return;
        };
        let endpoint = active.endpoint.clone();
        let on_wss = active.ladder.link() == Link::Wss && !active.ladder.udp_proven();
        self.push_probe(Link::Udp, endpoint.clone());
        if on_wss {
            self.push_probe(Link::Wss, endpoint);
        }
    }

    fn push_probe(&mut self, link: Link, endpoint: String) {
        if self.expires_at_unix == 0 {
            return;
        }
        while self.control.len() + 2 > MAX_QUEUED_CONTROL {
            self.control.pop_front();
        }
        self.control.push_back(Control {
            link,
            endpoint: endpoint.clone(),
            frame: frame::register_frame(&self.self_id, self.expires_at_unix, &self.token),
        });
        self.control.push_back(Control {
            link,
            endpoint,
            frame: frame::ping_frame(&self.self_id),
        });
    }
}

/// Parses a 16-byte node id from its canonical UUID text form.
pub fn parse_node_id(text: &str) -> Option<NodeId> {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    if hex.len() != ID_LEN * 2 {
        return None;
    }
    crate::hex_decode(&hex)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{observed_frame, FORWARDED, HEADER, PING, REGISTER, SEND};

    const SELF: NodeId = [1; ID_LEN];
    const PEER_ID: NodeId = [2; ID_LEN];
    const PEER_KEY: PublicKey = [9; 32];

    fn relays() -> Vec<RelayOption> {
        parse_relay_lines(
            "relay-a.example.au:3478\tap-southeast-2\twss://relay-a.example.au/v1/relay\n\
             relay-x.example.com:3478\tus-east-1\twss://relay-x.example.com/v1/relay\n\
             relay-b.example.au:3478\taustraliaeast\t\n",
        )
    }

    fn session(now: Instant) -> MobileRelay {
        let mut relay = MobileRelay::new(SELF, true);
        relay.configure([5; TOKEN_LEN], 4_000_000_000, relays(), now);
        relay.set_peer(PEER_KEY, PEER_ID, true);
        relay
    }

    fn drain(relay: &mut MobileRelay) -> Vec<Control> {
        std::iter::from_fn(|| relay.poll()).collect()
    }

    fn observed() -> Vec<u8> {
        observed_frame(&SELF, "203.0.113.7:40000".parse().unwrap())
    }

    #[test]
    fn relay_list_drops_offshore_entries_and_unsafe_urls() {
        let parsed = relays();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].endpoint, "relay-a.example.au:3478");
        assert_eq!(parsed[1].wss, None);
        let unsafe_url = parse_relay_lines(
            "r:1\tap-southeast-2\thttps://r/relay\nq:1\tap-southeast-2\twss://user:pw@q/relay\n",
        );
        assert!(unsafe_url.iter().all(|relay| relay.wss.is_none()));
    }

    #[test]
    fn registers_with_first_australian_relay_and_wraps_traffic() {
        let now = Instant::now();
        let mut relay = session(now);
        let control = drain(&mut relay);
        assert_eq!(control.len(), 2);
        assert!(control
            .iter()
            .all(|c| c.link == Link::Udp && c.endpoint == "relay-a.example.au:3478"));
        assert_eq!(control[0].frame[0], REGISTER);
        assert_eq!(control[1].frame[0], PING);

        let mut fresh = MobileRelay::new(SELF, true);
        fresh.configure([5; TOKEN_LEN], 4_000_000_000, relays(), now);
        fresh.set_peer(PEER_KEY, PEER_ID, false);
        assert_eq!(
            fresh.outbound(&PEER_KEY, now),
            Outbound {
                direct: false,
                relay: Some(Link::Udp)
            }
        );
        let mut out = [0u8; 64];
        let id = fresh.peer_id(&PEER_KEY).unwrap();
        let len = frame::write_send_frame(&id, b"ct", &mut out).unwrap();
        assert_eq!(out[0], SEND);
        assert_eq!(&out[1..HEADER], &PEER_ID);
        assert_eq!(len, HEADER + 2);
    }

    #[test]
    fn forwarded_frames_are_accepted_only_from_the_active_relay_and_known_peers() {
        let now = Instant::now();
        let mut relay = session(now);
        let frame = [&[FORWARDED][..], &PEER_ID[..], b"cipher"].concat();
        assert_eq!(
            relay.inbound(&frame, Link::Udp, "relay-a.example.au:3478", now),
            Some((PEER_KEY, &b"cipher"[..]))
        );
        assert_eq!(
            relay.inbound(&frame, Link::Udp, "relay-b.example.au:3478", now),
            None
        );
        assert_eq!(relay.inbound(&frame, Link::Wss, "", now), None);
        let unknown = [&[FORWARDED][..], &[4u8; ID_LEN][..], b"x"].concat();
        assert_eq!(
            relay.inbound(&unknown, Link::Udp, "relay-a.example.au:3478", now),
            None
        );
    }

    #[test]
    fn udp_silence_moves_to_wss_and_answers_promote_back() {
        let start = Instant::now();
        let mut relay = session(start);
        drain(&mut relay);
        let mut now = start;
        for _ in 0..3 {
            now += Duration::from_secs(5);
            relay.tick(now);
        }
        let status = relay.status(now);
        assert_eq!(status.relay_link, Some(Link::Wss));
        assert_eq!(
            status.wss_url.as_deref(),
            Some("wss://relay-a.example.au/v1/relay")
        );
        let control = drain(&mut relay);
        assert!(control.iter().any(|c| c.link == Link::Wss));
        assert!(
            control.iter().any(|c| c.link == Link::Udp),
            "UDP keeps probing"
        );
        // WSS registration answered: relay healthy, traffic relayed over WSS.
        relay.inbound(&observed(), Link::Wss, "", now);
        assert!(relay.status(now).relay_healthy);
        let mut relayed = MobileRelay::new(SELF, true);
        relayed.configure([5; TOKEN_LEN], 4_000_000_000, relays(), start);
        relayed.set_peer(PEER_KEY, PEER_ID, false);
        let mut t = start;
        for _ in 0..3 {
            t += Duration::from_secs(5);
            relayed.tick(t);
        }
        assert_eq!(relayed.outbound(&PEER_KEY, t).relay, Some(Link::Wss));
        assert_eq!(relayed.status(t).transport, "relay-wss");
        // Three answered UDP rounds promote back to UDP.
        for _ in 0..3 {
            relay.inbound(&observed(), Link::Udp, "relay-a.example.au:3478", now);
            now += Duration::from_secs(25);
            relay.tick(now);
        }
        assert_eq!(relay.status(now).relay_link, Some(Link::Udp));
        assert_eq!(relay.status(now).wss_url, None);
    }

    #[test]
    fn wss_reregistration_stops_once_udp_answers_again() {
        let start = Instant::now();
        let mut relay = session(start);
        let mut now = start;
        for _ in 0..3 {
            now += Duration::from_secs(5);
            relay.tick(now);
        }
        assert!(drain(&mut relay).iter().any(|c| c.link == Link::Wss));
        // UDP answers: the next round probes UDP only, so a WSS REGISTER
        // cannot steal the relay registration from the working UDP probe.
        relay.inbound(&observed(), Link::Udp, "relay-a.example.au:3478", now);
        now += Duration::from_secs(25);
        relay.tick(now);
        let control = drain(&mut relay);
        assert!(!control.is_empty());
        assert!(control.iter().all(|c| c.link == Link::Udp));
        assert_eq!(relay.status(now).relay_link, Some(Link::Wss));
    }

    #[test]
    fn android_without_wss_never_leaves_udp() {
        let start = Instant::now();
        let mut relay = MobileRelay::new(SELF, false);
        relay.configure([5; TOKEN_LEN], 4_000_000_000, relays(), start);
        for step in 1..=6 {
            relay.tick(start + Duration::from_secs(5 * step));
        }
        assert_eq!(relay.status(start).relay_link, Some(Link::Udp));
    }

    #[test]
    fn silent_relay_fails_over_then_fails_back_after_probe() {
        let start = Instant::now();
        let mut relay = session(start);
        drain(&mut relay);
        let mut now = start;
        // Nothing answers on either link through the grace period.
        while now < start + RELAY_GRACE {
            now += Duration::from_secs(1);
            relay.tick(now);
        }
        let status = relay.status(now);
        assert_eq!(
            status.relay_endpoint.as_deref(),
            Some("relay-b.example.au:3478")
        );
        assert_eq!(status.failovers, 1);
        relay.inbound(&observed(), Link::Udp, "relay-b.example.au:3478", now);
        drain(&mut relay);
        // After relay-a's back-off a probe is sent; only an answer fails back.
        now += Duration::from_secs(31);
        relay.inbound(&observed(), Link::Udp, "relay-b.example.au:3478", now);
        relay.tick(now);
        let probes = drain(&mut relay);
        assert!(probes
            .iter()
            .any(|c| c.endpoint == "relay-a.example.au:3478" && c.frame[0] == PING));
        assert_eq!(
            relay.status(now).relay_endpoint.as_deref(),
            Some("relay-b.example.au:3478")
        );
        relay.inbound(&observed(), Link::Udp, "relay-a.example.au:3478", now);
        assert_eq!(
            relay.status(now).relay_endpoint.as_deref(),
            Some("relay-a.example.au:3478")
        );
    }

    #[test]
    fn token_refresh_reregisters_and_peer_refresh_prunes() {
        let now = Instant::now();
        let mut relay = session(now);
        drain(&mut relay);
        relay.configure([6; TOKEN_LEN], 4_000_000_100, relays(), now);
        let control = drain(&mut relay);
        assert_eq!(control[0].frame[0], REGISTER);
        assert_eq!(&control[0].frame[HEADER + 8..], &[6; TOKEN_LEN]);
        relay.begin_peer_refresh();
        relay.end_peer_refresh();
        assert_eq!(relay.peer_id(&PEER_KEY), None);
        assert_eq!(relay.status(now).transport, "none");
    }

    #[test]
    fn node_ids_parse_from_uuid_text() {
        assert_eq!(
            parse_node_id("01020304-0506-0708-090a-0b0c0d0e0f10"),
            Some([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        );
        assert_eq!(parse_node_id("nope"), None);
    }
}
