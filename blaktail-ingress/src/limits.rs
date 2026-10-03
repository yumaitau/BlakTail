//! Per-route request rate limiting (token buckets): one bucket per client
//! (IPv6 clients by /64, since one host usually holds a whole /64) and one
//! for the route as a whole, so many distinct sources cannot multiply it.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    time::Instant,
};

const MAX_TRACKED_CLIENTS: usize = 10_000;
/// The whole route may take this many times one client's rate.
const ROUTE_FACTOR: f64 = 100.0;

struct Bucket {
    tokens: f64,
    updated: Instant,
}

impl Bucket {
    fn full(capacity: f64, now: Instant) -> Self {
        Self {
            tokens: capacity,
            updated: now,
        }
    }

    fn take(&mut self, rate: f64, capacity: f64, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.updated).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate).min(capacity);
        self.updated = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct RateLimiter {
    /// Tokens added per second.
    rate: f64,
    /// Burst: ten seconds' worth of requests, at least one.
    capacity: f64,
    clients: HashMap<IpAddr, Bucket>,
    route: Bucket,
}

/// The rate-limit key: IPv4 (including IPv4-mapped IPv6) per address, IPv6
/// per /64.
fn client_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(Ipv6Addr::from(
                u128::from(v6) & 0xffff_ffff_ffff_ffff_0000_0000_0000_0000,
            )),
        },
        ip => ip,
    }
}

impl RateLimiter {
    pub fn per_minute(requests: u32) -> Self {
        let rate = f64::from(requests.max(1)) / 60.0;
        let capacity = (rate * 10.0).max(1.0);
        Self {
            rate,
            capacity,
            clients: HashMap::new(),
            route: Bucket::full(capacity * ROUTE_FACTOR, Instant::now()),
        }
    }

    pub fn allow(&mut self, client: IpAddr) -> bool {
        self.allow_at(client, Instant::now())
    }

    fn allow_at(&mut self, client: IpAddr, now: Instant) -> bool {
        let client = client_key(client);
        if !self.clients.contains_key(&client) && self.clients.len() >= MAX_TRACKED_CLIENTS {
            let (rate, capacity) = (self.rate, self.capacity);
            // Clients whose bucket has refilled are indistinguishable from new.
            self.clients.retain(|_, bucket| {
                bucket.tokens + now.saturating_duration_since(bucket.updated).as_secs_f64() * rate
                    < capacity
            });
            if self.clients.len() >= MAX_TRACKED_CLIENTS {
                // Forget the least recently seen client rather than refuse
                // everyone new; the route bucket still bounds the total.
                if let Some(oldest) = self
                    .clients
                    .iter()
                    .min_by_key(|(_, bucket)| bucket.updated)
                    .map(|(ip, _)| *ip)
                {
                    self.clients.remove(&oldest);
                }
            }
        }
        let (rate, capacity) = (self.rate, self.capacity);
        let allowed = self
            .clients
            .entry(client)
            .or_insert_with(|| Bucket::full(capacity, now))
            .take(rate, capacity, now);
        allowed
            && self
                .route
                .take(rate * ROUTE_FACTOR, capacity * ROUTE_FACTOR, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn buckets_are_per_client_and_refill() {
        let mut limiter = RateLimiter::per_minute(60);
        let start = Instant::now();
        let a: IpAddr = "203.0.113.1".parse().unwrap();
        let b: IpAddr = "203.0.113.2".parse().unwrap();
        for _ in 0..10 {
            assert!(limiter.allow_at(a, start));
        }
        assert!(!limiter.allow_at(a, start));
        assert!(limiter.allow_at(b, start), "another client is unaffected");
        assert!(limiter.allow_at(a, start + Duration::from_secs(1)));
        assert!(!limiter.allow_at(a, start + Duration::from_secs(1)));
    }

    #[test]
    fn tiny_rates_still_allow_one_request() {
        let mut limiter = RateLimiter::per_minute(1);
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        let start = Instant::now();
        assert!(limiter.allow_at(ip, start));
        assert!(!limiter.allow_at(ip, start + Duration::from_secs(30)));
        assert!(limiter.allow_at(ip, start + Duration::from_secs(61)));
    }

    #[test]
    fn ipv6_clients_share_a_bucket_per_64() {
        let mut limiter = RateLimiter::per_minute(6);
        let start = Instant::now();
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let same_64: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let other_64: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert!(limiter.allow_at(a, start));
        assert!(!limiter.allow_at(same_64, start), "rotating within a /64");
        assert!(limiter.allow_at(other_64, start));
        let mapped: IpAddr = "::ffff:203.0.113.1".parse().unwrap();
        assert_eq!(client_key(mapped), "203.0.113.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn a_full_table_evicts_the_oldest_client_instead_of_refusing() {
        let mut limiter = RateLimiter::per_minute(6);
        let start = Instant::now();
        // Fill the table with drained buckets, each a little later.
        for i in 0..MAX_TRACKED_CLIENTS {
            let ip = IpAddr::from([10, (i >> 16) as u8, (i >> 8) as u8, i as u8]);
            let at = start + Duration::from_millis(i as u64);
            assert!(limiter.allow_at(ip, at));
            limiter.route.tokens = f64::MAX;
        }
        let late = start + Duration::from_millis(MAX_TRACKED_CLIENTS as u64);
        let newcomer: IpAddr = "203.0.113.50".parse().unwrap();
        assert!(limiter.allow_at(newcomer, late));
        assert_eq!(limiter.clients.len(), MAX_TRACKED_CLIENTS);
        assert!(!limiter.clients.contains_key(&IpAddr::from([10, 0, 0, 0])));
    }

    #[test]
    fn the_route_bucket_caps_many_distinct_clients() {
        let mut limiter = RateLimiter::per_minute(6);
        let start = Instant::now();
        // One-token buckets per client; the route allows 100 at once.
        let allowed = (0..500u32)
            .filter(|i| limiter.allow_at(IpAddr::V4((0xcb00_7100 + i).into()), start))
            .count();
        assert_eq!(allowed, 100);
    }
}
