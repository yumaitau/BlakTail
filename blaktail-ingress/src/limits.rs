//! Per-route, per-client request rate limiting (token buckets).

use std::{collections::HashMap, net::IpAddr, time::Instant};

const MAX_TRACKED_CLIENTS: usize = 10_000;

struct Bucket {
    tokens: f64,
    updated: Instant,
}

pub struct RateLimiter {
    /// Tokens added per second.
    rate: f64,
    /// Burst: ten seconds' worth of requests, at least one.
    capacity: f64,
    clients: HashMap<IpAddr, Bucket>,
}

impl RateLimiter {
    pub fn per_minute(requests: u32) -> Self {
        let rate = f64::from(requests.max(1)) / 60.0;
        Self {
            rate,
            capacity: (rate * 10.0).max(1.0),
            clients: HashMap::new(),
        }
    }

    pub fn allow(&mut self, client: IpAddr) -> bool {
        self.allow_at(client, Instant::now())
    }

    fn allow_at(&mut self, client: IpAddr, now: Instant) -> bool {
        if !self.clients.contains_key(&client) && self.clients.len() >= MAX_TRACKED_CLIENTS {
            let (rate, capacity) = (self.rate, self.capacity);
            self.clients.retain(|_, bucket| {
                bucket.tokens + now.duration_since(bucket.updated).as_secs_f64() * rate < capacity
            });
            if self.clients.len() >= MAX_TRACKED_CLIENTS {
                // Too many distinct clients to track fairly: fail closed.
                return false;
            }
        }
        let capacity = self.capacity;
        let bucket = self.clients.entry(client).or_insert(Bucket {
            tokens: capacity,
            updated: now,
        });
        let elapsed = now.duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate).min(capacity);
        bucket.updated = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
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
}
