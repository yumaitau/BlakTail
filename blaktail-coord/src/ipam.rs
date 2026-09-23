//! IP address management helpers for coordinator pools (issue #51).
//!
//! Pure pool math: no I/O, no database access. The HTTP/DB layer owns
//! persistence; this module only answers "which address may be handed out".
//! IPv4 and IPv6 pools are both supported; only std + serde + thiserror.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

/// Upper bound on host probes per pool during allocation so a giant pool with
/// pathological exclusions cannot spin the coordinator.
const MAX_ALLOC_PROBES: u64 = 65_536;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IpamError {
    #[error("invalid CIDR '{0}'")]
    InvalidCidr(String),
    #[error("invalid IP address '{0}'")]
    InvalidAddress(String),
    #[error("address {address} is the network address of pool {pool}")]
    NetworkAddress { address: String, pool: String },
    #[error("address {address} is the broadcast address of pool {pool}")]
    BroadcastAddress { address: String, pool: String },
    #[error("address {address} is outside pool {pool}")]
    OutsidePool { address: String, pool: String },
    #[error("address {address} is excluded in pool {pool}")]
    Excluded { address: String, pool: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpamPool {
    pub name: String,
    pub cidr: String,
    #[serde(default)]
    pub exclusions: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationState {
    Active,
    Reserved,
    Released,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reservation {
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrol_key: Option<String>,
    pub state: ReservationState,
    #[serde(default)]
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<i64>,
}

/// Parse `addr/prefix`, returning the masked network address and prefix len.
pub fn parse_cidr(cidr: &str) -> Result<(IpAddr, u8), IpamError> {
    let (addr_s, prefix_s) = cidr
        .split_once('/')
        .ok_or_else(|| IpamError::InvalidCidr(cidr.to_owned()))?;
    let addr: IpAddr = addr_s
        .trim()
        .parse()
        .map_err(|_| IpamError::InvalidCidr(cidr.to_owned()))?;
    let prefix: u8 = prefix_s
        .trim()
        .parse()
        .map_err(|_| IpamError::InvalidCidr(cidr.to_owned()))?;
    let max = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max {
        return Err(IpamError::InvalidCidr(cidr.to_owned()));
    }
    Ok((mask_addr(addr, prefix), prefix))
}

fn mask_addr(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v) => {
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(v) & mask))
        }
        IpAddr::V6(v) => {
            let mask = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix)
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(v) & mask))
        }
    }
}

/// True when `ip` lies inside `network/prefix`. Cross-family is always false.
fn cidr_contains(network: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (network, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(n) & mask == u32::from(i) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            let mask = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(n) & mask == u128::from(i) & mask
        }
        _ => false,
    }
}

/// True when two CIDR blocks share at least one address.
pub fn pools_overlap(a_cidr: &str, b_cidr: &str) -> Result<bool, IpamError> {
    let (a_net, a_pre) = parse_cidr(a_cidr)?;
    let (b_net, b_pre) = parse_cidr(b_cidr)?;
    if std::mem::discriminant(&a_net) != std::mem::discriminant(&b_net) {
        return Ok(false);
    }
    Ok(cidr_contains(a_net, a_pre, b_net) || cidr_contains(b_net, b_pre, a_net))
}

/// Every pool must be fully inside `supernet` (same family, longer prefix).
pub fn pools_within_supernet(pools: &[IpamPool], supernet: &str) -> Result<(), String> {
    let (s_net, s_pre) = parse_cidr(supernet).map_err(|e| e.to_string())?;
    for pool in pools {
        let (net, pre) = parse_cidr(&pool.cidr).map_err(|e| format!("pool {}: {e}", pool.name))?;
        let inside = std::mem::discriminant(&net) == std::mem::discriminant(&s_net)
            && pre >= s_pre
            && cidr_contains(s_net, s_pre, net);
        if !inside {
            return Err(format!(
                "pool {} ({}) is not within supernet {supernet}",
                pool.name, pool.cidr
            ));
        }
    }
    Ok(())
}

fn exclusion_matches(addr: IpAddr, exclusion: &str) -> Result<bool, IpamError> {
    let text = exclusion.trim();
    if text.contains('/') {
        let (net, pre) = parse_cidr(text)?;
        Ok(cidr_contains(net, pre, addr))
    } else {
        let ip: IpAddr = text
            .parse()
            .map_err(|_| IpamError::InvalidCidr(exclusion.to_owned()))?;
        Ok(ip == addr)
    }
}

fn excluded(addr: IpAddr, exclusions: &[String]) -> bool {
    // Allocation-time helper: an unparseable exclusion is a pool-admission bug,
    // surfaced by validate_reservation/address_in_pool; never silently block.
    exclusions
        .iter()
        .any(|e| exclusion_matches(addr, e).unwrap_or(false))
}

/// True when `address` is usable from `pool` (inside, not excluded).
/// Network/broadcast checks belong to [`validate_reservation`], not here.
pub fn address_in_pool(address: &str, pool: &IpamPool) -> Result<bool, IpamError> {
    let addr: IpAddr = address
        .trim()
        .parse()
        .map_err(|_| IpamError::InvalidAddress(address.to_owned()))?;
    let (net, pre) = parse_cidr(&pool.cidr)?;
    if !cidr_contains(net, pre, addr) {
        return Ok(false);
    }
    for e in &pool.exclusions {
        if exclusion_matches(addr, e)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn usable_v4_range(base: u32, prefix: u8) -> (u32, u32) {
    if prefix == 32 {
        return (base, base);
    }
    if prefix == 31 {
        return (base, base + 1); // RFC 3021: both usable
    }
    let broadcast = base | (u32::MAX >> prefix);
    (base + 1, broadcast - 1)
}

/// Validate an exact-host reservation: must sit in exactly one usable,
/// non-excluded, non-network/broadcast slot of the given pools.
pub fn validate_reservation(pools: &[IpamPool], address: &str) -> Result<(), IpamError> {
    let addr: IpAddr = address
        .trim()
        .parse()
        .map_err(|_| IpamError::InvalidAddress(address.to_owned()))?;
    let label = address.trim().to_owned();
    for pool in pools {
        let (net, pre) = parse_cidr(&pool.cidr)?;
        if !cidr_contains(net, pre, addr) {
            continue;
        }
        for e in &pool.exclusions {
            if exclusion_matches(addr, e)? {
                return Err(IpamError::Excluded {
                    address: label,
                    pool: pool.name.clone(),
                });
            }
        }
        match (net, addr) {
            (IpAddr::V4(n), IpAddr::V4(i)) => {
                let (first, last) = usable_v4_range(u32::from(n), pre);
                let host = u32::from(i);
                if host < first {
                    return Err(IpamError::NetworkAddress {
                        address: label,
                        pool: pool.name.clone(),
                    });
                }
                if host > last {
                    return Err(IpamError::BroadcastAddress {
                        address: label,
                        pool: pool.name.clone(),
                    });
                }
            }
            (IpAddr::V6(n), IpAddr::V6(i)) => {
                if u128::from(i) == u128::from(n) {
                    return Err(IpamError::NetworkAddress {
                        address: label,
                        pool: pool.name.clone(),
                    });
                }
            }
            _ => continue,
        }
        return Ok(());
    }
    let scope = if pools.len() == 1 {
        pools[0].name.clone()
    } else {
        "any pool".to_owned()
    };
    Err(IpamError::OutsidePool {
        address: label,
        pool: scope,
    })
}

/// First free host address across `pools` in order, skipping used addresses,
/// held reservations (any state except `Released`), exclusions, and
/// network/broadcast addresses.
pub fn allocate_from_pools(
    used: &[String],
    pools: &[IpamPool],
    reservations: &[Reservation],
) -> Option<String> {
    let used_set: HashSet<IpAddr> = used.iter().filter_map(|s| s.trim().parse().ok()).collect();
    let held: HashSet<IpAddr> = reservations
        .iter()
        .filter(|r| r.state != ReservationState::Released)
        .filter_map(|r| r.address.trim().parse().ok())
        .collect();
    for pool in pools {
        let (net, prefix) = parse_cidr(&pool.cidr).ok()?;
        match net {
            IpAddr::V4(n) => {
                let (mut cur, last) = usable_v4_range(u32::from(n), prefix);
                for _ in 0..MAX_ALLOC_PROBES {
                    let ip = IpAddr::V4(Ipv4Addr::from(cur));
                    if !used_set.contains(&ip)
                        && !held.contains(&ip)
                        && !excluded(ip, &pool.exclusions)
                    {
                        return Some(ip.to_string());
                    }
                    if cur == last {
                        break;
                    }
                    cur += 1;
                }
            }
            IpAddr::V6(n) => {
                let base = u128::from(n);
                // Skip subnet-router anycast (all-zero).
                for offset in 1..=u128::from(MAX_ALLOC_PROBES) {
                    let cand = base.checked_add(offset)?;
                    if !cidr_contains(net, prefix, IpAddr::V6(Ipv6Addr::from(cand))) {
                        break;
                    }
                    let ip = IpAddr::V6(Ipv6Addr::from(cand));
                    if !used_set.contains(&ip)
                        && !held.contains(&ip)
                        && !excluded(ip, &pool.exclusions)
                    {
                        return Some(ip.to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(name: &str, cidr: &str, exclusions: &[&str]) -> IpamPool {
        IpamPool {
            name: name.into(),
            cidr: cidr.into(),
            exclusions: exclusions.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn reservation(address: &str, state: ReservationState) -> Reservation {
        Reservation {
            address: address.into(),
            node_id: None,
            enrol_key: None,
            state,
            reason: "test".into(),
            expires: None,
        }
    }

    #[test]
    fn overlap_detected() {
        assert!(pools_overlap("10.0.0.0/24", "10.0.0.128/25").unwrap());
        assert!(pools_overlap("10.0.0.0/25", "10.0.0.0/24").unwrap());
        assert!(!pools_overlap("10.0.0.0/24", "10.0.1.0/24").unwrap());
        assert!(!pools_overlap("10.0.0.0/24", "fd00::/64").unwrap());
    }

    #[test]
    fn supernet_membership() {
        let pools = vec![pool("a", "10.0.0.0/24", &[]), pool("b", "10.0.1.0/24", &[])];
        assert!(pools_within_supernet(&pools, "10.0.0.0/16").is_ok());
        let bad = vec![pool("c", "10.1.0.0/24", &[])];
        assert!(pools_within_supernet(&bad, "10.0.0.0/16").is_err());
        let too_big = vec![pool("d", "10.0.0.0/8", &[])];
        assert!(pools_within_supernet(&too_big, "10.0.0.0/16").is_err());
    }

    #[test]
    fn network_and_broadcast_skipped() {
        let pools = vec![pool("p", "10.1.0.0/30", &[])];
        assert_eq!(
            allocate_from_pools(&[], &pools, &[]).as_deref(),
            Some("10.1.0.1")
        );
        assert!(matches!(
            validate_reservation(&pools, "10.1.0.0"),
            Err(IpamError::NetworkAddress { .. })
        ));
        assert!(matches!(
            validate_reservation(&pools, "10.1.0.3"),
            Err(IpamError::BroadcastAddress { .. })
        ));
    }

    #[test]
    fn exclusion_blocks_allocation_and_validation() {
        let pools = vec![pool(
            "p",
            "192.168.1.0/30",
            &["192.168.1.1", "192.168.1.2/32"],
        )];
        assert_eq!(allocate_from_pools(&[], &pools, &[]), None);
        assert!(matches!(
            validate_reservation(&pools, "192.168.1.1"),
            Err(IpamError::Excluded { .. })
        ));
        assert!(!address_in_pool("192.168.1.2", &pools[0]).unwrap());
    }

    #[test]
    fn reserved_and_used_are_skipped() {
        let pools = vec![pool("p", "10.0.0.0/29", &[])];
        let used = vec!["10.0.0.1".to_owned(), "10.0.0.2".to_owned()];
        let held = vec![
            reservation("10.0.0.3", ReservationState::Reserved),
            reservation("10.0.0.4", ReservationState::Released), // free again
        ];
        assert_eq!(
            allocate_from_pools(&used, &pools, &held).as_deref(),
            Some("10.0.0.4")
        );
    }
}
