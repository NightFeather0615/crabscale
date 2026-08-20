//! Random tailnet IP allocation within configured prefixes.
//!
//! The allocator draws uniformly from the host range of a prefix and skips
//! reserved addresses (the network and broadcast addresses for IPv4, and the
//! subnet-router anycast address for IPv6). Callers are responsible for
//! passing the set of addresses already in use so allocations never collide.

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use rand::Rng;

/// Errors returned by the IP allocator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAllocatorError {
    /// The prefix leaves no allocatable host addresses.
    NoAddresses,
    /// The host range is exhausted.
    Exhausted,
}

impl std::fmt::Display for IpAllocatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAddresses => write!(f, "prefix has no allocatable host addresses"),
            Self::Exhausted => write!(f, "no free addresses remain in prefix"),
        }
    }
}

impl std::error::Error for IpAllocatorError {}

/// Allocates random IPv4 and IPv6 addresses inside configured prefixes.
#[derive(Clone, Debug)]
pub struct IpAllocator {
    ipv4_prefix: Ipv4Addr,
    ipv4_prefix_len: u8,
    ipv6_prefix: Ipv6Addr,
    ipv6_prefix_len: u8,
}

impl IpAllocator {
    /// Create an allocator for the given IPv4 and IPv6 prefixes.
    pub fn new(
        ipv4_prefix: Ipv4Addr,
        ipv4_prefix_len: u8,
        ipv6_prefix: Ipv6Addr,
        ipv6_prefix_len: u8,
    ) -> Self {
        Self {
            ipv4_prefix,
            ipv4_prefix_len,
            ipv6_prefix,
            ipv6_prefix_len,
        }
    }

    /// Allocate a random IPv4 address inside the configured prefix.
    pub fn allocate_ipv4(&self, used: &HashSet<Ipv4Addr>) -> Result<Ipv4Addr, IpAllocatorError> {
        let (first, count) = ipv4_host_range(self.ipv4_prefix, self.ipv4_prefix_len)?;
        let mut rng = rand::thread_rng();
        for _ in 0..1024 {
            let offset = rng.gen_range(0..count);
            let candidate = Ipv4Addr::from(first + offset);
            if !used.contains(&candidate) {
                return Ok(candidate);
            }
        }
        Err(IpAllocatorError::Exhausted)
    }

    /// Allocate a random IPv6 address inside the configured prefix.
    pub fn allocate_ipv6(&self, used: &HashSet<Ipv6Addr>) -> Result<Ipv6Addr, IpAllocatorError> {
        let (first, count) = ipv6_host_range(self.ipv6_prefix, self.ipv6_prefix_len)?;
        let mut rng = rand::thread_rng();
        for _ in 0..1024 {
            let offset = rng.gen_range(0..count);
            let candidate = Ipv6Addr::from(first + offset);
            if !used.contains(&candidate) {
                return Ok(candidate);
            }
        }
        Err(IpAllocatorError::Exhausted)
    }

    /// Allocate a random IPv4 and IPv6 pair, skipping any already-used
    /// addresses in the supplied sets.
    pub fn allocate(
        &self,
        used_ipv4: &HashSet<Ipv4Addr>,
        used_ipv6: &HashSet<Ipv6Addr>,
    ) -> Result<(Ipv4Addr, Ipv6Addr), IpAllocatorError> {
        let ipv4 = self.allocate_ipv4(used_ipv4)?;
        let ipv6 = self.allocate_ipv6(used_ipv6)?;
        Ok((ipv4, ipv6))
    }
}

/// Return `(first_host, host_count)` for an IPv4 prefix.
fn ipv4_host_range(prefix: Ipv4Addr, prefix_len: u8) -> Result<(u32, u32), IpAllocatorError> {
    if prefix_len == 0 || prefix_len > 32 {
        return Err(IpAllocatorError::NoAddresses);
    }
    let mask = u32::MAX << (32 - prefix_len);
    let network = u32::from(prefix) & mask;
    let host_bits = 32 - prefix_len;
    if host_bits < 2 {
        return Err(IpAllocatorError::NoAddresses);
    }
    let host_count = 1u32 << host_bits;
    // Skip the network and broadcast addresses.
    let first = network + 1;
    let count = host_count - 2;
    if count == 0 {
        return Err(IpAllocatorError::NoAddresses);
    }
    Ok((first, count))
}

/// Return `(first_host, host_count)` for an IPv6 prefix.
fn ipv6_host_range(prefix: Ipv6Addr, prefix_len: u8) -> Result<(u128, u128), IpAllocatorError> {
    if prefix_len == 0 || prefix_len > 128 {
        return Err(IpAllocatorError::NoAddresses);
    }
    let mask = u128::MAX << (128 - prefix_len);
    let network = u128::from(prefix) & mask;
    let host_bits = 128 - prefix_len;
    if host_bits < 1 {
        return Err(IpAllocatorError::NoAddresses);
    }
    let host_count = 1u128 << host_bits;
    // Skip the subnet-router anycast address (the first address).
    let first = network + 1;
    let count = host_count - 1;
    if count == 0 {
        return Err(IpAllocatorError::NoAddresses);
    }
    Ok((first, count))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_allocator() -> IpAllocator {
        IpAllocator::new(
            Ipv4Addr::new(100, 64, 0, 0),
            10,
            Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0),
            48,
        )
    }

    #[test]
    fn allocates_within_prefix_and_skips_reserved() {
        let allocator = test_allocator();
        let mut used_v4 = HashSet::new();
        let mut used_v6 = HashSet::new();
        for _ in 0..100 {
            let (v4, v6) = allocator.allocate(&used_v4, &used_v6).unwrap();
            assert!(v4.octets()[0] == 100 && v4.octets()[1] & 0xc0 == 0x40);
            assert!(v4 != Ipv4Addr::new(100, 64, 0, 0));
            assert!(v4 != Ipv4Addr::new(100, 127, 255, 255));
            assert!(v6 != Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0));
            used_v4.insert(v4);
            used_v6.insert(v6);
        }
    }

    #[test]
    fn no_duplicates_over_1000_allocations() {
        let allocator = test_allocator();
        let mut used_v4 = HashSet::new();
        let mut used_v6 = HashSet::new();
        for _ in 0..1000 {
            let (v4, v6) = allocator.allocate(&used_v4, &used_v6).unwrap();
            assert!(used_v4.insert(v4), "duplicate IPv4 allocation");
            assert!(used_v6.insert(v6), "duplicate IPv6 allocation");
        }
    }

    #[test]
    fn tiny_prefix_reports_no_addresses() {
        let allocator = IpAllocator::new(
            Ipv4Addr::new(192, 168, 0, 0),
            31,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0),
            128,
        );
        assert_eq!(
            allocator.allocate_ipv4(&HashSet::new()),
            Err(IpAllocatorError::NoAddresses)
        );
        assert_eq!(
            allocator.allocate_ipv6(&HashSet::new()),
            Err(IpAllocatorError::NoAddresses)
        );
    }
}
