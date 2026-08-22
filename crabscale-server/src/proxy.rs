//! Trusted reverse-proxy handling: resolve the real client IP.
//!
//! When the server is deployed behind a reverse proxy (nginx, Caddy,
//! edge load balancer), the TCP peer is the proxy itself, not the client.
//! `X-Forwarded-For` (and `X-Real-IP`) support lets the
//! `/ts2021` rate limiter and connection logging key on the real client IP
//! instead of the proxy's IP.
//!
//! A proxy is trusted only when its address (the TCP peer) is inside one of
//! the configured CIDRs. Requests from any other peer are never allowed to
//! spoof the client IP.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use http::HeaderMap;
use ipnet::IpNet;

/// The header carrying the client-chain that proxies append to.
const X_FORWARDED_FOR: &str = "x-forwarded-for";
/// A convenience header some proxies set for the origin client IP.
const X_REAL_IP: &str = "x-real-ip";

/// Networks (CIDRs) whose `X-Forwarded-For` values are honored.
///
/// Clones share one immutable snapshot so the set can be attached to many
/// connections cheaply.
#[derive(Clone, Debug, Default)]
pub struct TrustedProxies {
    networks: Arc<Vec<IpNet>>,
}

impl TrustedProxies {
    /// An empty set: no header is honored and the peer address is authoritative.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Parse a list of CIDR strings such as `"127.0.0.1/32, ::1/128"`.
    ///
    /// Returns an error naming the offending network so operators can fix
    /// their configuration at startup instead of silently trusting nothing.
    pub fn from_cidrs<S: AsRef<str>>(cidrs: &[S]) -> Result<Self, String> {
        let mut networks = Vec::with_capacity(cidrs.len());
        for cidr in cidrs {
            let cidr = cidr.as_ref().trim();
            if cidr.is_empty() {
                continue;
            }
            let net = IpNet::from_str(cidr)
                .map_err(|e| format!("invalid trusted proxy CIDR {cidr:?}: {e}"))?;
            networks.push(net);
        }
        if networks.is_empty() {
            return Ok(Self::empty());
        }
        Ok(Self {
            networks: Arc::new(networks),
        })
    }

    /// Whether `ip` is one of the trusted proxy addresses.
    pub fn trusts(&self, ip: IpAddr) -> bool {
        self.networks.iter().any(|net| net.contains(&ip))
    }

    /// Whether no proxy is trusted (fast path for direct deployments).
    pub fn is_empty(&self) -> bool {
        self.networks.is_empty()
    }

    /// Resolve the client IP as seen from `peer` with the given request headers.
    ///
    /// - When `peer` is not a trusted proxy, `peer` is returned unchanged; any
    ///   forwarding header is ignored (spoofing protection).
    /// - When `peer` is trusted, the `X-Forwarded-For` chain is scanned from
    ///   the rightmost (nearest proxy) entry, skipping values that are
    ///   themselves trusted proxies. The first untrusted address is the real
    ///   client. If every entry is trusted (or the header is absent),
    ///   `X-Real-IP` is used, and finally `peer` as a fallback.
    pub fn resolve_client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        if self.is_empty() || !self.trusts(peer) {
            return peer;
        }

        let chain = forwarded_chain(headers);
        if let Some(found) = chain.iter().rev().copied().find(|ip| !self.trusts(*ip)) {
            return found;
        }
        // The whole chain is trusted (or empty): use the leftmost reported
        // value as the client, then X-Real-IP, then the peer as a last resort.
        chain
            .first()
            .copied()
            .or_else(|| real_ip(headers))
            .unwrap_or(peer)
    }
}

/// Collect every IP in the (possibly repeated) `X-Forwarded-For` headers.
fn forwarded_chain(headers: &HeaderMap) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for value in headers.get_all(X_FORWARDED_FOR) {
        let Ok(value) = value.to_str() else { continue };
        for part in value.split(',') {
            if let Ok(ip) = IpAddr::from_str(part.trim()) {
                out.push(ip);
            }
        }
    }
    out
}

/// Read the `X-Real-IP` header, ignoring malformed values.
fn real_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get(X_REAL_IP)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| IpAddr::from_str(v.trim()).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.append(
                http::HeaderName::from_str(k).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    #[test]
    fn empty_proxy_set_never_honors_headers() {
        let proxies = TrustedProxies::empty();
        let headers = headers(&[("x-forwarded-for", "198.51.100.7")]);
        assert_eq!(
            proxies.resolve_client_ip(v4([192, 0, 2, 10]), &headers),
            v4([192, 0, 2, 10]),
            "untrusted peer must keep its own address"
        );
    }

    #[test]
    fn untrusted_peer_cannot_spoof() {
        let proxies = TrustedProxies::from_cidrs(&["127.0.0.1/32"]).unwrap();
        // The attacker connects directly (peer is not the trusted proxy) and
        // lies about X-Forwarded-For; the header must be ignored.
        let headers = headers(&[("x-forwarded-for", "198.51.100.7")]);
        assert_eq!(
            proxies.resolve_client_ip(v4([203, 0, 113, 9]), &headers),
            v4([203, 0, 113, 9])
        );
    }

    #[test]
    fn trusted_proxy_honors_forwarded_chain() {
        let proxies =
            TrustedProxies::from_cidrs(&["127.0.0.1/32", "10.0.0.0/8", "::1/128"]).unwrap();
        // Proxies appended client, p1, p2; p2 (rightmost) is the immediate peer.
        let headers = headers(&[("x-forwarded-for", "198.51.100.7, 10.0.0.5, 127.0.0.1")]);
        assert_eq!(
            proxies.resolve_client_ip(v4([127, 0, 0, 1]), &headers),
            v4([198, 51, 100, 7])
        );
    }

    #[test]
    fn trusted_proxy_falls_back_when_chain_is_all_trusted() {
        let proxies = TrustedProxies::from_cidrs(&["10.0.0.0/8", "127.0.0.1/32"]).unwrap();
        let headers = headers(&[("x-forwarded-for", "10.0.0.1, 127.0.0.1")]);
        assert_eq!(
            proxies.resolve_client_ip(v4([127, 0, 0, 1]), &headers),
            v4([10, 0, 0, 1]),
            "leftmost value is kept when every hop is trusted"
        );
    }

    #[test]
    fn trusted_proxy_uses_x_real_ip_without_forwarded_for() {
        let proxies = TrustedProxies::from_cidrs(&["127.0.0.1/32"]).unwrap();
        let headers = headers(&[("x-real-ip", "198.51.100.42")]);
        assert_eq!(
            proxies.resolve_client_ip(v4([127, 0, 0, 1]), &headers),
            v4([198, 51, 100, 42])
        );
    }

    #[test]
    fn trusted_proxy_falls_back_to_peer_without_headers() {
        let proxies = TrustedProxies::from_cidrs(&["127.0.0.1/32"]).unwrap();
        let headers = headers(&[]);
        assert_eq!(
            proxies.resolve_client_ip(v4([127, 0, 0, 1]), &headers),
            v4([127, 0, 0, 1])
        );
    }

    #[test]
    fn skips_trusted_middle_hops() {
        let proxies = TrustedProxies::from_cidrs(&["127.0.0.1/32", "10.0.0.0/8"]).unwrap();
        let headers = headers(&[("x-forwarded-for", "198.51.100.7, 10.0.0.5, 10.0.0.6")]);
        assert_eq!(
            proxies.resolve_client_ip(v4([127, 0, 0, 1]), &headers),
            v4([198, 51, 100, 7])
        );
    }

    #[test]
    fn handles_ipv6_cidrs() {
        let proxies = TrustedProxies::from_cidrs(&["::1/128", "fc00::/7"]).unwrap();
        let client: IpAddr = "2001:db8::1".parse().unwrap();
        let trusted_hop: IpAddr = "fc00::10".parse().unwrap();
        let localhost = IpAddr::V6(Ipv6Addr::LOCALHOST);

        let hdr = headers(&[("x-forwarded-for", &client.to_string())]);
        assert_eq!(
            proxies.resolve_client_ip(localhost, &hdr),
            client,
            "a literal set of trusted hops resolves the untrusted client"
        );

        // A trusted hop in the middle must be skipped.
        let hdr = headers(&[("x-forwarded-for", &format!("{client}, {trusted_hop}"))]);
        assert_eq!(proxies.resolve_client_ip(localhost, &hdr), client);
    }

    #[test]
    fn rejects_bad_cidrs() {
        assert!(TrustedProxies::from_cidrs(&["not-a-cidr"]).is_err());
        assert!(TrustedProxies::from_cidrs(&["10.0.0.0/33"]).is_err());
        // Empty input is valid and means "trust nobody".
        assert!(TrustedProxies::from_cidrs(&["", "  "]).unwrap().is_empty());
    }
}
