//! `/bootstrap-dns` handler (Spec-Control-API, Bootstrap DNS).
//!
//! Before the tailnet interface is up a client cannot yet use its configured
//! DNS resolvers, so the relay publishes a small DNS bootstrap map: hostnames
//! the client should reach directly, resolved to their current IP addresses.
//! The endpoint answers `GET /bootstrap-dns?q=<name>`; when the queried name
//! is present only that entry is returned, otherwise the full published map
//! is returned so clients can discover names too.

use std::collections::BTreeMap;
use std::net::IpAddr;

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::Full;

/// A snapshot of the published bootstrap DNS names and their addresses.
///
/// The map is intentionally plain and clone-safe: the server resolves the
/// configured names at startup (or in tests, seeds them directly) and serves
/// the cached snapshot. Address order is randomized by the resolver, which a
/// relay may re-shuffle before publishing if it wants to avoid an IPv6 bias.
#[derive(Clone, Debug, Default)]
pub struct BootstrapDns {
    entries: BTreeMap<String, Vec<IpAddr>>,
}

impl BootstrapDns {
    /// Build a snapshot from explicit name-to-address entries (used by
    /// tests so no live DNS lookup is needed).
    pub fn from_entries(entries: BTreeMap<String, Vec<IpAddr>>) -> Self {
        Self { entries }
    }

    /// Resolve a list of names to their IP addresses.
    ///
    /// Names that fail to resolve are skipped; an empty map is a valid
    /// "nothing published yet" snapshot.
    pub async fn resolve(names: &[String]) -> Self {
        let mut entries = BTreeMap::new();
        for raw in names {
            let name = raw.trim();
            if name.is_empty() {
                continue;
            }
            match tokio::net::lookup_host((name, 0)).await {
                Ok(addrs) => {
                    let mut ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                    ips.dedup();
                    ips.sort();
                    if !ips.is_empty() {
                        entries.insert(name.to_string(), ips);
                    }
                }
                Err(e) => {
                    eprintln!("bootstrap-dns: lookup {name}: {e}");
                }
            }
        }
        Self { entries }
    }

    /// Whether any names have been published.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Snapshot of the published entries.
    pub fn entries(&self) -> &BTreeMap<String, Vec<IpAddr>> {
        &self.entries
    }

    /// Serve a `GET /bootstrap-dns` response for an optional `q` parameter.
    pub fn handle(&self, q: Option<&str>) -> Response<Full<Bytes>> {
        let queried = q.map(str::trim).filter(|q| !q.is_empty());
        let body: BTreeMap<String, Vec<IpAddr>> = match queried {
            Some(name) => match self.entries.get(name) {
                Some(ips) => BTreeMap::from([(name.to_string(), ips.clone())]),
                None => self.entries.clone(),
            },
            None => self.entries.clone(),
        };
        let json = serde_json::to_string(&body).unwrap_or_else(|_| "{}".to_string());
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .header("Connection", "close")
            .body(Full::new(Bytes::from(json)))
            .expect("static response is valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_dns() -> BootstrapDns {
        BootstrapDns::from_entries(BTreeMap::from([
            (
                "derp.example.com".to_string(),
                vec![
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                ],
            ),
            (
                "control.example.com".to_string(),
                vec![IpAddr::V6("2001:db8::3".parse().unwrap())],
            ),
        ]))
    }

    /// Destructure a response into its JSON body and raw bytes.
    fn body_of(response: Response<Full<Bytes>>) -> (serde_json::Value, Bytes) {
        let (_parts, body) = response.into_parts();
        let bytes = body.into_inner().unwrap_or_default();
        let json = serde_json::from_slice(&bytes).unwrap();
        (json, bytes)
    }

    #[test]
    fn returns_full_map_without_query() {
        let dns = test_dns();
        let response = dns.handle(None);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "application/json");
        let (json, _bytes) = body_of(response);
        assert_eq!(json["derp.example.com"][0], serde_json::json!("192.0.2.1"));
        assert_eq!(json["derp.example.com"][1], serde_json::json!("192.0.2.2"));
        assert_eq!(
            json["control.example.com"][0],
            serde_json::json!("2001:db8::3")
        );
    }

    #[test]
    fn returns_only_queried_name_when_known() {
        let dns = test_dns();
        let (json, _bytes) = body_of(dns.handle(Some("derp.example.com")));
        assert!(json.get("derp.example.com").is_some());
        assert!(json.get("control.example.com").is_none());
    }

    #[test]
    fn unknown_query_falls_back_to_full_map() {
        let dns = test_dns();
        let (json, _bytes) = body_of(dns.handle(Some("unknown.example.com")));
        assert_eq!(json.as_object().unwrap().len(), 2);
    }
}
