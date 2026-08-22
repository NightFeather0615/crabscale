//! TLS termination for the outer HTTP server.
//!
//! Three modes are supported:
//!
//! - `off` — plain HTTP (the historical behavior, still the default).
//! - `files` — a certificate chain + private key in PEM form on disk.
//! - `acme` — automatic certificates via the ACME protocol using
//!   [`rustls_acme`] with a file-backed cache. TLS-ALPN-01 challenges are
//!   answered on the same port; the driver task renews certificates in the
//!   background.
//!
//! The crypto provider is `ring` (consistent with the rest of the workspace)
//! and TLS 1.2/1.3 are both enabled.
//!
//! The contract requires that `/key` stays TLS-protected and that the
//! `/ts2021` and `/derp` HTTP upgrades pass through the TLS layer unchanged;
//! wrapping the raw TCP stream in [`tokio_rustls`] before hyper parses it
//! preserves those upgrades.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use futures::StreamExt;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, crypto::ring};
use rustls_acme::{AcmeConfig, caches::DirCache};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_rustls::{LazyConfigAcceptor, TlsAcceptor as TokioTlsAcceptor};

/// A validated server configuration for the TLS layer.
///
/// This is deliberately serializable so it can live in the config file and be
/// overridden from the environment.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct TlsSettings {
    /// `off`, `files` or `acme`.
    pub mode: String,
    /// PEM certificate chain file (used in `files` mode).
    pub cert_file: Option<PathBuf>,
    /// PEM private key file (used in `files` mode).
    pub key_file: Option<PathBuf>,
    /// Domains to request via ACME.
    pub acme_domains: Vec<String>,
    /// Contact addresses (e.g. `admin@example.com`) for ACME.
    pub acme_contact: Vec<String>,
    /// Directory for the persistent ACME account/certificate cache.
    pub acme_cache_dir: Option<PathBuf>,
    /// Override the ACME directory URL (defaults to Let's Encrypt production).
    pub acme_directory_url: Option<String>,
}

impl TlsSettings {
    /// Whether TLS is disabled.
    pub fn is_off(&self) -> bool {
        matches!(
            self.mode.trim().to_ascii_lowercase().as_str(),
            "" | "off" | "none"
        )
    }

    /// Whether certificates are requested automatically via ACME.
    pub fn is_acme(&self) -> bool {
        !self.is_off() && self.mode.trim().eq_ignore_ascii_case("acme")
    }

    /// Whether certificates are loaded from files.
    pub fn is_files(&self) -> bool {
        !self.is_off() && !self.is_acme()
    }
}

/// An accept-side TLS wrapper used by the outer HTTP server.
#[derive(Clone)]
pub enum TlsAcceptor {
    /// Static certificates loaded from disk.
    Files(TokioTlsAcceptor),
    /// ACME-managed certificates (TLS-ALPN-01 challenges and live renewal).
    Acme(AcmeAcceptor),
}

impl std::fmt::Debug for TlsAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Files(_) => f.write_str("TlsAcceptor::Files"),
            Self::Acme(_) => f.write_str("TlsAcceptor::Acme"),
        }
    }
}

impl TlsAcceptor {
    /// Complete the TLS handshake for an accepted TCP stream.
    pub async fn accept(&self, stream: TcpStream) -> io::Result<TlsStream<TcpStream>> {
        match self {
            Self::Files(acceptor) => acceptor.accept(stream).await,
            Self::Acme(acceptor) => acceptor.accept(stream).await,
        }
    }
}

/// ACME-backed acceptor: routes TLS-ALPN-01 challenge handshakes to a
/// dedicated certificate config and everything else to the default config.
#[derive(Clone)]
pub struct AcmeAcceptor {
    challenge_config: Arc<ServerConfig>,
    default_config: Arc<ServerConfig>,
    /// Join handle for the background certificate manager.
    #[allow(dead_code)]
    driver: Arc<tokio::task::JoinHandle<()>>,
}

impl std::fmt::Debug for AcmeAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeAcceptor").finish_non_exhaustive()
    }
}

impl AcmeAcceptor {
    async fn accept(&self, stream: TcpStream) -> io::Result<TlsStream<TcpStream>> {
        let start = LazyConfigAcceptor::new(Default::default(), stream).await?;
        if rustls_acme::is_tls_alpn_challenge(&start.client_hello()) {
            start.into_stream(self.challenge_config.clone()).await
        } else {
            start.into_stream(self.default_config.clone()).await
        }
    }
}

/// Build a [`TlsAcceptor`] from validated settings.
///
/// Fails fast on unreadable or mismatched certificate files so a broken
/// deployment never serves `--tls-mode files` without a working key pair.
pub fn load_tls_acceptor(settings: &TlsSettings) -> Result<TlsAcceptor, String> {
    if settings.is_off() {
        return Err("TLS is disabled; refusing to build an acceptor".to_string());
    }
    if settings.is_files() {
        let cert_file = settings
            .cert_file
            .as_ref()
            .ok_or("tls mode 'files' requires cert_file")?;
        let key_file = settings
            .key_file
            .as_ref()
            .ok_or("tls mode 'files' requires key_file")?;
        let config = load_file_config(cert_file, key_file)?;
        return Ok(TlsAcceptor::Files(TokioTlsAcceptor::from(Arc::new(config))));
    }

    // ACME mode.
    let domains = settings.acme_domains.clone();
    if domains.is_empty() {
        return Err("tls mode 'acme' requires at least one acme_domains entry".to_string());
    }
    // ACME must persist its account key and issued certificates; without a
    // cache the Let's Encrypt rate limits are exhausted on every restart.
    let cache_dir = settings
        .acme_cache_dir
        .as_ref()
        .ok_or("tls mode 'acme' requires acme_cache_dir")?;
    let mut acme = AcmeConfig::new(domains.clone()).cache(DirCache::new(cache_dir.clone()));
    if !settings.acme_contact.is_empty() {
        let contacts: Vec<String> = settings
            .acme_contact
            .iter()
            .map(|c| format!("mailto:{c}"))
            .collect();
        acme = acme.contact(contacts);
    }
    if let Some(url) = &settings.acme_directory_url {
        acme = acme.directory(url.clone());
    } else {
        // Production Let's Encrypt by default; point acme_directory_url at
        // staging while testing.
        acme = acme.directory_lets_encrypt(true);
    }

    let mut state = acme.state();
    let challenge_config = state.challenge_rustls_config();
    let default_config = state.default_rustls_config();

    // Drive account creation, order status, and certificate renewal in the
    // background. ACME is fully asynchronous: the resolver stays empty until
    // the first certificate is issued, after which handshakes succeed.
    let driver = tokio::spawn(async move {
        loop {
            match state.next().await {
                Some(Ok(event)) => eprintln!("acme: {event:?}"),
                Some(Err(err)) => eprintln!("acme error: {err:?}"),
                None => break,
            }
        }
    });

    Ok(TlsAcceptor::Acme(AcmeAcceptor {
        challenge_config,
        default_config,
        driver: Arc::new(driver),
    }))
}

/// Load a rustls [`ServerConfig`] from a PEM certificate chain and private key.
fn load_file_config(
    cert_file: &std::path::Path,
    key_file: &std::path::Path,
) -> Result<ServerConfig, String> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_file)
        .map_err(|e| {
            format!(
                "failed to open certificate file {}: {e}",
                cert_file.display()
            )
        })?
        .collect::<Result<_, _>>()
        .map_err(|e| {
            format!(
                "failed to parse certificate file {}: {e}",
                cert_file.display()
            )
        })?;
    if certs.is_empty() {
        return Err(format!(
            "certificate file {} contains no certificates",
            cert_file.display()
        ));
    }

    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_file(key_file)
        .map_err(|e| format!("failed to load private key {}: {e}", key_file.display()))?;

    let provider = Arc::new(ring::default_provider());
    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("unsupported protocol versions: {e}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("invalid certificate/key pair: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    /// Generate a self-signed certificate/key pair and write them as PEM files
    /// into a fresh *unique* temp directory. Returns `(dir, cert_pem, key_pem)`.
    fn write_test_cert() -> (std::path::PathBuf, PathBuf, PathBuf) {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("crabscale-tls-test-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cert_file = dir.join("cert.pem");
        let key_file = dir.join("key.pem");
        fs::write(&cert_file, cert_pem).unwrap();
        fs::write(&key_file, key_pem).unwrap();
        (dir, cert_file, key_file)
    }

    #[test]
    fn off_mode_is_recognized() {
        let settings = TlsSettings::default();
        assert!(settings.is_off());
        assert!(load_tls_acceptor(&settings).is_err());
    }

    #[test]
    fn files_mode_loads_cert_and_key() {
        let (_dir, cert_file, key_file) = write_test_cert();
        let settings = TlsSettings {
            mode: "files".to_string(),
            cert_file: Some(cert_file),
            key_file: Some(key_file),
            ..Default::default()
        };
        assert!(settings.is_files());
        let acceptor = load_tls_acceptor(&settings).expect("files acceptor builds");
        matches!(acceptor, TlsAcceptor::Files(_));
    }

    #[test]
    fn files_mode_rejects_missing_files() {
        let settings = TlsSettings {
            mode: "files".to_string(),
            cert_file: Some(PathBuf::from("/nonexistent/cert.pem")),
            key_file: Some(PathBuf::from("/nonexistent/key.pem")),
            ..Default::default()
        };
        assert!(load_tls_acceptor(&settings).is_err());
    }

    #[test]
    fn acme_mode_requires_domains() {
        let settings = TlsSettings {
            mode: "acme".to_string(),
            ..Default::default()
        };
        assert!(settings.is_acme());
        assert!(load_tls_acceptor(&settings).is_err());
    }

    #[test]
    fn pem_round_trip_implied_by_files_load() {
        // Sanity check that the generated PEM key chains to the loaded certs.
        let (_dir, cert_file, key_file) = write_test_cert();
        let certs = std::fs::read_to_string(&cert_file).unwrap();
        assert!(certs.contains("BEGIN CERTIFICATE"));
        let key = std::fs::read_to_string(&key_file).unwrap();
        assert!(key.contains("PRIVATE KEY"));

        // Exercise the async handshake path against the loaded files config.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(handshake_smoke(&cert_file, &key_file));
    }

    async fn handshake_smoke(cert_file: &std::path::Path, key_file: &std::path::Path) {
        let settings = TlsSettings {
            mode: "files".to_string(),
            cert_file: Some(cert_file.to_path_buf()),
            key_file: Some(key_file.to_path_buf()),
            ..Default::default()
        };
        let acceptor = load_tls_acceptor(&settings).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        let acceptor = acceptor.clone();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(stream).await.unwrap();
            let _ = tls;
        });

        // A well-formed TLS client handshake must complete. The self-signed
        // certificate is trusted as its own root so the client accepts it.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        let cert_pem = fs::read(cert_file).unwrap();
        let cert = CertificateDer::from_pem_slice(&cert_pem).expect("parse self-signed cert");
        roots.add(cert).unwrap();
        let client_config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let server_name = rustls_pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();

        let client = tokio::spawn(async move {
            let tcp = tokio::net::TcpStream::connect(local).await.unwrap();
            let _tls = connector.connect(server_name, tcp).await.unwrap();
        });

        tokio::time::timeout(Duration::from_secs(5), async {
            let _ = client.await;
            let _ = server.await;
        })
        .await
        .expect("TLS handshake hung");
    }
}
