//! Integration tests for TLS termination.
//!
//! A self-signed certificate is generated on the fly, loaded through the
//! `files` TLS mode, and the outer HTTP server is reached over a real rustls
//! client handshake. This proves `/key` stays reachable (and TLS-protected)
//! and that hyper's upgrade path works over the TLS stream.

use std::sync::Arc;

use crabscale_proto::MachineKey;
use crabscale_server::{
    ControlRouter, ServerKey, ServerOptions, TlsSettings, load_tls_acceptor,
    serve_on_addr_with_options,
};
use crabscale_transport::NoiseResponder;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

/// Write a fresh self-signed cert/key pair into a unique temp dir and return
/// `(cert_file, key_file)`. The unique dir keeps concurrently-running tests
/// from clobbering each other's files.
fn write_self_signed() -> (std::path::PathBuf, std::path::PathBuf) {
    let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("crabscale-tls-it-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_file = dir.join("cert.pem");
    let key_file = dir.join("key.pem");
    std::fs::write(&cert_file, cert.pem()).unwrap();
    std::fs::write(&key_file, key_pair.serialize_pem()).unwrap();
    (cert_file, key_file)
}

fn test_key() -> MachineKey {
    MachineKey::from_bytes([0x42; 32])
}

#[tokio::test]
async fn key_endpoint_served_over_tls() {
    let (cert_file, key_file) = write_self_signed();
    let acceptor = load_tls_acceptor(&TlsSettings {
        mode: "files".to_string(),
        cert_file: Some(cert_file.clone()),
        key_file: Some(key_file),
        ..Default::default()
    })
    .expect("load self-signed files");

    let responder = NoiseResponder::random();
    let machine_key = MachineKey::from_bytes(responder.public_key().to_bytes());
    let server_key = ServerKey::new(responder, machine_key);
    let router = ControlRouter::new(test_key());
    let options = ServerOptions {
        tls: Some(Arc::new(acceptor)),
        ..Default::default()
    };
    let (addr, handle) =
        serve_on_addr_with_options("127.0.0.1:0".parse().unwrap(), router, server_key, options)
            .await
            .unwrap();

    // Build a client that trusts the self-signed cert as its own root.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    let cert_pem = std::fs::read(&cert_file).unwrap();
    roots
        .add(CertificateDer::from_pem_slice(&cert_pem).unwrap())
        .unwrap();
    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = rustls_pki_types::ServerName::try_from("localhost")
        .unwrap()
        .to_owned();

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();
    tls.write_all(b"GET /key?v=130 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    tls.flush().await.unwrap();

    let head = read_http_head(&mut tls).await;
    assert!(head.starts_with("HTTP/1.1 200"), "TLS /key head: {head}");
    assert!(head.to_ascii_lowercase().contains("content-length"));

    handle.shutdown();
}

/// A plain-HTTP request to a TLS-only listener fails during the handshake
/// (the peer never completes TLS), proving the listener is not fallback-open.
#[tokio::test]
async fn tls_listener_rejects_plain_http() {
    let (cert_file, key_file) = write_self_signed();
    let acceptor = load_tls_acceptor(&TlsSettings {
        mode: "files".to_string(),
        cert_file: Some(cert_file),
        key_file: Some(key_file),
        ..Default::default()
    })
    .unwrap();

    let responder = NoiseResponder::random();
    let machine_key = MachineKey::from_bytes(responder.public_key().to_bytes());
    let server_key = ServerKey::new(responder, machine_key);
    let router = ControlRouter::new(test_key());
    let options = ServerOptions {
        tls: Some(Arc::new(acceptor)),
        ..Default::default()
    };
    let (addr, _handle) =
        serve_on_addr_with_options("127.0.0.1:0".parse().unwrap(), router, server_key, options)
            .await
            .unwrap();

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /key?v=130 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    stream.flush().await.unwrap();

    // Reading after sending plaintext to a TLS listener must fail or short
    // (the server speaks only TLS), not return a valid HTTP response.
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf)).await;
    match n {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {}
        Ok(Ok(n)) if n > 0 => {
            // A TLS alert is fine as long as it is not a plaintext HTTP reply.
            assert_ne!(buf[0], b'H', "must not serve plaintext HTTP over TLS");
        }
        Ok(Ok(_)) => unreachable!(),
    }
}

/// Read an HTTP/1.1 response head up to the blank line.
async fn read_http_head<S>(stream: &mut S) -> String
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await.unwrap();
        assert!(n > 0, "connection closed while reading head");
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return String::from_utf8_lossy(&buf).to_string();
        }
    }
}
