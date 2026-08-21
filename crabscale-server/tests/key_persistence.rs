//! Control key persistence across server restarts (M4-03, #26 acceptance).
//!
//! A `--key-file` path is the single source of truth for the long-term Noise
//! key. Restarting the server over the same file must advertise the *same*
//! machine public key, which is what a Docker volume mount provides in the
//! container deployment.

use crabscale_proto::MachineKey;
use crabscale_server::{ControlRouter, ServerKey, serve_on_addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn server_key(path: &std::path::Path) -> ServerKey {
    use crabscale_server::load_or_create_machine_key;
    load_or_create_machine_key(path).unwrap()
}

async fn advertised_key(addr: std::net::SocketAddr) -> serde_json::Value {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /key?v=130 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    stream.flush().await.unwrap();
    let (head, body) = read_http_response(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "head: {head}");
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn key_file_survives_restart() {
    let dir = std::env::temp_dir().join(format!("crabscale-key-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key_file = dir.join("crabscale.key");

    // First boot: create the key file and advertise its public half on /key.
    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let key1 = server_key(&key_file);
    let router1 = ControlRouter::new(key1.public_key());
    let (addr1, handle1) = serve_on_addr(bind, router1, key1).await.unwrap();
    let first = advertised_key(addr1).await;
    handle1.shutdown();

    // Second boot: same key file, no re-generation.
    let key2 = server_key(&key_file);
    let pub2 = key2.public_key();
    let router2 = ControlRouter::new(pub2);
    let (addr2, handle2) = serve_on_addr(bind, router2, key2).await.unwrap();
    let second = advertised_key(addr2).await;
    handle2.shutdown();

    assert_eq!(
        first, second,
        "the advertised machine key must persist across restart"
    );
    assert_ne!(
        pub2,
        MachineKey::from_bytes([0u8; 32]),
        "the persisted key must not be the all-zero placeholder"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Read an HTTP/1.1 response head and body using Content-Length.
async fn read_http_response<S>(stream: &mut S) -> (String, Vec<u8>)
where
    S: tokio::io::AsyncRead + Unpin,
{
    let head = read_http_head(stream).await;
    let content_length = head
        .lines()
        .find_map(|line| {
            let lower = line.to_ascii_lowercase();
            lower
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        stream.read_exact(&mut body).await.unwrap();
    }
    (head, body)
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
