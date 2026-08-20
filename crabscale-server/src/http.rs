//! Outer HTTP/1.1 control server built on tokio's `net` feature and hyper.
//!
//! This module serves the two outer endpoints required by Spec-Transport:
//!
//! - `GET /key?v=<capability_version>` returns the server machine key.
//! - `POST /ts2021` upgrades the connection to the TS2021 Noise transport and
//!   then hands the resulting stream to the inner HTTP/2 control router.
//!
//! The server uses `tokio::net` (and therefore `mio`) plus `hyper` for HTTP/1.1
//! parsing instead of a hand-rolled parser. See the wiki `Architecture` page
//! for the decision and the limitations that no longer apply.

use std::io;
use std::net::SocketAddr;

use bytes::Bytes;
use crabscale_transport::{
    HANDSHAKE_HEADER, NoiseStream, UPGRADE_HEADER_VALUE, parse_init_message,
    validate_native_upgrade,
};
use http::{HeaderValue, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::key::ServerKey;
use crate::router::{ControlRouter, serve_control};

/// A handle to a running outer control server, used to request shutdown.
#[derive(Clone)]
pub struct ServerHandle {
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

impl ServerHandle {
    /// Ask the accept loop to stop accepting new connections.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// Bind `addr` and serve the outer control endpoints until shutdown is
/// requested. Returns the actual bound address (useful when `addr` uses port
/// 0) and a handle that can be used to stop the server.
pub async fn serve_on_addr(
    addr: SocketAddr,
    router: ControlRouter,
    server_key: ServerKey,
) -> io::Result<(SocketAddr, ServerHandle)> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = ServerHandle { shutdown_tx };
    tokio::spawn(async move {
        let _ = serve(listener, router, server_key, shutdown_rx).await;
    });
    Ok((local, handle))
}

/// Accept connections and serve the outer control endpoints until shutdown is
/// requested.
pub async fn serve(
    listener: TcpListener,
    router: ControlRouter,
    server_key: ServerKey,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                return Ok(());
            }
            res = listener.accept() => {
                let (stream, _) = res?;
                let router = router.clone();
                let server_key = server_key.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, router, server_key).await;
                });
            }
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    router: ControlRouter,
    server_key: ServerKey,
) -> io::Result<()> {
    let service = service_fn(move |req| handle_request(req, router.clone(), server_key.clone()));
    http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await
        .map_err(|e| io::Error::other(e.to_string()))
}

async fn handle_request(
    req: Request<Incoming>,
    router: ControlRouter,
    server_key: ServerKey,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    if method == http::Method::GET && path == "/key" {
        let capver = query_param(req.uri().query(), "v");
        let response = router.handle_key(capver);
        return Ok(response.map(Full::new));
    }

    if method == http::Method::POST && path == "/ts2021" {
        return Ok(handle_ts2021(req, router, server_key).await);
    }

    // `GET /register/{id}` serves the interactive-registration approval page
    // (Spec-Registration section 4). Unknown or expired ids return 404.
    if let Some(auth_id) = register_auth_id(&path) {
        if method == http::Method::GET {
            let response = router.handle_register_page(auth_id);
            return Ok(response.map(Full::new));
        }
    }

    Ok(plain_response(StatusCode::NOT_FOUND, "not found"))
}

/// Extract the auth id from a `/register/{id}` path.
///
/// Returns `None` for any other path shape, including ids containing a slash.
fn register_auth_id(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/register/")?;
    if rest.is_empty() || rest.contains('/') {
        return None;
    }
    Some(rest)
}

async fn handle_ts2021(
    req: Request<Incoming>,
    router: ControlRouter,
    server_key: ServerKey,
) -> Response<Full<Bytes>> {
    let headers = req.headers();
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());

    let init = match validate_native_upgrade(
        "POST",
        get("upgrade"),
        get("connection"),
        get(HANDSHAKE_HEADER),
    ) {
        Ok(init) => init,
        Err(_) => {
            return plain_response(StatusCode::BAD_REQUEST, "invalid upgrade request");
        }
    };

    let init = match parse_init_message(&init) {
        Ok(init) => init,
        Err(_) => {
            return plain_response(StatusCode::BAD_REQUEST, "invalid handshake");
        }
    };

    let prologue = format!("Tailscale Control Protocol v{}", init.version);
    let output = match server_key.responder().respond(&init, prologue.as_bytes()) {
        Ok(output) => output,
        Err(_) => {
            return plain_response(StatusCode::BAD_REQUEST, "handshake rejected");
        }
    };

    let mut res = Response::new(Full::new(Bytes::new()));
    *res.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    res.headers_mut().insert(
        http::header::UPGRADE,
        HeaderValue::from_static(UPGRADE_HEADER_VALUE),
    );
    res.headers_mut().insert(
        http::header::CONNECTION,
        HeaderValue::from_static("upgrade"),
    );

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut upgraded = TokioIo::new(upgraded);
                if let Err(e) = upgraded.write_all(&output.response).await {
                    eprintln!("failed to write Noise response: {e}");
                    return;
                }
                if let Err(e) = upgraded.flush().await {
                    eprintln!("failed to flush Noise response: {e}");
                    return;
                }
                let noise_stream = NoiseStream::new(
                    upgraded,
                    output.session.initiator_to_responder,
                    output.session.responder_to_initiator,
                );
                let _ = serve_control(noise_stream, router).await;
            }
            Err(e) => {
                eprintln!("upgrade failed: {e}");
            }
        }
    });

    res
}

/// Extract a query parameter from a URI query like `v=130`.
fn query_param<'a>(query: Option<&'a str>, name: &str) -> Option<&'a str> {
    let query = query?;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=')?;
        if k == name {
            return Some(v);
        }
    }
    None
}

fn plain_response(status: StatusCode, text: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from_static(text.as_bytes())))
        .expect("static response is valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_query_param() {
        assert_eq!(query_param(Some("v=130"), "v"), Some("130"));
        assert_eq!(query_param(None, "v"), None);
    }

    #[test]
    fn extracts_register_auth_id() {
        assert_eq!(register_auth_id("/register/abc123"), Some("abc123"));
        assert_eq!(register_auth_id("/register/abc/def"), None);
        assert_eq!(register_auth_id("/register/"), None);
        assert_eq!(register_auth_id("/register"), None);
        assert_eq!(register_auth_id("/key"), None);
    }
}
