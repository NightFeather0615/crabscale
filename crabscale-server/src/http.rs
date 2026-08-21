//! Outer HTTP/1.1 control server built on tokio's `net` feature and hyper.
//!
//! This module serves the outer endpoints required by the control protocol:
//!
//! - `GET /key?v=<capability_version>` returns the server machine key.
//! - `POST /ts2021` upgrades the connection to the TS2021 Noise transport and
//!   then hands the resulting stream to the inner HTTP/2 control router.
//!
//! The server uses `tokio::net` (and therefore `mio`) plus `hyper` for HTTP/1.1
//! parsing instead of a hand-rolled parser. See the wiki `Architecture` page
//! for the decision and the limitations that no longer apply.
//!
//! ## M4-03 (deployment, #26)
//!
//! - TLS is terminated here (rustls) when configured, so `/key` stays
//!   TLS-protected and the `/ts2021` and `/derp` HTTP upgrades pass through the
//!   TLS layer unchanged.
//! - A separate plain-HTTP listener can redirect browsers to HTTPS while the
//!   upgrade endpoints remain on the TLS listener.
//! - Trusted proxy CIDRs are honored when resolving the client IP for the
//!   `/ts2021` rate limiter (see [`crate::proxy`]).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use crabscale_transport::{
    HANDSHAKE_HEADER, HANDSHAKE_TIMEOUT, NoiseStream, UPGRADE_HEADER_VALUE, parse_init_message,
    validate_native_upgrade,
};
use http::{HeaderValue, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use crate::key::ServerKey;
use crate::proxy::TrustedProxies;
use crate::router::{ControlRouter, VERIFY_MAX_BODY_LEN, serve_control_as};
use crate::tls::TlsAcceptor;

/// Minimal object-safe supertrait so TLS and plain sockets share one boxed type.
trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}

/// A handle to a running outer control server, used to request shutdown.
#[derive(Clone)]
pub struct ServerHandle {
    shutdown_tx: watch::Sender<bool>,
}

impl ServerHandle {
    /// Ask the accept loop to stop accepting new connections.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// Extra deployment options for the outer HTTP server (M4-03, #26).
///
/// The plain [`serve_on_addr`] / [`serve`] entry points use the `Default`
/// (plain HTTP, no trusted proxies) so existing tests and the harness keep
/// working unchanged.
#[derive(Clone, Debug, Default)]
pub struct ServerOptions {
    /// Trusted proxy networks whose `X-Forwarded-For` is honored. `None`
    /// means the peer address is always authoritative.
    pub trusted_proxies: Option<Arc<TrustedProxies>>,
    /// Optional TLS acceptor. When present every accepted connection is
    /// upgraded to TLS before hyper parses the request.
    pub tls: Option<Arc<TlsAcceptor>>,
}

/// Bind `addr` with default options and serve until shutdown. Returns the
/// actual bound address (useful when `addr` uses port 0) and a handle.
pub async fn serve_on_addr(
    addr: SocketAddr,
    router: ControlRouter,
    server_key: ServerKey,
) -> io::Result<(SocketAddr, ServerHandle)> {
    serve_on_addr_with_options(addr, router, server_key, ServerOptions::default()).await
}

/// Bind `addr` with explicit deployment [`ServerOptions`] (TLS + proxies).
pub async fn serve_on_addr_with_options(
    addr: SocketAddr,
    router: ControlRouter,
    server_key: ServerKey,
    options: ServerOptions,
) -> io::Result<(SocketAddr, ServerHandle)> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = ServerHandle { shutdown_tx };
    tokio::spawn(async move {
        let _ = serve_with_options(listener, router, server_key, shutdown_rx, options).await;
    });
    Ok((local, handle))
}

/// Accept connections with default options and serve until shutdown.
pub async fn serve(
    listener: TcpListener,
    router: ControlRouter,
    server_key: ServerKey,
    shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    serve_with_options(
        listener,
        router,
        server_key,
        shutdown,
        ServerOptions::default(),
    )
    .await
}

/// Accept connections with explicit deployment [`ServerOptions`] and serve
/// until shutdown is requested.
pub async fn serve_with_options(
    listener: TcpListener,
    router: ControlRouter,
    server_key: ServerKey,
    mut shutdown: watch::Receiver<bool>,
    options: ServerOptions,
) -> io::Result<()> {
    let options = Arc::new(options);
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                return Ok(());
            }
            res = listener.accept() => {
                let (stream, peer_addr) = res?;
                let router = router.clone();
                let server_key = server_key.clone();
                let options = options.clone();
                tokio::spawn(async move {
                    let _ =
                        handle_connection(stream, peer_addr, router, server_key, options).await;
                });
            }
        }
    }
}

/// Build a `301 Moved Permanently` response pointing at the HTTPS URL for the
/// same authority and path.
fn redirect_response(req: Request<()>, fallback_host: String) -> Response<Full<Bytes>> {
    let host = req
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or(fallback_host);
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let location = format!("https://{host}{path}");

    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = StatusCode::MOVED_PERMANENTLY;
    response.headers_mut().insert(
        http::header::LOCATION,
        HeaderValue::from_str(&location).unwrap_or_else(|_| HeaderValue::from_static("https://")),
    );
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("max-age=3600"),
    );
    response
        .headers_mut()
        .insert(http::header::CONNECTION, HeaderValue::from_static("close"));
    response
}

/// Bind a plain-HTTP listener that redirects every request to HTTPS (M4-03).
///
/// The `fallback_host` (e.g. `control.example.com`) is used when the request
/// carries no `Host` header. Upgrade requests are intentionally *not*
/// redirected here: when the server terminates TLS itself the whole redirect
/// listener is plain HTTP, so an upgrade cannot be tunneled; the operator
/// configures the proxy to forward upgrades to the TLS listener instead.
pub async fn serve_redirect_on_addr(
    addr: SocketAddr,
    fallback_host: String,
) -> io::Result<(SocketAddr, ServerHandle)> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = ServerHandle { shutdown_tx };
    tokio::spawn(async move {
        let _ = serve_redirect(listener, fallback_host, shutdown_rx).await;
    });
    Ok((local, handle))
}

async fn serve_redirect(
    listener: TcpListener,
    fallback_host: String,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            res = listener.accept() => {
                let (stream, _peer) = res?;
                let fallback_host = fallback_host.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        let fallback_host = fallback_host.clone();
                        async move {
                            Ok::<_, hyper::Error>(redirect_response(req.map(|_| ()), fallback_host))
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    router: ControlRouter,
    server_key: ServerKey,
    options: Arc<ServerOptions>,
) -> io::Result<()> {
    // TLS and plain sockets have different concrete types; box them behind
    // the same trait object so hyper sees one I/O abstraction.
    let io: TokioIo<Box<dyn IoStream>> = if let Some(acceptor) = &options.tls {
        let tls = acceptor.accept(stream).await?;
        TokioIo::new(Box::new(tls))
    } else {
        TokioIo::new(Box::new(stream))
    };

    let service = service_fn(move |req| {
        handle_request(
            req,
            peer_addr,
            router.clone(),
            server_key.clone(),
            options.clone(),
        )
    });
    http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades()
        .await
        .map_err(|e| io::Error::other(e.to_string()))
}

async fn handle_request(
    req: Request<Incoming>,
    peer_addr: SocketAddr,
    router: ControlRouter,
    server_key: ServerKey,
    options: Arc<ServerOptions>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // Resolve the real client IP once per request: when the peer is a trusted
    // proxy, `X-Forwarded-For`/`X-Real-IP` are honored (M4-03).
    let client_ip = options
        .trusted_proxies
        .as_deref()
        .map(|proxies| proxies.resolve_client_ip(peer_addr.ip(), req.headers()))
        .unwrap_or(peer_addr.ip());

    if method == http::Method::GET && path == "/key" {
        let capver = query_param(req.uri().query(), "v");
        let response = router.handle_key(capver);
        return Ok(response.map(Full::new));
    }

    // `GET /health`, `GET /version`, and `GET /metrics` are the M4-04
    // operational endpoints. Any non-GET method is rejected with 405.
    if path == "/health" || path == "/version" || path == "/metrics" {
        if method != http::Method::GET {
            return Ok(plain_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            ));
        }
        let response = match path.as_str() {
            "/health" => router.handle_health(),
            "/version" => router.handle_version(),
            "/metrics" => router.handle_metrics(),
            _ => unreachable!("guarded by the path check above"),
        };
        return Ok(response.map(Full::new));
    }

    // `POST /ts2021` is rate-limited per client IP (M4-02). The limiter is
    // consulted before the upgrade request is parsed so a limited peer cannot
    // even feed the handshake parser. M4-03 uses the proxy-resolved client IP.
    if method == http::Method::POST && path == "/ts2021" {
        if let Some(retry_after) = router.check_ts2021_rate(client_ip) {
            return Ok(rate_limited_response(retry_after));
        }
        return Ok(handle_ts2021(req, router, server_key).await);
    }

    // `POST /verify` is the embedded relay's admission check. The body is
    // capped at 4 KiB (Spec-Control-API `POST /verify`); a larger request is
    // rejected before the JSON is parsed, and any non-POST method is rejected
    // with `405`.
    if path == "/verify" {
        if method != http::Method::POST {
            return Ok(plain_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            ));
        }
        let limited = Limited::new(req.into_body(), VERIFY_MAX_BODY_LEN);
        let collected = match limited.collect().await {
            Ok(collected) => collected,
            Err(e)
                if e.downcast_ref::<http_body_util::LengthLimitError>()
                    .is_some() =>
            {
                return Ok(plain_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "body too large",
                ));
            }
            Err(_) => {
                return Ok(plain_response(
                    StatusCode::BAD_REQUEST,
                    "invalid request body",
                ));
            }
        };
        let response = router.handle_verify(&collected.to_bytes());
        return Ok(response.map(Full::new));
    }

    // `GET /bootstrap-dns` serves the relay's bootstrap DNS snapshot. When no
    // snapshot is configured the router returns 404, and any non-GET method
    // is rejected with 405 (Spec-Control-API, Bootstrap DNS).
    if path == "/bootstrap-dns" {
        if method != http::Method::GET {
            return Ok(plain_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            ));
        }
        let q = query_param(req.uri().query(), "q");
        let response = router.handle_bootstrap_dns(q);
        return Ok(response.map(Full::new));
    }

    // `GET /register/{id}` serves the interactive-registration approval page
    // (Spec-Registration section 4). Unknown or expired ids return 404. When
    // OIDC is configured it redirects to the provider instead.
    if let Some(auth_id) = register_auth_id(&path) {
        if method == http::Method::GET {
            let response = router.handle_register_page(auth_id);
            return Ok(response.map(Full::new));
        }
    }

    // `GET /oidc/callback` completes the OIDC authorization-code flow. It is
    // always an outer (browser) endpoint: no Noise handshake is involved.
    if method == http::Method::GET && path == "/oidc/callback" {
        let response = router
            .handle_oidc_callback(req.uri().query().unwrap_or(""))
            .await;
        return Ok(response.map(Full::new));
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
        // Bound ONLY the handshake (the 101 upgrade wait plus the Noise
        // response write) by the documented TS2021 handshake timeout. The
        // inner control session (`serve_control_as`) runs after the timeout
        // future completes, so streaming map sessions are never capped by
        // the handshake timeout (Spec-Transport section 3).
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, ts2021_handshake(req, output)).await {
            Ok(Ok((noise_stream, peer_machine_key))) => {
                let _ = serve_control_as(noise_stream, router, peer_machine_key).await;
            }
            Ok(Err(e)) => {
                eprintln!("ts2021 handshake failed: {e}");
            }
            Err(_) => {
                eprintln!("ts2021 handshake timed out");
            }
        }
    });

    res
}

/// Perform the TS2021 handshake: wait for the HTTP upgrade and write the
/// 51-byte Noise response.
///
/// The machine key attached to inner requests is the client's Noise machine
/// key recovered from the handshake (`peer_static_public`), so per-client
/// authorization and registration rate limiting key on the authenticated
/// identity rather than the server's own key.
async fn ts2021_handshake(
    req: Request<Incoming>,
    output: crabscale_transport::ResponderOutput,
) -> std::io::Result<(
    NoiseStream<TokioIo<hyper::upgrade::Upgraded>>,
    crabscale_proto::MachineKey,
)> {
    let upgraded = hyper::upgrade::on(req)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut upgraded = TokioIo::new(upgraded);
    upgraded.write_all(&output.response).await?;
    upgraded.flush().await?;
    let peer_machine_key =
        crabscale_proto::MachineKey::from_bytes(output.peer_static_public.to_bytes());
    let noise_stream = NoiseStream::new(
        upgraded,
        output.session.initiator_to_responder,
        output.session.responder_to_initiator,
    );
    Ok((noise_stream, peer_machine_key))
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

/// A `429 Too Many Requests` response with a delta-seconds `Retry-After`
/// header, used by the `/ts2021` rate limiter (M4-02).
fn rate_limited_response(retry_after: u64) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("Content-Type", "text/plain")
        .header("Retry-After", retry_after.to_string())
        .body(Full::new(Bytes::from_static(b"rate limit exceeded")))
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

    #[tokio::test]
    async fn rate_limited_response_sets_status_and_retry_after() {
        use http_body_util::BodyExt as _;
        let response = rate_limited_response(7);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get("retry-after")
                .unwrap()
                .to_str()
                .unwrap(),
            "7"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"rate limit exceeded");
    }

    #[test]
    fn redirect_response_points_at_https() {
        let req = Request::builder()
            .method("GET")
            .uri("/key?v=130")
            .header("Host", "control.example.com")
            .body(())
            .unwrap();
        let res = redirect_response(req, "fallback.example".to_string());
        assert_eq!(res.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            res.headers().get("location").unwrap().to_str().unwrap(),
            "https://control.example.com/key?v=130"
        );
    }
}
