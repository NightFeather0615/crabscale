//! HTTP/2 server glue layered on a Noise stream.
//!
//! After the Noise handshake and the optional early payload, the control
//! protocol runs a single HTTP/2 connection over the Noise-framed byte
//! stream. This module provides the server side of that glue: it accepts
//! HTTP/2 requests, attaches the Noise machine public key to each request,
//! and hands them to a caller-supplied handler.

use std::future::Future;

use bytes::Bytes;
use crabscale_proto::{ChallengeKey, MachineKey};
use h2::RecvStream;
use h2::server::{self, SendResponse};
use http::Request;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::early::encode_early_payload;
use crate::error::TransportError;
use crate::stream::NoiseStream;

/// Maximum size of an inner request body, in bytes (1 MiB).
pub const MAX_INNER_BODY_LEN: usize = 1024 * 1024;

/// Serve HTTP/2 requests on a Noise stream.
///
/// Before the HTTP/2 preface, the server writes the early payload carrying
/// `challenge` (Spec-Transport section 5). Each accepted request is then passed to
/// `handler` together with the Noise machine public key recovered from the
/// handshake. The handler is spawned as a detached task so concurrent streams
/// are served independently; in-flight handlers are dropped when the
/// connection closes.
pub async fn serve_http2<T, H, Fut>(
    mut stream: NoiseStream<T>,
    machine_key: MachineKey,
    challenge: ChallengeKey,
    handler: H,
) -> Result<(), TransportError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: Fn(Request<RecvStream>, SendResponse<Bytes>, MachineKey) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let early = encode_early_payload(challenge)?;
    stream
        .write_all(&early)
        .await
        .map_err(|e| TransportError::Http2(e.to_string()))?;

    let mut connection = server::handshake(stream)
        .await
        .map_err(|e| TransportError::Http2(e.to_string()))?;

    while let Some(result) = connection.accept().await {
        let (request, respond) = result.map_err(|e| TransportError::Http2(e.to_string()))?;
        let fut = handler(request, respond, machine_key);
        tokio::spawn(fut);
    }

    Ok(())
}

/// Read a request body up to `limit` bytes.
///
/// Returns [`TransportError::BodyTooLarge`] if the body exceeds the limit.
/// Flow-control capacity is released as chunks are consumed.
pub async fn read_body_limited(
    body: &mut RecvStream,
    limit: usize,
) -> Result<Vec<u8>, TransportError> {
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|e| TransportError::Http2(e.to_string()))?;
        if out.len() + chunk.len() > limit {
            return Err(TransportError::BodyTooLarge);
        }
        out.extend_from_slice(&chunk);
        let _ = body.flow_control().release_capacity(chunk.len());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use h2::client;
    use tokio::io::{DuplexStream, duplex};
    use x25519_dalek::StaticSecret;

    use crate::early::{EARLY_PAYLOAD_MAGIC, decode_early_payload, random_challenge};
    use crate::loopback::loopback_handshake;
    use crate::noise::NoiseResponder;

    #[tokio::test]
    async fn serves_http2_over_noise_with_machine_key() {
        let server = NoiseResponder::random();
        let machine_key = MachineKey::from_bytes(server.public_key().to_bytes());
        let challenge = random_challenge();
        let (mut client_stream, server_stream) =
            loopback_handshake(&server, StaticSecret::random(), 113)
                .await
                .unwrap();

        let server_task = tokio::spawn(async move {
            serve_http2(
                server_stream,
                machine_key,
                challenge,
                |request, mut respond, key| async move {
                    let (_, mut body) = request.into_parts();
                    let _ = read_body_limited(&mut body, MAX_INNER_BODY_LEN).await;
                    let response = http::Response::new(());
                    let mut send = respond.send_response(response, false).unwrap();
                    send.send_data(Bytes::from(key.to_string()), true).unwrap();
                },
            )
            .await
        });

        // The server writes the early payload before the HTTP/2 preface; read
        // and verify it on the client side.
        let received = read_early_payload(&mut client_stream).await;
        assert_eq!(received, challenge);

        let (mut client, conn) = client::handshake(client_stream).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/machine/whoami")
            .body(())
            .unwrap();
        let (response, _send_stream) = client.send_request(request, true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), 200);

        let mut body = response.into_body();
        let mut buf = Vec::new();
        while let Some(chunk) = body.data().await {
            buf.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(buf, machine_key.to_string().as_bytes());

        // The server task runs until the connection closes; the response has
        // already been verified, so we let the runtime drop it.
        drop(server_task);
    }

    async fn read_early_payload(stream: &mut NoiseStream<DuplexStream>) -> ChallengeKey {
        let mut magic = [0u8; EARLY_PAYLOAD_MAGIC.len()];
        stream.read_exact(&mut magic).await.unwrap();
        assert_eq!(&magic, &EARLY_PAYLOAD_MAGIC);
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.unwrap();
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await.unwrap();
        let mut buf = Vec::with_capacity(magic.len() + len_buf.len() + body.len());
        buf.extend_from_slice(&magic);
        buf.extend_from_slice(&len_buf);
        buf.extend_from_slice(&body);
        decode_early_payload(&buf).unwrap()
    }

    #[tokio::test]
    async fn read_body_limited_rejects_oversized_body() {
        let (client, server) = duplex(64 * 1024);
        let client_task = tokio::spawn(async move {
            let (mut send, conn) = client::handshake(client).await.unwrap();
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let request = http::Request::builder()
                .method("POST")
                .uri("/machine/map")
                .body(())
                .unwrap();
            let (response, mut send_stream) = send.send_request(request, false).unwrap();
            send_stream
                .send_data(Bytes::from_static(b"0123456789A"), true)
                .unwrap();
            let _ = response.await;
        });

        let server_task = tokio::spawn(async move {
            let mut connection = server::handshake(server).await.unwrap();
            let (request, respond) = connection.accept().await.unwrap().unwrap();
            let (_, mut body) = request.into_parts();
            let result = read_body_limited(&mut body, 10).await;
            assert_eq!(result, Err(TransportError::BodyTooLarge));
            let _ = respond;
        });

        let _ = tokio::join!(client_task, server_task);
    }
}
