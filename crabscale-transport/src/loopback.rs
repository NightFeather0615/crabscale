//! In-process loopback harness for TS2021 handshake tests.
//!
//! This module provides a test-only helper that runs a full Noise IK
//! handshake between a client and server over an in-memory duplex stream.

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
use x25519_dalek::StaticSecret;

use crate::error::TransportError;
use crate::messages::{INIT_MESSAGE_LEN, RESPONSE_MESSAGE_LEN, parse_init_message};
use crate::noise::{NoiseInitiator, NoiseResponder};
use crate::stream::NoiseStream;

/// Run a complete TS2021 handshake over an in-memory duplex stream.
///
/// Returns the client-side and server-side Noise-framed streams.
pub async fn loopback_handshake(
    server: &NoiseResponder,
    client_static: StaticSecret,
    version: u16,
) -> Result<(NoiseStream<DuplexStream>, NoiseStream<DuplexStream>), TransportError> {
    let (client_side, server_side) = duplex(64 * 1024);
    let prologue = format!("Tailscale Control Protocol v{version}");
    let prologue2 = prologue.clone();

    let (client_stream, server_stream) = tokio::try_join!(
        async move {
            let (initiator, init_bytes) = NoiseInitiator::initialize(
                client_static,
                server.public_key(),
                prologue.as_bytes(),
                version,
            );
            let mut conn = client_side;
            conn.write_all(&init_bytes).await.map_err(io_err)?;
            let mut response = [0u8; RESPONSE_MESSAGE_LEN];
            conn.read_exact(&mut response).await.map_err(io_err)?;
            let session = initiator.finish(&response)?;
            Ok::<_, TransportError>(NoiseStream::new(
                conn,
                session.responder_to_initiator,
                session.initiator_to_responder,
            ))
        },
        async move {
            let mut conn = server_side;
            let mut init = [0u8; INIT_MESSAGE_LEN];
            conn.read_exact(&mut init).await.map_err(io_err)?;
            let parsed = parse_init_message(&init)?;
            let output = server.respond(&parsed, prologue2.as_bytes())?;
            conn.write_all(&output.response).await.map_err(io_err)?;
            Ok::<_, TransportError>(NoiseStream::new(
                conn,
                output.session.initiator_to_responder,
                output.session.responder_to_initiator,
            ))
        }
    )?;

    Ok((client_stream, server_stream))
}

fn io_err(_e: std::io::Error) -> TransportError {
    TransportError::HandshakeFailed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_round_trip() {
        let server = NoiseResponder::random();
        let (mut client, mut server_stream) =
            loopback_handshake(&server, StaticSecret::random(), 113)
                .await
                .unwrap();

        let client_task = async {
            client.write_all(b"ping").await.unwrap();
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).await.unwrap();
            buf
        };
        let server_task = async {
            let mut buf = [0u8; 4];
            server_stream.read_exact(&mut buf).await.unwrap();
            server_stream.write_all(b"pong").await.unwrap();
            buf
        };

        let (client_buf, server_buf) = tokio::join!(client_task, server_task);
        assert_eq!(client_buf, *b"pong");
        assert_eq!(server_buf, *b"ping");
    }

    #[tokio::test]
    async fn rejects_unsupported_version() {
        let server = NoiseResponder::random();
        let result = loopback_handshake(&server, StaticSecret::random(), 112).await;
        assert!(matches!(
            result,
            Err(TransportError::UnsupportedCapabilityVersion(112))
        ));
    }
}
