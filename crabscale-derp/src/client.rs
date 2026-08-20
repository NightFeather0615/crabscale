//! Minimal DERP client used by loopback tests and tooling.
//!
//! The client performs the `ServerKey`/`ClientInfo`/`ServerInfo` handshake
//! over an in-memory or real stream and then offers `send_packet`/`recv_packet`
//! helpers that hide control frames (keepalive, ping/pong, peer presence).

use std::io;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::codec::{Frame, read_frame, write_frame};
use crate::frame::{FrameType, PROTOCOL_VERSION};
use crate::frames::{
    ClientInfoBody, NotePreferredBody, PeerGoneBody, PeerGoneReason, PeerPresentBody, PongBody,
    RecvPacketBody, SendPacketBody, ServerInfoBody, ServerKeyBody,
};
use crate::handshake::{ClientInfoPayload, ServerInfoPayload, make_client_info, open_server_info};
use crate::keys::{NodeKey, SecretKey};

/// A DERP client speaking the raw wire format over an arbitrary stream.
pub struct Client<R, W> {
    reader: R,
    writer: W,
    node_key: NodeKey,
    server_public: NodeKey,
}

/// Connect over read/write halves of a stream that the caller already split.
///
/// Returns a client pinned to the concrete half types from the caller's
/// split stream.
pub async fn connect_halves<R2, W2>(
    read_half: R2,
    write_half: W2,
    client_secret: SecretKey,
) -> Client<R2, W2>
where
    R2: AsyncRead + Unpin + Send + 'static,
    W2: AsyncWrite + Unpin + Send + 'static,
{
    let mut reader = read_half;
    let mut writer = write_half;

    // Step 1: server -> client `ServerKey`.
    let Ok(Some(server_key_frame)) = read_frame(&mut reader).await else {
        panic!("stream ended before ServerKey");
    };
    debug_assert_eq!(server_key_frame.ty, FrameType::ServerKey);
    let server_key_body =
        ServerKeyBody::decode(&server_key_frame.payload).expect("server sent an invalid ServerKey");
    let server_public = server_key_body.key;

    // Step 2: client -> server `ClientInfo`.
    let payload = ClientInfoPayload {
        can_ack_pings: true,
        version: PROTOCOL_VERSION,
        ..Default::default()
    };
    let (node_key, nonce, ciphertext) =
        make_client_info(&client_secret, &server_public, &payload).unwrap();
    let body = ClientInfoBody {
        key: node_key,
        nonce,
    }
    .encode_prefix()
    .to_vec();
    let mut full = body;
    full.extend_from_slice(&ciphertext);
    write_frame(
        &mut writer,
        Frame::new(FrameType::ClientInfo, Bytes::from(full)),
    )
    .await
    .expect("failed to send ClientInfo");

    // Step 3: server -> client `ServerInfo`.
    let Ok(Some(info_frame)) = read_frame(&mut reader).await else {
        panic!("stream ended before ServerInfo");
    };
    debug_assert_eq!(info_frame.ty, FrameType::ServerInfo);
    let prefix = ServerInfoBody::decode_prefix(&info_frame.payload).unwrap();
    let encrypted = &info_frame.payload[ServerInfoBody::PREFIX_LEN..];
    let info: ServerInfoPayload =
        open_server_info(&server_public, &client_secret, &prefix.nonce, encrypted)
            .expect("failed to open ServerInfo");
    debug_assert!(info.version >= PROTOCOL_VERSION);

    Client {
        reader,
        writer,
        node_key,
        server_public,
    }
}

impl<R, W> Client<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// The node key this client registered under.
    pub fn node_key(&self) -> NodeKey {
        self.node_key
    }

    /// The server's DERP public key.
    pub fn server_public(&self) -> NodeKey {
        self.server_public
    }

    /// Send a packet to another node through the relay.
    pub async fn send_packet(&mut self, dest: NodeKey, packet: &[u8]) -> io::Result<()> {
        let mut body = Vec::with_capacity(SendPacketBody::PREFIX_LEN + packet.len());
        body.extend_from_slice(&SendPacketBody { dest }.encode_prefix());
        body.extend_from_slice(packet);
        write_frame(
            &mut self.writer,
            Frame::new(FrameType::SendPacket, Bytes::from(body)),
        )
        .await
    }

    /// Write a raw frame to the server (used by protocol tests).
    pub async fn send_frame(&mut self, frame: Frame) -> io::Result<()> {
        write_frame(&mut self.writer, frame).await
    }

    /// Read the next frame from the server.
    pub async fn next(&mut self) -> Option<io::Result<Frame>> {
        read_frame(&mut self.reader).await.transpose()
    }

    /// Receive the next relayed packet, transparently handling control frames.
    ///
    /// The returned `Bytes` borrows the body of the packet; it is detached
    /// from the transport so callers can keep it after the next read.
    pub async fn recv_packet(&mut self) -> io::Result<(NodeKey, Bytes)> {
        loop {
            let Some(frame) = self.next().await else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "DERP stream ended",
                ));
            };
            let frame = frame?;
            match frame.ty {
                FrameType::RecvPacket => {
                    let body = RecvPacketBody::decode_prefix(&frame.payload).map_err(io_err)?;
                    let packet = frame.payload.slice(RecvPacketBody::PREFIX_LEN..);
                    return Ok((body.src, packet));
                }
                FrameType::Ping => {
                    let mut payload = [0u8; 8];
                    payload.copy_from_slice(&frame.payload[..frame.payload.len().min(8)]);
                    let pong = PongBody { payload };
                    self.send_frame(Frame::new(
                        FrameType::Pong,
                        Bytes::from(pong.encode().to_vec()),
                    ))
                    .await?;
                }
                // Everything else is informational for this client.
                FrameType::KeepAlive
                | FrameType::PeerGone
                | FrameType::PeerPresent
                | FrameType::NotePreferred
                | FrameType::Health
                | FrameType::ServerKey
                | FrameType::ServerInfo
                | FrameType::Restarting => {}
                other => {
                    return Err(io::Error::other(format!(
                        "unexpected frame type from server: {other:?}"
                    )));
                }
            }
        }
    }

    /// Wait until a `PeerGone` frame arrives and return its details.
    pub async fn recv_peer_gone(&mut self) -> io::Result<(NodeKey, PeerGoneReason)> {
        loop {
            let Some(frame) = self.next().await else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "DERP stream ended",
                ));
            };
            let frame = frame?;
            match frame.ty {
                FrameType::PeerGone => {
                    let body = PeerGoneBody::decode(&frame.payload).map_err(io_err)?;
                    return Ok((body.key, body.reason));
                }
                _ => continue,
            }
        }
    }

    /// Wait until a `PeerPresent` frame arrives and return the peer key.
    pub async fn recv_peer_present(&mut self) -> io::Result<NodeKey> {
        loop {
            let Some(frame) = self.next().await else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "DERP stream ended",
                ));
            };
            let frame = frame?;
            match frame.ty {
                FrameType::PeerPresent => {
                    let body = PeerPresentBody::decode(&frame.payload).map_err(io_err)?;
                    return Ok(body.key);
                }
                _ => continue,
            }
        }
    }

    /// Wait until a `NotePreferred` frame arrives.
    #[allow(dead_code)]
    pub async fn recv_note_preferred(&mut self) -> io::Result<NotePreferredBody> {
        loop {
            let Some(frame) = self.next().await else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "DERP stream ended",
                ));
            };
            let frame = frame?;
            match frame.ty {
                FrameType::NotePreferred => {
                    return NotePreferredBody::decode(&frame.payload).map_err(io_err);
                }
                _ => continue,
            }
        }
    }
}

fn io_err(e: crate::frame::FrameError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}
