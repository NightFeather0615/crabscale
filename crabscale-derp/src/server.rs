//! Relay core: client registry, packet routing, keepalive, and peer
//! presence notifications (Spec-DERP-STUN §4).
//!
//! A [`Relay`] owns the server secret key and the registry of connected
//! clients. Each accepted connection runs one task that performs the login
//! handshake and then enters the steady-state read loop, while a per-connect
//! writer task drains an outbound channel. Duplicate connections for the same
//! node key are allowed; the registry keeps a set of ids per key.
//!
//! An optional admission-control callback may be attached with
//! [`Relay::with_verify`] so the relay only admits known, authorized node
//! keys (Spec-DERP-STUN §8 / Spec-Control-API `POST /verify`). Multi-node mesh
//! remains out of scope for this milestone.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, mpsc};

use crate::codec::{Frame, read_frame, write_frame};
use crate::frame::{FrameType, MAX_PACKET_PAYLOAD_LEN, PROTOCOL_VERSION};
use crate::frames::{
    ClientInfoBody, PeerGoneBody, PeerGoneReason, PeerPresentBody, PeerPresentFlags,
    RecvPacketBody, SendPacketBody, ServerInfoBody, ServerKeyBody,
};
use crate::handshake::{ServerInfoPayload, make_server_info, open_client_info};
use crate::keys::{NodeKey, SecretKey};

/// Default keepalive interval (Spec-DERP-STUN §4: roughly every 60 seconds).
pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(60);

/// Default outbound channel capacity per connection.
pub const OUTBOUND_CAPACITY: usize = 256;

/// Admission control callback used by the relay during the login handshake.
///
/// The callback receives the node key declared in `ClientInfo` (the clear
/// prefix of the message) and returns `true` when the node is allowed to use
/// the relay. When the callback denies a key, the connection is closed after
/// `ServerKey` without sending `ServerInfo`.
pub type VerifyFn = Arc<dyn Fn(NodeKey) -> bool + Send + Sync + 'static>;

/// A unique id for one accepted relay connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClientId(u64);

#[derive(Default)]
struct Registry {
    /// node key -> set of connection ids; duplicate keys are allowed.
    by_key: HashMap<NodeKey, HashSet<ClientId>>,
    /// connection id -> registered node key and outbound channel.
    conns: HashMap<ClientId, ConnEntry>,
}

struct ConnEntry {
    node: NodeKey,
    out: mpsc::Sender<Frame>,
}

/// A single-node DERP relay.
pub struct Relay {
    server_secret: SecretKey,
    server_public: NodeKey,
    registry: Mutex<Registry>,
    next_id: AtomicU64,
    /// Per-connection keepalive interval; `None` disables periodic keepalives.
    keepalive: Option<Duration>,
    /// Optional admission check; `None` admits every decrypted client.
    verify: Option<VerifyFn>,
}

impl Relay {
    /// Create a relay with the given long-term secret key.
    pub fn new(server_secret: SecretKey) -> Self {
        let server_public = server_secret.public();
        Self {
            server_secret,
            server_public,
            registry: Mutex::new(Registry::default()),
            next_id: AtomicU64::new(1),
            keepalive: None,
            verify: None,
        }
    }

    /// Create a relay with a freshly generated secret key.
    pub fn random() -> Self {
        Self::new(SecretKey::random())
    }

    /// Enable per-connection keepalive broadcasts at `interval`.
    pub fn with_keepalive_interval(mut self, interval: Duration) -> Self {
        self.keepalive = Some(interval);
        self
    }

    /// Attach an admission-control callback used during the login handshake.
    ///
    /// When set, a client whose node key the callback rejects is disconnected
    /// after `ServerKey` instead of receiving `ServerInfo`.
    pub fn with_verify(mut self, verify: VerifyFn) -> Self {
        self.verify = Some(verify);
        self
    }

    /// The relay's DERP public key, advertised in the `ServerKey` frame.
    pub fn server_public(&self) -> NodeKey {
        self.server_public
    }

    /// Run one accepted client connection to completion.
    ///
    /// The stream performs the `ServerKey`/`ClientInfo`/`ServerInfo`
    /// handshake, registers the client, and then routes packets until the
    /// connection closes.
    pub async fn run_conn<S>(self: &Arc<Self>, stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut reader, mut writer) = tokio::io::split(stream);

        // Step 1: server -> client `ServerKey` (magic + public key).
        let server_key = ServerKeyBody {
            key: self.server_public,
        }
        .encode()
        .to_vec();
        if write_frame(
            &mut writer,
            Frame::new(FrameType::ServerKey, Bytes::from(server_key)),
        )
        .await
        .is_err()
        {
            return;
        }

        // Step 2: client -> server `ClientInfo` (key + nonce + sealed JSON).
        let client = loop {
            let Ok(Some(frame)) = read_frame(&mut reader).await else {
                return;
            };
            if frame.ty == FrameType::ClientInfo {
                break frame.payload;
            }
            // Ignore anything else until ClientInfo arrives.
        };

        let node_key = match self.accept_client_info(&client).await {
            Some(key) => key,
            None => return,
        };

        // Step 3: server -> client `ServerInfo` (sealed JSON).
        let info = ServerInfoPayload {
            version: PROTOCOL_VERSION,
            ..Default::default()
        };
        let Ok((nonce, ciphertext)) = make_server_info(&self.server_secret, &node_key, &info)
        else {
            return;
        };
        let mut info_body = ServerInfoBody { nonce }.encode_prefix().to_vec();
        info_body.extend_from_slice(&ciphertext);
        if write_frame(
            &mut writer,
            Frame::new(FrameType::ServerInfo, Bytes::from(info_body)),
        )
        .await
        .is_err()
        {
            return;
        }

        // Register the client and wire the outbound channel to a writer task.
        let (out_tx, out_rx) = mpsc::channel(OUTBOUND_CAPACITY);
        let id = self.register(node_key, out_tx.clone()).await;
        let writer_task = tokio::spawn(async move {
            let mut writer = writer;
            let mut out_rx = out_rx;
            while let Some(frame) = out_rx.recv().await {
                if write_frame(&mut writer, frame).await.is_err() {
                    break;
                }
            }
        });

        // Optional per-connection keepalive broadcaster.
        let keepalive_task = match self.keepalive {
            Some(interval) => {
                let relay = Arc::clone(self);
                Some(tokio::spawn(async move {
                    let mut timer = tokio::time::interval(interval);
                    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        timer.tick().await;
                        relay.send_keepalive(id).await;
                    }
                }))
            }
            None => None,
        };

        // Steady state: route packets until the connection drops.
        loop {
            let next = read_frame(&mut reader).await;
            match next {
                Ok(Some(frame)) => {
                    if !self.handle_data_frame(id, node_key, frame).await {
                        break;
                    }
                }
                _ => break,
            }
        }

        self.deregister(id).await;
        drop(out_tx);
        if let Some(task) = keepalive_task {
            task.abort();
        }
        let _ = writer_task.await;
    }

    /// Handle one frame in the steady-state read loop.
    ///
    /// Returns `false` when the connection should be torn down.
    async fn handle_data_frame(&self, id: ClientId, _node_key: NodeKey, frame: Frame) -> bool {
        match frame.ty {
            FrameType::SendPacket => {
                let Ok(body) = SendPacketBody::decode_prefix(&frame.payload) else {
                    return true;
                };
                let packet = &frame.payload[SendPacketBody::PREFIX_LEN..];
                self.route_send_packet(id, body.dest, packet).await;
                true
            }
            // Client-side keepalive acknowledgement; nothing to do.
            FrameType::Pong => true,
            // Mesh frames and privileged operations are unsupported in this
            // milestone; drop them without disrupting the connection.
            FrameType::ForwardPacket
            | FrameType::WatchConns
            | FrameType::PeerPresent
            | FrameType::PeerGone => true,
            // `Ping` is server -> client only; a client sending one is a
            // protocol violation and tears the connection down.
            FrameType::Ping => false,
            // Anything else from a client is a protocol violation.
            _ => false,
        }
    }

    async fn accept_client_info(self: &Arc<Self>, body: &[u8]) -> Option<NodeKey> {
        let prefix = ClientInfoBody::decode_prefix(body).ok()?;
        let encrypted = &body[ClientInfoBody::PREFIX_LEN..];
        let _payload =
            open_client_info(&prefix.key, &self.server_secret, &prefix.nonce, encrypted).ok()?;
        // Admission control: an attached verify callback may deny a known
        // node key, closing the connection before ServerInfo.
        if let Some(verify) = &self.verify {
            if !verify(prefix.key) {
                return None;
            }
        }
        Some(prefix.key)
    }

    /// Register a new client, announcing it to peers and vice versa.
    async fn register(&self, node: NodeKey, out: mpsc::Sender<Frame>) -> ClientId {
        let mut reg = self.registry.lock().await;
        let id = ClientId(self.next_id.fetch_add(1, Ordering::Relaxed));

        // Announce the newcomer to everyone already connected.
        let present = Frame::new(
            FrameType::PeerPresent,
            Bytes::from(PeerPresentBody::new(node, PeerPresentFlags::Regular as u8).encode()),
        );
        for entry in reg.conns.values() {
            let _ = entry.out.try_send(present.clone());
        }

        // Snap the existing peers to the newcomer so it knows who is present.
        let mut announced = HashSet::new();
        for peer in reg.by_key.keys() {
            if *peer != node && announced.insert(*peer) {
                let frame = Frame::new(
                    FrameType::PeerPresent,
                    Bytes::from(
                        PeerPresentBody::new(*peer, PeerPresentFlags::Regular as u8).encode(),
                    ),
                );
                let _ = out.try_send(frame);
            }
        }

        reg.by_key.entry(node).or_default().insert(id);
        reg.conns.insert(
            id,
            ConnEntry {
                node,
                out: out.clone(),
            },
        );
        id
    }

    /// Remove a client and announce its departure to the remaining peers.
    ///
    /// Because duplicate connections are allowed, `PeerGone(Disconnected)` is
    /// only broadcast when this was the node's last live connection; other
    /// connections for the same node key keep the path alive.
    async fn deregister(&self, id: ClientId) {
        let mut reg = self.registry.lock().await;
        let Some(entry) = reg.conns.remove(&id) else {
            return;
        };
        let node = entry.node;
        let was_last = if let Some(set) = reg.by_key.get_mut(&node) {
            set.remove(&id);
            if set.is_empty() {
                reg.by_key.remove(&node);
                true
            } else {
                false
            }
        } else {
            false
        };

        if was_last {
            let gone = Frame::new(
                FrameType::PeerGone,
                Bytes::from(
                    PeerGoneBody {
                        key: node,
                        reason: PeerGoneReason::Disconnected,
                    }
                    .encode()
                    .to_vec(),
                ),
            );
            for peer in reg.conns.values() {
                let _ = peer.out.try_send(gone.clone());
            }
        }
    }

    /// Route a `SendPacket` to the destination's connection(s).
    ///
    /// An unknown destination answers the sender with `PeerGone` reason
    /// `NotHere` (0x01). Packet payloads larger than 64 KiB are dropped.
    async fn route_send_packet(&self, from: ClientId, dest: NodeKey, packet: &[u8]) {
        if packet.len() > MAX_PACKET_PAYLOAD_LEN {
            crabscale_metrics::registry()
                .derp_packets_dropped_total
                .inc();
            return;
        }
        let reg = self.registry.lock().await;
        let Some(sender) = reg.conns.get(&from) else {
            return;
        };
        let src = sender.node;

        let some_targets = reg.by_key.get(&dest).is_some_and(|set| !set.is_empty());
        if !some_targets {
            crabscale_metrics::registry()
                .derp_packets_dropped_total
                .inc();
            let gone = Frame::new(
                FrameType::PeerGone,
                Bytes::from(
                    PeerGoneBody {
                        key: dest,
                        reason: PeerGoneReason::NotHere,
                    }
                    .encode()
                    .to_vec(),
                ),
            );
            let _ = sender.out.try_send(gone);
            return;
        }
        let targets = reg.by_key.get(&dest).expect("targets checked above");

        let mut recv_body = Vec::with_capacity(RecvPacketBody::PREFIX_LEN + packet.len());
        recv_body.extend_from_slice(&RecvPacketBody { src }.encode_prefix());
        recv_body.extend_from_slice(packet);
        let recv = Frame::new(FrameType::RecvPacket, Bytes::from(recv_body));

        let mut delivered = false;
        for target in targets {
            if let Some(entry) = reg.conns.get(target) {
                if entry.out.try_send(recv.clone()).is_ok() {
                    delivered = true;
                }
            }
        }
        if delivered {
            crabscale_metrics::registry().derp_packets_total.inc();
        } else {
            crabscale_metrics::registry()
                .derp_packets_dropped_total
                .inc();
        }
    }

    /// Send a keepalive frame to one connection.
    async fn send_keepalive(&self, id: ClientId) {
        let reg = self.registry.lock().await;
        if let Some(entry) = reg.conns.get(&id) {
            let _ = entry
                .out
                .try_send(Frame::new(FrameType::KeepAlive, Bytes::new()));
        }
    }

    /// Number of distinct node keys currently registered (used by tests).
    pub async fn registered_nodes(&self) -> usize {
        self.registry.lock().await.by_key.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frames::PeerGoneReason;
    use crate::{Client, FRAME_HEADER_LEN, KEY_LEN, MAX_FRAME_BODY_LEN};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf, duplex};

    type LoopbackClient = Client<ReadHalf<DuplexStream>, WriteHalf<DuplexStream>>;

    /// Open a loopback client connection against a relay and finish the login
    /// handshake.
    async fn connect_client(relay: &Arc<Relay>, secret: SecretKey) -> LoopbackClient {
        let (client_side, server_side) = duplex(128 * 1024);
        let relay2 = Arc::clone(relay);
        tokio::spawn(async move {
            relay2.run_conn(server_side).await;
        });
        let (read_half, write_half) = tokio::io::split(client_side);
        crate::client::connect_halves(read_half, write_half, secret).await
    }

    #[tokio::test]
    async fn two_loopback_clients_exchange_packets() {
        let relay = Arc::new(Relay::random());
        let secret_a = SecretKey::random();
        let secret_b = SecretKey::random();
        let mut a = connect_client(&relay, secret_a).await;
        let mut b = connect_client(&relay, secret_b).await;
        let key_a = a.node_key();
        let key_b = b.node_key();

        // Client A -> client B through the relay.
        a.send_packet(key_b, b"hello from the sun").await.unwrap();
        let (src, packet) = b.recv_packet().await.unwrap();
        assert_eq!(src, key_a);
        assert_eq!(&packet[..], b"hello from the sun");

        // Client B -> client A through the relay.
        b.send_packet(key_a, b"hello from the moon").await.unwrap();
        let (src, packet) = a.recv_packet().await.unwrap();
        assert_eq!(src, key_b);
        assert_eq!(&packet[..], b"hello from the moon");
    }

    #[tokio::test]
    async fn relayed_packets_increment_derp_metric() {
        // Packet routing must be observable. The global counter
        // is monotonic, so comparing deltas is safe even when other tests in
        // the same process relay packets concurrently.
        let before = crabscale_metrics::registry().derp_packets_total.get();
        let relay = Arc::new(Relay::random());
        let secret_a = SecretKey::random();
        let secret_b = SecretKey::random();
        let mut a = connect_client(&relay, secret_a).await;
        let mut b = connect_client(&relay, secret_b).await;
        let key_a = a.node_key();
        let key_b = b.node_key();

        a.send_packet(key_b, b"one").await.unwrap();
        let (_src, packet) = b.recv_packet().await.unwrap();
        assert_eq!(&packet[..], b"one");
        b.send_packet(key_a, b"two").await.unwrap();
        let (_src, packet) = a.recv_packet().await.unwrap();
        assert_eq!(&packet[..], b"two");

        let after = crabscale_metrics::registry().derp_packets_total.get();
        assert!(
            after >= before + 2,
            "expected at least 2 relayed packets, got {after}"
        );
    }

    #[tokio::test]
    async fn unknown_destination_gets_peer_gone_not_here() {
        let relay = Arc::new(Relay::random());
        let mut a = connect_client(&relay, SecretKey::random()).await;
        let missing = NodeKey::from_bytes([9; KEY_LEN]);

        a.send_packet(missing, b"who is there?").await.unwrap();
        let (key, reason) = a.recv_peer_gone().await.unwrap();
        assert_eq!(key, missing);
        assert_eq!(reason, PeerGoneReason::NotHere);
    }

    #[tokio::test]
    async fn peer_disconnect_is_announced() {
        let relay = Arc::new(Relay::random());
        let mut a = connect_client(&relay, SecretKey::random()).await;
        let key_b = {
            let b = connect_client(&relay, SecretKey::random()).await;
            let key = b.node_key();
            // Dropping `b` closes its halves; the relay should notify `a`.
            drop(b);
            key
        };

        let (key, reason) = a.recv_peer_gone().await.unwrap();
        assert_eq!(key, key_b);
        assert_eq!(reason, PeerGoneReason::Disconnected);
    }

    #[tokio::test]
    async fn newcomer_and_existing_peer_are_announced() {
        let relay = Arc::new(Relay::random());
        let mut a = connect_client(&relay, SecretKey::random()).await;
        let key_a = a.node_key();
        let mut b = connect_client(&relay, SecretKey::random()).await;
        let key_b = b.node_key();

        // The existing peer learns about the newcomer...
        let present = a.recv_peer_present().await.unwrap();
        assert_eq!(present, key_b);
        // ...and the newcomer learns about the existing peer.
        let present = b.recv_peer_present().await.unwrap();
        assert_eq!(present, key_a);
    }

    #[tokio::test]
    async fn registration_registry_contains_both_clients() {
        let relay = Arc::new(Relay::random());
        let _a = connect_client(&relay, SecretKey::random()).await;
        let _b = connect_client(&relay, SecretKey::random()).await;
        assert_eq!(relay.registered_nodes().await, 2);
    }

    #[tokio::test]
    async fn verify_callback_denies_unknown_node_key() {
        use crate::codec::{read_frame, write_frame};
        use crate::handshake::{ClientInfoPayload, make_client_info};

        let allowed = SecretKey::random();
        let denied = SecretKey::random();
        let allowed_key = allowed.public();
        let relay =
            Arc::new(Relay::random().with_verify(Arc::new(move |key: NodeKey| key == allowed_key)));

        // A denied client receives ServerKey but never ServerInfo: the relay
        // closes the connection after admission control rejects it.
        let (mut client_side, server_side) = duplex(128 * 1024);
        let relay2 = Arc::clone(&relay);
        tokio::spawn(async move {
            relay2.run_conn(server_side).await;
        });

        let Ok(Some(server_key)) = read_frame(&mut client_side).await else {
            panic!("server did not send ServerKey");
        };
        assert_eq!(server_key.ty, FrameType::ServerKey);
        let server_public = ServerKeyBody::decode(&server_key.payload).unwrap().key;
        let (_, nonce, ciphertext) = make_client_info(
            &denied,
            &server_public,
            &ClientInfoPayload {
                version: PROTOCOL_VERSION,
                ..Default::default()
            },
        )
        .unwrap();
        let mut info = ClientInfoBody {
            key: denied.public(),
            nonce,
        }
        .encode_prefix()
        .to_vec();
        info.extend_from_slice(&ciphertext);
        write_frame(
            &mut client_side,
            Frame::new(FrameType::ClientInfo, Bytes::from(info)),
        )
        .await
        .unwrap();

        // The next frame is EOF: the server never sent ServerInfo.
        let after = read_frame(&mut client_side).await;
        assert!(
            matches!(after, Ok(None)),
            "denied client must be disconnected with no ServerInfo: {after:?}"
        );

        // An allowed client completes the handshake normally.
        let client = connect_client(&relay, allowed).await;
        assert_eq!(client.node_key(), allowed_key);
    }

    #[tokio::test]
    async fn peer_gone_only_broadcast_after_last_connection() {
        let relay = Arc::new(Relay::random());
        let mut a = connect_client(&relay, SecretKey::random()).await;
        let secret_b = SecretKey::random();
        let key_b = secret_b.public();

        let b1 = connect_client(&relay, secret_b.clone()).await;
        let b2 = connect_client(&relay, secret_b.clone()).await;
        assert_eq!(b1.node_key(), key_b);
        assert_eq!(b2.node_key(), key_b);

        // Dropping one duplicate must not announce PeerGone while another of
        // the same node key remains connected.
        drop(b1);
        let early = tokio::time::timeout(Duration::from_millis(250), a.recv_peer_gone()).await;
        assert!(
            early.is_err(),
            "PeerGone must not fire while a duplicate connection remains"
        );

        // Dropping the last duplicate announces the departure.
        drop(b2);
        let (key, reason) = a.recv_peer_gone().await.unwrap();
        assert_eq!(key, key_b);
        assert_eq!(reason, PeerGoneReason::Disconnected);
    }

    #[tokio::test]
    async fn keepalive_is_emitted() {
        let relay = Arc::new(
            Relay::new(SecretKey::random()).with_keepalive_interval(Duration::from_millis(40)),
        );
        let mut a = connect_client(&relay, SecretKey::random()).await;

        let found = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let frame = a
                    .next()
                    .await
                    .expect("stream alive while keepalive pending")
                    .unwrap();
                if frame.ty == FrameType::KeepAlive {
                    break;
                }
            }
        })
        .await;
        assert!(found.is_ok(), "keepalive frame did not arrive");
    }

    #[tokio::test]
    async fn oversized_frame_closes_the_connection() {
        use crate::codec::{read_frame, write_frame};
        use crate::handshake::{ClientInfoPayload, make_client_info};

        let relay = Arc::new(Relay::random());
        let (mut client_side, server_side) = duplex(128 * 1024);
        let relay2 = Arc::clone(&relay);
        tokio::spawn(async move {
            relay2.run_conn(server_side).await;
        });

        // Complete the login handshake over the raw stream.
        let Ok(Some(server_key)) = read_frame(&mut client_side).await else {
            panic!("server did not send ServerKey");
        };
        assert_eq!(server_key.ty, FrameType::ServerKey);
        let client_secret = SecretKey::random();
        let server_public = ServerKeyBody::decode(&server_key.payload).unwrap().key;
        let (_, nonce, ciphertext) = make_client_info(
            &client_secret,
            &server_public,
            &ClientInfoPayload {
                version: PROTOCOL_VERSION,
                ..Default::default()
            },
        )
        .unwrap();
        let mut info = ClientInfoBody {
            key: client_secret.public(),
            nonce,
        }
        .encode_prefix()
        .to_vec();
        info.extend_from_slice(&ciphertext);
        write_frame(
            &mut client_side,
            Frame::new(FrameType::ClientInfo, Bytes::from(info)),
        )
        .await
        .unwrap();
        read_frame(&mut client_side)
            .await
            .expect("server sends ServerInfo");

        // Now send a header declaring a body one byte above the 1 MiB ceiling.
        let mut header = [0u8; FRAME_HEADER_LEN];
        header[0] = FrameType::Health as u8;
        header[1..].copy_from_slice(&((MAX_FRAME_BODY_LEN + 1) as u32).to_be_bytes());
        client_side.write_all(&header).await.unwrap();

        // The server must reject the oversized header without allocating and
        // close the connection; reading the client side yields EOF.
        let mut buf = [0u8; 16];
        let n = client_side.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "server should close after an oversized frame");
    }

    #[tokio::test]
    async fn oversized_packet_is_not_relayed() {
        let relay = Arc::new(Relay::random());
        let mut a = connect_client(&relay, SecretKey::random()).await;
        let mut b = connect_client(&relay, SecretKey::random()).await;
        let key_b = b.node_key();

        let big = vec![0xabu8; MAX_PACKET_PAYLOAD_LEN + 1];
        a.send_packet(key_b, &big).await.unwrap();

        // The oversized packet must not reach the destination; a subsequent
        // well-sized packet still flows, proving the relay stayed healthy.
        a.send_packet(key_b, b"still alive").await.unwrap();
        let (_, packet) = b.recv_packet().await.unwrap();
        assert_eq!(&packet[..], b"still alive");
    }
}
