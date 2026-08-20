//! Typed DERP frame bodies (Spec-DERP-STUN §2).
//!
//! Each type owns the byte layout of one frame payload. Fixed-width bodies
//! are decoded against their exact length; packet and JSON-carrying frames
//! keep a variable-length trailing section that the caller handles with the
//! shared frame codec.

use crate::frame::{FrameError, FrameType, MAGIC, MAX_FRAME_BODY_LEN, MAX_PACKET_PAYLOAD_LEN};
use crate::keys::{KEY_LEN, NodeKey};

/// Length of the NaCl nonce used for `crypto_box`.
pub const NONCE_LEN: usize = 24;

/// Fixed bytes of a `ServerKey` body: magic + server public key.
pub const SERVER_KEY_BODY_LEN: usize = MAGIC.len() + KEY_LEN;

/// Fixed prefix of a `ClientInfo` body: client key + nonce.
pub const CLIENT_INFO_PREFIX_LEN: usize = KEY_LEN + NONCE_LEN;

/// Fixed prefix of a `ServerInfo` body: nonce.
pub const SERVER_INFO_PREFIX_LEN: usize = NONCE_LEN;

/// Fixed prefix of a `SendPacket` body: destination key.
pub const SEND_PACKET_PREFIX_LEN: usize = KEY_LEN;

/// Fixed prefix of a `RecvPacket` body: source key.
pub const RECV_PACKET_PREFIX_LEN: usize = KEY_LEN;

/// Fixed prefix of a `ForwardPacket` body: source and destination keys.
pub const FORWARD_PACKET_PREFIX_LEN: usize = KEY_LEN * 2;

/// Fixed length of a `PeerGone` body: peer key + reason byte.
pub const PEER_GONE_BODY_LEN: usize = KEY_LEN + 1;

/// Fixed length of a `NotePreferred` body: one byte.
pub const NOTE_PREFERRED_BODY_LEN: usize = 1;

/// Fixed length of a `Ping` or `Pong` body.
pub const PING_BODY_LEN: usize = 8;

/// Fixed length of a `Restarting` body: two big-endian u32 durations.
pub const RESTARTING_BODY_LEN: usize = 8;

/// Fixed length of the short `PeerPresent` body: peer key + flags byte.
pub const PEER_PRESENT_SHORT_LEN: usize = KEY_LEN + 1;

/// Fixed length of the extended `PeerPresent` body:
/// peer key + 16-byte IP + 2-byte port + flags byte.
pub const PEER_PRESENT_FULL_LEN: usize = KEY_LEN + 16 + 2 + 1;

/// `PeerPresent` flag bits (Spec-DERP-STUN §3 steady state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerPresentFlags {
    /// A regular node connected to the relay.
    Regular = 0x01,
    /// A meshed relay node.
    MeshPeer = 0x02,
    /// A connectivity prober.
    Prober = 0x04,
}

/// `PeerGone` reason codes (Spec-DERP-STUN §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerGoneReason {
    /// The peer was connected here but has disconnected.
    Disconnected = 0x00,
    /// The relay has no record of the peer.
    NotHere = 0x01,
}

impl TryFrom<u8> for PeerGoneReason {
    type Error = FrameError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Disconnected),
            0x01 => Ok(Self::NotHere),
            other => Err(FrameError::InvalidPeerGoneReason(other)),
        }
    }
}

impl From<PeerGoneReason> for u8 {
    fn from(value: PeerGoneReason) -> Self {
        value as u8
    }
}

/// Body of a `ServerKey` frame (login flow step 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerKeyBody {
    /// The relay's DERP public key.
    pub key: NodeKey,
}

impl ServerKeyBody {
    /// The fixed encoded length of this body.
    pub const LEN: usize = SERVER_KEY_BODY_LEN;

    /// Encode the body: connection magic followed by the public key.
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[..MAGIC.len()].copy_from_slice(&MAGIC);
        out[MAGIC.len()..].copy_from_slice(&self.key.to_bytes());
        out
    }

    /// Decode and validate a `ServerKey` body, checking the magic prefix.
    pub fn decode(body: &[u8]) -> Result<Self, FrameError> {
        if body.len() != Self::LEN {
            return Err(FrameError::InvalidBodyLength {
                expected: Self::LEN,
                actual: body.len(),
            });
        }
        if body[..MAGIC.len()] != MAGIC {
            return Err(FrameError::InvalidMagic);
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&body[MAGIC.len()..]);
        Ok(Self {
            key: NodeKey::from_bytes(key),
        })
    }
}

/// Fixed prefix of a `ClientInfo` frame (login flow step 2).
///
/// The encrypted JSON payload follows the prefix in the same frame body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientInfoBody {
    /// The client's node public key (in the clear).
    pub key: NodeKey,
    /// The nonce used to seal the trailing encrypted JSON.
    pub nonce: [u8; NONCE_LEN],
}

impl ClientInfoBody {
    /// The fixed prefix length of this body.
    pub const PREFIX_LEN: usize = CLIENT_INFO_PREFIX_LEN;

    /// Encode the fixed prefix.
    pub fn encode_prefix(&self) -> [u8; Self::PREFIX_LEN] {
        let mut out = [0u8; Self::PREFIX_LEN];
        out[..KEY_LEN].copy_from_slice(&self.key.to_bytes());
        out[KEY_LEN..].copy_from_slice(&self.nonce);
        out
    }

    /// Decode the fixed prefix from the front of a `ClientInfo` body.
    pub fn decode_prefix(body: &[u8]) -> Result<Self, FrameError> {
        if body.len() < Self::PREFIX_LEN {
            return Err(FrameError::Truncated);
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&body[..KEY_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&body[KEY_LEN..Self::PREFIX_LEN]);
        Ok(Self {
            key: NodeKey::from_bytes(key),
            nonce,
        })
    }
}

/// Fixed prefix of a `ServerInfo` frame (login flow step 4).
///
/// The encrypted JSON payload follows the prefix in the same frame body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerInfoBody {
    /// The nonce used to seal the trailing encrypted JSON.
    pub nonce: [u8; NONCE_LEN],
}

impl ServerInfoBody {
    /// The fixed prefix length of this body.
    pub const PREFIX_LEN: usize = SERVER_INFO_PREFIX_LEN;

    /// Encode the fixed prefix.
    pub fn encode_prefix(&self) -> [u8; Self::PREFIX_LEN] {
        let mut out = [0u8; Self::PREFIX_LEN];
        out.copy_from_slice(&self.nonce);
        out
    }

    /// Decode the fixed prefix from the front of a `ServerInfo` body.
    pub fn decode_prefix(body: &[u8]) -> Result<Self, FrameError> {
        if body.len() < Self::PREFIX_LEN {
            return Err(FrameError::Truncated);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&body[..Self::PREFIX_LEN]);
        Ok(Self { nonce })
    }
}

/// Body of a `SendPacket` frame: destination key plus the packet bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendPacketBody {
    /// The destination node key.
    pub dest: NodeKey,
}

impl SendPacketBody {
    /// The fixed prefix length of this body.
    pub const PREFIX_LEN: usize = SEND_PACKET_PREFIX_LEN;

    /// Encode the destination key prefix.
    pub fn encode_prefix(&self) -> [u8; Self::PREFIX_LEN] {
        self.dest.to_bytes()
    }

    /// Decode the destination key from the front of a `SendPacket` body.
    pub fn decode_prefix(body: &[u8]) -> Result<Self, FrameError> {
        if body.len() < Self::PREFIX_LEN {
            return Err(FrameError::Truncated);
        }
        let mut dest = [0u8; KEY_LEN];
        dest.copy_from_slice(&body[..Self::PREFIX_LEN]);
        Ok(Self {
            dest: NodeKey::from_bytes(dest),
        })
    }
}

/// Body of a `RecvPacket` frame: source key plus the packet bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvPacketBody {
    /// The source node key.
    pub src: NodeKey,
}

impl RecvPacketBody {
    /// The fixed prefix length of this body.
    pub const PREFIX_LEN: usize = RECV_PACKET_PREFIX_LEN;

    /// Encode the source key prefix.
    pub fn encode_prefix(&self) -> [u8; Self::PREFIX_LEN] {
        self.src.to_bytes()
    }

    /// Decode the source key from the front of a `RecvPacket` body.
    pub fn decode_prefix(body: &[u8]) -> Result<Self, FrameError> {
        if body.len() < Self::PREFIX_LEN {
            return Err(FrameError::Truncated);
        }
        let mut src = [0u8; KEY_LEN];
        src.copy_from_slice(&body[..Self::PREFIX_LEN]);
        Ok(Self {
            src: NodeKey::from_bytes(src),
        })
    }
}

/// Body of a `ForwardPacket` frame (mesh): source + destination + packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardPacketBody {
    /// The original source node key.
    pub src: NodeKey,
    /// The destination node key.
    pub dest: NodeKey,
}

impl ForwardPacketBody {
    /// The fixed prefix length of this body.
    pub const PREFIX_LEN: usize = FORWARD_PACKET_PREFIX_LEN;

    /// Encode the source and destination key prefix.
    pub fn encode_prefix(&self) -> [u8; Self::PREFIX_LEN] {
        let mut out = [0u8; Self::PREFIX_LEN];
        out[..KEY_LEN].copy_from_slice(&self.src.to_bytes());
        out[KEY_LEN..].copy_from_slice(&self.dest.to_bytes());
        out
    }

    /// Decode the keys from the front of a `ForwardPacket` body.
    pub fn decode_prefix(body: &[u8]) -> Result<Self, FrameError> {
        if body.len() < Self::PREFIX_LEN {
            return Err(FrameError::Truncated);
        }
        let mut src = [0u8; KEY_LEN];
        src.copy_from_slice(&body[..KEY_LEN]);
        let mut dest = [0u8; KEY_LEN];
        dest.copy_from_slice(&body[KEY_LEN..Self::PREFIX_LEN]);
        Ok(Self {
            src: NodeKey::from_bytes(src),
            dest: NodeKey::from_bytes(dest),
        })
    }
}

/// Body of a `KeepAlive` frame: no payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepAliveBody;

/// Body of a `NotePreferred` frame: a single boolean byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotePreferredBody {
    /// Whether this relay is the client's preferred home node.
    pub preferred: bool,
}

impl NotePreferredBody {
    /// The fixed encoded length of this body.
    pub const LEN: usize = NOTE_PREFERRED_BODY_LEN;

    /// Encode the body as a single byte.
    pub fn encode(&self) -> [u8; Self::LEN] {
        [u8::from(self.preferred)]
    }

    /// Decode the single-byte body.
    pub fn decode(body: &[u8]) -> Result<Self, FrameError> {
        if body.len() != Self::LEN {
            return Err(FrameError::InvalidBodyLength {
                expected: Self::LEN,
                actual: body.len(),
            });
        }
        Ok(Self {
            preferred: body[0] != 0,
        })
    }
}

/// Body of a `PeerGone` frame: peer key and a reason code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerGoneBody {
    /// The peer that is gone.
    pub key: NodeKey,
    /// Why the path is gone.
    pub reason: PeerGoneReason,
}

impl PeerGoneBody {
    /// The fixed encoded length of this body.
    pub const LEN: usize = PEER_GONE_BODY_LEN;

    /// Encode the body.
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[..KEY_LEN].copy_from_slice(&self.key.to_bytes());
        out[KEY_LEN] = self.reason as u8;
        out
    }

    /// Decode the body.
    pub fn decode(body: &[u8]) -> Result<Self, FrameError> {
        if body.len() != Self::LEN {
            return Err(FrameError::InvalidBodyLength {
                expected: Self::LEN,
                actual: body.len(),
            });
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&body[..KEY_LEN]);
        Ok(Self {
            key: NodeKey::from_bytes(key),
            reason: PeerGoneReason::try_from(body[KEY_LEN])?,
        })
    }
}

/// Body of a `PeerPresent` frame.
///
/// The short form carries the peer key and a flags byte; the extended form
/// also carries the peer's IP address and port. The IP and port are advisory
/// and only emitted by meshed relays, so the decoder accepts both forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerPresentBody {
    /// The peer that became present.
    pub key: NodeKey,
    /// The peer's IP address, when known.
    pub ip: Option<[u8; 16]>,
    /// The peer's port, when known.
    pub port: Option<u16>,
    /// Presence flags from [`PeerPresentFlags`].
    pub flags: u8,
}

impl PeerPresentBody {
    /// Build a short-form body carrying only a peer key and flags.
    pub fn new(key: NodeKey, flags: u8) -> Self {
        Self {
            key,
            ip: None,
            port: None,
            flags,
        }
    }

    /// Encode the body, choosing the short or extended form automatically.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PEER_PRESENT_SHORT_LEN);
        out.extend_from_slice(&self.key.to_bytes());
        if let (Some(ip), Some(port)) = (self.ip, self.port) {
            out.extend_from_slice(&ip);
            out.extend_from_slice(&port.to_be_bytes());
        }
        out.push(self.flags);
        out
    }

    /// Decode the body, accepting both the short and extended forms.
    pub fn decode(body: &[u8]) -> Result<Self, FrameError> {
        match body.len() {
            PEER_PRESENT_SHORT_LEN => {
                let mut key = [0u8; KEY_LEN];
                key.copy_from_slice(&body[..KEY_LEN]);
                Ok(Self {
                    key: NodeKey::from_bytes(key),
                    ip: None,
                    port: None,
                    flags: body[KEY_LEN],
                })
            }
            PEER_PRESENT_FULL_LEN => {
                let mut key = [0u8; KEY_LEN];
                key.copy_from_slice(&body[..KEY_LEN]);
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&body[KEY_LEN..KEY_LEN + 16]);
                let mut addr = [0u8; 2];
                addr.copy_from_slice(&body[KEY_LEN + 16..KEY_LEN + 16 + 2]);
                Ok(Self {
                    key: NodeKey::from_bytes(key),
                    ip: Some(ip),
                    port: Some(u16::from_be_bytes(addr)),
                    flags: body[KEY_LEN + 16 + 2],
                })
            }
            other => Err(FrameError::InvalidBodyLength {
                expected: PEER_PRESENT_SHORT_LEN,
                actual: other,
            }),
        }
    }
}

/// Body of a `Ping` frame: an 8-byte payload echoed in the `Pong`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingBody {
    /// The 8-byte payload to echo.
    pub payload: [u8; PING_BODY_LEN],
}

impl PingBody {
    /// The fixed encoded length of this body.
    pub const LEN: usize = PING_BODY_LEN;

    /// Encode the body.
    pub fn encode(&self) -> [u8; Self::LEN] {
        self.payload
    }

    /// Decode the body.
    pub fn decode(body: &[u8]) -> Result<Self, FrameError> {
        if body.len() != Self::LEN {
            return Err(FrameError::InvalidBodyLength {
                expected: Self::LEN,
                actual: body.len(),
            });
        }
        let mut payload = [0u8; PING_BODY_LEN];
        payload.copy_from_slice(body);
        Ok(Self { payload })
    }
}

/// Body of a `Pong` frame: the payload from the `Ping` being answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PongBody {
    /// The echoed 8-byte payload.
    pub payload: [u8; PING_BODY_LEN],
}

impl PongBody {
    /// The fixed encoded length of this body.
    pub const LEN: usize = PING_BODY_LEN;

    /// Encode the body.
    pub fn encode(&self) -> [u8; Self::LEN] {
        self.payload
    }

    /// Decode the body.
    pub fn decode(body: &[u8]) -> Result<Self, FrameError> {
        if body.len() != Self::LEN {
            return Err(FrameError::InvalidBodyLength {
                expected: Self::LEN,
                actual: body.len(),
            });
        }
        let mut payload = [0u8; PING_BODY_LEN];
        payload.copy_from_slice(body);
        Ok(Self { payload })
    }
}

/// Body of a `Health` frame: a UTF-8 diagnostic message, or empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthBody(pub String);

impl HealthBody {
    /// Encode the message.
    pub fn encode(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    /// Decode the message, accepting any bytes that are valid UTF-8.
    pub fn decode(body: &[u8]) -> Result<Self, FrameError> {
        String::from_utf8(body.to_vec())
            .map(Self)
            .map_err(|_| FrameError::InvalidBodyLength {
                expected: 0,
                actual: body.len(),
            })
    }
}

/// Body of a `Restarting` frame: reconnect guidance in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartingBody {
    /// How long to wait before reconnecting.
    pub reconnect_ms: u32,
    /// How long to keep trying to reconnect, overall.
    pub total_ms: u32,
}

impl RestartingBody {
    /// The fixed encoded length of this body.
    pub const LEN: usize = RESTARTING_BODY_LEN;

    /// Encode the body as two big-endian u32 values.
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[..4].copy_from_slice(&self.reconnect_ms.to_be_bytes());
        out[4..].copy_from_slice(&self.total_ms.to_be_bytes());
        out
    }

    /// Decode the body.
    pub fn decode(body: &[u8]) -> Result<Self, FrameError> {
        if body.len() != Self::LEN {
            return Err(FrameError::InvalidBodyLength {
                expected: Self::LEN,
                actual: body.len(),
            });
        }
        Ok(Self {
            reconnect_ms: u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
            total_ms: u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
        })
    }
}

/// Validate a decoded frame body against the limits in the spec.
///
/// The packet payload length is derived from the fixed prefix of each
/// packet-carrying frame type (`SendPacket`, `RecvPacket`, `ForwardPacket`);
/// all other frame types pass through unchanged.
pub fn validate_frame_body(ty: FrameType, body_len: usize) -> Result<(), FrameError> {
    if body_len > MAX_FRAME_BODY_LEN {
        return Err(FrameError::Oversized);
    }
    let packet_len = match ty {
        FrameType::SendPacket | FrameType::RecvPacket => {
            body_len.saturating_sub(SEND_PACKET_PREFIX_LEN)
        }
        FrameType::ForwardPacket => body_len.saturating_sub(FORWARD_PACKET_PREFIX_LEN),
        _ => 0,
    };
    if packet_len > MAX_PACKET_PAYLOAD_LEN {
        return Err(FrameError::PacketTooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_key_round_trip() {
        let key = NodeKey::from_bytes([0x55; KEY_LEN]);
        let body = ServerKeyBody { key };
        let parsed = ServerKeyBody::decode(&body.encode()).unwrap();
        assert_eq!(parsed, body);
    }

    #[test]
    fn server_key_rejects_bad_magic() {
        let key = NodeKey::from_bytes([0x55; KEY_LEN]);
        let mut encoded = ServerKeyBody { key }.encode();
        encoded[0] ^= 0xff;
        assert_eq!(
            ServerKeyBody::decode(&encoded),
            Err(FrameError::InvalidMagic)
        );
    }

    #[test]
    fn client_info_prefix_round_trip() {
        let body = ClientInfoBody {
            key: NodeKey::from_bytes([1; KEY_LEN]),
            nonce: [2; NONCE_LEN],
        };
        let prefix = body.encode_prefix();
        let parsed = ClientInfoBody::decode_prefix(&prefix).unwrap();
        assert_eq!(parsed, body);
        // A shortcut body still carries the nonce once the payload arrives.
        let mut full = prefix.to_vec();
        full.extend_from_slice(b"encrypted");
        let parsed = ClientInfoBody::decode_prefix(&full).unwrap();
        assert_eq!(parsed, body);
    }

    #[test]
    fn send_recv_packet_prefixes_round_trip() {
        let send = SendPacketBody {
            dest: NodeKey::from_bytes([3; KEY_LEN]),
        };
        let recv = RecvPacketBody {
            src: NodeKey::from_bytes([4; KEY_LEN]),
        };
        assert_eq!(
            SendPacketBody::decode_prefix(&send.encode_prefix()).unwrap(),
            send
        );
        assert_eq!(
            RecvPacketBody::decode_prefix(&recv.encode_prefix()).unwrap(),
            recv
        );
    }

    #[test]
    fn peer_gone_round_trip() {
        let body = PeerGoneBody {
            key: NodeKey::from_bytes([9; KEY_LEN]),
            reason: PeerGoneReason::NotHere,
        };
        let parsed = PeerGoneBody::decode(&body.encode()).unwrap();
        assert_eq!(parsed, body);
    }

    #[test]
    fn peer_present_encodes_short_and_full_forms() {
        let key = NodeKey::from_bytes([8; KEY_LEN]);
        let short = PeerPresentBody::new(key, PeerPresentFlags::Regular as u8);
        let short_bytes = short.encode();
        assert_eq!(short_bytes.len(), PEER_PRESENT_SHORT_LEN);
        assert_eq!(PeerPresentBody::decode(&short_bytes).unwrap(), short);

        let full = PeerPresentBody {
            key,
            ip: Some([0; 16]),
            port: Some(443),
            flags: PeerPresentFlags::MeshPeer as u8,
        };
        let full_bytes = full.encode();
        assert_eq!(full_bytes.len(), PEER_PRESENT_FULL_LEN);
        assert_eq!(PeerPresentBody::decode(&full_bytes).unwrap(), full);
    }

    #[test]
    fn ping_pong_round_trip() {
        let ping = PingBody { payload: [0x11; 8] };
        let pong = PongBody { payload: [0x11; 8] };
        assert_eq!(PingBody::decode(&ping.encode()).unwrap(), ping);
        assert_eq!(PongBody::decode(&pong.encode()).unwrap(), pong);
    }

    #[test]
    fn note_preferred_round_trip() {
        let body = NotePreferredBody { preferred: true };
        assert_eq!(NotePreferredBody::decode(&body.encode()).unwrap(), body);
        assert_eq!(body.encode(), [1]);
    }

    #[test]
    fn restarting_uses_big_endian_durations() {
        let body = RestartingBody {
            reconnect_ms: 0x0001_0002,
            total_ms: 0x0003_0004,
        };
        let encoded = body.encode();
        assert_eq!(&encoded[..4], &[0x00, 0x01, 0x00, 0x02]);
        assert_eq!(&encoded[4..], &[0x00, 0x03, 0x00, 0x04]);
        assert_eq!(RestartingBody::decode(&encoded).unwrap(), body);
    }

    #[test]
    fn packet_limits_are_enforced() {
        assert_eq!(
            validate_frame_body(
                FrameType::SendPacket,
                SEND_PACKET_PREFIX_LEN + MAX_PACKET_PAYLOAD_LEN + 1
            ),
            Err(FrameError::PacketTooLarge)
        );
        assert_eq!(
            validate_frame_body(FrameType::Health, MAX_FRAME_BODY_LEN + 1),
            Err(FrameError::Oversized)
        );
    }
}
