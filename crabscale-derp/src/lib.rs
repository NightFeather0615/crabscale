//! DERP relay core: frame codec, login handshake, client registry, packet
//! routing, keepalive, and peer presence notifications.
//!
//! This crate implements the relay protocol described in the project wiki:
//! [Spec-DERP-STUN](https://github.com/NightFeather0615/crabscale/wiki/Spec-DERP-STUN.md).
//! It owns the wire-level DERP frame format, the NaCl `crypto_box` login
//! handshake, the single-node relay core, and the raw / WebSocket transport
//! negotiation used by the server's `/derp` endpoint.
//!
//! STUN Binding answering (RFC 5389) is part of this crate; multi-node mesh
//! remains out of scope and will land in a follow-up.

pub mod client;
pub mod codec;
pub mod frame;
pub mod frames;
pub mod handshake;
pub mod keys;
pub mod server;
pub mod stun;
pub mod upgrade;
pub mod websocket;

pub use client::{Client, connect_halves};
pub use codec::{CodecError, DerpCodec, Frame};
pub use frame::{
    FRAME_HEADER_LEN, FrameDecoder, FrameError, FrameHeader, FrameType, MAGIC, MAX_FRAME_BODY_LEN,
    MAX_PACKET_PAYLOAD_LEN, PROTOCOL_VERSION, decode_frame, encode_frame,
};
pub use frames::{
    ClientInfoBody, ForwardPacketBody, HealthBody, KeepAliveBody, NotePreferredBody, PeerGoneBody,
    PeerGoneReason, PeerPresentBody, PeerPresentFlags, PingBody, PongBody, RecvPacketBody,
    RestartingBody, SendPacketBody, ServerInfoBody, ServerKeyBody,
};
pub use handshake::{
    ClientInfoPayload, HandshakeError, ServerInfoPayload, make_client_info, make_server_info,
    open_client_info, open_from, open_server_info, seal_to,
};
pub use keys::{KEY_LEN, NodeKey, SecretKey};
pub use server::{ClientId, DEFAULT_KEEPALIVE_INTERVAL, OUTBOUND_CAPACITY, Relay};
pub use stun::{
    HEADER_LEN, StunError, TXID_LEN, TxId, build_binding_response, parse_binding_request,
    parse_binding_response,
};
pub use upgrade::{
    DerpRequest, TransportKind, UpgradeError, UpgradedRequest, build_derp_response,
    compute_websocket_accept, negotiate, validate_method,
};
pub use websocket::{WebSocketByteStream, WebSocketCodec, WebSocketRole, WsError, WsFrame};
