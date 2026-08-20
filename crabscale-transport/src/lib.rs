//! TS2021 upgrade, Noise responder, Noise-framed stream, and HTTP/2 glue.
//!
//! This crate owns the transport layer of the control protocol: the `/ts2021`
//! HTTP upgrade (native and WebSocket), the Noise IK responder handshake, the
//! 4096-byte record framing, and the optional early payload sent before HTTP/2.
//!
//! Wire rules are documented in the project wiki:
//! [Spec-Transport](https://github.com/NightFeather0615/crabscale/wiki/Spec-Transport.md).

mod early;
mod error;
mod http2;
mod loopback;
mod messages;
mod noise;
mod record;
mod stream;
mod upgrade;

pub use early::{
    EARLY_PAYLOAD_MAGIC, decode_early_payload, encode_early_payload, random_challenge,
};
pub use error::TransportError;
pub use http2::{MAX_INNER_BODY_LEN, read_body_limited, serve_http2};
pub use loopback::loopback_handshake;
pub use messages::{
    AEAD_TAG_LEN, INIT_MESSAGE_LEN, InitMessage, MAX_EARLY_PAYLOAD_LEN, MAX_RECORD_FRAME_SIZE,
    MAX_RECORD_PLAINTEXT, MSG_TYPE_ERROR, MSG_TYPE_INIT, MSG_TYPE_RECORD, MSG_TYPE_RESPONSE,
    RECORD_HEADER_LEN, RESPONSE_MESSAGE_LEN, ResponseMessage, parse_init_message,
    parse_response_message, write_response_message,
};
pub use noise::{NoiseInitiator, NoiseResponder, PROTOCOL_NAME, ResponderOutput, Role, Session};
pub use record::{RecordCipher, RecordDecoder};
pub use stream::NoiseStream;
pub use upgrade::{
    HANDSHAKE_HEADER, UPGRADE_HEADER_VALUE, validate_native_upgrade, validate_websocket_upgrade,
};
