//! STUN Binding protocol (RFC 5389) for the relay (Spec-DERP-STUN §6).
//!
//! The relay answers Binding requests with a Binding response that copies the
//! transaction ID and carries the sender's observed `XOR-MAPPED-ADDRESS`.
//! This module owns the pure byte-level encoding and decoding: no sockets,
//! no async runtime, and no external dependency beyond `std`.
//!
//! The implementation deliberately accepts any RFC 5389 Binding request; it
//! does not require Tailscale's `SOFTWARE`/`FINGERPRINT` attributes so generic
//! STUN clients work too.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Length of the STUN message header (type + length + cookie + transaction ID).
pub const HEADER_LEN: usize = 20;

/// Length of a STUN transaction ID in bytes.
pub const TXID_LEN: usize = 12;

/// The STUN magic cookie (RFC 5389 section 6).
const MAGIC_COOKIE: u32 = 0x2112_A442;

/// STUN message type: Binding request.
const TYPE_BINDING_REQUEST: u16 = 0x0001;
/// STUN message type: Binding success response.
const TYPE_BINDING_RESPONSE: u16 = 0x0101;

/// Attribute type: XOR-MAPPED-ADDRESS (RFC 5389 section 15.2).
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Address family value for IPv4 (RFC 5389 section 15.2).
const FAMILY_IPV4: u8 = 0x01;
/// Address family value for IPv6 (RFC 5389 section 15.2).
const FAMILY_IPV6: u8 = 0x02;

/// A STUN transaction ID.
///
/// The server copies this verbatim from the request into its response so a
/// client can correlate replies (Spec-DERP-STUN §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxId([u8; TXID_LEN]);

impl TxId {
    /// Build a transaction ID from an explicit 12-byte value.
    pub const fn from_bytes(bytes: [u8; TXID_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw 12-byte transaction ID.
    pub const fn as_bytes(&self) -> &[u8; TXID_LEN] {
        &self.0
    }
}

/// Errors returned while parsing or building STUN messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunError {
    /// The datagram is shorter than the STUN header.
    Truncated,
    /// The datagram does not begin with the STUN magic cookie.
    NotStun,
    /// The message type is not a Binding request (or response, when one was
    /// expected).
    NotBinding,
    /// The attribute area is malformed or the message length does not match.
    MalformedAttributes,
    /// The XOR-MAPPED-ADDRESS attribute is missing from a binding response.
    MissingXorMappedAddress,
    /// The address family in the XOR-MAPPED-ADDRESS attribute is unknown.
    UnsupportedFamily(u8),
}

impl fmt::Display for StunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "STUN packet is shorter than the header"),
            Self::NotStun => write!(f, "packet does not have the STUN magic cookie"),
            Self::NotBinding => write!(f, "STUN message is not a Binding message"),
            Self::MalformedAttributes => write!(f, "STUN attributes are malformed"),
            Self::MissingXorMappedAddress => {
                write!(f, "STUN binding response has no XOR-MAPPED-ADDRESS")
            }
            Self::UnsupportedFamily(family) => {
                write!(
                    f,
                    "STUN XOR-MAPPED-ADDRESS has unknown family {family:#04x}"
                )
            }
        }
    }
}

impl std::error::Error for StunError {}

/// Parse an RFC 5389 Binding request and return its transaction ID.
///
/// Returns [`StunError::NotStun`] when the magic cookie is missing and
/// [`StunError::NotBinding`] when the cookie is present but the message is not
/// a Binding request. The attributes are not validated beyond ensuring the
/// declared length fits the datagram.
pub fn parse_binding_request(packet: &[u8]) -> Result<TxId, StunError> {
    let (msg_type, length, cookie, tx) = parse_header(packet)?;
    if msg_type != TYPE_BINDING_REQUEST {
        return Err(StunError::NotBinding);
    }
    let _ = cookie;
    // The declared attribute length must fit in the remaining bytes.
    if HEADER_LEN + length as usize > packet.len() {
        return Err(StunError::MalformedAttributes);
    }
    Ok(tx)
}

/// Parse an RFC 5389 Binding success response.
///
/// Returns the transaction ID and the address reported in the
/// `XOR-MAPPED-ADDRESS` attribute.
pub fn parse_binding_response(packet: &[u8]) -> Result<(TxId, IpAddr, u16), StunError> {
    let (msg_type, length, cookie, tx) = parse_header(packet)?;
    if msg_type != TYPE_BINDING_RESPONSE {
        return Err(StunError::NotBinding);
    }
    if HEADER_LEN + length as usize > packet.len() {
        return Err(StunError::MalformedAttributes);
    }
    let _ = cookie;

    let attrs = &packet[HEADER_LEN..HEADER_LEN + length as usize];
    for attr in attributes(attrs) {
        let Ok(attr) = attr else {
            return Err(StunError::MalformedAttributes);
        };
        if attr.ty == ATTR_XOR_MAPPED_ADDRESS {
            let (addr, port) = decode_xor_mapped_address(attr.value, tx)?;
            return Ok((tx, addr, port));
        }
    }
    Err(StunError::MissingXorMappedAddress)
}

/// Build a Binding success response for `tx_id`.
///
/// The response carries a single `XOR-MAPPED-ADDRESS` attribute describing
/// the source address observed at the relay, which lets the client learn its
/// public `ip:port`.
pub fn build_binding_response(tx_id: TxId, addr: IpAddr, port: u16) -> Vec<u8> {
    let value = encode_xor_mapped_address(addr, port, tx_id);
    // The message length covers the attribute area: the 4-byte attribute
    // header plus the attribute value.
    let attr_area = 4 + value.len();
    let mut packet = Vec::with_capacity(HEADER_LEN + attr_area);
    write_u16(&mut packet, TYPE_BINDING_RESPONSE);
    write_u16(&mut packet, attr_area as u16);
    write_u32(&mut packet, MAGIC_COOKIE);
    packet.extend_from_slice(tx_id.as_bytes());
    write_u16(&mut packet, ATTR_XOR_MAPPED_ADDRESS);
    write_u16(&mut packet, value.len() as u16);
    packet.extend_from_slice(&value);
    packet
}

/// Decode an `XOR-MAPPED-ADDRESS` attribute value into an address and port.
fn decode_xor_mapped_address(value: &[u8], tx: TxId) -> Result<(IpAddr, u16), StunError> {
    if value.len() < 4 {
        return Err(StunError::MalformedAttributes);
    }
    // Byte 0 is unused/padding; byte 1 is the address family.
    let family = value[1];
    let x_port = u16::from_be_bytes([value[2], value[3]]);
    let port = x_port ^ (MAGIC_COOKIE as u16);

    match family {
        FAMILY_IPV4 => {
            if value.len() < 8 {
                return Err(StunError::MalformedAttributes);
            }
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&value[4..8]);
            let cookie = MAGIC_COOKIE.to_be_bytes();
            for i in 0..4 {
                bytes[i] ^= cookie[i];
            }
            Ok((IpAddr::V4(Ipv4Addr::from(bytes)), port))
        }
        FAMILY_IPV6 => {
            if value.len() < 20 {
                return Err(StunError::MalformedAttributes);
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&value[4..20]);
            let cookie = MAGIC_COOKIE.to_be_bytes();
            for (i, byte) in bytes.iter_mut().enumerate() {
                let mask = if i < 4 {
                    cookie[i]
                } else {
                    tx.as_bytes()[i - 4]
                };
                *byte ^= mask;
            }
            Ok((IpAddr::V6(Ipv6Addr::from(bytes)), port))
        }
        other => Err(StunError::UnsupportedFamily(other)),
    }
}

/// Encode an `XOR-MAPPED-ADDRESS` attribute value.
fn encode_xor_mapped_address(addr: IpAddr, port: u16, tx: TxId) -> Vec<u8> {
    let cookie = MAGIC_COOKIE.to_be_bytes();
    let mut value = Vec::with_capacity(20);
    value.push(0); // unused padding byte
    match addr {
        IpAddr::V4(v4) => {
            value.push(FAMILY_IPV4);
            value.extend_from_slice(&(port ^ (MAGIC_COOKIE as u16)).to_be_bytes());
            let bytes = v4.octets();
            for i in 0..4 {
                value.push(bytes[i] ^ cookie[i]);
            }
        }
        IpAddr::V6(v6) => {
            value.push(FAMILY_IPV6);
            value.extend_from_slice(&(port ^ (MAGIC_COOKIE as u16)).to_be_bytes());
            let bytes = v6.octets();
            for (i, byte) in bytes.iter().enumerate() {
                let mask = if i < 4 {
                    cookie[i]
                } else {
                    tx.as_bytes()[i - 4]
                };
                value.push(byte ^ mask);
            }
        }
    }
    value
}

/// Parse the STUN message header.
fn parse_header(packet: &[u8]) -> Result<(u16, u16, u32, TxId), StunError> {
    if packet.len() < HEADER_LEN {
        return Err(StunError::Truncated);
    }
    let msg_type = u16::from_be_bytes([packet[0], packet[1]]);
    let length = u16::from_be_bytes([packet[2], packet[3]]);
    let cookie = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(StunError::NotStun);
    }
    let mut tx = [0u8; TXID_LEN];
    tx.copy_from_slice(&packet[8..20]);
    Ok((msg_type, length, cookie, TxId(tx)))
}

/// An attribute parsed out of a STUN attribute area.
struct Attribute<'a> {
    ty: u16,
    value: &'a [u8],
}

/// Iterate the attributes in a STUN attribute area.
///
/// Attributes are `[2-byte type][2-byte length][value][padding to 4 bytes]`.
fn attributes(mut area: &[u8]) -> Vec<Result<Attribute<'_>, ()>> {
    let mut out = Vec::new();
    while !area.is_empty() {
        if area.len() < 4 {
            out.push(Err(()));
            return out;
        }
        let ty = u16::from_be_bytes([area[0], area[1]]);
        let len = u16::from_be_bytes([area[2], area[3]]) as usize;
        let padded = (len + 3) & !3;
        if area.len() < 4 + padded {
            out.push(Err(()));
            return out;
        }
        out.push(Ok(Attribute {
            ty,
            value: &area[4..4 + len],
        }));
        area = &area[4 + padded..];
    }
    out
}

fn write_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_binding_request_transaction_id() {
        let tx = TxId::from_bytes([7; TXID_LEN]);
        let mut packet = Vec::new();
        write_u16(&mut packet, TYPE_BINDING_REQUEST);
        write_u16(&mut packet, 0);
        write_u32(&mut packet, MAGIC_COOKIE);
        packet.extend_from_slice(tx.as_bytes());

        let parsed = parse_binding_request(&packet).unwrap();
        assert_eq!(parsed, tx);
    }

    #[test]
    fn rejects_non_stun_and_non_binding() {
        assert_eq!(parse_binding_request(b"nope"), Err(StunError::Truncated));
        // Wrong magic cookie.
        let mut packet = vec![0u8; HEADER_LEN];
        packet[0] = 0; // request bits leading byte
        packet[1] = 1;
        assert_eq!(parse_binding_request(&packet), Err(StunError::NotStun));
        // Correct cookie but not a binding request (e.g. an indication type).
        let mut packet = Vec::new();
        write_u16(&mut packet, 0x0002);
        write_u16(&mut packet, 0);
        write_u32(&mut packet, MAGIC_COOKIE);
        packet.extend_from_slice(&tx_bytes());
        assert_eq!(parse_binding_request(&packet), Err(StunError::NotBinding));
    }

    #[test]
    fn binding_response_round_trips_ipv4() {
        let tx = TxId::from_bytes([9; TXID_LEN]);
        let addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        let port = 41641;

        let response = build_binding_response(tx, addr, port);
        let (parsed_tx, parsed_addr, parsed_port) = parse_binding_response(&response).unwrap();
        assert_eq!(parsed_tx, tx, "transaction ID must round-trip");
        assert_eq!(parsed_addr, addr);
        assert_eq!(parsed_port, port);
    }

    #[test]
    fn binding_response_round_trips_ipv6() {
        let tx = TxId::from_bytes([0xAA, 0xBB, 0xCC, 0xDD, 1, 2, 3, 4, 5, 6, 7, 8]);
        let addr: IpAddr = "2001:db8::1".parse().unwrap();
        let port = 3478;

        let response = build_binding_response(tx, addr, port);
        let (parsed_tx, parsed_addr, parsed_port) = parse_binding_response(&response).unwrap();
        assert_eq!(parsed_tx, tx, "transaction ID must round-trip");
        assert_eq!(parsed_addr, addr);
        assert_eq!(parsed_port, port);
    }

    #[test]
    fn response_has_correct_stun_header() {
        let tx = TxId::from_bytes([1; TXID_LEN]);
        let response = build_binding_response(tx, IpAddr::V4(Ipv4Addr::LOCALHOST), 1111);
        assert_eq!(u16::from_be_bytes([response[0], response[1]]), 0x0101);
        assert_eq!(
            u32::from_be_bytes([response[4], response[5], response[6], response[7]]),
            MAGIC_COOKIE
        );
        assert_eq!(&response[8..20], tx.as_bytes());
        // Header length must account for exactly the one attribute.
        let length = u16::from_be_bytes([response[2], response[3]]) as usize;
        assert_eq!(length + HEADER_LEN, response.len());
    }

    fn tx_bytes() -> [u8; TXID_LEN] {
        [3; TXID_LEN]
    }
}
