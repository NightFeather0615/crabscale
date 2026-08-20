//! Typed public keys used on the control wire.
//!
//! Every key is serialized as a string of the form `<type>:<64 lowercase hex
//! chars>`, where `<type>` identifies the key kind. Parsing accepts both
//! upper- and lower-case hex digits; formatting always emits lower-case.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Errors returned when parsing a typed key string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyParseError {
    /// The string did not have the expected `<type>:<hex>` shape.
    InvalidFormat,
    /// The string had the right shape but the wrong length.
    InvalidLength,
    /// The type prefix did not match the key type being parsed.
    InvalidPrefix,
    /// The hex payload contained a non-hex character.
    InvalidHex,
}

impl fmt::Display for KeyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "key string is not of the form <type>:<hex>"),
            Self::InvalidLength => write!(f, "key string has the wrong length"),
            Self::InvalidPrefix => write!(f, "key string has the wrong type prefix"),
            Self::InvalidHex => write!(f, "key string contains a non-hex character"),
        }
    }
}

impl std::error::Error for KeyParseError {}

const KEY_BYTES: usize = 32;
const KEY_HEX_CHARS: usize = KEY_BYTES * 2;

fn encode_hex(bytes: &[u8; KEY_BYTES]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(KEY_HEX_CHARS);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex(hex: &str) -> Option<[u8; KEY_BYTES]> {
    if hex.len() != KEY_HEX_CHARS {
        return None;
    }
    let mut out = [0u8; KEY_BYTES];
    let bytes = hex.as_bytes();
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        *byte = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parse_key(prefix: &str, s: &str) -> Result<[u8; KEY_BYTES], KeyParseError> {
    let Some(hex) = s.strip_prefix(prefix) else {
        return Err(KeyParseError::InvalidPrefix);
    };
    let Some(hex) = hex.strip_prefix(':') else {
        return Err(KeyParseError::InvalidFormat);
    };
    if hex.contains(':') {
        return Err(KeyParseError::InvalidFormat);
    }
    if hex.len() != KEY_HEX_CHARS {
        return Err(KeyParseError::InvalidLength);
    }
    decode_hex(hex).ok_or(KeyParseError::InvalidHex)
}

macro_rules! key_type {
    ($(#[$doc:meta])* $name:ident, $prefix:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; KEY_BYTES]);

        impl $name {
            /// The wire prefix for this key type, without the trailing colon.
            pub const PREFIX: &'static str = $prefix;

            /// The number of raw key bytes.
            pub const LEN: usize = KEY_BYTES;

            /// Build a key from its raw 32-byte representation.
            pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
                Self(bytes)
            }

            /// Return the raw 32-byte representation.
            pub fn to_bytes(self) -> [u8; KEY_BYTES] {
                self.0
            }

            /// Return the canonical `<type>:<64 lowercase hex>` string.
            pub fn to_key_string(self) -> String {
                format!("{}:{}", Self::PREFIX, encode_hex(&self.0))
            }
        }

        impl FromStr for $name {
            type Err = KeyParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                parse_key(Self::PREFIX, s).map(Self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}:{}", Self::PREFIX, encode_hex(&self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, f)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct KeyVisitor;

                impl Visitor<'_> for KeyVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(
                            formatter,
                            "a string of the form '{}:<64 lowercase hex chars>'",
                            $name::PREFIX
                        )
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        value.parse().map_err(de::Error::custom)
                    }
                }

                deserializer.deserialize_str(KeyVisitor)
            }
        }
    };
}

key_type!(
    /// A long-term machine public key (`mkey`).
    MachineKey,
    "mkey"
);

key_type!(
    /// A WireGuard node public key (`nodekey`).
    NodeKey,
    "nodekey"
);

key_type!(
    /// A discovery protocol public key (`discokey`).
    DiscoKey,
    "discokey"
);

key_type!(
    /// A per-connection challenge public key (`chalpub`).
    ChallengeKey,
    "chalpub"
);

#[cfg(test)]
mod tests {
    use super::*;

    const ZEROS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn round_trips_through_string() {
        let key = NodeKey::from_bytes([0x42; KEY_BYTES]);
        let rendered = key.to_string();
        assert_eq!(rendered.len(), "nodekey:".len() + KEY_HEX_CHARS);
        assert!(rendered.starts_with("nodekey:"));
        assert_eq!(rendered.parse::<NodeKey>().unwrap(), key);
    }

    #[test]
    fn formats_lowercase_hex() {
        let key = NodeKey::from_bytes([0xab; KEY_BYTES]);
        assert_eq!(
            key.to_string(),
            format!("nodekey:{}", "ab".repeat(KEY_BYTES))
        );
    }

    #[test]
    fn accepts_uppercase_hex_on_parse() {
        let key = NodeKey::from_bytes([0xab; KEY_BYTES]);
        let rendered = format!("nodekey:{}", "AB".repeat(KEY_BYTES));
        assert_eq!(rendered.parse::<NodeKey>().unwrap(), key);
    }

    #[test]
    fn rejects_wrong_prefix() {
        assert_eq!(
            format!("mkey:{ZEROS}").parse::<NodeKey>(),
            Err(KeyParseError::InvalidPrefix)
        );
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(
            "nodekey:abcd".parse::<NodeKey>(),
            Err(KeyParseError::InvalidLength)
        );
    }

    #[test]
    fn rejects_invalid_hex() {
        assert_eq!(
            format!("nodekey:{}", "zz".repeat(KEY_BYTES)).parse::<NodeKey>(),
            Err(KeyParseError::InvalidHex)
        );
    }

    #[test]
    fn serde_round_trips() {
        let key = DiscoKey::from_bytes([7; KEY_BYTES]);
        let json = serde_json::to_string(&key).unwrap();
        assert_eq!(json, format!("\"discokey:{}\"", "07".repeat(KEY_BYTES)));
        assert_eq!(serde_json::from_str::<DiscoKey>(&json).unwrap(), key);
    }
}
