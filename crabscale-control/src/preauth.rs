//! Pre-auth key generation, hashing, and parsing.
//!
//! A pre-auth key has the form `hskey-auth-<prefix>-<secret>`. Only the
//! prefix and a salted hash of the secret are persisted; the plaintext secret
//! is never stored or logged.

use blake2::{Blake2b512, Digest};
use rand::RngCore;

/// The fixed prefix of every pre-auth key.
pub const AUTH_KEY_PREFIX: &str = "hskey-auth-";

/// Number of random bytes in a generated secret (64 hex chars).
const SECRET_BYTES: usize = 32;

/// Generate a random secret encoded as lowercase hex.
pub fn generate_secret() -> String {
    let mut bytes = [0u8; SECRET_BYTES];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Format a full pre-auth key from a prefix and secret.
pub fn format_auth_key(prefix: &str, secret: &str) -> String {
    format!("{AUTH_KEY_PREFIX}{prefix}-{secret}")
}

/// Split a full pre-auth key into its `(prefix, secret)` parts.
pub fn parse_auth_key(key: &str) -> Option<(String, String)> {
    let rest = key.strip_prefix(AUTH_KEY_PREFIX)?;
    let (prefix, secret) = rest.split_once('-')?;
    if prefix.is_empty() || secret.is_empty() {
        return None;
    }
    Some((prefix.to_string(), secret.to_string()))
}

/// Hash a secret with a random salt, returning `salt$hexhash`.
///
/// A single unsalted-stretching Blake2b512 pass is appropriate for the
/// high-entropy random secrets used here; do not reuse for low-entropy
/// passwords.
pub fn hash_secret(secret: &str) -> String {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut hasher = Blake2b512::new();
    hasher.update(salt);
    hasher.update(secret.as_bytes());
    let digest = hasher.finalize();
    let salt_hex: String = salt.iter().map(|b| format!("{b:02x}")).collect();
    let hash_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("{salt_hex}${hash_hex}")
}

/// Verify a plaintext secret against a stored `salt$hexhash` value.
///
/// The comparison is not constant-time, which is acceptable for 256-bit
/// random secrets that are never attacker-controlled in bulk.
pub fn verify_secret(secret: &str, stored: &str) -> bool {
    let Some((salt_hex, hash_hex)) = stored.split_once('$') else {
        return false;
    };
    let Ok(salt) = decode_hex(salt_hex) else {
        return false;
    };
    let mut hasher = Blake2b512::new();
    hasher.update(&salt);
    hasher.update(secret.as_bytes());
    let digest = hasher.finalize();
    let expected: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    expected == hash_hex
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_nibble(bytes[i]).ok_or(())?;
        let lo = hex_nibble(bytes[i + 1]).ok_or(())?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_key_round_trips() {
        let key = format_auth_key("test", "secret");
        assert_eq!(
            parse_auth_key(&key),
            Some(("test".to_string(), "secret".to_string()))
        );
    }

    #[test]
    fn rejects_malformed_keys() {
        assert_eq!(parse_auth_key("hskey-auth-test"), None);
        assert_eq!(parse_auth_key("hskey-auth--secret"), None);
        assert_eq!(parse_auth_key("hskey-auth-test-"), None);
        assert_eq!(parse_auth_key("other-test-secret"), None);
    }

    #[test]
    fn hash_verifies_and_hides_secret() {
        let stored = hash_secret("s3cret");
        assert!(verify_secret("s3cret", &stored));
        assert!(!verify_secret("wrong", &stored));
        assert!(!stored.contains("s3cret"));
    }

    #[test]
    fn generated_secret_is_unique_and_hex() {
        let a = generate_secret();
        let b = generate_secret();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
