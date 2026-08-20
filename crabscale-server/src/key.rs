//! Server machine key generation and persistence.
//!
//! The server's long-term Noise static key is persisted as a raw 32-byte file
//! with `0600` permissions. The public half is exposed as a [`MachineKey`] for
//! the `/key` endpoint and for attaching to inner requests.

use std::fs;
use std::io;
use std::path::Path;

use crabscale_proto::MachineKey;
use crabscale_transport::NoiseResponder;
use x25519_dalek::StaticSecret;

/// Default file name for the persisted server machine key.
pub const DEFAULT_KEY_FILE: &str = "crabscale.key";

/// A loaded server key: the Noise responder plus its public machine key.
#[derive(Clone)]
pub struct ServerKey {
    responder: NoiseResponder,
    public: MachineKey,
}

impl ServerKey {
    /// The Noise responder used for the TS2021 handshake.
    pub fn responder(&self) -> &NoiseResponder {
        &self.responder
    }

    /// The long-term machine public key advertised by `/key`.
    pub fn public_key(&self) -> MachineKey {
        self.public
    }
}

/// Load a server key from `path`, generating and persisting a new one if the
/// file does not exist.
pub fn load_or_create_machine_key(path: &Path) -> io::Result<ServerKey> {
    let secret = if path.exists() {
        let bytes = fs::read(path)?;
        if bytes.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "machine key file must contain exactly 32 bytes",
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    } else {
        let secret = StaticSecret::random();
        let bytes = secret.to_bytes();
        persist_machine_key(path, &bytes)?;
        bytes
    };

    let responder = NoiseResponder::from_bytes(secret);
    let public = MachineKey::from_bytes(responder.public_key().to_bytes());
    Ok(ServerKey { responder, public })
}

/// Persist a raw 32-byte machine key to `path` with `0600` permissions.
pub fn persist_machine_key(path: &Path, key: &[u8; 32]) -> io::Result<()> {
    fs::write(path, key)?;
    set_0600(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_0600(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn set_0600(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_and_round_trips_key() {
        let dir = std::env::temp_dir().join(format!("crabscale-key-test-{}", std::process::id()));
        let path = dir.join(DEFAULT_KEY_FILE);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let key = load_or_create_machine_key(&path).unwrap();
        let reloaded = load_or_create_machine_key(&path).unwrap();
        assert_eq!(key.public_key(), reloaded.public_key());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_wrong_length_file() {
        let dir = std::env::temp_dir().join(format!("crabscale-key-bad-{}", std::process::id()));
        let path = dir.join(DEFAULT_KEY_FILE);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(&path, [0u8; 16]).unwrap();
        assert!(load_or_create_machine_key(&path).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
