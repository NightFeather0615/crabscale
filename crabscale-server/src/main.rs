//! Server binary: wiring, config, TLS, HTTP routers, and metrics.
//!
//! This milestone wires the persisted server machine key and exposes the
//! control router library. The full outer HTTP server (TLS, `/ts2021`
//! upgrade, and `/key` over HTTP) is layered on top in later milestones.

use std::path::PathBuf;

use crabscale_server::{DEFAULT_KEY_FILE, load_or_create_machine_key};

fn main() {
    let key_file = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_KEY_FILE));

    match load_or_create_machine_key(&key_file) {
        Ok(key) => {
            println!("server machine key: {}", key.public_key());
            println!("key file: {}", key_file.display());
        }
        Err(e) => {
            eprintln!("failed to load or create machine key: {e}");
            std::process::exit(1);
        }
    }
}
