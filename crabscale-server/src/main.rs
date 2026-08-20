//! Server binary: wiring, config, TLS, HTTP routers, and metrics.
//!
//! This milestone wires the persisted server machine key and exposes the
//! control router library. The full outer HTTP server (TLS, `/ts2021`
//! upgrade, and `/key` over HTTP) is layered on top in later milestones.

use std::path::PathBuf;

use clap::Parser;
use crabscale_server::{DEFAULT_KEY_FILE, load_or_create_machine_key};

/// crabscale control server.
#[derive(Parser)]
#[command(name = "crabscale-server", about = "crabscale control server")]
struct Args {
    /// Path to the server machine key file.
    #[arg(default_value = DEFAULT_KEY_FILE)]
    key_file: PathBuf,
}

fn main() {
    let args = Args::parse();

    match load_or_create_machine_key(&args.key_file) {
        Ok(key) => {
            println!("server machine key: {}", key.public_key());
            println!("key file: {}", args.key_file.display());
        }
        Err(e) => {
            eprintln!("failed to load or create machine key: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_default_key_file() {
        let args = Args::try_parse_from(["crabscale-server"]).unwrap();
        assert_eq!(args.key_file, PathBuf::from(DEFAULT_KEY_FILE));
    }

    #[test]
    fn accepts_positional_key_file() {
        let args = Args::try_parse_from(["crabscale-server", "custom.key"]).unwrap();
        assert_eq!(args.key_file, PathBuf::from("custom.key"));
    }
}
