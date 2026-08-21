//! Fuzz smoke target: hermetic JSON decoders for the control wire types.
//!
//! Reads arbitrary bytes on stdin and feeds them to every wire-type JSON
//! decoder plus the generic JSON parser. Malformed input must be rejected
//! with an `Err`, never with a panic. The fuzz-smoke CI script treats a panic
//! (nonzero exit) as a crash.

use std::io::Read;

fn main() {
    let mut data = Vec::new();
    std::io::stdin().read_to_end(&mut data).expect("read stdin");
    if std::panic::catch_unwind(|| run(&data)).is_err() {
        eprintln!("json_fuzz: panic on {} bytes", data.len());
        std::process::exit(1);
    }
}

fn run(data: &[u8]) {
    // Generic JSON first: any valid JSON must round-trip.
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = serde_json::to_vec(&value);
    }
    // Control wire types. Each decoder must reject garbage without panicking.
    let _ = serde_json::from_slice::<crabscale_proto::RegisterRequest>(data);
    let _ = serde_json::from_slice::<crabscale_proto::RegisterResponse>(data);
    let _ = serde_json::from_slice::<crabscale_proto::MapRequest>(data);
    let _ = serde_json::from_slice::<crabscale_proto::MapResponse>(data);
    let _ = serde_json::from_slice::<crabscale_proto::LogoutRequest>(data);
    let _ = serde_json::from_slice::<crabscale_proto::VerifyRequest>(data);
    let _ = serde_json::from_slice::<crabscale_proto::VerifyResponse>(data);
    let _ = serde_json::from_slice::<crabscale_proto::Hostinfo>(data);
    let _ = serde_json::from_slice::<crabscale_proto::DerpMap>(data);
}
