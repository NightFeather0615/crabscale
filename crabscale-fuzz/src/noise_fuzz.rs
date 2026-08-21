//! Fuzz smoke target: TS2021 / Noise byte decoders.
//!
//! Feeds arbitrary stdin bytes to the init/response message parsers, the
//! per-connection early-payload decoder, and the record-frame decoder. Every
//! decoder must reject malformed input with an `Err` rather than panicking.

use std::io::Read;

fn main() {
    let mut data = Vec::new();
    std::io::stdin().read_to_end(&mut data).expect("read stdin");
    if std::panic::catch_unwind(|| run(&data)).is_err() {
        eprintln!("noise_fuzz: panic on {} bytes", data.len());
        std::process::exit(1);
    }
}

fn run(data: &[u8]) {
    let _ = crabscale_transport::parse_init_message(data);
    let _ = crabscale_transport::parse_response_message(data);
    let _ = crabscale_transport::decode_early_payload(data);

    // Record framing: a fixed directional cipher so decoding is deterministic.
    let mut cipher = crabscale_transport::RecordCipher::new([42u8; 32]);
    let _ = cipher.decode_one(data);

    // Streaming record decoder buffers partial frames and must not panic on
    // arbitrary boundaries either.
    let mut decoder = crabscale_transport::RecordDecoder::new([43u8; 32]);
    let _ = decoder.feed(data);
}
