//! Fuzz smoke target: DERP frame codecs.
//!
//! Feeds arbitrary stdin bytes to the byte-level `FrameHeader::decode` /
//! `decode_frame` helpers and the streaming `FrameDecoder`. All of them must
//! reject malformed prefixes and payloads without panicking.

use std::io::Read;

fn main() {
    let mut data = Vec::new();
    std::io::stdin().read_to_end(&mut data).expect("read stdin");
    if std::panic::catch_unwind(|| run(&data)).is_err() {
        eprintln!("derp_fuzz: panic on {} bytes", data.len());
        std::process::exit(1);
    }
}

fn run(data: &[u8]) {
    let _ = crabscale_derp::FrameHeader::decode(data);
    let _ = crabscale_derp::decode_frame(data);

    let mut decoder = crabscale_derp::FrameDecoder::new();
    let _ = decoder.feed(data);
}
