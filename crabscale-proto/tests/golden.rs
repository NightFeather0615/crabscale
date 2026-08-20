//! Golden tests for the JSON examples in the spec wiki pages.
//!
//! Each fixture under `tests/fixtures` contains the spec `input`, the
//! canonical `expected` serialization, and a `note` describing the behavior
//! being locked. Tests compare parsed-and-reserialized values as JSON, so
//! formatting differences do not matter.

use std::fmt::Debug;
use std::fs;
use std::path::Path;

use crabscale_proto::{EarlyNoise, MapRequest, MapResponse, RegisterRequest, RegisterResponse};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

#[derive(Debug, serde::Deserialize)]
struct Fixture {
    input: Value,
    expected: Value,
    #[serde(default)]
    note: String,
}

fn load_fixture(path: &str) -> Fixture {
    let text = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|e| panic!("failed to read fixture {path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("failed to parse fixture {path}: {e}"))
}

fn check<T>(path: &str)
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let fixture = load_fixture(path);
    let parsed: T = serde_json::from_value(fixture.input.clone())
        .unwrap_or_else(|e| panic!("failed to deserialize {path}: {e}"));
    let actual = serde_json::to_value(&parsed).expect("serialization must not fail");
    assert_eq!(
        actual, fixture.expected,
        "canonical serialization mismatch for {path} ({})",
        fixture.note
    );

    // Round-trip: the canonical form must deserialize back to the same value.
    let reparsed: T = serde_json::from_value(fixture.expected)
        .unwrap_or_else(|e| panic!("failed to reparse canonical form of {path}: {e}"));
    assert_eq!(reparsed, parsed, "round-trip mismatch for {path}");
}

#[test]
fn register_request_golden() {
    check::<RegisterRequest>("tests/fixtures/register/register-request.json");
}

#[test]
fn register_response_golden() {
    check::<RegisterResponse>("tests/fixtures/register/register-response.json");
}

#[test]
fn map_request_golden() {
    check::<MapRequest>("tests/fixtures/netmap/map-request.json");
}

#[test]
fn map_response_golden() {
    check::<MapResponse>("tests/fixtures/netmap/map-response.json");
}

#[test]
fn early_noise_golden() {
    check::<EarlyNoise>("tests/fixtures/transport/early-noise.json");
}
