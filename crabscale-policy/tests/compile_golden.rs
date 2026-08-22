//! Golden fixture tests for the ACL/grants compiler.
//!
//! Every `tests/fixtures/compile/<name>.hujson` policy is compiled against the
//! node set declared in `<name>.json`, and the resulting global filter,
//! per-node filters, and peer visibility must match the expected JSON byte for
//! byte. This is the golden "expected filter JSON" contract.

use std::fs;
use std::path::{Path, PathBuf};

use crabscale_policy::{CompileNode, compile_policy, parse_policy};
use serde_json::Value as JsonValue;

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join("compile")
}

fn fixture_paths() -> Vec<PathBuf> {
    let dir = fixtures_dir();
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("failed to read {dir:?}: {e}"))
        .map(|entry| entry.expect("read entry").path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "hujson"))
        .collect();
    paths.sort();
    paths
}

fn build_nodes(value: &JsonValue) -> Vec<CompileNode> {
    value["nodes"]
        .as_array()
        .expect("expected decompile JSON must declare `nodes`")
        .iter()
        .map(|n| CompileNode {
            id: n["id"].as_u64().expect("node id"),
            stable_id: n
                .get("stableId")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_default(),
            user_login: n
                .get("userLogin")
                .and_then(|v| v.as_str())
                .map(String::from),
            addresses: n["addresses"]
                .as_array()
                .expect("node addresses")
                .iter()
                .map(|a| a.as_str().expect("address string").to_string())
                .collect(),
            tags: n
                .get("tags")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .map(|t| t.as_str().expect("tag string").to_string())
                        .collect()
                })
                .unwrap_or_default(),
        })
        .collect()
}

fn compiled_json(compiled: &crabscale_policy::CompiledPolicy) -> JsonValue {
    serde_json::json!({
        "globalFilter": compiled.global_filter,
        "nodeFilters": compiled.node_filters,
        "peerVisibility": compiled.peer_visibility,
    })
}

#[test]
fn every_compile_fixture_matches_expected_filter_json() {
    for path in fixture_paths() {
        let policy_text = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        let policy = parse_policy(&policy_text)
            .unwrap_or_else(|e| panic!("valid policy {} must parse, got {e}", path.display()));

        let expected_path = path.with_extension("json");
        let expected_text = fs::read_to_string(&expected_path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", expected_path.display()));
        let expected: JsonValue = serde_json::from_str(&expected_text)
            .unwrap_or_else(|e| panic!("bad expected JSON {}: {e}", expected_path.display()));

        let nodes = build_nodes(&expected);
        let compiled = compile_policy(&policy, &nodes);

        let actual = compiled_json(&compiled);
        // The `nodes` key describes the compile input, not the output.
        let mut expected_output = expected.clone();
        expected_output.as_object_mut().unwrap().remove("nodes");
        assert_eq!(
            actual,
            expected_output,
            "compiled output for {} does not match expected golden JSON",
            path.display()
        );
    }
}

#[test]
fn deny_all_fixture_serializes_empty_base_filter() {
    let dir = fixtures_dir();
    let policy_text = fs::read_to_string(dir.join("deny-all.hujson")).unwrap();
    let policy = parse_policy(&policy_text).unwrap();
    let expected_text = fs::read_to_string(dir.join("deny-all.json")).unwrap();
    let expected: JsonValue = serde_json::from_str(&expected_text).unwrap();
    let nodes = build_nodes(&expected);
    let compiled = compile_policy(&policy, &nodes);

    let node_filters = compiled_json(&compiled);
    assert_eq!(
        node_filters["nodeFilters"]["1"],
        serde_json::json!([]),
        "deny-all must serialize an empty base filter as []"
    );
    let json = serde_json::to_value(serde_json::json!({
        "PacketFilters": { "base": compiled.node_filters.get(&1).unwrap() }
    }))
    .unwrap();
    assert_eq!(json["PacketFilters"]["base"], serde_json::json!([]));
}

#[test]
fn invisible_peer_is_absent_from_map() {
    let dir = fixtures_dir();
    let policy_text = fs::read_to_string(dir.join("peer-visibility.hujson")).unwrap();
    let policy = parse_policy(&policy_text).unwrap();
    let expected_text = fs::read_to_string(dir.join("peer-visibility.json")).unwrap();
    let expected: JsonValue = serde_json::from_str(&expected_text).unwrap();
    let nodes = build_nodes(&expected);
    let compiled = compile_policy(&policy, &nodes);

    // Node 3 is invisible in both directions: its peer set is empty and it is
    // absent from every other node's set.
    assert!(compiled.peer_visibility[&3].is_empty());
    assert!(!compiled.peer_visibility[&1].contains(&3));
    assert!(!compiled.peer_visibility[&2].contains(&3));
    assert!(compiled.peer_visibility[&1].contains(&2));
    assert!(compiled.peer_visibility[&2].contains(&1));
}
