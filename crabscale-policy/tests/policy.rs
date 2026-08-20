//! Fixture-driven tests for the HUJSON policy parser and model.
//!
//! Every file under `tests/fixtures/valid` must parse into a typed, validated
//! [`Policy`]. Every file under `tests/fixtures/invalid` must be rejected with
//! an error that carries a line number - including the minimal allow-all
//! example from [Spec-Policy].

use std::fs;
use std::path::{Path, PathBuf};

use crabscale_policy::{Acl, Policy, parse_policy};

fn fixtures_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn fixture_paths(dir_name: &str) -> Vec<PathBuf> {
    let dir = fixtures_dir(dir_name);
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("failed to read {dir:?}: {e}"))
        .map(|entry| entry.expect("read entry").path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "hujson"))
        .collect();
    paths.sort();
    paths
}

#[test]
fn all_valid_fixtures_parse() {
    for path in fixture_paths("valid") {
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        let policy = parse_policy(&text)
            .unwrap_or_else(|e| panic!("valid fixture {} must parse, got {e}", path.display()));
        assert_eq!(
            policy,
            parse_policy(&text).unwrap(),
            "parsing a valid fixture twice must be deterministic: {}",
            path.display()
        );
    }
}

#[test]
fn all_invalid_fixtures_fail_with_line() {
    for path in fixture_paths("invalid") {
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        let err = match parse_policy(&text) {
            Ok(ok) => panic!(
                "invalid fixture {} must fail, but parsed successfully: {ok:?}",
                path.display()
            ),
            Err(e) => e,
        };
        assert!(
            err.line >= 1,
            "error for {} must carry a line number, got {:?}",
            path.display(),
            err
        );
    }
}

#[test]
fn minimal_allow_all_example_parses_to_expected_model() {
    // The exact minimal allow-all policy from Spec-Policy.
    let text = r#"{
  // Accept all node-to-node traffic.
  "acls": [
    { "action": "accept", "src": ["*"], "dst": ["*:*"] }
  ]
}"#;
    let policy = parse_policy(text).expect("minimal allow-all must parse");
    assert_eq!(
        policy.acls,
        vec![Acl {
            action: "accept".to_string(),
            src: vec!["*".to_string()],
            dst: vec!["*:*".to_string()],
            proto: None,
        }]
    );
    assert_eq!(policy.groups.len(), 0);
    assert_eq!(policy.hosts.len(), 0);
    assert!(policy.grants.is_empty());
    assert!(policy.tag_owners.is_empty());
    assert!(policy.ssh.is_empty());
    assert!(policy.node_attrs.is_empty());
    assert!(policy.tests.is_empty());
    assert!(policy.ssh_tests.is_empty());
    let _ = Policy::default();
}
