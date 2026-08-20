//! HUJSON parser, typed policy model, policy validation, and the ACL/grants
//! compiler.
//!
//! This crate owns the access-control policy layer: parsing a HUJSON policy
//! file (JSON plus comments and trailing commas) into a typed model,
//! validating that model so malformed policies are rejected with
//! line-numbered errors, and compiling ACLs/grants into per-node packet
//! filters, peer visibility, and capability grants.
//!
//! Grammar and schema are documented in the project wiki:
//! [Spec-Policy](https://github.com/NightFeather0615/crabscale/wiki/Spec-Policy.md).

mod compile;
mod error;
mod hujson;
mod model;
mod routes;
mod tags;
mod validate;

pub use compile::{CompileNode, CompiledPolicy, compile_policy, node_attributes};
pub use error::HujsonError;
pub use hujson::parse as parse_hujson;
pub use model::{Acl, AutoApprovers, Grant, NodeAttrGrant, Policy, PolicyTest, SshRule, SshTest};
pub use routes::{auto_approved_routes, canonical_route, is_exit_route, is_route};
pub use tags::{is_valid_tag, tag_owned_by_tags, unauthorized_tags, user_can_use_tag};
pub use validate::{validate_policy, validate_unknown_keys};

/// Parse a HUJSON policy document into a typed, validated [`Policy`].
///
/// The document is first parsed as HUJSON (comments and trailing commas are
/// accepted, duplicate keys and syntax errors are rejected with a line
/// number), then converted into the typed model, and finally validated
/// semantically. This function never panics on malformed input.
pub fn parse_policy(source: &str) -> Result<Policy, HujsonError> {
    let value = hujson::parse(source)?;
    validate_unknown_keys(source, &value)?;
    let policy: Policy = serde_json::from_value(value)
        .map_err(|err| HujsonError::at_line(1, format!("invalid policy value: {err}")))?;
    validate_policy(source, &policy)?;
    Ok(policy)
}
