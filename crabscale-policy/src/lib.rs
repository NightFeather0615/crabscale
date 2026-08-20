//! HUJSON parser, typed policy model, and policy validation.
//!
//! This crate owns the access-control policy layer: parsing a HUJSON policy
//! file (JSON plus comments and trailing commas) into a typed model, and
//! validating that model so malformed policies are rejected with
//! line-numbered errors. Packet filter compilation and SSH behavior are
//! deliberately out of scope for the current milestone and will live in later
//! modules.
//!
//! Grammar and schema are documented in the project wiki:
//! [Spec-Policy](https://github.com/NightFeather0615/crabscale/wiki/Spec-Policy.md).

mod error;
mod hujson;
mod model;
mod validate;

pub use error::HujsonError;
pub use hujson::parse as parse_hujson;
pub use model::{Acl, AutoApprovers, Grant, NodeAttrGrant, Policy, PolicyTest, SshRule, SshTest};
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
