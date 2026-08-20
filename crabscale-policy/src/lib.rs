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

pub use error::HujsonError;
pub use hujson::parse as parse_hujson;
