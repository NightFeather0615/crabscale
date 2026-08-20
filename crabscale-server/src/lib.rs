//! Server library: control router, machine key persistence, and wiring.
//!
//! This crate owns the server-side control plane: the outer `/key` endpoint,
//! the inner `/machine/*` router served over HTTP/2-over-Noise, and the
//! persisted server machine key.

pub mod http;
pub mod key;
pub mod router;

pub use http::{ServerHandle, serve, serve_on_addr};
pub use key::{DEFAULT_KEY_FILE, ServerKey, load_or_create_machine_key, persist_machine_key};
pub use router::{ControlRouter, PROTOCOL_VERSION, serve_control};
