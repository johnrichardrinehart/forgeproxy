//! Authentication and authorisation subsystem.
//!
//! Provides validation of SSH public keys and HTTP Basic / Bearer credentials
//! against the upstream forge API, with a Valkey-backed cache layer.

pub mod cache;
pub mod http_validator;
pub mod middleware;
pub mod ssh_resolver;
pub mod webhook;
