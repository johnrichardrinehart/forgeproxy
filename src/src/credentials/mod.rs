//! Upstream credential retrieval.
//!
//! Loads PATs and SSH keys from the Linux kernel keyring or environment
//! variables, supporting per-organisation credential overrides.

pub mod keyring;
pub mod ssh_to_https;
pub mod upstream;
