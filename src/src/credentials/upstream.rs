//! Upstream credential retrieval.
//!
//! Loads PATs and SSH keys from the Linux kernel keyring or environment
//! variables, supporting per-organisation credential overrides.
//!
//! Currently unused — the HTTP handler and SSH proxy build credentials inline
//! from environment variables and the application config.
