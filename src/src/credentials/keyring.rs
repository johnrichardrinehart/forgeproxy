//! Linux kernel keyring integration.
//!
//! Reads secrets from the session keyring via the `linux-keyutils` crate
//! (direct syscall) or the `keyctl` CLI tool as fallback.
//!
//! Currently unused — credentials are resolved from environment variables
//! at runtime.
