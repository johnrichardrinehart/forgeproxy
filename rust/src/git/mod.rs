//! Git command wrappers and bare repository management.
//!
//! All operations shell out to the `git` binary using `tokio::process::Command`
//! for non-blocking execution. SSH and PAT credential injection is handled
//! transparently through environment variables and URL rewriting.

pub mod bare_repo;
pub mod commands;
