//! Git command wrappers and bare repository management.
//!
//! All operations shell out to the `git` binary using `tokio::process::Command`
//! for non-blocking execution. SSH and PAT credential injection is handled
//! transparently through environment variables and URL rewriting.

pub mod bare_repo;
pub mod commands;

pub use bare_repo::{init_bare_repo, remove_repo, repo_size_bytes, set_remote, validate_bare_repo};
pub use commands::{
    git_bundle_create, git_bundle_unbundle, git_clone_bare, git_fetch, git_for_each_ref,
    git_ls_remote, git_upload_pack, git_upload_pack_streamed, FetchResult,
};
