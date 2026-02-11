//! SSH server module for the GHE caching reverse proxy.
//!
//! Accepts SSH connections from Git clients, authenticates them via public-key
//! verification (backed by KeyDB cache and GHE admin API), and serves
//! `git-upload-pack` from a local bare-repo cache or by proxying upstream to
//! GHE.  Push operations (`git-receive-pack`) are unconditionally rejected.

pub mod server;
pub mod session;
pub mod upstream;

pub use server::start_ssh_server;
