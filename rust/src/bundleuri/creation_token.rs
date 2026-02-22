//! Monotonic creation token management for Git bundle-URI.
//!
//! Each bundle in a bundle-list carries a `creationToken` that clients use to
//! determine which bundles they already have (from a previous clone or fetch)
//! and which they still need.  Tokens must be **strictly monotonically
//! increasing** within a given repository's bundle-list.
//!
//! This module provides two strategies for assigning tokens:
//!
//! 1. **Atomic counter** ([`next_creation_token`]) -- increments a per-repo
//!    counter in KeyDB by a fixed step (1000) to leave room for manual
//!    insertions.  This is the primary strategy used during incremental bundle
//!    generation.
//!
//! 2. **Deterministic timestamp-based** ([`creation_token_for_bundle_type`]) --
//!    derives a token from the bundle type and the current UTC timestamp.
//!    This is used for consolidation bundles where a predictable token value
//!    simplifies reasoning about ordering (base < daily < hourly).

use anyhow::{Context, Result};
use fred::interfaces::HashesInterface;

// ---------------------------------------------------------------------------
// Atomic counter
// ---------------------------------------------------------------------------

/// Atomically allocate the next creation token for a repository.
///
/// Increments the `latest_creation_token` field in the repo's KeyDB hash
/// by 1000 and returns the new value.  The step of 1000 leaves room for
/// out-of-band insertions or manual corrections without risking collisions.
///
/// Key: `forgeproxy:repo:{owner_repo}`, field: `latest_creation_token`.
pub async fn next_creation_token(state: &crate::AppState, owner_repo: &str) -> Result<u64> {
    let key = format!("forgeproxy:repo:{owner_repo}");
    let new_val: i64 = HashesInterface::hincrby(&state.keydb, &key, "latest_creation_token", 1000)
        .await
        .with_context(|| format!("failed to increment creation token for {owner_repo}"))?;
    Ok(new_val as u64)
}
