//! Least Frequently Used (LFU) eviction policy backed by KeyDB.
//!
//! Each clone/fetch increments a per-repo counter stored in the KeyDB hash
//! `forgecache:repo:{owner/repo}` under the `clone_count` field.  When the cache
//! manager needs to free space, this module ranks repos by ascending clone
//! count and returns the least-accessed ones as eviction candidates.
//!
//! Repos that are marked as "pinned" via the `eviction_priority` field in
//! their KeyDB hash are never returned as eviction candidates.

use anyhow::Result;
use fred::interfaces::HashesInterface;
use tracing::debug;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Return up to `count` repos from `repos` ordered by ascending clone count
/// (least frequently used first).
///
/// Repos whose `eviction_priority` field is set to `"pinned"` in KeyDB are
/// excluded and will never be returned as eviction candidates.
pub async fn get_eviction_candidates(
    keydb: &fred::clients::Pool,
    repos: &[String],
    count: usize,
) -> Result<Vec<String>> {
    if repos.is_empty() || count == 0 {
        return Ok(Vec::new());
    }

    let mut scored: Vec<(String, i64)> = Vec::with_capacity(repos.len());

    for owner_repo in repos {
        let key = repo_key(owner_repo);

        // Fetch both clone_count and eviction_priority in one round-trip.
        let clone_count: Option<i64> = keydb.hget(&key, "clone_count").await.unwrap_or(None);

        let priority: Option<String> = keydb.hget(&key, "eviction_priority").await.unwrap_or(None);

        // Never evict pinned repos.
        if priority.as_deref() == Some("pinned") {
            debug!(repo = %owner_repo, "skipping pinned repo for eviction");
            continue;
        }

        scored.push((owner_repo.clone(), clone_count.unwrap_or(0)));
    }

    // Sort ascending by clone count (lowest count = least frequently used).
    scored.sort_by_key(|(_repo, count)| *count);

    let candidates: Vec<String> = scored
        .into_iter()
        .take(count)
        .map(|(repo, _count)| repo)
        .collect();

    debug!(
        candidate_count = candidates.len(),
        requested = count,
        "selected LFU eviction candidates"
    );

    Ok(candidates)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the KeyDB hash key for a given `owner/repo`.
fn repo_key(owner_repo: &str) -> String {
    format!("forgecache:repo:{owner_repo}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_key_format() {
        assert_eq!(repo_key("acme/widgets"), "forgecache:repo:acme/widgets");
    }
}
