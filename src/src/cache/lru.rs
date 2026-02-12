//! Least Recently Used (LRU) eviction policy backed by KeyDB.
//!
//! Ranks repos by ascending `last_fetch_ts` — repos that were fetched longest
//! ago are evicted first.
//!
//! Repos that are marked as "pinned" via the `eviction_priority` field in
//! their KeyDB hash are never returned as eviction candidates.

use anyhow::Result;
use fred::interfaces::HashesInterface;
use tracing::debug;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Return up to `count` repos from `repos` ordered by ascending last-fetch
/// timestamp (least recently used first).
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
        let key = crate::coordination::registry::repo_key(owner_repo);

        let last_fetch_ts: Option<i64> = keydb.hget(&key, "last_fetch_ts").await.unwrap_or(None);

        let priority: Option<String> = keydb.hget(&key, "eviction_priority").await.unwrap_or(None);

        // Never evict pinned repos.
        if priority.as_deref() == Some("pinned") {
            debug!(repo = %owner_repo, "skipping pinned repo for eviction");
            continue;
        }

        scored.push((owner_repo.clone(), last_fetch_ts.unwrap_or(0)));
    }

    // Sort ascending by last_fetch_ts (oldest fetch = least recently used).
    scored.sort_by_key(|(_repo, ts)| *ts);

    let candidates: Vec<String> = scored
        .into_iter()
        .take(count)
        .map(|(repo, _ts)| repo)
        .collect();

    debug!(
        candidate_count = candidates.len(),
        requested = count,
        "selected LRU eviction candidates"
    );

    Ok(candidates)
}

#[cfg(test)]
mod tests {
    #[test]
    fn repo_key_format() {
        assert_eq!(
            crate::coordination::registry::repo_key("acme/widgets"),
            "forgecache:repo:acme/widgets",
        );
    }
}
