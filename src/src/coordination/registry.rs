use std::collections::HashMap;

use anyhow::{Context, Result};
use base64::Engine;
use fred::interfaces::{ClientLike, HashesInterface};
use fred::types::CustomCommand;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

/// Metadata about a cached repository.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepoInfo {
    pub status: String,
    /// Comma-separated list of node IDs that hold a local clone.
    pub node_ids: String,
    /// S3 key where the bundle-list manifest is stored.
    pub s3_bundle_list_key: String,
    /// Unix timestamp of the last successful fetch from the origin.
    pub last_fetch_ts: i64,
    /// Unix timestamp of the last bundle creation.
    pub last_bundle_ts: i64,
    /// Monotonically increasing creation token for bundle URI protocol.
    pub latest_creation_token: u64,
    /// SHA-256 of the sorted refs advertisement — used for change detection.
    pub refs_hash: String,
    /// Approximate repository size on disk.
    pub size_bytes: u64,
    /// Lifetime clone counter.
    pub clone_count: u64,
}

/// Adaptive fetch schedule for a repository.
#[derive(Debug, Clone, Default)]
pub struct FetchSchedule {
    pub current_interval: u64,
    pub rolling_avg_delta: u64,
    pub delta_threshold: u64,
    pub max_interval: u64,
    pub last_delta_bytes: u64,
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

pub(crate) fn repo_key(owner_repo: &str) -> String {
    // Normalize: strip trailing ".git" so that "owner/repo" and
    // "owner/repo.git" map to the same KeyDB key.
    let normalized = owner_repo.strip_suffix(".git").unwrap_or(owner_repo);
    format!("forgecache:repo:{normalized}")
}

fn fetch_schedule_key(owner_repo: &str) -> String {
    let normalized = owner_repo.strip_suffix(".git").unwrap_or(owner_repo);
    format!("forgecache:repo:{normalized}:fetch_schedule")
}

// ---------------------------------------------------------------------------
// RepoInfo helpers — convert to/from a flat HashMap for HSET / HGETALL
// ---------------------------------------------------------------------------

fn repo_info_to_pairs(info: &RepoInfo) -> Vec<(String, String)> {
    vec![
        ("status".into(), info.status.clone()),
        ("node_ids".into(), info.node_ids.clone()),
        ("s3_bundle_list_key".into(), info.s3_bundle_list_key.clone()),
        ("last_fetch_ts".into(), info.last_fetch_ts.to_string()),
        ("last_bundle_ts".into(), info.last_bundle_ts.to_string()),
        (
            "latest_creation_token".into(),
            info.latest_creation_token.to_string(),
        ),
        ("refs_hash".into(), info.refs_hash.clone()),
        ("size_bytes".into(), info.size_bytes.to_string()),
        ("clone_count".into(), info.clone_count.to_string()),
    ]
}

fn repo_info_from_map(map: HashMap<String, String>) -> RepoInfo {
    RepoInfo {
        status: map.get("status").cloned().unwrap_or_default(),
        node_ids: map.get("node_ids").cloned().unwrap_or_default(),
        s3_bundle_list_key: map.get("s3_bundle_list_key").cloned().unwrap_or_default(),
        last_fetch_ts: map
            .get("last_fetch_ts")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        last_bundle_ts: map
            .get("last_bundle_ts")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        latest_creation_token: map
            .get("latest_creation_token")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        refs_hash: map.get("refs_hash").cloned().unwrap_or_default(),
        size_bytes: map
            .get("size_bytes")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        clone_count: map
            .get("clone_count")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Retrieve full repo metadata.  Returns `None` if the key does not exist.
pub async fn get_repo_info(
    pool: &fred::clients::Pool,
    owner_repo: &str,
) -> Result<Option<RepoInfo>> {
    let key = repo_key(owner_repo);
    let map: HashMap<String, String> = pool.hgetall(&key).await.context("HGETALL repo info")?;
    if map.is_empty() {
        trace!(%owner_repo, "repo info not found");
        return Ok(None);
    }
    Ok(Some(repo_info_from_map(map)))
}

/// Write full repo metadata (overwrites all fields).
pub async fn set_repo_info(
    pool: &fred::clients::Pool,
    owner_repo: &str,
    info: &RepoInfo,
) -> Result<()> {
    let key = repo_key(owner_repo);
    let pairs = repo_info_to_pairs(info);
    let _: () = pool.hset(&key, pairs).await.context("HSET repo info")?;
    debug!(%owner_repo, "repo info written");
    Ok(())
}

/// Update a single field of repo metadata.
pub async fn update_repo_field(
    pool: &fred::clients::Pool,
    owner_repo: &str,
    field: &str,
    value: &str,
) -> Result<()> {
    let key = repo_key(owner_repo);
    let _: () = pool
        .hset(&key, vec![(field.to_string(), value.to_string())])
        .await
        .context("HSET single field")?;
    trace!(%owner_repo, %field, %value, "repo field updated");
    Ok(())
}

/// Retrieve the adaptive fetch schedule for a repository.
pub async fn get_fetch_schedule(
    pool: &fred::clients::Pool,
    owner_repo: &str,
) -> Result<Option<FetchSchedule>> {
    let key = fetch_schedule_key(owner_repo);
    let map: HashMap<String, String> =
        pool.hgetall(&key).await.context("HGETALL fetch_schedule")?;
    if map.is_empty() {
        return Ok(None);
    }
    Ok(Some(FetchSchedule {
        current_interval: map
            .get("current_interval")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        rolling_avg_delta: map
            .get("rolling_avg_delta")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        delta_threshold: map
            .get("delta_threshold")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        max_interval: map
            .get("max_interval")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        last_delta_bytes: map
            .get("last_delta_bytes")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
    }))
}

/// Write the adaptive fetch schedule for a repository.
pub async fn set_fetch_schedule(
    pool: &fred::clients::Pool,
    owner_repo: &str,
    schedule: &FetchSchedule,
) -> Result<()> {
    let key = fetch_schedule_key(owner_repo);
    let pairs: Vec<(String, String)> = vec![
        (
            "current_interval".into(),
            schedule.current_interval.to_string(),
        ),
        (
            "rolling_avg_delta".into(),
            schedule.rolling_avg_delta.to_string(),
        ),
        (
            "delta_threshold".into(),
            schedule.delta_threshold.to_string(),
        ),
        ("max_interval".into(), schedule.max_interval.to_string()),
        (
            "last_delta_bytes".into(),
            schedule.last_delta_bytes.to_string(),
        ),
    ];
    let _: () = pool
        .hset(&key, pairs)
        .await
        .context("HSET fetch_schedule")?;
    debug!(%owner_repo, "fetch schedule written");
    Ok(())
}

/// Check whether a repository is cached locally and still within its freshness
/// threshold.  Returns `true` if a local clone exists AND the last fetch
/// timestamp is within the configured (or per-repo override) window.
pub async fn is_repo_cached_and_fresh(state: &crate::AppState, owner_repo: &str) -> Result<bool> {
    // Check local presence first.
    if !state.cache_manager.has_repo(owner_repo) {
        return Ok(false);
    }

    // Look up the last fetch timestamp in KeyDB.
    let info = get_repo_info(&state.keydb, owner_repo).await?;
    let last_fetch_ts = match info {
        Some(ref ri) => ri.last_fetch_ts as u64,
        None => return Ok(false),
    };

    // Determine the freshness threshold (per-repo override or global).
    let threshold = state
        .config
        .repo_overrides
        .get(owner_repo)
        .and_then(|o| o.freshness_threshold)
        .unwrap_or(state.config.clone.freshness_threshold);

    let now = chrono::Utc::now().timestamp() as u64;
    Ok(last_fetch_ts + threshold > now)
}

/// Ensure that a bare clone of `owner/repo` exists on this node.
///
/// Acquires a distributed lock so that only one node clones at a time.  If
/// the lock is already held, waits for the cloning node to finish.  After the
/// clone completes the repo is registered in KeyDB and a "ready" notification
/// is published.
pub async fn ensure_repo_cloned(
    state: &crate::AppState,
    owner: &str,
    repo: &str,
    auth_header: &str,
) -> Result<()> {
    // Strip trailing ".git" from repo if present to avoid double-suffixing
    // (the URL path extractor preserves it, and we append ".git" below).
    let repo_clean = repo.strip_suffix(".git").unwrap_or(repo);
    let owner_repo = format!("{owner}/{repo_clean}");
    let lock_key = format!("forgecache:lock:clone:{owner_repo}");
    let node_id = crate::coordination::node::node_id();

    // Try to acquire the distributed clone lock.
    let lock_acquired = crate::coordination::locks::acquire_lock(
        &state.keydb,
        &lock_key,
        &node_id,
        state.config.clone.lock_ttl,
    )
    .await?;

    if !lock_acquired {
        // Another node is cloning; wait for it.
        let timeout = std::time::Duration::from_secs(state.config.clone.lock_wait_timeout);
        crate::coordination::locks::wait_for_lock(&state.keydb, &lock_key, timeout).await?;
        return Ok(());
    }

    // We hold the lock — perform the clone.
    let result = async {
        let repo_path = state.cache_manager.ensure_repo_dir(&owner_repo)?;

        // Build the GHE clone URL with embedded credentials.
        // For Basic auth, decode the base64 to recover "user:pass" and embed
        // directly in the URL.  For Bearer/token auth, use the x-access-token
        // format understood by GitHub/Gitea.
        let clone_url = if let Some(b64) = auth_header.strip_prefix("Basic ") {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .unwrap_or_default();
            format!(
                "https://{decoded}@{}/{owner}/{repo_clean}.git",
                state.config.upstream.hostname,
            )
        } else {
            let token = auth_header
                .strip_prefix("Bearer ")
                .or_else(|| auth_header.strip_prefix("token "))
                .unwrap_or(auth_header);
            format!(
                "https://x-access-token:{token}@{}/{owner}/{repo_clean}.git",
                state.config.upstream.hostname,
            )
        };

        // Acquire the clone semaphore to respect concurrency limits.
        let _permit = state
            .clone_semaphore
            .acquire()
            .await
            .map_err(|e| anyhow::anyhow!("clone semaphore closed: {e}"))?;

        let env_vars: Vec<(String, String)> =
            vec![("GIT_TERMINAL_PROMPT".to_string(), "0".to_string())];

        crate::git::commands::git_clone_bare(&clone_url, &repo_path, &env_vars).await?;

        // Register in KeyDB.
        let now = chrono::Utc::now().timestamp();
        let info = RepoInfo {
            status: "ready".to_string(),
            node_ids: node_id.clone(),
            last_fetch_ts: now,
            ..Default::default()
        };
        set_repo_info(&state.keydb, &owner_repo, &info).await?;

        // Publish ready notification.
        crate::coordination::pubsub::publish_ready(&state.keydb, &owner_repo, &node_id).await?;

        Ok::<(), anyhow::Error>(())
    }
    .await;

    // Always release the lock.
    let _ = crate::coordination::locks::release_lock(&state.keydb, &lock_key, &node_id).await;

    result
}

/// List all tracked repository names by scanning for `forgecache:repo:*` keys
/// (excluding `:fetch_schedule` sub-keys).
///
/// Uses the `KEYS` command which is acceptable for small-to-moderate key
/// spaces.  For very large deployments consider replacing with `SCAN`.
pub async fn list_all_repos(pool: &fred::clients::Pool) -> Result<Vec<String>> {
    let keys: Vec<String> = pool
        .custom(
            CustomCommand::new_static("KEYS", None::<u16>, false),
            vec!["forgecache:repo:*".to_string()],
        )
        .await
        .context("KEYS forgecache:repo:*")?;

    let repos: Vec<String> = keys
        .into_iter()
        .filter_map(|k| {
            // Skip sub-keys like forgecache:repo:owner/name:fetch_schedule
            let stripped = k.strip_prefix("forgecache:repo:")?;
            // A valid owner/repo has exactly one '/' and no trailing sub-key
            if stripped.matches(':').count() > 0 {
                return None;
            }
            if stripped.contains('/') {
                Some(stripped.to_string())
            } else {
                None
            }
        })
        .collect();

    debug!(count = repos.len(), "listed all repos");
    Ok(repos)
}
