use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use base64::Engine;
use fred::interfaces::{ClientLike, HashesInterface, SortedSetsInterface};
use fred::types::CustomCommand;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, trace};

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
    // "owner/repo.git" map to the same Valkey key.
    let normalized = owner_repo.strip_suffix(".git").unwrap_or(owner_repo);
    format!("forgeproxy:repo:{normalized}")
}

fn fetch_schedule_key(owner_repo: &str) -> String {
    let normalized = owner_repo.strip_suffix(".git").unwrap_or(owner_repo);
    format!("forgeproxy:repo:{normalized}:fetch_schedule")
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

    // Look up the last fetch timestamp in Valkey.
    let info = get_repo_info(&state.valkey, owner_repo).await?;
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

/// Ensure that a bare clone of `owner/repo` exists on this node, but do not
/// wait if another node/task is already hydrating it.
///
/// This is intended for fire-and-forget background hydration triggered by live
/// client traffic. At most one hydrator should actively clone a repo at a time;
/// duplicate attempts should simply observe the held lock and return.
pub async fn try_ensure_repo_cloned(
    state: &crate::AppState,
    owner: &str,
    repo: &str,
    auth_header: Option<&str>,
) -> Result<()> {
    // Strip trailing ".git" from repo if present to avoid double-suffixing
    // (the URL path extractor preserves it, and we append ".git" below).
    let repo_clean = repo.strip_suffix(".git").unwrap_or(repo);
    let owner_repo = format!("{owner}/{repo_clean}");
    let lock_key = format!("forgeproxy:lock:clone:{owner_repo}");
    let node_id = crate::coordination::node::node_id();

    // Try to acquire the distributed clone lock.
    let lock_acquired = crate::coordination::locks::acquire_lock(
        &state.valkey,
        &lock_key,
        &node_id,
        state.config.clone.lock_ttl,
    )
    .await?;

    if !lock_acquired {
        debug!(%owner_repo, "hydrate already in progress; skipping duplicate background clone");
        return Ok(());
    }

    // We hold the lock — perform the clone.
    let result = async {
        let repo_path = state.cache_manager.ensure_repo_dir(&owner_repo)?;
        reset_partial_repo_if_needed(&state.cache_manager, &owner_repo, &repo_path).await?;

        match try_restore_repo_from_s3(state, &owner_repo, &repo_path).await {
            Ok(true) => {
                let now = chrono::Utc::now().timestamp();
                let mut info = get_repo_info(&state.valkey, &owner_repo)
                    .await?
                    .unwrap_or_default();
                info.status = "ready".to_string();
                info.node_ids = node_id.clone();
                if info.last_fetch_ts == 0 {
                    info.last_fetch_ts = now;
                }
                set_repo_info(&state.valkey, &owner_repo, &info).await?;
                crate::coordination::pubsub::publish_ready(&state.valkey, &owner_repo, &node_id)
                    .await?;
                info!(%owner_repo, "repo hydrated from S3 bundle");
                return Ok::<(), anyhow::Error>(());
            }
            Ok(false) => {}
            Err(error) => {
                info!(
                    %owner_repo,
                    error = %error,
                    "S3 hydration unavailable; falling back to upstream clone"
                );
                if repo_path.exists() {
                    tokio::fs::remove_dir_all(&repo_path)
                        .await
                        .with_context(|| {
                            format!(
                                "failed to remove failed S3 hydration repo at {}",
                                repo_path.display()
                            )
                        })?;
                }
            }
        }

        // Build the upstream clone URL with embedded credentials.
        // For Basic auth, decode the base64 to recover "user:pass" and embed
        // directly in the URL.  For Bearer/token auth, use the x-access-token
        // format understood by GitHub/Gitea.
        let clone_url = if let Some(b64) = auth_header.and_then(|h| h.strip_prefix("Basic ")) {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .unwrap_or_default();
            format!(
                "https://{decoded}@{}/{owner}/{repo_clean}.git",
                state.config.upstream.hostname,
            )
        } else if let Some(header) = auth_header.filter(|h| !h.trim().is_empty()) {
            let token = header
                .strip_prefix("Bearer ")
                .or_else(|| header.strip_prefix("token "))
                .unwrap_or(header);
            format!(
                "https://x-access-token:{token}@{}/{owner}/{repo_clean}.git",
                state.config.upstream.hostname,
            )
        } else {
            format!(
                "https://{}/{owner}/{repo_clean}.git",
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

        let bundle =
            crate::bundleuri::generator::generate_full_bundle(state, &repo_path, &owner_repo)
                .await
                .with_context(|| format!("failed to generate bootstrap bundle for {owner_repo}"))?;

        let s3_key = format!(
            "{}{}/bundles/{}.bundle",
            state.config.storage.s3.prefix, owner_repo, bundle.creation_token,
        );
        crate::storage::s3::upload_bundle(
            &state.s3_client,
            &state.config.storage.s3.bucket,
            &s3_key,
            &bundle.bundle_path,
        )
        .await
        .with_context(|| format!("failed to upload bootstrap bundle for {owner_repo}"))?;

        register_bundle_in_valkey(
            state,
            &owner_repo,
            &repo_path,
            &s3_key,
            bundle.creation_token,
        )
        .await?;

        // Register in Valkey.
        let now = chrono::Utc::now().timestamp();
        let info = RepoInfo {
            status: "ready".to_string(),
            node_ids: node_id.clone(),
            last_fetch_ts: now,
            last_bundle_ts: now,
            latest_creation_token: bundle.creation_token,
            ..Default::default()
        };
        set_repo_info(&state.valkey, &owner_repo, &info).await?;

        // Publish ready notification.
        crate::coordination::pubsub::publish_ready(&state.valkey, &owner_repo, &node_id).await?;

        Ok::<(), anyhow::Error>(())
    }
    .await;

    // Always release the lock.
    let _ = crate::coordination::locks::release_lock(&state.valkey, &lock_key, &node_id).await;

    result
}

async fn reset_partial_repo_if_needed(
    cache_manager: &crate::cache::CacheManager,
    owner_repo: &str,
    repo_path: &Path,
) -> Result<()> {
    if repo_path.exists() && !cache_manager.has_repo(owner_repo) {
        tokio::fs::remove_dir_all(repo_path)
            .await
            .with_context(|| format!("failed to remove partial repo at {}", repo_path.display()))?;
    }
    Ok(())
}

async fn try_restore_repo_from_s3(
    state: &crate::AppState,
    owner_repo: &str,
    repo_path: &Path,
) -> Result<bool> {
    let repo_key = repo_key(owner_repo);
    let latest_bundle_s3_key: Option<String> =
        HashesInterface::hget(&state.valkey, &repo_key, "latest_bundle_s3_key")
            .await
            .unwrap_or(None);
    let base_bundle_s3_key: Option<String> =
        HashesInterface::hget(&state.valkey, &repo_key, "base_bundle_s3_key")
            .await
            .unwrap_or(None);
    let Some(s3_key) = latest_bundle_s3_key.or(base_bundle_s3_key) else {
        return Ok(false);
    };

    let tmp_dir = tempfile::tempdir().context("failed to create temp dir for S3 hydration")?;
    let bundle_path = tmp_dir.path().join("hydrate.bundle");
    crate::storage::s3::download_to_path(
        &state.s3_client,
        &state.config.storage.s3.bucket,
        &s3_key,
        &bundle_path,
    )
    .await
    .with_context(|| format!("failed to download S3 bundle for {owner_repo}"))?;

    crate::git::commands::git_init_bare(repo_path).await?;
    crate::git::commands::git_fetch_bundle(repo_path, &bundle_path).await?;

    Ok(state.cache_manager.has_repo(owner_repo))
}

async fn register_bundle_in_valkey(
    state: &crate::AppState,
    owner_repo: &str,
    repo_path: &Path,
    s3_key: &str,
    creation_token: u64,
) -> Result<()> {
    let refs = crate::bundleuri::generator::get_refs(repo_path).await?;
    let refs_json = serde_json::to_string(&refs)?;
    let repo_key = repo_key(owner_repo);

    HashesInterface::hset::<(), _, _>(
        &state.valkey,
        &repo_key,
        [
            ("prev_refs", refs_json.as_str()),
            ("latest_bundle_s3_key", s3_key),
            ("latest_bundle_token", &creation_token.to_string()),
        ],
    )
    .await?;

    let bundle_name = format!("bootstrap-{creation_token}");
    let bundle_registry_key = format!("bundles:{owner_repo}");
    HashesInterface::hset::<(), _, _>(
        &state.valkey,
        &bundle_registry_key,
        [(bundle_name.as_str(), s3_key)],
    )
    .await?;

    let bundle_tokens_key = format!("bundle_tokens:{owner_repo}");
    SortedSetsInterface::zadd::<(), _, _>(
        &state.valkey,
        &bundle_tokens_key,
        None,
        None,
        false,
        false,
        (creation_token as f64, bundle_name.as_str()),
    )
    .await?;

    Ok(())
}

/// List all tracked repository names by scanning for `forgeproxy:repo:*` keys
/// (excluding `:fetch_schedule` sub-keys).
///
/// Uses the `KEYS` command which is acceptable for small-to-moderate key
/// spaces.  For very large deployments consider replacing with `SCAN`.
pub async fn list_all_repos(pool: &fred::clients::Pool) -> Result<Vec<String>> {
    let keys: Vec<String> = pool
        .custom(
            CustomCommand::new_static("KEYS", None::<u16>, false),
            vec!["forgeproxy:repo:*".to_string()],
        )
        .await
        .context("KEYS forgeproxy:repo:*")?;

    let repos: Vec<String> = keys
        .into_iter()
        .filter_map(|k| {
            // Skip sub-keys like forgeproxy:repo:owner/name:fetch_schedule
            let stripped = k.strip_prefix("forgeproxy:repo:")?;
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
