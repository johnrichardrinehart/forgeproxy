use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine;
use fred::interfaces::{ClientLike, HashesInterface, SortedSetsInterface};
use fred::types::CustomCommand;
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedMutexGuard, OwnedSemaphorePermit};
use tracing::{debug, info, trace, warn};

/// Metadata about a cached repository.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepoInfo {
    pub status: String,
    /// Comma-separated list of node IDs that hold a local clone.
    pub node_ids: String,
    /// Node currently hydrating this repo, if any.
    pub hydrating_node_id: String,
    /// Unix timestamp when the current hydration attempt started.
    pub hydrating_since_ts: i64,
    /// Whether the current hydrator still needs to publish a bootstrap S3
    /// bundle before the repo is warm for other nodes.
    pub bootstrap_bundle_pending: bool,
    /// S3 key where the bundle-list manifest is stored.
    pub s3_bundle_list_key: String,
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
        ("hydrating_node_id".into(), info.hydrating_node_id.clone()),
        (
            "hydrating_since_ts".into(),
            info.hydrating_since_ts.to_string(),
        ),
        (
            "bootstrap_bundle_pending".into(),
            info.bootstrap_bundle_pending.to_string(),
        ),
        ("s3_bundle_list_key".into(), info.s3_bundle_list_key.clone()),
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
        hydrating_node_id: map.get("hydrating_node_id").cloned().unwrap_or_default(),
        hydrating_since_ts: map
            .get("hydrating_since_ts")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        bootstrap_bundle_pending: map
            .get("bootstrap_bundle_pending")
            .and_then(|v| v.parse().ok())
            .unwrap_or(false),
        s3_bundle_list_key: map.get("s3_bundle_list_key").cloned().unwrap_or_default(),
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

pub async fn try_ensure_repo_cloned_from_tee(
    state: &crate::AppState,
    owner: &str,
    repo: &str,
    auth_header: Option<&str>,
    capture_dir: PathBuf,
) -> Result<()> {
    try_ensure_repo_cloned_inner(state, owner, repo, auth_header, Some(capture_dir), None).await
}

pub struct CloneHydrationPermits {
    _global_clone_permit: OwnedSemaphorePermit,
    _local_repo_permit: OwnedSemaphorePermit,
    distributed_repo_permit: crate::coordination::locks::SemaphoreLease,
}

pub async fn try_acquire_clone_hydration_permits(
    state: &crate::AppState,
    owner_repo: &str,
) -> Result<Option<CloneHydrationPermits>> {
    let global_clone_permit = state
        .clone_semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|e| anyhow::anyhow!("clone semaphore closed: {e}"))?;
    let local_repo_permit = acquire_local_repo_clone_permit(state, owner_repo).await?;
    let distributed_permit_key = format!("forgeproxy:semaphore:clone:{owner_repo}");
    let Some(distributed_repo_permit) = crate::coordination::locks::acquire_semaphore_lease(
        &state.valkey,
        &distributed_permit_key,
        &state.node_id,
        state
            .config
            .clone
            .max_concurrent_upstream_clones_per_repo_across_instances,
        state.config.clone.lock_ttl,
    )
    .await?
    else {
        return Ok(None);
    };

    Ok(Some(CloneHydrationPermits {
        _global_clone_permit: global_clone_permit,
        _local_repo_permit: local_repo_permit,
        distributed_repo_permit,
    }))
}

pub async fn release_clone_hydration_permits(
    state: &crate::AppState,
    permits: CloneHydrationPermits,
) -> Result<()> {
    crate::coordination::locks::release_semaphore_lease(
        &state.valkey,
        &permits.distributed_repo_permit,
    )
    .await
}

pub async fn try_ensure_repo_cloned_from_tee_with_permits(
    state: &crate::AppState,
    owner: &str,
    repo: &str,
    auth_header: Option<&str>,
    capture_dir: PathBuf,
    permits: CloneHydrationPermits,
) -> Result<()> {
    try_ensure_repo_cloned_inner(
        state,
        owner,
        repo,
        auth_header,
        Some(capture_dir),
        Some(permits),
    )
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TeeHydrationOutcome {
    NotHydrated,
    HydratedWithFollowOnFetch,
    PublishedFromCapture,
}

async fn cleanup_tee_capture_dir(capture_dir: &Path) -> Result<()> {
    if capture_dir.exists() {
        tokio::fs::remove_dir_all(capture_dir)
            .await
            .with_context(|| {
                format!("failed to remove tee capture at {}", capture_dir.display())
            })?;
    }
    Ok(())
}

async fn acquire_local_repo_clone_permit(
    state: &crate::AppState,
    owner_repo: &str,
) -> Result<OwnedSemaphorePermit> {
    let semaphore = {
        let mut semaphores = state.repo_clone_semaphores.lock().await;
        semaphores
            .entry(owner_repo.to_string())
            .or_insert_with(|| {
                std::sync::Arc::new(tokio::sync::Semaphore::new(
                    state
                        .config
                        .clone
                        .max_concurrent_upstream_clones_per_repo_per_instance,
                ))
            })
            .clone()
    };

    semaphore
        .acquire_owned()
        .await
        .map_err(|e| anyhow::anyhow!("repo clone semaphore closed: {e}"))
}

async fn acquire_local_repo_publish_guard(
    state: &crate::AppState,
    owner_repo: &str,
) -> OwnedMutexGuard<()> {
    let mutex = {
        let mut mutexes = state.repo_publish_mutexes.lock().await;
        mutexes
            .entry(owner_repo.to_string())
            .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };

    mutex.lock_owned().await
}

async fn register_active_generation(
    state: &crate::AppState,
    owner_repo: &str,
    staged_repo_path: &Path,
) {
    let mut active_generations = state.active_repo_generations.lock().await;
    active_generations
        .entry(owner_repo.to_string())
        .or_default()
        .insert(staged_repo_path.to_path_buf());
}

async fn unregister_active_generation(
    state: &crate::AppState,
    owner_repo: &str,
    staged_repo_path: &Path,
) {
    let mut active_generations = state.active_repo_generations.lock().await;
    if let Some(paths) = active_generations.get_mut(owner_repo) {
        paths.remove(staged_repo_path);
        if paths.is_empty() {
            active_generations.remove(owner_repo);
        }
    }
}

async fn active_generation_paths(
    state: &crate::AppState,
    owner_repo: &str,
) -> std::collections::HashSet<PathBuf> {
    state
        .active_repo_generations
        .lock()
        .await
        .get(owner_repo)
        .cloned()
        .unwrap_or_default()
}

async fn try_ensure_repo_cloned_inner(
    state: &crate::AppState,
    owner: &str,
    repo: &str,
    auth_header: Option<&str>,
    tee_capture_dir: Option<PathBuf>,
    preacquired_permits: Option<CloneHydrationPermits>,
) -> Result<()> {
    // Strip trailing ".git" from repo if present to avoid double-suffixing
    // (the URL path extractor preserves it, and we append ".git" below).
    let repo_clean = repo.strip_suffix(".git").unwrap_or(repo);
    let owner_repo = format!("{owner}/{repo_clean}");
    let node_id = state.node_id.clone();
    let had_local_repo_at_start = state.cache_manager.has_repo(&owner_repo);

    let published_repo_path = state.cache_manager.ensure_repo_dir(&owner_repo)?;
    reset_partial_repo_if_needed(&state.cache_manager, &owner_repo, &published_repo_path).await?;
    let staged_repo_path = state.cache_manager.create_staging_repo_path(&owner_repo)?;
    register_active_generation(state, &owner_repo, &staged_repo_path).await;
    let mut clone_hydration_permits = preacquired_permits;

    let result = async {
        info!(repo = %owner_repo, path = %staged_repo_path.display(), "starting staged repo hydration");
        if !(had_local_repo_at_start && tee_capture_dir.is_some()) {
            match try_restore_repo_from_s3(state, &owner_repo, &staged_repo_path).await {
                Ok(true) => {
                    info!(repo = %owner_repo, path = %staged_repo_path.display(), "restored repo from S3 bundle");
                    let _repo_generation_guard =
                        acquire_local_repo_publish_guard(state, &owner_repo).await;
                    if state.cache_manager.has_repo(&owner_repo) {
                        info!(
                            repo = %owner_repo,
                            published = %state.cache_manager.repo_path(&owner_repo).display(),
                            path = %staged_repo_path.display(),
                            "repo was published by another hydration; skipping redundant finalize/publish work"
                        );
                        return Ok::<(), anyhow::Error>(());
                    }
                    ensure_bare_head_ref(&staged_repo_path)
                        .await
                        .with_context(|| format!("failed to set bare HEAD after S3 restore for {owner_repo}"))?;
                    validate_ready_repo(state, &owner_repo, &staged_repo_path, "S3 restore")
                        .await
                        .with_context(|| format!("S3-restored repo validation failed for {owner_repo}"))?;
                    let published_repo_path =
                        publish_ready_repo(state, &owner_repo, &staged_repo_path, "S3 restore")
                            .await?;

                    let mut info = get_repo_info(&state.valkey, &owner_repo)
                        .await?
                        .unwrap_or_default();
                    info.status = "ready".to_string();
                    info.node_ids = node_id.clone();
                    info.hydrating_node_id.clear();
                    info.hydrating_since_ts = 0;
                    info.bootstrap_bundle_pending = false;
                    set_repo_info(&state.valkey, &owner_repo, &info).await?;
                    crate::coordination::pubsub::publish_ready(&state.valkey, &owner_repo, &node_id)
                        .await?;
                    info!(%owner_repo, published = %published_repo_path.display(), "repo hydrated from S3 bundle");
                    return Ok::<(), anyhow::Error>(());
                }
                Ok(false) => {}
                Err(error) => {
                    info!(
                        %owner_repo,
                        error = %error,
                        "S3 hydration unavailable; falling back to upstream clone"
                    );
                    if staged_repo_path.exists() {
                        tokio::fs::remove_dir_all(&staged_repo_path)
                            .await
                            .with_context(|| {
                                format!(
                                    "failed to remove failed S3 hydration repo at {}",
                                    staged_repo_path.display()
                                )
                            })?;
                    }
                }
            }
        }

        let clone_url = clone_url(state, owner, repo_clean, auth_header);
        let update_existing_repo = had_local_repo_at_start && tee_capture_dir.is_some();

        if had_local_repo_at_start && !update_existing_repo {
            info!(
                repo = %owner_repo,
                published = %state.cache_manager.repo_path(&owner_repo).display(),
                "repo became locally available before hydration started; skipping redundant upstream hydration"
            );
            return Ok::<(), anyhow::Error>(());
        }

        if clone_hydration_permits.is_none() {
            clone_hydration_permits = try_acquire_clone_hydration_permits(state, &owner_repo).await?;
        }
        if clone_hydration_permits.is_none() {
            if let Some(capture_dir) = tee_capture_dir.as_ref() {
                cleanup_tee_capture_dir(capture_dir).await?;
            }
            info!(
                repo = %owner_repo,
                per_instance_limit = state.config.clone.max_concurrent_upstream_clones_per_repo_per_instance,
                cross_instance_limit = state.config.clone.max_concurrent_upstream_clones_per_repo_across_instances,
                lease_ttl_secs = state.config.clone.lock_ttl,
                "skipping upstream hydration because the repo clone semaphore is saturated"
            );
            return Ok(());
        }
        let hydrate_started_at = chrono::Utc::now().timestamp();
        let mut info = get_repo_info(&state.valkey, &owner_repo)
            .await?
            .unwrap_or_default();
        if !info.hydrating_node_id.is_empty() && info.hydrating_node_id != node_id {
            warn!(
                repo = %owner_repo,
                previous_node = %info.hydrating_node_id,
                previous_started_at = info.hydrating_since_ts,
                "recording hydration activity while another node is already marked as hydrator"
            );
        }
        info.status = "hydrating".to_string();
        info.hydrating_node_id = node_id.clone();
        info.hydrating_since_ts = hydrate_started_at;
        info.bootstrap_bundle_pending = false;
        set_repo_info(&state.valkey, &owner_repo, &info).await?;

        let env_vars: Vec<(String, String)> =
            vec![("GIT_TERMINAL_PROMPT".to_string(), "0".to_string())];

        let hydrate_result = async {
            let tee_outcome = if let Some(capture_dir) = tee_capture_dir.as_ref() {
                info!(
                    repo = %owner_repo,
                    capture_dir = %capture_dir.display(),
                    "attempting tee-based hydration from captured upstream stream"
                );
                hydrate_repo_from_tee_capture(
                    state,
                    &owner_repo,
                    &staged_repo_path,
                    &clone_url,
                    capture_dir,
                    update_existing_repo,
                )
                .await?
            } else {
                TeeHydrationOutcome::NotHydrated
            };

            if tee_outcome == TeeHydrationOutcome::NotHydrated {
                info!(repo = %owner_repo, path = %staged_repo_path.display(), "starting upstream bare clone");
                crate::git::commands::git_clone_bare(&clone_url, &staged_repo_path, &env_vars)
                    .await
                    .with_context(|| format!("upstream bare clone failed for {owner_repo}"))?;
                info!(repo = %owner_repo, path = %staged_repo_path.display(), "upstream bare clone completed");
            }

            Ok::<TeeHydrationOutcome, anyhow::Error>(tee_outcome)
        }
        .await;
        let release_result = if let Some(permits) = clone_hydration_permits.take() {
            release_clone_hydration_permits(state, permits).await
        } else {
            Ok(())
        };
        let tee_outcome = hydrate_result?;
        release_result?;

        let _repo_generation_guard = acquire_local_repo_publish_guard(state, &owner_repo).await;
        if state.cache_manager.has_repo(&owner_repo) && !update_existing_repo {
            info!(
                repo = %owner_repo,
                published = %state.cache_manager.repo_path(&owner_repo).display(),
                path = %staged_repo_path.display(),
                "repo was published by another hydration; skipping redundant finalize/publish work"
            );
            return Ok::<(), anyhow::Error>(());
        }

        ensure_bare_head_ref(&staged_repo_path)
            .await
            .with_context(|| format!("failed to set bare HEAD after hydration for {owner_repo}"))?;
        validate_ready_repo(
            state,
            &owner_repo,
            &staged_repo_path,
            match tee_outcome {
                TeeHydrationOutcome::HydratedWithFollowOnFetch => "tee hydration",
                TeeHydrationOutcome::PublishedFromCapture => "tee capture publish",
                TeeHydrationOutcome::NotHydrated => "upstream clone",
            },
        )
        .await
        .with_context(|| format!("ready-repo validation failed for {owner_repo}"))?;
        let published_generation_path = publish_ready_repo(
            state,
            &owner_repo,
            &staged_repo_path,
            match tee_outcome {
                TeeHydrationOutcome::HydratedWithFollowOnFetch => "tee hydration",
                TeeHydrationOutcome::PublishedFromCapture => "tee capture publish",
                TeeHydrationOutcome::NotHydrated => "upstream clone",
            },
        )
        .await?;
        let published_repo_path = state.cache_manager.repo_path(&owner_repo);

        let mut info = get_repo_info(&state.valkey, &owner_repo)
            .await?
            .unwrap_or_default();
        info.status = "ready".to_string();
        info.node_ids = node_id.clone();
        info.hydrating_node_id.clear();
        info.hydrating_since_ts = 0;
        info.bootstrap_bundle_pending = false;
        set_repo_info(&state.valkey, &owner_repo, &info).await?;

        crate::coordination::pubsub::publish_ready(&state.valkey, &owner_repo, &node_id).await?;

        if tee_outcome == TeeHydrationOutcome::PublishedFromCapture {
            spawn_capture_convergence(
                state.clone(),
                owner_repo.clone(),
                clone_url.clone(),
                auth_header.map(ToOwned::to_owned),
            );
        } else {
            publish_bootstrap_bundle(state, &owner_repo, &published_repo_path).await?;
        }

        debug!(
            repo = %owner_repo,
            generation = %published_generation_path.display(),
            published = %published_repo_path.display(),
            "post-publish work is using the stable published repo path"
        );

        Ok::<(), anyhow::Error>(())
    }
    .await;

    if let Some(permits) = clone_hydration_permits.take() {
        release_clone_hydration_permits(state, permits).await?;
    }

    if let Err(error) = &result {
        clear_hydration_state(state, &owner_repo, "failed").await?;
        warn!(repo = %owner_repo, error = %error, "repo hydration failed");
        if staged_repo_path.exists() {
            tokio::fs::remove_dir_all(&staged_repo_path)
                .await
                .with_context(|| {
                    format!(
                        "failed to remove failed staged repo generation at {}",
                        staged_repo_path.display()
                    )
                })?;
        }
    }

    if let Some(capture_dir) = tee_capture_dir.as_ref() {
        let cleanup_result = cleanup_tee_capture_dir(capture_dir).await;
        if result.is_ok() {
            cleanup_result?;
        } else if let Err(cleanup_error) = cleanup_result {
            warn!(
                repo = %owner_repo,
                capture_dir = %capture_dir.display(),
                error = %cleanup_error,
                "tee capture cleanup failed after hydration error; stale capture directory remains"
            );
        }
    }

    unregister_active_generation(state, &owner_repo, &staged_repo_path).await;

    result
}

fn clone_url(
    state: &crate::AppState,
    owner: &str,
    repo_clean: &str,
    auth_header: Option<&str>,
) -> String {
    if let Some(b64) = auth_header.and_then(|h| h.strip_prefix("Basic ")) {
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
    }
}

fn redacted_clone_url(state: &crate::AppState, clone_url: &str) -> String {
    crate::git::commands::redact_url_secret(
        clone_url,
        state.config.upstream.log_secret_unmask_chars,
    )
}

async fn seed_temp_want_refs(repo_path: &Path, wants: &[String]) -> Result<Option<PathBuf>> {
    if wants.is_empty() {
        return Ok(None);
    }

    let seed_root = repo_path.join("refs/forgeproxy/tee-wants");
    tokio::fs::create_dir_all(&seed_root)
        .await
        .with_context(|| format!("create temp want-ref dir {}", seed_root.display()))?;

    for (idx, oid) in wants.iter().enumerate() {
        let ref_path = seed_root.join(idx.to_string());
        tokio::fs::write(&ref_path, format!("{oid}\n"))
            .await
            .with_context(|| format!("write temp want ref {}", ref_path.display()))?;
    }

    Ok(Some(seed_root))
}

async fn cleanup_temp_want_refs(seed_root: Option<&Path>) -> Result<()> {
    let Some(seed_root) = seed_root else {
        return Ok(());
    };

    if seed_root.exists() {
        tokio::fs::remove_dir_all(seed_root)
            .await
            .with_context(|| format!("remove temp want-ref dir {}", seed_root.display()))?;
    }

    Ok(())
}

async fn clear_hydration_state(
    state: &crate::AppState,
    owner_repo: &str,
    fallback_status: &str,
) -> Result<()> {
    let has_local_repo = state.cache_manager.has_repo(owner_repo);
    let mut info = get_repo_info(&state.valkey, owner_repo)
        .await?
        .unwrap_or_default();
    info.status = if has_local_repo {
        "ready".to_string()
    } else {
        fallback_status.to_string()
    };
    if !has_local_repo {
        info.node_ids.clear();
    }
    info.hydrating_node_id.clear();
    info.hydrating_since_ts = 0;
    info.bootstrap_bundle_pending = false;
    set_repo_info(&state.valkey, owner_repo, &info).await?;
    Ok(())
}

async fn publish_ready_repo(
    state: &crate::AppState,
    owner_repo: &str,
    staged_repo_path: &Path,
    source: &str,
) -> Result<PathBuf> {
    let final_repo_path =
        fold_overlapping_generations(state, owner_repo, staged_repo_path, source).await?;
    let mut retained_generations: Vec<PathBuf> = active_generation_paths(state, owner_repo)
        .await
        .into_iter()
        .collect();
    if !retained_generations
        .iter()
        .any(|path| path == &final_repo_path)
    {
        retained_generations.push(final_repo_path.clone());
    }

    info!(
        repo = %owner_repo,
        path = %final_repo_path.display(),
        source,
        "publishing ready repo generation"
    );
    state
        .cache_manager
        .publish_staged_repo(owner_repo, &final_repo_path)
        .with_context(|| {
            format!(
                "failed to publish ready repo generation {} for {}",
                final_repo_path.display(),
                owner_repo,
            )
        })?;
    state
        .cache_manager
        .prune_generations_except(owner_repo, &retained_generations)?;
    info!(
        repo = %owner_repo,
        path = %final_repo_path.display(),
        published = %state.cache_manager.repo_path(owner_repo).display(),
        "published repo generation and pruned superseded generations"
    );
    Ok(final_repo_path)
}

async fn fold_overlapping_generations(
    state: &crate::AppState,
    owner_repo: &str,
    staged_repo_path: &Path,
    source: &str,
) -> Result<PathBuf> {
    let active_generations = active_generation_paths(state, owner_repo).await;
    let other_generations: Vec<PathBuf> = state
        .cache_manager
        .list_generation_dirs(owner_repo)?
        .into_iter()
        .filter(|path| path != staged_repo_path)
        .filter(|path| !active_generations.contains(path))
        .filter(|path| state.cache_manager.has_repo_at(path))
        .collect();

    if other_generations.is_empty() {
        return Ok(staged_repo_path.to_path_buf());
    }

    let consolidation_path = state.cache_manager.create_staging_repo_path(owner_repo)?;
    info!(
        repo = %owner_repo,
        source,
        seed = %staged_repo_path.display(),
        destination = %consolidation_path.display(),
        generations_to_fold = other_generations.len(),
        "folding overlapping staged generations into a single published repo"
    );

    let consolidation_result = async {
        let mut sorted_generations = other_generations.clone();
        sorted_generations.sort();
        let seed_generation = sorted_generations
            .first()
            .cloned()
            .unwrap_or_else(|| staged_repo_path.to_path_buf());

        crate::git::commands::git_clone_bare_local(&seed_generation, &consolidation_path)
            .await
            .with_context(|| {
                format!(
                    "failed to seed consolidated generation {} from {}",
                    consolidation_path.display(),
                    seed_generation.display()
                )
            })?;

        let mut generations_to_fetch: Vec<PathBuf> = sorted_generations
            .iter()
            .filter(|path| *path != &seed_generation)
            .cloned()
            .collect();
        generations_to_fetch.push(staged_repo_path.to_path_buf());

        for generation_path in &generations_to_fetch {
            info!(
                repo = %owner_repo,
                source_generation = %generation_path.display(),
                destination = %consolidation_path.display(),
                "folding staged generation into consolidated repo"
            );
            let generation_remote = generation_path.to_string_lossy().to_string();
            crate::git::commands::git_fetch(&consolidation_path, &generation_remote, &[])
                .await
                .with_context(|| {
                    format!(
                        "failed to fold generation {} into {}",
                        generation_path.display(),
                        consolidation_path.display()
                    )
                })?;
        }

        ensure_bare_head_ref(&consolidation_path)
            .await
            .with_context(|| {
                format!("failed to set bare HEAD after generation fold for {owner_repo}")
            })?;
        validate_ready_repo(state, owner_repo, &consolidation_path, "generation fold")
            .await
            .with_context(|| format!("generation fold validation failed for {owner_repo}"))?;
        Ok::<(), anyhow::Error>(())
    }
    .await;

    if let Err(error) = consolidation_result {
        if consolidation_path.exists() {
            tokio::fs::remove_dir_all(&consolidation_path)
                .await
                .with_context(|| {
                    format!(
                        "failed to remove unsuccessful consolidated generation at {}",
                        consolidation_path.display()
                    )
                })?;
        }
        warn!(
            repo = %owner_repo,
            path = %staged_repo_path.display(),
            error = %error,
            "generation fold failed; publishing the validated staged generation directly"
        );
        return Ok(staged_repo_path.to_path_buf());
    }

    Ok(consolidation_path)
}

async fn reset_partial_repo_if_needed(
    cache_manager: &crate::cache::CacheManager,
    owner_repo: &str,
    repo_path: &Path,
) -> Result<()> {
    if repo_path.exists() && !cache_manager.has_repo(owner_repo) {
        let metadata = tokio::fs::symlink_metadata(repo_path)
            .await
            .with_context(|| format!("failed to stat partial repo at {}", repo_path.display()))?;
        if metadata.file_type().is_symlink() {
            tokio::fs::remove_file(repo_path).await.with_context(|| {
                format!(
                    "failed to remove broken repo symlink at {}",
                    repo_path.display()
                )
            })?;
        } else {
            tokio::fs::remove_dir_all(repo_path)
                .await
                .with_context(|| {
                    format!("failed to remove partial repo at {}", repo_path.display())
                })?;
        }
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

    Ok(state.cache_manager.has_repo_at(repo_path))
}

async fn materialize_capture_refs(
    repo_path: &Path,
    capture_dir: &Path,
) -> Result<crate::tee_hydration::CapturedRefMetadata> {
    let metadata = crate::tee_hydration::extract_captured_ref_metadata(capture_dir).await?;
    for (refname, oid) in &metadata.refs {
        let ref_path = repo_path.join(refname);
        if let Some(parent) = ref_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("create captured ref parent {}", parent.display()))?;
        }
        tokio::fs::write(&ref_path, format!("{oid}\n"))
            .await
            .with_context(|| format!("write captured ref {}", ref_path.display()))?;
    }

    if let Some(head_target) = metadata.head_symref_target.as_deref()
        && metadata.refs.contains_key(head_target)
    {
        crate::git::commands::git_set_head_symbolic_ref(repo_path, head_target).await?;
    }

    Ok(metadata)
}

fn spawn_capture_convergence(
    state: crate::AppState,
    owner_repo: String,
    clone_url: String,
    _auth_header: Option<String>,
) {
    tokio::spawn(async move {
        if let Err(error) =
            converge_published_repo_generation(&state, &owner_repo, &clone_url).await
        {
            warn!(
                repo = %owner_repo,
                error = %error,
                "capture convergence generation failed"
            );
        }
    });
}

async fn converge_published_repo_generation(
    state: &crate::AppState,
    owner_repo: &str,
    clone_url: &str,
) -> Result<()> {
    let published_repo_path = state.cache_manager.repo_path(owner_repo);
    if !state.cache_manager.has_repo(owner_repo) {
        bail!("published repo is not available for convergence");
    }

    let staged_repo_path = state.cache_manager.create_staging_repo_path(owner_repo)?;
    register_active_generation(state, owner_repo, &staged_repo_path).await;
    crate::git::commands::git_clone_bare_local(&published_repo_path, &staged_repo_path)
        .await
        .with_context(|| {
            format!(
                "failed to seed convergence generation {} from {}",
                staged_repo_path.display(),
                published_repo_path.display()
            )
        })?;

    let redacted_clone_url = redacted_clone_url(state, clone_url);
    info!(
        repo = %owner_repo,
        destination = %staged_repo_path.display(),
        clone_url = %redacted_clone_url,
        "starting capture convergence follow-on git fetch"
    );
    let result = async {
        let fetch_result =
            crate::git::commands::git_fetch(&staged_repo_path, clone_url, &[]).await?;
        let _repo_generation_guard = acquire_local_repo_publish_guard(state, owner_repo).await;
        ensure_bare_head_ref(&staged_repo_path).await?;
        validate_ready_repo(state, owner_repo, &staged_repo_path, "capture convergence").await?;
        let published_repo_path =
            publish_ready_repo(state, owner_repo, &staged_repo_path, "capture convergence").await?;
        publish_bootstrap_bundle(state, owner_repo, &published_repo_path).await?;
        info!(
            repo = %owner_repo,
            destination = %published_repo_path.display(),
            clone_url = %redacted_clone_url,
            refs_updated = fetch_result.refs_updated,
            bytes_received = fetch_result.bytes_received,
            "capture convergence follow-on git fetch finished"
        );
        Ok(())
    }
    .await;
    unregister_active_generation(state, owner_repo, &staged_repo_path).await;
    result
}

async fn hydrate_repo_from_tee_capture(
    state: &crate::AppState,
    owner_repo: &str,
    repo_path: &Path,
    clone_url: &str,
    capture_dir: &Path,
    allow_existing_repo_publish: bool,
) -> Result<TeeHydrationOutcome> {
    let Some(pack_path) = crate::tee_hydration::extract_pack_from_capture(capture_dir).await?
    else {
        info!(
            repo = %owner_repo,
            capture_dir = %capture_dir.display(),
            "tee hydration skipped because no pack payload was extracted"
        );
        return Ok(TeeHydrationOutcome::NotHydrated);
    };
    let captured_fetch_metadata =
        crate::tee_hydration::extract_captured_fetch_metadata(capture_dir).await?;
    let captured_wants = captured_fetch_metadata.want_oids.clone();
    let uses_shallow = captured_fetch_metadata.uses_shallow;

    if uses_shallow {
        info!(
            repo = %owner_repo,
            capture_dir = %capture_dir.display(),
            captured_wants = captured_wants.len(),
            "tee capture represents a shallow clone; skipping tee hydration and falling back to background full upstream clone"
        );
        return Ok(TeeHydrationOutcome::NotHydrated);
    }

    let extracted_pack_size = tokio::fs::metadata(&pack_path)
        .await
        .map(|m| m.len())
        .unwrap_or_default();
    info!(
        repo = %owner_repo,
        capture_dir = %capture_dir.display(),
        pack = %pack_path.display(),
        extracted_pack_size,
        destination = %repo_path.display(),
        "starting tee hydration from captured pack"
    );

    if state.cache_manager.has_repo(owner_repo) && !allow_existing_repo_publish {
        info!(
            repo = %owner_repo,
            capture_dir = %capture_dir.display(),
            published = %state.cache_manager.repo_path(owner_repo).display(),
            "repo was published before tee hydration initialization; skipping redundant tee hydration"
        );
        return Ok(TeeHydrationOutcome::NotHydrated);
    }

    crate::git::commands::git_init_bare(repo_path).await?;
    if state.cache_manager.has_repo(owner_repo) && !allow_existing_repo_publish {
        info!(
            repo = %owner_repo,
            capture_dir = %capture_dir.display(),
            destination = %repo_path.display(),
            published = %state.cache_manager.repo_path(owner_repo).display(),
            "repo was published after tee hydration initialization; abandoning redundant tee hydration"
        );
        return Ok(TeeHydrationOutcome::NotHydrated);
    }
    info!(
        repo = %owner_repo,
        pack = %pack_path.display(),
        destination = %repo_path.display(),
        "starting tee hydration index-pack"
    );
    crate::git::commands::git_index_pack(repo_path, &pack_path).await?;
    if state.cache_manager.has_repo(owner_repo) && !allow_existing_repo_publish {
        info!(
            repo = %owner_repo,
            capture_dir = %capture_dir.display(),
            destination = %repo_path.display(),
            published = %state.cache_manager.repo_path(owner_repo).display(),
            "repo was published while tee hydration was indexing; skipping redundant publish/fetch work"
        );
        return Ok(TeeHydrationOutcome::NotHydrated);
    }
    info!(
        repo = %owner_repo,
        pack = %pack_path.display(),
        destination = %repo_path.display(),
        "tee hydration index-pack finished"
    );
    if state.config.clone.hydration_mode == crate::config::HydrationMode::PublishFromCapture {
        let metadata = materialize_capture_refs(repo_path, capture_dir).await?;
        if !metadata.refs.is_empty() && state.cache_manager.has_repo_at(repo_path) {
            let direct_publish_ready = async {
                ensure_bare_head_ref(repo_path).await?;
                check_ready_repo(state, owner_repo, repo_path, "tee capture publish").await?;
                Ok::<(), anyhow::Error>(())
            }
            .await;

            match direct_publish_ready {
                Ok(()) => {
                    info!(
                        repo = %owner_repo,
                        destination = %repo_path.display(),
                        refs_materialized = metadata.refs.len(),
                        head = ?metadata.head_symref_target,
                        "publishing generation directly from tee capture metadata"
                    );
                    return Ok(TeeHydrationOutcome::PublishedFromCapture);
                }
                Err(error) => {
                    info!(
                        repo = %owner_repo,
                        destination = %repo_path.display(),
                        refs_materialized = metadata.refs.len(),
                        head = ?metadata.head_symref_target,
                        error = %error,
                        "capture metadata was insufficient for direct publish; falling back to follow-on fetch"
                    );
                }
            }
        } else {
            info!(
                repo = %owner_repo,
                destination = %repo_path.display(),
                refs_materialized = metadata.refs.len(),
                "capture metadata was insufficient for direct publish; falling back to follow-on fetch"
            );
        }
    }

    let seeded_want_ref_dir = seed_temp_want_refs(repo_path, &captured_wants).await?;
    if !captured_wants.is_empty() {
        info!(
            repo = %owner_repo,
            destination = %repo_path.display(),
            seeded_wants = captured_wants.len(),
            "seeded temporary want refs before tee hydration follow-on git fetch"
        );
    }
    let redacted_clone_url = redacted_clone_url(state, clone_url);
    info!(
        repo = %owner_repo,
        destination = %repo_path.display(),
        clone_url = %redacted_clone_url,
        "starting tee hydration follow-on git fetch"
    );
    let fetch_result = crate::git::commands::git_fetch(repo_path, clone_url, &[]).await;
    let cleanup_result = cleanup_temp_want_refs(seeded_want_ref_dir.as_deref()).await;
    let fetch_result = fetch_result?;
    cleanup_result?;
    info!(
        repo = %owner_repo,
        destination = %repo_path.display(),
        clone_url = %redacted_clone_url,
        refs_updated = fetch_result.refs_updated,
        bytes_received = fetch_result.bytes_received,
        "tee hydration follow-on git fetch finished"
    );

    if state.cache_manager.has_repo_at(repo_path) {
        Ok(TeeHydrationOutcome::HydratedWithFollowOnFetch)
    } else {
        Ok(TeeHydrationOutcome::NotHydrated)
    }
}

async fn check_ready_repo(
    state: &crate::AppState,
    owner_repo: &str,
    repo_path: &Path,
    source: &str,
) -> Result<()> {
    if !state.cache_manager.has_repo_at(repo_path) {
        bail!("repo is missing required bare-repo refs after {source}");
    }

    crate::git::commands::git_fsck_connectivity_only(repo_path)
        .await
        .with_context(|| {
            format!("connectivity validation failed for {owner_repo} after {source}")
        })?;

    Ok(())
}

async fn validate_ready_repo(
    state: &crate::AppState,
    owner_repo: &str,
    repo_path: &Path,
    source: &str,
) -> Result<()> {
    let validation_result = check_ready_repo(state, owner_repo, repo_path, source).await;

    if let Err(error) = validation_result {
        if repo_path.exists() {
            tokio::fs::remove_dir_all(repo_path)
                .await
                .with_context(|| {
                    format!(
                        "failed to remove invalid repo at {} after {}",
                        repo_path.display(),
                        source
                    )
                })?;
        }
        return Err(error);
    }

    Ok(())
}

async fn ensure_bare_head_ref(repo_path: &Path) -> Result<()> {
    let refs = crate::git::commands::git_for_each_ref(repo_path).await?;
    let branch_refs: Vec<&str> = refs
        .keys()
        .map(String::as_str)
        .filter(|refname| refname.starts_with("refs/heads/"))
        .collect();

    let head_ref = if branch_refs.contains(&"refs/heads/main") {
        Some("refs/heads/main")
    } else if branch_refs.contains(&"refs/heads/master") {
        Some("refs/heads/master")
    } else if branch_refs.len() == 1 {
        branch_refs.first().copied()
    } else {
        None
    };

    let Some(head_ref) = head_ref else {
        return Ok(());
    };

    crate::git::commands::git_set_head_symbolic_ref(repo_path, head_ref).await
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

async fn publish_bootstrap_bundle(
    state: &crate::AppState,
    owner_repo: &str,
    published_repo_path: &Path,
) -> Result<()> {
    let now = chrono::Utc::now().timestamp();
    match crate::bundleuri::generator::generate_full_bundle(state, published_repo_path, owner_repo)
        .await
    {
        Ok(bundle) => {
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
                owner_repo,
                published_repo_path,
                &s3_key,
                bundle.creation_token,
            )
            .await?;

            let mut info = get_repo_info(&state.valkey, owner_repo)
                .await?
                .unwrap_or_default();
            info.last_bundle_ts = now;
            info.latest_creation_token = bundle.creation_token;
            set_repo_info(&state.valkey, owner_repo, &info).await?;
        }
        Err(error) => {
            warn!(
                %owner_repo,
                error = %error,
                "bootstrap bundle generation failed; keeping locally cached repo"
            );
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalRepoAvailability {
    pub had_local_repo_before_check: bool,
    pub restored_from_s3_for_request: bool,
    pub available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalServeDecision {
    Unavailable {
        had_local_repo_before_check: bool,
        restored_from_s3_for_request: bool,
    },
    SatisfiesWants {
        had_local_repo_before_check: bool,
        restored_from_s3_for_request: bool,
        want_count: usize,
    },
    MissingWantedObjects {
        had_local_repo_before_check: bool,
        restored_from_s3_for_request: bool,
        want_count: usize,
        missing_wants: Vec<String>,
    },
}

async fn ensure_repo_available_locally_detailed(
    state: &crate::AppState,
    owner_repo: &str,
) -> Result<LocalRepoAvailability> {
    let had_local_repo_before_check = state.cache_manager.has_repo(owner_repo);
    if had_local_repo_before_check {
        return Ok(LocalRepoAvailability {
            had_local_repo_before_check,
            restored_from_s3_for_request: false,
            available: true,
        });
    }

    if state.cache_manager.has_repo(owner_repo) {
        return Ok(LocalRepoAvailability {
            had_local_repo_before_check,
            restored_from_s3_for_request: false,
            available: true,
        });
    }

    let _repo_generation_guard = acquire_local_repo_publish_guard(state, owner_repo).await;
    let published_repo_path = state.cache_manager.ensure_repo_dir(owner_repo)?;
    reset_partial_repo_if_needed(&state.cache_manager, owner_repo, &published_repo_path).await?;
    let staged_repo_path = state.cache_manager.create_staging_repo_path(owner_repo)?;
    let restore_result = try_restore_repo_from_s3(state, owner_repo, &staged_repo_path).await;

    let availability = match restore_result {
        Ok(true) => {
            if state.cache_manager.has_repo(owner_repo) {
                LocalRepoAvailability {
                    had_local_repo_before_check,
                    restored_from_s3_for_request: false,
                    available: true,
                }
            } else {
                ensure_bare_head_ref(&staged_repo_path)
                    .await
                    .with_context(|| {
                        format!("failed to set bare HEAD after S3 restore for {owner_repo}")
                    })?;
                validate_ready_repo(
                    state,
                    owner_repo,
                    &staged_repo_path,
                    "S3 restore for request",
                )
                .await
                .with_context(|| format!("S3-restored repo validation failed for {owner_repo}"))?;
                publish_ready_repo(
                    state,
                    owner_repo,
                    &staged_repo_path,
                    "S3 restore for request",
                )
                .await?;

                let mut info = get_repo_info(&state.valkey, owner_repo)
                    .await?
                    .unwrap_or_default();
                info.status = "ready".to_string();
                info.node_ids = state.node_id.clone();
                info.hydrating_node_id.clear();
                info.hydrating_since_ts = 0;
                info.bootstrap_bundle_pending = false;
                set_repo_info(&state.valkey, owner_repo, &info).await?;
                LocalRepoAvailability {
                    had_local_repo_before_check,
                    restored_from_s3_for_request: true,
                    available: true,
                }
            }
        }
        Ok(false) => LocalRepoAvailability {
            had_local_repo_before_check,
            restored_from_s3_for_request: false,
            available: false,
        },
        Err(error) => {
            if staged_repo_path.exists() {
                tokio::fs::remove_dir_all(&staged_repo_path)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to remove failed request-time S3 restore at {}",
                            staged_repo_path.display()
                        )
                    })?;
            }
            return Err(error);
        }
    };

    if !availability.available && staged_repo_path.exists() {
        tokio::fs::remove_dir_all(&staged_repo_path)
            .await
            .with_context(|| {
                format!(
                    "failed to remove unused request-time S3 restore at {}",
                    staged_repo_path.display()
                )
            })?;
    }

    Ok(availability)
}

pub async fn classify_local_wants_satisfaction(
    state: &crate::AppState,
    owner_repo: &str,
    wants: &[String],
) -> Result<LocalServeDecision> {
    if wants.is_empty() {
        return Ok(LocalServeDecision::Unavailable {
            had_local_repo_before_check: state.cache_manager.has_repo(owner_repo),
            restored_from_s3_for_request: false,
        });
    }

    let availability = ensure_repo_available_locally_detailed(state, owner_repo).await?;
    if !availability.available {
        return Ok(LocalServeDecision::Unavailable {
            had_local_repo_before_check: availability.had_local_repo_before_check,
            restored_from_s3_for_request: availability.restored_from_s3_for_request,
        });
    }

    let repo_path = state.cache_manager.repo_path(owner_repo);
    let mut missing_wants = Vec::new();
    for want in wants {
        if !crate::git::commands::git_has_object(&repo_path, want).await? {
            missing_wants.push(want.clone());
        }
    }

    if missing_wants.is_empty() {
        Ok(LocalServeDecision::SatisfiesWants {
            had_local_repo_before_check: availability.had_local_repo_before_check,
            restored_from_s3_for_request: availability.restored_from_s3_for_request,
            want_count: wants.len(),
        })
    } else {
        Ok(LocalServeDecision::MissingWantedObjects {
            had_local_repo_before_check: availability.had_local_repo_before_check,
            restored_from_s3_for_request: availability.restored_from_s3_for_request,
            want_count: wants.len(),
            missing_wants,
        })
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_info_round_trip_preserves_hydration_fields() {
        let info = RepoInfo {
            status: "hydrating".to_string(),
            node_ids: "node-a".to_string(),
            hydrating_node_id: "node-a".to_string(),
            hydrating_since_ts: 1234,
            bootstrap_bundle_pending: true,
            s3_bundle_list_key: "bundle-list".to_string(),
            last_bundle_ts: 10,
            latest_creation_token: 11,
            refs_hash: "abc".to_string(),
            size_bytes: 12,
            clone_count: 13,
        };

        let round_trip = repo_info_from_map(repo_info_to_pairs(&info).into_iter().collect());
        assert_eq!(round_trip.status, "hydrating");
        assert_eq!(round_trip.hydrating_node_id, "node-a");
        assert_eq!(round_trip.hydrating_since_ts, 1234);
        assert!(round_trip.bootstrap_bundle_pending);
    }
}
