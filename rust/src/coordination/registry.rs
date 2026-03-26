use std::collections::{BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use base64::Engine;
use fred::interfaces::{ClientLike, HashesInterface, KeysInterface, SortedSetsInterface};
use fred::types::CustomCommand;
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedMutexGuard, OwnedSemaphorePermit, TryAcquireError};
use tracing::{debug, error, info, trace, warn};

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

fn clone_hydration_semaphore_key(owner_repo: &str) -> String {
    let normalized = owner_repo.strip_suffix(".git").unwrap_or(owner_repo);
    format!("forgeproxy:semaphore:clone:{normalized}")
}

const VALKEY_RETRY_ATTEMPTS: usize = 5;
const VALKEY_RETRY_BASE_DELAY_MS: u64 = 250;

async fn retry_valkey_op<T, F, Fut>(owner_repo: &str, operation: &str, mut f: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut last_error = None;

    for attempt in 0..VALKEY_RETRY_ATTEMPTS {
        match f().await {
            Ok(value) => return Ok(value),
            Err(error) => {
                last_error = Some(error);
                if attempt + 1 == VALKEY_RETRY_ATTEMPTS {
                    break;
                }

                let delay_ms = VALKEY_RETRY_BASE_DELAY_MS * (1_u64 << attempt);
                warn!(
                    owner_repo,
                    operation,
                    attempt = attempt + 1,
                    delay_ms,
                    "Valkey operation failed; retrying"
                );
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
        }
    }

    Err(last_error.expect("retry loop must capture an error"))
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
    let map: HashMap<String, String> = retry_valkey_op(owner_repo, "HGETALL repo info", || async {
        pool.hgetall(&key).await.context("HGETALL repo info")
    })
    .await?;
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
    retry_valkey_op(owner_repo, "HSET repo info", || {
        let pairs = pairs.clone();
        async {
            let _: () = pool.hset(&key, pairs).await.context("HSET repo info")?;
            Ok(())
        }
    })
    .await?;
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
    try_ensure_repo_cloned_inner(
        state,
        owner,
        repo,
        auth_header,
        Some(capture_dir),
        None,
        None,
    )
    .await
}

pub async fn ensure_repo_cloned_from_upstream(
    state: &crate::AppState,
    owner: &str,
    repo: &str,
    auth_header: Option<&str>,
) -> Result<()> {
    try_ensure_repo_cloned_inner(state, owner, repo, auth_header, None, None, None).await
}

async fn ensure_repo_cloned_from_upstream_with_refspecs(
    state: &crate::AppState,
    owner: &str,
    repo: &str,
    auth_header: Option<&str>,
    request_refspecs: Option<&[String]>,
) -> Result<()> {
    try_ensure_repo_cloned_inner(
        state,
        owner,
        repo,
        auth_header,
        None,
        None,
        request_refspecs,
    )
    .await
}

pub struct CloneHydrationPermits {
    _global_clone_permit: OwnedSemaphorePermit,
    _local_repo_permit: OwnedSemaphorePermit,
    distributed_repo_permit: crate::coordination::locks::SemaphoreLease,
}

fn normalize_owner_repo(owner_repo: &str) -> &str {
    owner_repo.strip_suffix(".git").unwrap_or(owner_repo)
}

pub async fn try_acquire_clone_hydration_permits(
    state: &crate::AppState,
    owner_repo: &str,
) -> Result<Option<CloneHydrationPermits>> {
    let owner_repo = normalize_owner_repo(owner_repo);
    let global_clone_permit = match state.clone_semaphore.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(TryAcquireError::NoPermits) => return Ok(None),
        Err(TryAcquireError::Closed) => {
            return Err(anyhow::anyhow!("clone semaphore closed"));
        }
    };
    let Some(local_repo_permit) = acquire_local_repo_clone_permit(state, owner_repo).await? else {
        return Ok(None);
    };
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
        Some(&state.metrics),
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

pub async fn acquire_clone_hydration_permits(
    state: &crate::AppState,
    owner_repo: &str,
) -> Result<Option<CloneHydrationPermits>> {
    let owner_repo = normalize_owner_repo(owner_repo);
    if state.config.clone.max_concurrent_upstream_clones == 0
        || state
            .config
            .clone
            .max_concurrent_upstream_clones_per_repo_per_instance
            == 0
        || state
            .config
            .clone
            .max_concurrent_upstream_clones_per_repo_across_instances
            == 0
    {
        return Ok(None);
    }

    let global_clone_permit = state
        .clone_semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| anyhow::anyhow!("clone semaphore closed"))?;
    let local_repo_permit = acquire_local_repo_clone_permit_waiting(state, owner_repo).await?;
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
        Some(&state.metrics),
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
        Some(&state.metrics),
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
        None,
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

fn create_temporary_initial_repo_clone_path(mirror_path: &Path) -> Result<PathBuf> {
    let parent = mirror_path
        .parent()
        .with_context(|| format!("repo mirror path has no parent: {}", mirror_path.display()))?;
    std::fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create temp repo mirror parent {}",
            parent.display()
        )
    })?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let stem = mirror_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("repo.git");
    Ok(parent.join(format!(
        ".{stem}.hydrating-{nanos}-{}.git",
        std::process::id()
    )))
}

async fn promote_initial_repo_clone(temp_repo_path: &Path, mirror_path: &Path) -> Result<()> {
    reset_partial_repo_path_if_needed(mirror_path).await?;
    tokio::fs::rename(temp_repo_path, mirror_path)
        .await
        .with_context(|| {
            format!(
                "failed to promote hydrated repo {} into mirror {}",
                temp_repo_path.display(),
                mirror_path.display()
            )
        })?;
    Ok(())
}

async fn acquire_local_repo_clone_permit(
    state: &crate::AppState,
    owner_repo: &str,
) -> Result<Option<OwnedSemaphorePermit>> {
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

    match semaphore.try_acquire_owned() {
        Ok(permit) => Ok(Some(permit)),
        Err(TryAcquireError::NoPermits) => Ok(None),
        Err(TryAcquireError::Closed) => Err(anyhow::anyhow!("repo clone semaphore closed")),
    }
}

async fn acquire_local_repo_clone_permit_waiting(
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
        .map_err(|_| anyhow::anyhow!("repo clone semaphore closed"))
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

async fn try_acquire_local_repo_publish_guard(
    state: &crate::AppState,
    owner_repo: &str,
) -> Option<OwnedMutexGuard<()>> {
    let mutex = {
        let mut mutexes = state.repo_publish_mutexes.lock().await;
        mutexes
            .entry(owner_repo.to_string())
            .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };

    mutex.try_lock_owned().ok()
}

fn leased_generation_paths(state: &crate::AppState, owner_repo: &str) -> HashSet<PathBuf> {
    state
        .published_generation_leases
        .lock()
        .unwrap()
        .get(owner_repo)
        .map(|paths| {
            paths
                .iter()
                .filter(|(_, count)| **count > 0)
                .map(|(path, _)| path.clone())
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) async fn prune_retired_generations(
    state: &crate::AppState,
    owner_repo: &str,
) -> Result<()> {
    let mut retain = leased_generation_paths(state, owner_repo)
        .into_iter()
        .collect::<Vec<PathBuf>>();
    if let Some(current_target) = state.cache_manager.current_repo_target(owner_repo)?
        && !retain.iter().any(|path| path == &current_target)
    {
        retain.push(current_target);
    }

    state
        .cache_manager
        .prune_generations_except(owner_repo, &retain)
}

pub struct PublishedGenerationLease {
    owner_repo: String,
    generation_path: PathBuf,
    cache_manager: crate::cache::CacheManager,
    repo_publish_mutexes:
        std::sync::Arc<tokio::sync::Mutex<HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>>,
    published_generation_leases:
        std::sync::Arc<std::sync::Mutex<HashMap<String, HashMap<PathBuf, usize>>>>,
}

impl PublishedGenerationLease {
    pub fn repo_path(&self) -> &Path {
        &self.generation_path
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalServeRepoSource {
    PublishedGeneration,
}

pub enum LocalServeRepoLease {
    Published(PublishedGenerationLease),
}

impl LocalServeRepoLease {
    pub fn repo_path(&self) -> &Path {
        match self {
            Self::Published(lease) => lease.repo_path(),
        }
    }
}

impl Drop for PublishedGenerationLease {
    fn drop(&mut self) {
        let mut leases = self.published_generation_leases.lock().unwrap();
        let should_try_prune = if let Some(repo_leases) = leases.get_mut(&self.owner_repo) {
            if let Some(count) = repo_leases.get_mut(&self.generation_path) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    repo_leases.remove(&self.generation_path);
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };
        if let Some(repo_leases) = leases.get(&self.owner_repo)
            && repo_leases.is_empty()
        {
            leases.remove(&self.owner_repo);
        }
        drop(leases);

        if !should_try_prune {
            return;
        }

        let owner_repo = self.owner_repo.clone();
        let cache_manager = self.cache_manager.clone();
        let repo_publish_mutexes = std::sync::Arc::clone(&self.repo_publish_mutexes);
        let published_generation_leases = std::sync::Arc::clone(&self.published_generation_leases);
        tokio::spawn(async move {
            let mutex = {
                let mut mutexes = repo_publish_mutexes.lock().await;
                mutexes
                    .entry(owner_repo.clone())
                    .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
                    .clone()
            };
            let _guard = mutex.lock_owned().await;

            let mut retain = published_generation_leases
                .lock()
                .unwrap()
                .get(&owner_repo)
                .map(|paths| {
                    paths
                        .iter()
                        .filter(|(_, count)| **count > 0)
                        .map(|(path, _)| path.clone())
                        .collect::<Vec<PathBuf>>()
                })
                .unwrap_or_default();
            if let Ok(Some(current_target)) = cache_manager.current_repo_target(&owner_repo)
                && !retain.iter().any(|path| path == &current_target)
            {
                retain.push(current_target);
            }

            if let Err(error) = cache_manager.prune_generations_except(&owner_repo, &retain) {
                warn!(
                    repo = %owner_repo,
                    error = %error,
                    "failed to prune retired generations after the last reader lease was released"
                );
            }
        });
    }
}

pub fn acquire_published_generation_lease(
    state: &crate::AppState,
    owner_repo: &str,
) -> Result<PublishedGenerationLease> {
    let generation_path = state
        .cache_manager
        .current_repo_target(owner_repo)?
        .ok_or_else(|| anyhow::anyhow!("published repo generation is not available"))?;

    let mut leases = state.published_generation_leases.lock().unwrap();
    let count = leases
        .entry(owner_repo.to_string())
        .or_default()
        .entry(generation_path.clone())
        .or_insert(0);
    *count += 1;
    drop(leases);

    Ok(PublishedGenerationLease {
        owner_repo: owner_repo.to_string(),
        generation_path,
        cache_manager: state.cache_manager.clone(),
        repo_publish_mutexes: std::sync::Arc::clone(&state.repo_publish_mutexes),
        published_generation_leases: std::sync::Arc::clone(&state.published_generation_leases),
    })
}

pub async fn acquire_local_serve_repo_lease(
    state: &crate::AppState,
    owner_repo: &str,
    source: LocalServeRepoSource,
) -> Result<LocalServeRepoLease> {
    match source {
        LocalServeRepoSource::PublishedGeneration => Ok(LocalServeRepoLease::Published(
            acquire_published_generation_lease(state, owner_repo)?,
        )),
    }
}

async fn try_ensure_repo_cloned_inner(
    state: &crate::AppState,
    owner: &str,
    repo: &str,
    auth_header: Option<&str>,
    tee_capture_dir: Option<PathBuf>,
    preacquired_permits: Option<CloneHydrationPermits>,
    request_refspecs: Option<&[String]>,
) -> Result<()> {
    // Strip trailing ".git" from repo if present to avoid double-suffixing
    // (the URL path extractor preserves it, and we append ".git" below).
    let repo_clean = repo.strip_suffix(".git").unwrap_or(repo);
    let owner_repo = format!("{owner}/{repo_clean}");
    repair_published_without_mirror_invariant(state, &owner_repo).await?;
    let node_id = state.node_id.clone();
    let had_local_repo_at_start = state.cache_manager.has_repo(&owner_repo);

    let published_repo_path = state.cache_manager.ensure_repo_dir(&owner_repo)?;
    reset_partial_repo_path_if_needed(&published_repo_path).await?;
    let mirror_path = state.cache_manager.ensure_repo_mirror_dir(&owner_repo)?;
    reset_partial_repo_path_if_needed(&mirror_path).await?;
    let mut clone_hydration_permits = preacquired_permits;

    let result = async {
        let clone_url = clone_url(state, owner, repo_clean, auth_header);
        let has_existing_local_state =
            had_local_repo_at_start || state.cache_manager.has_repo_mirror(&owner_repo);

        if has_existing_local_state {
            info!(
                repo = %owner_repo,
                mirror = %mirror_path.display(),
                published = %published_repo_path.display(),
                "updating existing repo through a delta workspace backed by the local mirror"
            );
            if clone_hydration_permits.is_none() {
                clone_hydration_permits =
                    acquire_clone_hydration_permits(state, &owner_repo).await?;
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
                    "skipping delta fetch because the repo clone semaphore is saturated"
                );
                return Ok(());
            }
            let hydrate_started_at = chrono::Utc::now().timestamp();
            let mut info = get_repo_info(&state.valkey, &owner_repo)
                .await?
                .unwrap_or_default();
            info.status = "hydrating".to_string();
            info.hydrating_node_id = node_id.clone();
            info.hydrating_since_ts = hydrate_started_at;
            info.bootstrap_bundle_pending = false;
            set_repo_info(&state.valkey, &owner_repo, &info).await?;

            let fetch_result =
                fetch_delta_into_repo_mirror(state, &owner_repo, &clone_url, request_refspecs)
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
            crate::coordination::pubsub::publish_ready(&state.valkey, &owner_repo, &node_id)
                .await?;
            info!(
                repo = %owner_repo,
                mirror = %mirror_path.display(),
                published = %published_repo_path.display(),
                refs_updated = fetch_result.refs_updated,
                bytes_received = fetch_result.bytes_received,
                "delta workspace fetch integrated into the local mirror and published"
            );
            return Ok::<(), anyhow::Error>(());
        }

        info!(
            repo = %owner_repo,
            mirror = %mirror_path.display(),
            "starting initial repo mirror hydration"
        );
        match try_restore_repo_from_s3(state, &owner_repo, &mirror_path).await {
            Ok(true) => {
                info!(repo = %owner_repo, path = %mirror_path.display(), "restored repo mirror from S3 bundle");
                let _repo_generation_guard =
                    acquire_local_repo_publish_guard(state, &owner_repo).await;
                ensure_bare_head_ref(&mirror_path)
                    .await
                    .with_context(|| format!("failed to set bare HEAD after S3 restore for {owner_repo}"))?;
                quick_check_ready_repo(state, &owner_repo, &mirror_path, "S3 restore", None)
                    .await
                    .with_context(|| {
                        format!("S3-restored repo quick verification failed for {owner_repo}")
                    })?;
                let published_generation_path =
                    publish_repo_mirror_generation(state, &owner_repo, "S3 restore").await?;
                let published_repo_path = state.cache_manager.repo_path(&owner_repo);
                publish_bootstrap_bundle(state, &owner_repo, &published_repo_path).await?;

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
                info!(
                    %owner_repo,
                    mirror = %mirror_path.display(),
                    generation = %published_generation_path.display(),
                    published = %published_repo_path.display(),
                    "repo hydrated from S3 bundle into the local mirror"
                );
                return Ok::<(), anyhow::Error>(());
            }
            Ok(false) => {}
            Err(error) => {
                info!(
                    %owner_repo,
                    error = %error,
                    "S3 hydration unavailable; falling back to upstream clone"
                );
                if mirror_path.exists() {
                    tokio::fs::remove_dir_all(&mirror_path)
                        .await
                        .with_context(|| {
                            format!(
                                "failed to remove failed S3 hydration repo at {}",
                                mirror_path.display()
                            )
                        })?;
                }
            }
        }

        if clone_hydration_permits.is_none() {
            clone_hydration_permits =
                acquire_clone_hydration_permits(state, &owner_repo).await?;
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
                    "attempting tee-based hydration into the repo mirror from the captured upstream stream"
                );
                hydrate_repo_from_tee_capture(
                    state,
                    &owner_repo,
                    &mirror_path,
                    &clone_url,
                    capture_dir,
                    false,
                )
                .await?
            } else {
                TeeHydrationOutcome::NotHydrated
            };

            let mut initial_clone_path = None;

            if tee_outcome == TeeHydrationOutcome::NotHydrated {
                let temp_clone_path = create_temporary_initial_repo_clone_path(&mirror_path)?;
                info!(
                    repo = %owner_repo,
                    temporary = %temp_clone_path.display(),
                    mirror = %mirror_path.display(),
                    "starting upstream bare clone into temporary repo mirror"
                );
                crate::git::commands::git_clone_bare(&clone_url, &temp_clone_path, &env_vars)
                    .await
                    .with_context(|| format!("upstream bare clone failed for {owner_repo}"))?;
                info!(
                    repo = %owner_repo,
                    temporary = %temp_clone_path.display(),
                    mirror = %mirror_path.display(),
                    "upstream bare clone into temporary repo mirror completed"
                );
                ensure_bare_head_ref(&temp_clone_path).await.with_context(|| {
                    format!(
                        "failed to set bare HEAD after temporary upstream clone for {owner_repo}"
                    )
                })?;
                quick_check_ready_repo(
                    state,
                    &owner_repo,
                    &temp_clone_path,
                    "temporary upstream clone",
                    None,
                )
                .await
                .with_context(|| {
                    format!(
                        "temporary upstream clone quick verification failed for {owner_repo}"
                    )
                })?;
                initial_clone_path = Some(temp_clone_path);
            }

            Ok::<(TeeHydrationOutcome, Option<PathBuf>), anyhow::Error>((
                tee_outcome,
                initial_clone_path,
            ))
        }
        .await;
        let release_result = if let Some(permits) = clone_hydration_permits.take() {
            release_clone_hydration_permits(state, permits).await
        } else {
            Ok(())
        };
        let (tee_outcome, initial_clone_path) = hydrate_result?;
        release_result?;

        let _repo_generation_guard = acquire_local_repo_publish_guard(state, &owner_repo).await;
        if let Some(initial_clone_path) = initial_clone_path.as_ref() {
            if state.cache_manager.has_repo_mirror(&owner_repo) {
                info!(
                    repo = %owner_repo,
                    temporary = %initial_clone_path.display(),
                    mirror = %mirror_path.display(),
                    "discarding temporary initial repo clone because a writer-owned mirror already exists"
                );
                tokio::fs::remove_dir_all(initial_clone_path)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to remove redundant temporary initial repo clone at {}",
                            initial_clone_path.display()
                        )
                    })?;
            } else {
                info!(
                    repo = %owner_repo,
                    temporary = %initial_clone_path.display(),
                    mirror = %mirror_path.display(),
                    "promoting temporary initial repo clone into the writer-owned mirror"
                );
                promote_initial_repo_clone(initial_clone_path, &mirror_path).await?;
            }
        }
        ensure_bare_head_ref(&mirror_path)
            .await
            .with_context(|| format!("failed to set bare HEAD after hydration for {owner_repo}"))?;
        quick_check_ready_repo(
            state,
            &owner_repo,
            &mirror_path,
            match tee_outcome {
                TeeHydrationOutcome::HydratedWithFollowOnFetch => "tee hydration",
                TeeHydrationOutcome::PublishedFromCapture => "tee capture publish",
                TeeHydrationOutcome::NotHydrated => "upstream clone",
            },
            None,
        )
        .await
        .with_context(|| format!("ready-repo quick verification failed for {owner_repo}"))?;
        let published_generation_path = publish_repo_mirror_generation(
            state,
            &owner_repo,
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
            mirror = %mirror_path.display(),
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
        warn!(
            repo = %owner_repo,
            error = %error,
            error_chain = %format!("{error:#}"),
            "repo hydration failed"
        );
        if !had_local_repo_at_start
            && mirror_path.exists()
            && !state.cache_manager.has_repo_at(&mirror_path)
        {
            tokio::fs::remove_dir_all(&mirror_path)
                .await
                .with_context(|| {
                    format!(
                        "failed to remove failed repo mirror at {}",
                        mirror_path.display()
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
                error_chain = %format!("{cleanup_error:#}"),
                "tee capture cleanup failed after hydration error; stale capture directory remains"
            );
        }
    }

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
            "{}/{owner}/{repo_clean}.git",
            authenticated_git_base_url(state, &decoded),
        )
    } else if let Some(header) = auth_header.filter(|h| !h.trim().is_empty()) {
        let token = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("token "))
            .unwrap_or(header);
        format!(
            "{}/{owner}/{repo_clean}.git",
            authenticated_git_base_url(state, &format!("x-access-token:{token}")),
        )
    } else {
        format!(
            "{}/{owner}/{repo_clean}.git",
            state.config.upstream.git_url_base(),
        )
    }
}

fn authenticated_git_base_url(state: &crate::AppState, userinfo: &str) -> String {
    let base = state.config.upstream.git_url_base();
    if let Ok(mut parsed) = url::Url::parse(&base) {
        if let Some((username, password)) = userinfo.split_once(':') {
            let _ = parsed.set_username(username);
            let _ = parsed.set_password(Some(password));
        } else {
            let _ = parsed.set_username(userinfo);
        }
        parsed.to_string().trim_end_matches('/').to_string()
    } else {
        base
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

async fn repair_published_without_mirror_invariant(
    state: &crate::AppState,
    owner_repo: &str,
) -> Result<bool> {
    let published_repo_path = state.cache_manager.repo_path(owner_repo);
    if !state.cache_manager.has_repo_at(&published_repo_path)
        || state.cache_manager.has_repo_mirror(owner_repo)
    {
        return Ok(false);
    }

    let _repo_generation_guard = acquire_local_repo_publish_guard(state, owner_repo).await;
    if !state.cache_manager.has_repo_at(&published_repo_path)
        || state.cache_manager.has_repo_mirror(owner_repo)
    {
        return Ok(false);
    }

    let generations_dir = state.cache_manager.repo_generations_dir(owner_repo);
    error!(
        repo = %owner_repo,
        published = %published_repo_path.display(),
        generations = %generations_dir.display(),
        mirror = %state.cache_manager.repo_mirror_path(owner_repo).display(),
        "published repo invariant violated; removing published snapshots because the writer-owned mirror is missing"
    );
    state
        .cache_manager
        .remove_published_repo_generations(owner_repo)
        .await?;
    Ok(true)
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
    info!(
        repo = %owner_repo,
        path = %staged_repo_path.display(),
        source,
        "publishing ready repo generation"
    );
    state
        .cache_manager
        .publish_staged_repo(owner_repo, staged_repo_path)
        .with_context(|| {
            format!(
                "failed to publish ready repo generation {} for {}",
                staged_repo_path.display(),
                owner_repo,
            )
        })?;
    prune_retired_generations(state, owner_repo).await?;
    info!(
        repo = %owner_repo,
        path = %staged_repo_path.display(),
        published = %state.cache_manager.repo_path(owner_repo).display(),
        "published repo generation"
    );
    Ok(staged_repo_path.to_path_buf())
}

async fn reset_partial_repo_path_if_needed(repo_path: &Path) -> Result<()> {
    if repo_path.exists() && !crate::cache::manager::is_usable_bare_repo(repo_path) {
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

async fn require_existing_repo_mirror(
    state: &crate::AppState,
    owner_repo: &str,
) -> Result<PathBuf> {
    let mirror_path = state.cache_manager.ensure_repo_mirror_dir(owner_repo)?;
    reset_partial_repo_path_if_needed(&mirror_path).await?;

    if state.cache_manager.has_repo_at(&mirror_path) {
        return Ok(mirror_path);
    }
    bail!("repo mirror is not available");
}

async fn publish_repo_mirror_generation(
    state: &crate::AppState,
    owner_repo: &str,
    source: &str,
) -> Result<PathBuf> {
    let mirror_path = state.cache_manager.ensure_repo_mirror_dir(owner_repo)?;
    if !state.cache_manager.has_repo_at(&mirror_path) {
        bail!("repo mirror is not available for publication");
    }

    let staged_repo_path = state.cache_manager.create_staging_repo_path(owner_repo)?;
    let result = async {
        let stage_clone_started_at = Instant::now();
        info!(
            repo = %owner_repo,
            source,
            mirror = %mirror_path.display(),
            staged = %staged_repo_path.display(),
            snapshot_mode = "git-clone-local",
            "materializing staged generation from mirror"
        );
        crate::git::commands::git_clone_bare_local(&mirror_path, &staged_repo_path)
            .await
            .with_context(|| {
                format!(
                    "failed to materialize staged generation {} from mirror {}",
                    staged_repo_path.display(),
                    mirror_path.display()
                )
            })?;
        info!(
            repo = %owner_repo,
            source,
            mirror = %mirror_path.display(),
            staged = %staged_repo_path.display(),
            snapshot_mode = "git-clone-local",
            elapsed_ms = stage_clone_started_at.elapsed().as_millis(),
            "finished materializing staged generation from mirror"
        );

        let staged_head_started_at = Instant::now();
        info!(
            repo = %owner_repo,
            source,
            staged = %staged_repo_path.display(),
            "ensuring staged generation HEAD"
        );
        ensure_bare_head_ref(&staged_repo_path).await?;
        info!(
            repo = %owner_repo,
            source,
            staged = %staged_repo_path.display(),
            elapsed_ms = staged_head_started_at.elapsed().as_millis(),
            "finished ensuring staged generation HEAD"
        );

        let staged_validation_started_at = Instant::now();
        info!(
            repo = %owner_repo,
            source,
            staged = %staged_repo_path.display(),
            "performing quick staged-generation verification before publish"
        );
        quick_check_ready_repo(state, owner_repo, &staged_repo_path, source, None).await?;
        info!(
            repo = %owner_repo,
            source,
            staged = %staged_repo_path.display(),
            elapsed_ms = staged_validation_started_at.elapsed().as_millis(),
            "finished quick staged-generation verification before publish"
        );

        let publish_started_at = Instant::now();
        info!(
            repo = %owner_repo,
            source,
            staged = %staged_repo_path.display(),
            published = %state.cache_manager.repo_path(owner_repo).display(),
            "publishing staged generation"
        );
        let published_path =
            publish_ready_repo(state, owner_repo, &staged_repo_path, source).await?;
        spawn_generation_deep_validation(
            state.clone(),
            owner_repo.to_string(),
            published_path.clone(),
            source.to_string(),
        );
        spawn_mirror_deep_validation(
            state.clone(),
            owner_repo.to_string(),
            mirror_path.clone(),
            source.to_string(),
        );
        info!(
            repo = %owner_repo,
            source,
            staged = %staged_repo_path.display(),
            published = %state.cache_manager.repo_path(owner_repo).display(),
            elapsed_ms = publish_started_at.elapsed().as_millis(),
            "finished publishing staged generation"
        );
        Ok::<PathBuf, anyhow::Error>(published_path)
    }
    .await;
    match result {
        Ok(path) => Ok(path),
        Err(error) => {
            if staged_repo_path.exists() {
                tokio::fs::remove_dir_all(&staged_repo_path)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to remove unsuccessful staged generation at {}",
                            staged_repo_path.display()
                        )
                    })?;
            }
            Err(error)
        }
    }
}

async fn fetch_delta_into_repo_mirror(
    state: &crate::AppState,
    owner_repo: &str,
    clone_url: &str,
    request_refspecs: Option<&[String]>,
) -> Result<crate::git::commands::FetchResult> {
    let mirror_path = require_existing_repo_mirror(state, owner_repo).await?;
    if !state.cache_manager.has_repo_at(&mirror_path) {
        bail!("repo mirror is not available for delta fetch");
    }

    let delta_repo_path = state.cache_manager.create_delta_repo_path(owner_repo)?;
    let result = async {
        crate::git::commands::git_clone_bare_shared_local(&mirror_path, &delta_repo_path)
            .await
            .with_context(|| {
                format!(
                    "failed to create delta workspace {} from mirror {}",
                    delta_repo_path.display(),
                    mirror_path.display()
                )
            })?;

        let fetch_result =
            if let Some(refspecs) = request_refspecs.filter(|refspecs| !refspecs.is_empty()) {
                info!(
                    repo = %owner_repo,
                    refspec_count = refspecs.len(),
                    "request-time catch-up is fetching only refs needed for the current wants"
                );
                crate::git::commands::git_fetch_refspecs(
                    &delta_repo_path,
                    clone_url,
                    &[],
                    refspecs,
                    false,
                )
                .await?
            } else {
                crate::git::commands::git_fetch(&delta_repo_path, clone_url, &[]).await?
            };
        {
            // Keep the writer-owned mirror stable from the moment we merge the
            // delta workspace until a new published generation is ready.
            let _repo_generation_guard = acquire_local_repo_publish_guard(state, owner_repo).await;
            let delta_remote = delta_repo_path.to_string_lossy().to_string();
            if let Some(refspecs) = request_refspecs.filter(|refspecs| !refspecs.is_empty()) {
                crate::git::commands::git_fetch_refspecs(
                    &mirror_path,
                    &delta_remote,
                    &[],
                    refspecs,
                    false,
                )
                .await
                .with_context(|| {
                    format!(
                        "failed to integrate selected refs from delta workspace {} into mirror {}",
                        delta_repo_path.display(),
                        mirror_path.display()
                    )
                })?;
            } else {
                crate::git::commands::git_fetch(&mirror_path, &delta_remote, &[])
                    .await
                    .with_context(|| {
                        format!(
                            "failed to integrate delta workspace {} into mirror {}",
                            delta_repo_path.display(),
                            mirror_path.display()
                        )
                    })?;
            }
            ensure_bare_head_ref(&mirror_path).await?;
            let mirror_validation_started_at = Instant::now();
            info!(
                repo = %owner_repo,
                source = "delta workspace integration",
                path = %mirror_path.display(),
                "starting quick mirror verification before publishing a generation"
            );
            quick_check_ready_repo(
                state,
                owner_repo,
                &mirror_path,
                "delta workspace integration",
                None,
            )
            .await?;
            info!(
                repo = %owner_repo,
                source = "delta workspace integration",
                path = %mirror_path.display(),
                elapsed_ms = mirror_validation_started_at.elapsed().as_millis(),
                "finished quick mirror verification before publishing a generation"
            );
            let _published_generation_path =
                publish_repo_mirror_generation(state, owner_repo, "delta workspace integration")
                    .await?;
            let published_repo_path = state.cache_manager.repo_path(owner_repo);
            publish_bootstrap_bundle(state, owner_repo, &published_repo_path).await?;
        }
        Ok::<crate::git::commands::FetchResult, anyhow::Error>(fetch_result)
    }
    .await;

    if delta_repo_path.exists() {
        tokio::fs::remove_dir_all(&delta_repo_path)
            .await
            .with_context(|| {
                format!(
                    "failed to remove repo delta workspace at {}",
                    delta_repo_path.display()
                )
            })?;
    }

    result
}

async fn try_restore_repo_from_s3(
    state: &crate::AppState,
    owner_repo: &str,
    repo_path: &Path,
) -> Result<bool> {
    let Some(metadata) = latest_published_bundle_metadata(state, owner_repo).await? else {
        return Ok(false);
    };

    let tmp_dir = tempfile::tempdir().context("failed to create temp dir for S3 hydration")?;
    let bundle_path = tmp_dir.path().join("hydrate.bundle");
    crate::storage::s3::download_to_path(
        &state.s3_client,
        &state.metrics,
        &state.config.storage.s3.bucket,
        &metadata.bundle_s3_key,
        &bundle_path,
    )
    .await
    .with_context(|| format!("failed to download S3 bundle for {owner_repo}"))?;

    crate::git::commands::git_init_bare(repo_path).await?;
    crate::git::commands::git_fetch_bundle(repo_path, &bundle_path).await?;

    Ok(state.cache_manager.has_repo_at(repo_path))
}

pub(crate) async fn load_current_node_bundle_metadata(
    state: &crate::AppState,
    owner_repo: &str,
) -> Result<Option<crate::bundleuri::PublishedBundleMetadata>> {
    let metadata_key = crate::bundleuri::bundle_metadata_s3_key(
        &state.config.storage.s3.prefix,
        owner_repo,
        &state.bundle_publisher_id,
    );
    let Some(metadata_json) = crate::storage::s3::download_text_if_exists(
        &state.s3_client,
        &state.metrics,
        &state.config.storage.s3.bucket,
        &metadata_key,
    )
    .await?
    else {
        return Ok(None);
    };

    let metadata = serde_json::from_str(&metadata_json)
        .with_context(|| format!("parse published bundle metadata JSON for {owner_repo}"))?;
    Ok(Some(metadata))
}

async fn list_published_bundle_metadata(
    state: &crate::AppState,
    owner_repo: &str,
) -> Result<Vec<crate::bundleuri::PublishedBundleMetadata>> {
    let prefix =
        crate::bundleuri::bundle_metadata_s3_prefix(&state.config.storage.s3.prefix, owner_repo);
    let keys = crate::storage::s3::list_object_keys(
        &state.s3_client,
        &state.config.storage.s3.bucket,
        &prefix,
    )
    .await?;

    let mut metadata = Vec::new();
    for key in keys.into_iter().filter(|key| key.ends_with(".json")) {
        let Some(metadata_json) = crate::storage::s3::download_text_if_exists(
            &state.s3_client,
            &state.metrics,
            &state.config.storage.s3.bucket,
            &key,
        )
        .await?
        else {
            continue;
        };

        match serde_json::from_str::<crate::bundleuri::PublishedBundleMetadata>(&metadata_json) {
            Ok(item) => metadata.push(item),
            Err(error) => warn!(
                repo = %owner_repo,
                key = %key,
                error = %error,
                "skipping malformed published bundle metadata object"
            ),
        }
    }

    Ok(metadata)
}

async fn latest_published_bundle_metadata(
    state: &crate::AppState,
    owner_repo: &str,
) -> Result<Option<crate::bundleuri::PublishedBundleMetadata>> {
    let mut metadata = list_published_bundle_metadata(state, owner_repo).await?;
    metadata.sort_by_key(|item| (item.creation_token, item.updated_at_unix_secs));
    Ok(metadata.pop())
}

pub(crate) async fn publish_bundle_artifacts(
    state: &crate::AppState,
    owner_repo: &str,
    bundle: &crate::bundleuri::generator::BundleResult,
    filtered_bundle: Option<&crate::bundleuri::generator::BundleResult>,
) -> Result<crate::bundleuri::PublishedBundleMetadata> {
    let bundle_s3_key = crate::bundleuri::bundle_object_s3_key(
        &state.config.storage.s3.prefix,
        owner_repo,
        &state.bundle_publisher_id,
    );
    crate::storage::s3::upload_bundle(
        &state.s3_client,
        &state.metrics,
        &state.config.storage.s3.bucket,
        &bundle_s3_key,
        &bundle.bundle_path,
    )
    .await
    .with_context(|| format!("failed to upload published bundle for {owner_repo}"))?;

    let filtered_bundle_s3_key = if let Some(filtered_bundle) = filtered_bundle {
        let filtered_s3_key = crate::bundleuri::filtered_bundle_object_s3_key(
            &state.config.storage.s3.prefix,
            owner_repo,
            &state.bundle_publisher_id,
        );
        crate::storage::s3::upload_bundle(
            &state.s3_client,
            &state.metrics,
            &state.config.storage.s3.bucket,
            &filtered_s3_key,
            &filtered_bundle.bundle_path,
        )
        .await
        .with_context(|| format!("failed to upload filtered bundle for {owner_repo}"))?;
        Some(filtered_s3_key)
    } else {
        None
    };

    let metadata = crate::bundleuri::PublishedBundleMetadata {
        publisher_id: state.bundle_publisher_id.clone(),
        creation_token: bundle.creation_token,
        bundle_s3_key: bundle_s3_key.clone(),
        filtered_bundle_s3_key,
        updated_at_unix_secs: chrono::Utc::now().timestamp(),
        service_instance_id: state
            .runtime_resource_attributes
            .service_instance_id
            .clone(),
        service_machine_id: state.runtime_resource_attributes.service_machine_id.clone(),
    };
    let metadata_key = crate::bundleuri::bundle_metadata_s3_key(
        &state.config.storage.s3.prefix,
        owner_repo,
        &state.bundle_publisher_id,
    );
    let metadata_json =
        serde_json::to_string_pretty(&metadata).context("serialize published bundle metadata")?;
    crate::storage::s3::upload_text(
        &state.s3_client,
        &state.config.storage.s3.bucket,
        &metadata_key,
        &metadata_json,
    )
    .await
    .with_context(|| format!("failed to upload published bundle metadata for {owner_repo}"))?;

    let repo_key = repo_key(owner_repo);
    HashesInterface::hset::<(), _, _>(
        &state.valkey,
        &repo_key,
        [
            ("bundle_list_key", metadata_key.as_str()),
            ("latest_bundle_s3_key", bundle_s3_key.as_str()),
            ("latest_bundle_token", &bundle.creation_token.to_string()),
        ],
    )
    .await?;

    let mut info = get_repo_info(&state.valkey, owner_repo)
        .await?
        .unwrap_or_default();
    info.last_bundle_ts = metadata.updated_at_unix_secs;
    info.latest_creation_token = metadata.creation_token;
    info.s3_bundle_list_key = metadata_key;
    set_repo_info(&state.valkey, owner_repo, &info).await?;

    Ok(metadata)
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
    let redacted_clone_url = redacted_clone_url(state, clone_url);
    info!(
        repo = %owner_repo,
        mirror = %state.cache_manager.repo_mirror_path(owner_repo).display(),
        clone_url = %redacted_clone_url,
        "starting capture convergence follow-on delta fetch"
    );
    let fetch_result = fetch_delta_into_repo_mirror(state, owner_repo, clone_url, None).await?;
    info!(
        repo = %owner_repo,
        published = %state.cache_manager.repo_path(owner_repo).display(),
        clone_url = %redacted_clone_url,
        refs_updated = fetch_result.refs_updated,
        bytes_received = fetch_result.bytes_received,
        "capture convergence follow-on delta fetch finished"
    );
    Ok(())
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
        let materialize_refs_started_at = Instant::now();
        info!(
            repo = %owner_repo,
            destination = %repo_path.display(),
            capture_dir = %capture_dir.display(),
            "materializing capture refs into hydrated mirror"
        );
        let metadata = materialize_capture_refs(repo_path, capture_dir).await?;
        info!(
            repo = %owner_repo,
            destination = %repo_path.display(),
            capture_dir = %capture_dir.display(),
            refs_materialized = metadata.refs.len(),
            head = ?metadata.head_symref_target,
            elapsed_ms = materialize_refs_started_at.elapsed().as_millis(),
            "finished materializing capture refs into hydrated mirror"
        );
        if !metadata.refs.is_empty() && state.cache_manager.has_repo_at(repo_path) {
            let direct_publish_validation_started_at = Instant::now();
            info!(
                repo = %owner_repo,
                destination = %repo_path.display(),
                refs_materialized = metadata.refs.len(),
                head = ?metadata.head_symref_target,
                "validating tee-capture metadata for direct publish"
            );
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
                        elapsed_ms = direct_publish_validation_started_at.elapsed().as_millis(),
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
                        elapsed_ms = direct_publish_validation_started_at.elapsed().as_millis(),
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

async fn quick_check_ready_repo(
    state: &crate::AppState,
    _owner_repo: &str,
    repo_path: &Path,
    source: &str,
    wants: Option<&[String]>,
) -> Result<()> {
    if !state.cache_manager.has_repo_at(repo_path) {
        bail!("repo is missing required bare-repo refs after {source}");
    }

    if let Some(wants) = wants.filter(|wants| !wants.is_empty()) {
        let missing_wants = crate::git::commands::git_missing_objects(repo_path, wants).await?;
        if !missing_wants.is_empty() {
            let sample = missing_wants
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join(",");
            bail!(
                "repo is missing {} wanted objects after {} (sample: {})",
                missing_wants.len(),
                source,
                sample,
            );
        }
    }

    Ok(())
}

fn spawn_generation_deep_validation(
    state: crate::AppState,
    owner_repo: String,
    generation_path: PathBuf,
    source: String,
) {
    tokio::spawn(async move {
        let validation_started_at = Instant::now();
        info!(
            repo = %owner_repo,
            source,
            path = %generation_path.display(),
            "starting background deep validation for published generation"
        );
        match check_ready_repo(&state, &owner_repo, &generation_path, &source).await {
            Ok(()) => {
                info!(
                    repo = %owner_repo,
                    source,
                    path = %generation_path.display(),
                    elapsed_ms = validation_started_at.elapsed().as_millis(),
                    "finished background deep validation for published generation"
                );
            }
            Err(error) => {
                error!(
                    repo = %owner_repo,
                    source,
                    path = %generation_path.display(),
                    elapsed_ms = validation_started_at.elapsed().as_millis(),
                    error = %error,
                    "published generation failed background deep validation"
                );
            }
        }
    });
}

fn spawn_mirror_deep_validation(
    state: crate::AppState,
    owner_repo: String,
    mirror_path: PathBuf,
    source: String,
) {
    tokio::spawn(async move {
        let Some(_publish_guard) = try_acquire_local_repo_publish_guard(&state, &owner_repo).await
        else {
            info!(
                repo = %owner_repo,
                source,
                path = %mirror_path.display(),
                "skipping background deep validation for mirror because publish work is already in progress"
            );
            return;
        };

        if !state.cache_manager.has_repo_at(&mirror_path) {
            return;
        }

        let validation_root = state.cache_manager.base_path.join(".validation-work");
        if let Err(error) = std::fs::create_dir_all(&validation_root) {
            error!(
                repo = %owner_repo,
                source,
                path = %validation_root.display(),
                error = %error,
                "failed to create validation-work directory for background mirror validation"
            );
            return;
        }
        let temp_root = match tempfile::Builder::new()
            .prefix("mirror-validate-")
            .tempdir_in(&validation_root)
        {
            Ok(dir) => dir,
            Err(error) => {
                error!(
                    repo = %owner_repo,
                    source,
                    path = %mirror_path.display(),
                    error = %error,
                    "failed to create tempdir for background mirror validation"
                );
                return;
            }
        };
        let snapshot_path = temp_root.path().join("snapshot.git");
        info!(
            repo = %owner_repo,
            source,
            mirror = %mirror_path.display(),
            snapshot = %snapshot_path.display(),
            "creating local snapshot for background mirror validation"
        );
        if let Err(error) =
            crate::git::commands::git_clone_bare_local(&mirror_path, &snapshot_path).await
        {
            error!(
                repo = %owner_repo,
                source,
                mirror = %mirror_path.display(),
                snapshot = %snapshot_path.display(),
                error = %error,
                "failed to create local snapshot for background mirror validation"
            );
            return;
        }
        drop(_publish_guard);

        let validation_started_at = Instant::now();
        info!(
            repo = %owner_repo,
            source,
            mirror = %mirror_path.display(),
            snapshot = %snapshot_path.display(),
            "starting background deep validation for mirror snapshot"
        );
        match check_ready_repo(&state, &owner_repo, &snapshot_path, &source).await {
            Ok(()) => {
                info!(
                    repo = %owner_repo,
                    source,
                    mirror = %mirror_path.display(),
                    snapshot = %snapshot_path.display(),
                    elapsed_ms = validation_started_at.elapsed().as_millis(),
                    "finished background deep validation for mirror snapshot"
                );
            }
            Err(error) => {
                error!(
                    repo = %owner_repo,
                    source,
                    mirror = %mirror_path.display(),
                    snapshot = %snapshot_path.display(),
                    elapsed_ms = validation_started_at.elapsed().as_millis(),
                    error = %error,
                    "mirror snapshot failed background deep validation"
                );
            }
        }
    });
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

async fn publish_bootstrap_bundle(
    state: &crate::AppState,
    owner_repo: &str,
    published_repo_path: &Path,
) -> Result<()> {
    match crate::bundleuri::generator::generate_full_bundle(state, published_repo_path, owner_repo)
        .await
    {
        Ok(bundle) => {
            publish_bundle_artifacts(state, owner_repo, &bundle, None).await?;
        }
        Err(error) => {
            warn!(
                %owner_repo,
                error = %error,
                error_chain = %format!("{error:#}"),
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
        serve_from: LocalServeRepoSource,
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

pub fn clone_cache_status(decision: &LocalServeDecision) -> crate::metrics::CacheStatus {
    match decision {
        LocalServeDecision::SatisfiesWants {
            serve_from: LocalServeRepoSource::PublishedGeneration,
            had_local_repo_before_check: true,
            restored_from_s3_for_request: false,
            ..
        } => crate::metrics::CacheStatus::Hot,
        LocalServeDecision::SatisfiesWants {
            restored_from_s3_for_request: true,
            ..
        }
        | LocalServeDecision::Unavailable {
            had_local_repo_before_check: true,
            ..
        }
        | LocalServeDecision::Unavailable {
            restored_from_s3_for_request: true,
            ..
        }
        | LocalServeDecision::MissingWantedObjects {
            had_local_repo_before_check: true,
            ..
        }
        | LocalServeDecision::MissingWantedObjects {
            restored_from_s3_for_request: true,
            ..
        } => crate::metrics::CacheStatus::Warm,
        _ => crate::metrics::CacheStatus::Cold,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestCatchUpPlan {
    pub refspecs: Vec<String>,
    pub matched_wants: usize,
    pub unmatched_wants: usize,
}

pub fn derive_request_catch_up_plan(
    metadata: &crate::tee_hydration::CapturedRefMetadata,
    wants: &[String],
) -> RequestCatchUpPlan {
    let oid_to_refs = metadata.refs.iter().fold(
        HashMap::<&str, Vec<&str>>::new(),
        |mut acc, (refname, oid)| {
            acc.entry(oid.as_str()).or_default().push(refname.as_str());
            acc
        },
    );

    let mut refspecs = BTreeSet::new();
    let mut matched_wants = 0;
    let mut unmatched_wants = 0;

    for want in wants {
        if let Some(refnames) = oid_to_refs.get(want.as_str()) {
            matched_wants += 1;
            for refname in refnames {
                refspecs.insert(format!("+{refname}:{refname}"));
            }
        } else {
            unmatched_wants += 1;
        }
    }

    RequestCatchUpPlan {
        refspecs: refspecs.into_iter().collect(),
        matched_wants,
        unmatched_wants,
    }
}

pub fn derive_request_catch_up_plan_from_info_refs(
    info_refs_advertisement: &[u8],
    wants: &[String],
) -> RequestCatchUpPlan {
    let metadata =
        crate::tee_hydration::parse_info_refs_advertisement_metadata(info_refs_advertisement);
    derive_request_catch_up_plan(&metadata, wants)
}

async fn ensure_repo_available_locally_detailed(
    state: &crate::AppState,
    owner_repo: &str,
) -> Result<LocalRepoAvailability> {
    repair_published_without_mirror_invariant(state, owner_repo).await?;
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

    if state.cache_manager.has_repo_mirror(owner_repo) {
        debug!(
            repo = %owner_repo,
            mirror = %state.cache_manager.repo_mirror_path(owner_repo).display(),
            "using the local mirror for request-time serveability while the published generation is unavailable"
        );
        return Ok(LocalRepoAvailability {
            had_local_repo_before_check,
            restored_from_s3_for_request: false,
            available: true,
        });
    }

    let _repo_generation_guard = acquire_local_repo_publish_guard(state, owner_repo).await;
    let published_repo_path = state.cache_manager.repo_path(owner_repo);
    if state.cache_manager.has_repo_at(&published_repo_path)
        && !state.cache_manager.has_repo_mirror(owner_repo)
    {
        let generations_dir = state.cache_manager.repo_generations_dir(owner_repo);
        error!(
            repo = %owner_repo,
            published = %published_repo_path.display(),
            generations = %generations_dir.display(),
            mirror = %state.cache_manager.repo_mirror_path(owner_repo).display(),
            "published repo invariant violated; removing published snapshots because the writer-owned mirror is missing"
        );
        state
            .cache_manager
            .remove_published_repo_generations(owner_repo)
            .await?;
    }
    if state.cache_manager.has_repo(owner_repo) {
        return Ok(LocalRepoAvailability {
            had_local_repo_before_check,
            restored_from_s3_for_request: false,
            available: true,
        });
    }
    if state.cache_manager.has_repo_mirror(owner_repo) {
        debug!(
            repo = %owner_repo,
            mirror = %state.cache_manager.repo_mirror_path(owner_repo).display(),
            "using the local mirror for request-time serveability while the published generation is unavailable"
        );
        return Ok(LocalRepoAvailability {
            had_local_repo_before_check,
            restored_from_s3_for_request: false,
            available: true,
        });
    }

    let mirror_path = state.cache_manager.ensure_repo_mirror_dir(owner_repo)?;
    reset_partial_repo_path_if_needed(&mirror_path).await?;

    let restore_result = try_restore_repo_from_s3(state, owner_repo, &mirror_path).await;

    let availability = match restore_result {
        Ok(true) => {
            if state.cache_manager.has_repo(owner_repo) {
                LocalRepoAvailability {
                    had_local_repo_before_check,
                    restored_from_s3_for_request: false,
                    available: true,
                }
            } else {
                ensure_bare_head_ref(&mirror_path).await.with_context(|| {
                    format!("failed to set bare HEAD after S3 restore for {owner_repo}")
                })?;
                quick_check_ready_repo(
                    state,
                    owner_repo,
                    &mirror_path,
                    "S3 restore for request",
                    None,
                )
                .await
                .with_context(|| {
                    format!("S3-restored repo quick verification failed for {owner_repo}")
                })?;
                publish_repo_mirror_generation(state, owner_repo, "S3 restore for request").await?;

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
            if mirror_path.exists() && !state.cache_manager.has_repo_at(&mirror_path) {
                tokio::fs::remove_dir_all(&mirror_path)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to remove failed request-time S3 restore at {}",
                            mirror_path.display()
                        )
                    })?;
            }
            return Err(error);
        }
    };

    if !availability.available
        && mirror_path.exists()
        && !state.cache_manager.has_repo_at(&mirror_path)
    {
        tokio::fs::remove_dir_all(&mirror_path)
            .await
            .with_context(|| {
                format!(
                    "failed to remove unused request-time S3 restore at {}",
                    mirror_path.display()
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

    let published_repo_path = state.cache_manager.repo_path(owner_repo);
    if state.cache_manager.has_repo_at(&published_repo_path) {
        let missing_wants =
            crate::git::commands::git_missing_objects(&published_repo_path, wants).await?;
        if missing_wants.is_empty() {
            return Ok(LocalServeDecision::SatisfiesWants {
                serve_from: LocalServeRepoSource::PublishedGeneration,
                had_local_repo_before_check: availability.had_local_repo_before_check,
                restored_from_s3_for_request: availability.restored_from_s3_for_request,
                want_count: wants.len(),
            });
        }
    }

    let mirror_repo_path = state.cache_manager.repo_mirror_path(owner_repo);
    if state.cache_manager.has_repo_at(&mirror_repo_path)
        && let Some(_publish_guard) = try_acquire_local_repo_publish_guard(state, owner_repo).await
        && state.cache_manager.has_repo_at(&mirror_repo_path)
    {
        let missing_wants =
            crate::git::commands::git_missing_objects(&mirror_repo_path, wants).await?;
        return Ok(LocalServeDecision::MissingWantedObjects {
            had_local_repo_before_check: availability.had_local_repo_before_check,
            restored_from_s3_for_request: availability.restored_from_s3_for_request,
            want_count: wants.len(),
            missing_wants,
        });
    }

    if state.cache_manager.has_repo_at(&published_repo_path) {
        let missing_wants =
            crate::git::commands::git_missing_objects(&published_repo_path, wants).await?;
        Ok(LocalServeDecision::MissingWantedObjects {
            had_local_repo_before_check: availability.had_local_repo_before_check,
            restored_from_s3_for_request: availability.restored_from_s3_for_request,
            want_count: wants.len(),
            missing_wants,
        })
    } else {
        Ok(LocalServeDecision::Unavailable {
            had_local_repo_before_check: availability.had_local_repo_before_check,
            restored_from_s3_for_request: availability.restored_from_s3_for_request,
        })
    }
}

pub async fn wait_for_local_catch_up(
    state: &crate::AppState,
    owner: &str,
    repo: &str,
    auth_header: Option<&str>,
    wants: &[String],
    request_refspecs: Option<Vec<String>>,
) -> Result<LocalServeDecision> {
    let timeout = Duration::from_secs(state.config.clone.request_wait_for_local_catch_up_secs);
    let repo_clean = repo.strip_suffix(".git").unwrap_or(repo);
    let owner_repo = format!("{owner}/{repo_clean}");

    let initial_decision = classify_local_wants_satisfaction(state, &owner_repo, wants).await?;
    if !matches!(
        initial_decision,
        LocalServeDecision::MissingWantedObjects { .. }
    ) {
        return Ok(initial_decision);
    }
    if timeout.is_zero() {
        return Ok(initial_decision);
    }

    let has_published_repo = state.cache_manager.has_repo(&owner_repo);
    let repo_info = get_repo_info(&state.valkey, &owner_repo).await?;
    let should_start_refresh = if let Some(info) = repo_info {
        if !info.hydrating_node_id.is_empty() && !has_published_repo {
            let semaphore_key = clone_hydration_semaphore_key(&owner_repo);
            let hydration_lease_count: i64 = state.valkey.exists(semaphore_key.clone()).await?;
            if hydration_lease_count == 0 {
                warn!(
                    repo = %owner_repo,
                    hydrating_node = %info.hydrating_node_id,
                    hydrating_since_ts = info.hydrating_since_ts,
                    semaphore_key,
                    "clearing stale hydration state because the published generation is missing and no active clone lease exists"
                );
                clear_hydration_state(state, &owner_repo, "missing").await?;
                true
            } else {
                false
            }
        } else {
            info.hydrating_node_id.is_empty()
        }
    } else {
        true
    };
    let mut refresh_handle = if should_start_refresh {
        let state = state.clone();
        let owner = owner.to_string();
        let repo = repo_clean.to_string();
        let auth_header = auth_header.map(ToOwned::to_owned);
        let request_refspecs = request_refspecs.clone();
        Some(tokio::spawn(async move {
            ensure_repo_cloned_from_upstream_with_refspecs(
                &state,
                &owner,
                &repo,
                auth_header.as_deref(),
                request_refspecs.as_deref(),
            )
            .await
        }))
    } else {
        None
    };

    let started_at = Instant::now();
    let mut last_decision = initial_decision;
    info!(
        repo = %owner_repo,
        timeout_secs = timeout.as_secs(),
        started_refresh = should_start_refresh,
        has_published_repo,
        has_repo_mirror = state.cache_manager.has_repo_mirror(&owner_repo),
        "waiting for local published-generation catch-up before deciding whether to proxy upstream"
    );
    while started_at.elapsed() < timeout {
        if refresh_handle
            .as_ref()
            .is_some_and(tokio::task::JoinHandle::is_finished)
        {
            let refresh_result = refresh_handle.take().unwrap().await;
            match refresh_result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    error!(
                        repo = %owner_repo,
                        error = %error,
                        "request-time quick local verification failed; falling back to upstream proxy"
                    );
                    return Ok(last_decision);
                }
                Err(error) => {
                    error!(
                        repo = %owner_repo,
                        error = %error,
                        "request-time catch-up task failed; falling back to upstream proxy"
                    );
                    return Ok(last_decision);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        let decision = classify_local_wants_satisfaction(state, &owner_repo, wants).await?;
        if matches!(decision, LocalServeDecision::SatisfiesWants { .. }) {
            info!(
                repo = %owner_repo,
                elapsed_ms = started_at.elapsed().as_millis(),
                "local published-generation catch-up completed before request timeout"
            );
            return Ok(decision);
        }
        last_decision = decision;
    }

    info!(
        repo = %owner_repo,
        elapsed_ms = started_at.elapsed().as_millis(),
        "local published-generation catch-up timed out; falling back to upstream proxy"
    );
    Ok(last_decision)
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
    use std::collections::BTreeMap;

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

    #[test]
    fn derive_request_catch_up_plan_selects_only_matching_refs() {
        let metadata = crate::tee_hydration::CapturedRefMetadata {
            refs: BTreeMap::from([
                (
                    "refs/heads/main".to_string(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                ),
                (
                    "refs/tags/v1".to_string(),
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                ),
                (
                    "refs/tags/v1-dup".to_string(),
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                ),
            ]),
            head_symref_target: Some("refs/heads/main".to_string()),
        };

        let plan = derive_request_catch_up_plan(
            &metadata,
            &[
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                "cccccccccccccccccccccccccccccccccccccccc".to_string(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            ],
        );

        assert_eq!(plan.matched_wants, 2);
        assert_eq!(plan.unmatched_wants, 1);
        assert_eq!(
            plan.refspecs,
            vec![
                "+refs/heads/main:refs/heads/main".to_string(),
                "+refs/tags/v1-dup:refs/tags/v1-dup".to_string(),
                "+refs/tags/v1:refs/tags/v1".to_string(),
            ]
        );
    }
}
