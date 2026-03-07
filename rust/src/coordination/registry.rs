use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine;
use fred::interfaces::{ClientLike, HashesInterface, SortedSetsInterface};
use fred::types::CustomCommand;
use serde::{Deserialize, Serialize};
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

pub async fn try_ensure_repo_cloned_from_tee(
    state: &crate::AppState,
    owner: &str,
    repo: &str,
    auth_header: Option<&str>,
    capture_dir: PathBuf,
) -> Result<()> {
    try_ensure_repo_cloned_inner(state, owner, repo, auth_header, Some(capture_dir), false).await
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

async fn try_ensure_repo_cloned_inner(
    state: &crate::AppState,
    owner: &str,
    repo: &str,
    auth_header: Option<&str>,
    tee_capture_dir: Option<PathBuf>,
    waited_for_bootstrap: bool,
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
        if !waited_for_bootstrap && wait_for_bootstrap_bundle(state, &owner_repo, &node_id).await? {
            return Box::pin(try_ensure_repo_cloned_inner(
                state,
                owner,
                repo,
                auth_header,
                tee_capture_dir,
                true,
            ))
            .await;
        }

        if let Some(capture_dir) = tee_capture_dir.as_ref() {
            cleanup_tee_capture_dir(capture_dir).await?;
        }
        debug!(%owner_repo, "hydrate already in progress; skipping duplicate background clone");
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
            "claiming hydration after previous worker state was left behind"
        );
    }
    info.status = "hydrating".to_string();
    info.hydrating_node_id = node_id.clone();
    info.hydrating_since_ts = hydrate_started_at;
    info.bootstrap_bundle_pending = false;
    set_repo_info(&state.valkey, &owner_repo, &info).await?;

    let published_repo_path = state.cache_manager.ensure_repo_dir(&owner_repo)?;
    reset_partial_repo_if_needed(&state.cache_manager, &owner_repo, &published_repo_path).await?;
    let staged_repo_path = state.cache_manager.create_staging_repo_path(&owner_repo)?;

    // We hold the lock — perform the clone.
    let result = async {
        info!(repo = %owner_repo, path = %staged_repo_path.display(), "starting staged repo hydration");
        match try_restore_repo_from_s3(state, &owner_repo, &staged_repo_path).await {
            Ok(true) => {
                info!(repo = %owner_repo, path = %staged_repo_path.display(), "restored repo from S3 bundle");
                ensure_bare_head_ref(&staged_repo_path)
                    .await
                    .with_context(|| format!("failed to set bare HEAD after S3 restore for {owner_repo}"))?;
                validate_ready_repo(state, &owner_repo, &staged_repo_path, "S3 restore")
                    .await
                    .with_context(|| format!("S3-restored repo validation failed for {owner_repo}"))?;
                publish_ready_repo(state, &owner_repo, &staged_repo_path, "S3 restore").await?;

                let now = chrono::Utc::now().timestamp();
                let mut info = get_repo_info(&state.valkey, &owner_repo)
                    .await?
                    .unwrap_or_default();
                info.status = "ready".to_string();
                info.node_ids = node_id.clone();
                info.hydrating_node_id.clear();
                info.hydrating_since_ts = 0;
                info.bootstrap_bundle_pending = false;
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

        let clone_url = clone_url(state, owner, repo_clean, auth_header);

        // Acquire the clone semaphore to respect concurrency limits.
        let _permit = state
            .clone_semaphore
            .acquire()
            .await
            .map_err(|e| anyhow::anyhow!("clone semaphore closed: {e}"))?;

        let env_vars: Vec<(String, String)> =
            vec![("GIT_TERMINAL_PROMPT".to_string(), "0".to_string())];

        let hydrated_from_tee = if let Some(capture_dir) = tee_capture_dir.as_ref() {
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
            )
            .await?
        } else {
            false
        };

        if !hydrated_from_tee {
            info!(repo = %owner_repo, path = %staged_repo_path.display(), "starting upstream bare clone");
            crate::git::commands::git_clone_bare(&clone_url, &staged_repo_path, &env_vars)
                .await
                .with_context(|| format!("upstream bare clone failed for {owner_repo}"))?;
            info!(repo = %owner_repo, path = %staged_repo_path.display(), "upstream bare clone completed");
        }

        ensure_bare_head_ref(&staged_repo_path)
            .await
            .with_context(|| format!("failed to set bare HEAD after hydration for {owner_repo}"))?;
        validate_ready_repo(
            state,
            &owner_repo,
            &staged_repo_path,
            if hydrated_from_tee {
                "tee hydration"
            } else {
                "upstream clone"
            },
        )
        .await
        .with_context(|| format!("ready-repo validation failed for {owner_repo}"))?;

        publish_ready_repo(
            state,
            &owner_repo,
            &staged_repo_path,
            if hydrated_from_tee {
                "tee hydration"
            } else {
                "upstream clone"
            },
        )
        .await?;

        let now = chrono::Utc::now().timestamp();
        let mut info = RepoInfo {
            status: "ready".to_string(),
            node_ids: node_id.clone(),
            hydrating_node_id: String::new(),
            hydrating_since_ts: 0,
            bootstrap_bundle_pending: false,
            last_fetch_ts: now,
            ..Default::default()
        };
        set_repo_info(&state.valkey, &owner_repo, &info).await?;

        crate::coordination::pubsub::publish_ready(&state.valkey, &owner_repo, &node_id).await?;

        match crate::bundleuri::generator::generate_full_bundle(
            state,
            &staged_repo_path,
            &owner_repo,
        )
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
                    &owner_repo,
                    &staged_repo_path,
                    &s3_key,
                    bundle.creation_token,
                )
                .await?;

                info.last_bundle_ts = now;
                info.latest_creation_token = bundle.creation_token;
                set_repo_info(&state.valkey, &owner_repo, &info).await?;
            }
            Err(error) => {
                warn!(
                    %owner_repo,
                    error = %error,
                    "bootstrap bundle generation failed; keeping locally cached repo"
                );
            }
        }

        Ok::<(), anyhow::Error>(())
    }
    .await;

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

    // Always release the lock.
    let _ = crate::coordination::locks::release_lock(&state.valkey, &lock_key, &node_id).await;

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
) -> Result<()> {
    let final_repo_path =
        fold_overlapping_generations(state, owner_repo, staged_repo_path, source).await?;

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
        .prune_generations_except(owner_repo, std::slice::from_ref(&final_repo_path))?;
    info!(
        repo = %owner_repo,
        path = %final_repo_path.display(),
        published = %state.cache_manager.repo_path(owner_repo).display(),
        "published repo generation and pruned superseded generations"
    );
    Ok(())
}

async fn fold_overlapping_generations(
    state: &crate::AppState,
    owner_repo: &str,
    staged_repo_path: &Path,
    source: &str,
) -> Result<PathBuf> {
    let other_generations: Vec<PathBuf> = state
        .cache_manager
        .list_generation_dirs(owner_repo)?
        .into_iter()
        .filter(|path| path != staged_repo_path)
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
        crate::git::commands::git_clone_bare_local(staged_repo_path, &consolidation_path)
            .await
            .with_context(|| {
                format!(
                    "failed to seed consolidated generation {} from {}",
                    consolidation_path.display(),
                    staged_repo_path.display()
                )
            })?;

        for generation_path in &other_generations {
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

async fn hydrate_repo_from_tee_capture(
    state: &crate::AppState,
    owner_repo: &str,
    repo_path: &Path,
    clone_url: &str,
    capture_dir: &Path,
) -> Result<bool> {
    let Some(pack_path) = crate::tee_hydration::extract_pack_from_capture(capture_dir).await?
    else {
        info!(
            repo = %owner_repo,
            capture_dir = %capture_dir.display(),
            "tee hydration skipped because no pack payload was extracted"
        );
        return Ok(false);
    };
    let captured_wants = crate::tee_hydration::extract_want_oids_from_capture(capture_dir).await?;

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

    crate::git::commands::git_init_bare(repo_path).await?;
    info!(
        repo = %owner_repo,
        pack = %pack_path.display(),
        destination = %repo_path.display(),
        "starting tee hydration index-pack"
    );
    crate::git::commands::git_index_pack(repo_path, &pack_path).await?;
    info!(
        repo = %owner_repo,
        pack = %pack_path.display(),
        destination = %repo_path.display(),
        "tee hydration index-pack finished"
    );
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
    fetch_result?;
    cleanup_result?;
    info!(
        repo = %owner_repo,
        destination = %repo_path.display(),
        clone_url = %redacted_clone_url,
        "tee hydration follow-on git fetch finished"
    );

    Ok(state.cache_manager.has_repo_at(repo_path))
}

async fn validate_ready_repo(
    state: &crate::AppState,
    owner_repo: &str,
    repo_path: &Path,
    source: &str,
) -> Result<()> {
    let validation_result = async {
        if !state.cache_manager.has_repo_at(repo_path) {
            bail!("repo is missing required bare-repo refs after {source}");
        }

        crate::git::commands::git_fsck_connectivity_only(repo_path)
            .await
            .with_context(|| {
                format!("connectivity validation failed for {owner_repo} after {source}")
            })?;

        Ok::<(), anyhow::Error>(())
    }
    .await;

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

async fn wait_for_bootstrap_bundle(
    state: &crate::AppState,
    owner_repo: &str,
    node_id: &str,
) -> Result<bool> {
    let Some(info) = get_repo_info(&state.valkey, owner_repo).await? else {
        return Ok(false);
    };

    if info.hydrating_node_id.is_empty()
        || info.hydrating_node_id == node_id
        || !info.bootstrap_bundle_pending
    {
        return Ok(false);
    }

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    let poll_interval = std::time::Duration::from_millis(250);

    loop {
        let Some(info) = get_repo_info(&state.valkey, owner_repo).await? else {
            return Ok(false);
        };

        if !info.bootstrap_bundle_pending {
            let repo_key = repo_key(owner_repo);
            let latest_bundle_s3_key: Option<String> =
                HashesInterface::hget(&state.valkey, &repo_key, "latest_bundle_s3_key")
                    .await
                    .unwrap_or(None);
            let base_bundle_s3_key: Option<String> =
                HashesInterface::hget(&state.valkey, &repo_key, "base_bundle_s3_key")
                    .await
                    .unwrap_or(None);
            return Ok(latest_bundle_s3_key.or(base_bundle_s3_key).is_some());
        }

        if tokio::time::Instant::now() >= deadline {
            return Ok(false);
        }

        tokio::time::sleep(poll_interval).await;
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
            last_fetch_ts: 10,
            last_bundle_ts: 11,
            latest_creation_token: 12,
            refs_hash: "abc".to_string(),
            size_bytes: 13,
            clone_count: 14,
        };

        let round_trip = repo_info_from_map(repo_info_to_pairs(&info).into_iter().collect());
        assert_eq!(round_trip.status, "hydrating");
        assert_eq!(round_trip.hydrating_node_id, "node-a");
        assert_eq!(round_trip.hydrating_since_ts, 1234);
        assert!(round_trip.bootstrap_bundle_pending);
    }
}
