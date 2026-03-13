//! Bundle lifecycle scheduler.
//!
//! Runs background tasks on a periodic schedule to:
//!
//! 1. Scan the repo registry for repos that need a background fetch from the upstream forge.
//! 2. Generate incremental bundles after each fetch.
//! 3. Upload bundles to S3 and update the Valkey registry.
//! 4. Consolidate hourly bundles into daily bundles.
//! 5. Consolidate daily bundles into a new base bundle.
//!
//! The fetch interval for each repo is dynamically adjusted based on the delta
//! size observed in the most recent fetch: large deltas shorten the interval,
//! small deltas lengthen it (exponential backoff up to the configured max).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{Datelike, Timelike, Utc};
use fred::interfaces::HashesInterface;
use futures::{StreamExt, stream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, instrument, warn};

use crate::AppState;

fn format_error_chain(error: &anyhow::Error) -> String {
    error
        .chain()
        .map(|cause| cause.to_string())
        .collect::<Vec<_>>()
        .join(": ")
}

#[derive(Debug, Default)]
pub(crate) struct TickSummary {
    pub(crate) repos_scanned: usize,
    pub(crate) repos_completed: usize,
    pub(crate) skipped_not_due: usize,
    pub(crate) skipped_below_min_clone_count: usize,
    pub(crate) skipped_lock_held: usize,
    pub(crate) skipped_not_cached: usize,
    pub(crate) fetch_succeeded: usize,
    pub(crate) fetch_failed: usize,
    pub(crate) bundles_generated: usize,
    pub(crate) bundle_generation_failed: usize,
    pub(crate) bundle_upload_failed: usize,
    pub(crate) filtered_bundles_generated: usize,
    pub(crate) filtered_bundle_upload_failed: usize,
    pub(crate) repos_published: usize,
    pub(crate) repo_errors: usize,
}

impl TickSummary {
    fn record(&mut self, outcome: RepoTickOutcome) {
        self.repos_scanned += 1;

        match outcome.status {
            RepoTickStatus::Completed => self.repos_completed += 1,
            RepoTickStatus::SkippedNotDue => self.skipped_not_due += 1,
            RepoTickStatus::SkippedBelowMinCloneCount => self.skipped_below_min_clone_count += 1,
            RepoTickStatus::SkippedLockHeld => self.skipped_lock_held += 1,
            RepoTickStatus::SkippedNotCached => self.skipped_not_cached += 1,
            RepoTickStatus::FetchFailed => self.fetch_failed += 1,
            RepoTickStatus::BundleGenerationFailed => self.bundle_generation_failed += 1,
        }

        if outcome.fetch_succeeded {
            self.fetch_succeeded += 1;
        }
        if outcome.bundle_generated {
            self.bundles_generated += 1;
        }
        if outcome.bundle_upload_failed {
            self.bundle_upload_failed += 1;
        }
        if outcome.filtered_bundle_generated {
            self.filtered_bundles_generated += 1;
        }
        if outcome.filtered_bundle_upload_failed {
            self.filtered_bundle_upload_failed += 1;
        }
        if outcome.published {
            self.repos_published += 1;
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
enum RepoTickStatus {
    #[default]
    Completed,
    SkippedNotDue,
    SkippedBelowMinCloneCount,
    SkippedLockHeld,
    SkippedNotCached,
    FetchFailed,
    BundleGenerationFailed,
}

#[derive(Debug, Default, Clone, Copy)]
struct RepoTickOutcome {
    status: RepoTickStatus,
    fetch_succeeded: bool,
    bundle_generated: bool,
    bundle_upload_failed: bool,
    filtered_bundle_generated: bool,
    filtered_bundle_upload_failed: bool,
    published: bool,
}

impl RepoTickOutcome {
    fn with_status(status: RepoTickStatus) -> Self {
        Self {
            status,
            ..Self::default()
        }
    }

    fn completed() -> Self {
        Self::with_status(RepoTickStatus::Completed)
    }
}

struct BundleLockHeartbeat {
    lease: crate::coordination::locks::LockLease,
    shutdown_tx: watch::Sender<bool>,
    join_handle: JoinHandle<()>,
}

fn bundle_lock_heartbeat_interval(ttl_secs: u64) -> Duration {
    Duration::from_secs(std::cmp::max(1, ttl_secs / 3))
}

fn spawn_bundle_lock_heartbeat(
    state: &AppState,
    lease: crate::coordination::locks::LockLease,
    ttl_secs: u64,
) -> BundleLockHeartbeat {
    let interval = bundle_lock_heartbeat_interval(ttl_secs);
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let valkey = state.valkey.clone();
    let heartbeat_lease = lease.clone();

    let join_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    match crate::coordination::locks::renew_lock_lease(&valkey, &heartbeat_lease, ttl_secs).await {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(error) => {
                            warn!(
                                key = %heartbeat_lease.key,
                                node_id = %heartbeat_lease.node_id,
                                error = %error,
                                error_chain = %format_error_chain(&error),
                                "bundle lock heartbeat failed"
                            );
                            break;
                        }
                    }
                }
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }
    });

    BundleLockHeartbeat {
        lease,
        shutdown_tx,
        join_handle,
    }
}

async fn stop_bundle_lock_heartbeat(
    heartbeat: BundleLockHeartbeat,
) -> crate::coordination::locks::LockLease {
    let BundleLockHeartbeat {
        lease,
        shutdown_tx,
        join_handle,
    } = heartbeat;
    let _ = shutdown_tx.send(true);
    match join_handle.await {
        Ok(()) => {}
        Err(error) => {
            warn!(key = %lease.key, node_id = %lease.node_id, error = %error, "bundle lock heartbeat task ended unexpectedly")
        }
    }
    lease
}

// ---------------------------------------------------------------------------
// Main lifecycle loop
// ---------------------------------------------------------------------------

/// Main bundle lifecycle loop.
///
/// Runs on a 60-second tick, scanning the repo registry and performing
/// fetches + bundle generation as needed.  This function never returns under
/// normal operation; errors on individual ticks are logged and the loop
/// continues.
pub async fn run_bundle_lifecycle(state: Arc<AppState>) {
    let scan_interval = Duration::from_secs(60);

    info!("bundle lifecycle scheduler started");

    loop {
        if let Err(e) = tick(&state).await {
            error!(error = %e, "bundle lifecycle tick failed");
        }
        tokio::time::sleep(scan_interval).await;
    }
}

// ---------------------------------------------------------------------------
// Tick
// ---------------------------------------------------------------------------

/// A single lifecycle tick: iterate over all registered repos and process
/// those that are due for a fetch and bundle refresh.
#[instrument(skip(state))]
pub(crate) async fn tick(state: &AppState) -> Result<()> {
    let _ = tick_with_summary(state).await?;
    Ok(())
}

#[instrument(skip(state))]
pub(crate) async fn tick_with_summary(state: &AppState) -> Result<TickSummary> {
    let repos = crate::coordination::registry::list_all_repos(&state.valkey).await?;
    debug!(
        repo_count = repos.len(),
        concurrency = state.bundle_max_concurrency,
        "lifecycle tick: scanning repos"
    );
    let mut summary = TickSummary::default();

    let mut results = stream::iter(repos.into_iter().map(|owner_repo| async move {
        let result = process_repo(state, &owner_repo).await;
        (owner_repo, result)
    }))
    .buffer_unordered(state.bundle_max_concurrency);

    while let Some((owner_repo, result)) = results.next().await {
        match result {
            Ok(outcome) => summary.record(outcome),
            Err(e) => {
                summary.repo_errors += 1;
                warn!(
                    repo = %owner_repo,
                    error = %e,
                    error_chain = %format_error_chain(&e),
                    "failed to process repo in lifecycle tick"
                );
            }
        }
    }

    Ok(summary)
}

/// Process a single repo: check schedule, fetch if needed, generate bundle,
/// upload to S3.
#[instrument(skip(state), fields(%owner_repo))]
async fn process_repo(state: &AppState, owner_repo: &str) -> Result<RepoTickOutcome> {
    // 1. Read the dynamic fetch schedule for this repo.
    let schedule = crate::coordination::registry::get_fetch_schedule(&state.valkey, owner_repo)
        .await?
        .unwrap_or_default();

    // 2. Check if the repo is due for a fetch.
    // Use the repo info's last successful bundle/publication timestamp rather
    // than the removed fetch-freshness timestamp.
    let now = Utc::now().timestamp() as u64;
    let repo_info = crate::coordination::registry::get_repo_info(&state.valkey, owner_repo).await?;
    let last_bundle = repo_info
        .as_ref()
        .map(|r| r.last_bundle_ts as u64)
        .unwrap_or(0);
    let interval = effective_interval(state, owner_repo, schedule.current_interval);
    // ^ uses the current_interval from FetchSchedule

    if last_bundle + interval > now {
        debug!(
            repo = %owner_repo,
            next_in_secs = (last_bundle + interval).saturating_sub(now),
            "repo not yet due for fetch"
        );
        return Ok(RepoTickOutcome::with_status(RepoTickStatus::SkippedNotDue));
    }

    // 3. Check minimum clone count threshold before investing in bundles.
    let repo_key = crate::coordination::registry::repo_key(owner_repo);
    let clone_count: Option<i64> = HashesInterface::hget(&state.valkey, &repo_key, "clone_count")
        .await
        .unwrap_or(None);
    let min_clones = state.config.bundles.min_clone_count_for_bundles;
    if (clone_count.unwrap_or(0) as u64) < min_clones {
        debug!(
            repo = %owner_repo,
            clone_count = clone_count.unwrap_or(0),
            min_clones = min_clones,
            "repo below minimum clone count for bundle generation"
        );
        return Ok(RepoTickOutcome::with_status(
            RepoTickStatus::SkippedBelowMinCloneCount,
        ));
    }

    // 4. Attempt to acquire the distributed fetch/bundle lock.
    let lock_key = format!("forgeproxy:lock:bundle:{owner_repo}");
    let lock_ttl = state.config.bundles.bundle_lock_ttl;
    let node_id = crate::coordination::node::node_id();
    let Some(lock_lease) = crate::coordination::locks::acquire_lock_lease(
        &state.valkey,
        &lock_key,
        &node_id,
        lock_ttl,
    )
    .await?
    else {
        debug!(repo = %owner_repo, "another node holds the bundle lock; skipping");
        return Ok(RepoTickOutcome::with_status(
            RepoTickStatus::SkippedLockHeld,
        ));
    };
    let bundle_lock_heartbeat = spawn_bundle_lock_heartbeat(state, lock_lease, lock_ttl);

    // 5. Perform the fetch.
    info!(repo = %owner_repo, "starting background fetch for bundle generation");

    let repo_path = state.cache_manager.repo_path(owner_repo);
    let staged_repo_path = state.cache_manager.create_staging_repo_path(owner_repo)?;
    let mut published = false;
    let mut outcome = RepoTickOutcome::completed();

    let fetch_result = if state.cache_manager.has_repo(owner_repo) {
        // Repo is locally cached -- do an incremental fetch.
        let upstream_url = format!(
            "https://{}/{}.git",
            state.config.upstream.hostname, owner_repo,
        );
        let admin_token =
            crate::credentials::keyring::resolve_secret(&state.config.upstream.admin_token_env)
                .await
                .unwrap_or_default();
        let env_vars = vec![("GIT_TERMINAL_PROMPT".to_string(), "0".to_string())];
        let env_with_auth: Vec<(String, String)> = if admin_token.is_empty() {
            env_vars
        } else {
            let mut v = env_vars;
            v.push(("GIT_ASKPASS".to_string(), "/bin/true".to_string()));
            v
        };

        let url_with_token = if admin_token.is_empty() {
            upstream_url
        } else {
            format!(
                "https://x-access-token:{admin_token}@{}/{}.git",
                state.config.upstream.hostname, owner_repo,
            )
        };

        crate::git::commands::git_clone_bare_local(&repo_path, &staged_repo_path).await?;
        crate::git::commands::git_fetch(&staged_repo_path, &url_with_token, &env_with_auth).await
    } else {
        debug!(
            repo = %owner_repo,
            "repo not locally cached; skipping bundle generation"
        );
        // Release lock and return.
        let lock_lease = stop_bundle_lock_heartbeat(bundle_lock_heartbeat).await;
        let _ =
            crate::coordination::locks::release_lock_lease(&state.valkey, &lock_lease, true).await;
        return Ok(RepoTickOutcome::with_status(
            RepoTickStatus::SkippedNotCached,
        ));
    };

    match fetch_result {
        Ok(result) => {
            outcome.fetch_succeeded = true;
            info!(
                repo = %owner_repo,
                refs_updated = result.refs_updated,
                bytes_received = result.bytes_received,
                "background fetch completed"
            );

            // 7. Update dynamic schedule based on delta size.
            let _new_interval =
                update_fetch_schedule(state, owner_repo, result.bytes_received).await?;

            // 8. Generate an incremental bundle.
            // Read the previously recorded refs (if any) from Valkey.
            let prev_refs_json: Option<String> =
                HashesInterface::hget(&state.valkey, &repo_key, "prev_refs")
                    .await
                    .unwrap_or(None);

            let prev_refs: std::collections::HashMap<String, String> = prev_refs_json
                .and_then(|json: String| serde_json::from_str(&json).ok())
                .unwrap_or_default();

            let bundle_result = crate::bundleuri::generator::generate_incremental_bundle(
                state,
                &staged_repo_path,
                owner_repo,
                &prev_refs,
            )
            .await;

            match bundle_result {
                Ok(bundle) => {
                    outcome.bundle_generated = true;
                    info!(
                        repo = %owner_repo,
                        bundle_path = %bundle.bundle_path.display(),
                        creation_token = bundle.creation_token,
                        size_bytes = bundle.size_bytes,
                        "incremental bundle generated"
                    );

                    // 9. Upload bundle to S3.
                    let s3_key = format!(
                        "{}{}/bundles/{}.bundle",
                        state.config.storage.s3.prefix, owner_repo, bundle.creation_token,
                    );

                    if let Err(e) = crate::storage::s3::upload_bundle(
                        &state.s3_client,
                        &state.config.storage.s3.bucket,
                        &s3_key,
                        &bundle.bundle_path,
                    )
                    .await
                    {
                        outcome.bundle_upload_failed = true;
                        warn!(
                            repo = %owner_repo,
                            s3_key = %s3_key,
                            error = %e,
                            "failed to upload bundle to S3"
                        );
                    }

                    // Record the current refs snapshot for the next incremental.
                    let current_refs =
                        crate::bundleuri::generator::get_refs(&staged_repo_path).await?;
                    let refs_json = serde_json::to_string(&current_refs)?;
                    HashesInterface::hset::<(), _, _>(
                        &state.valkey,
                        &repo_key,
                        [
                            ("prev_refs", refs_json.as_str()),
                            ("latest_bundle_s3_key", s3_key.as_str()),
                            ("latest_bundle_token", &bundle.creation_token.to_string()),
                        ],
                    )
                    .await?;
                    state
                        .cache_manager
                        .publish_staged_repo(owner_repo, &staged_repo_path)?;
                    published = true;
                    outcome.published = true;

                    // Generate filtered (blobless) bundle variant if configured.
                    if state.config.bundles.generate_filtered_bundles {
                        match crate::bundleuri::generator::generate_filtered_bundle(
                            state,
                            &staged_repo_path,
                            owner_repo,
                        )
                        .await
                        {
                            Ok(filtered) => {
                                outcome.filtered_bundle_generated = true;
                                let filtered_s3_key = format!(
                                    "{}{}/bundles/{}.filtered.bundle",
                                    state.config.storage.s3.prefix,
                                    owner_repo,
                                    filtered.creation_token,
                                );
                                if let Err(e) = crate::storage::s3::upload_bundle(
                                    &state.s3_client,
                                    &state.config.storage.s3.bucket,
                                    &filtered_s3_key,
                                    &filtered.bundle_path,
                                )
                                .await
                                {
                                    outcome.filtered_bundle_upload_failed = true;
                                    warn!(
                                        repo = %owner_repo,
                                        error = %e,
                                        "failed to upload filtered bundle to S3"
                                    );
                                }
                            }
                            Err(e) => {
                                warn!(
                                    repo = %owner_repo,
                                    error = %e,
                                    "filtered bundle generation failed (Git 2.40+ required)"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    outcome.status = RepoTickStatus::BundleGenerationFailed;
                    warn!(
                        repo = %owner_repo,
                        error = %e,
                        error_chain = %format_error_chain(&e),
                        "bundle generation failed"
                    );
                }
            }
        }
        Err(e) => {
            outcome.status = RepoTickStatus::FetchFailed;
            warn!(
                repo = %owner_repo,
                error = %e,
                error_chain = %format_error_chain(&e),
                "background fetch failed"
            );
        }
    }

    // Release the distributed lock.
    let lock_lease = stop_bundle_lock_heartbeat(bundle_lock_heartbeat).await;
    let _ = crate::coordination::locks::release_lock_lease(&state.valkey, &lock_lease, true).await;

    if !published && staged_repo_path.exists() {
        tokio::fs::remove_dir_all(&staged_repo_path)
            .await
            .with_context(|| {
                format!(
                    "failed to remove unpublished staged repo generation at {}",
                    staged_repo_path.display()
                )
            })?;
    }

    Ok(outcome)
}

// ---------------------------------------------------------------------------
// Dynamic schedule
// ---------------------------------------------------------------------------

/// Compute the effective fetch interval for a repo, taking into account
/// per-repo overrides from the configuration.
fn effective_interval(state: &AppState, owner_repo: &str, schedule_secs: u64) -> u64 {
    // Check for a per-repo override.
    if let Some(override_cfg) = state.config.repo_overrides.get(owner_repo)
        && let Some(interval) = override_cfg.fetch_interval
    {
        return interval;
    }

    if schedule_secs == 0 {
        return state.config.fetch_schedule.default_interval;
    }

    schedule_secs
}

/// Compute an Exponential Moving Average (EMA) value.
///
/// `alpha` is the smoothing factor (0.0 .. 1.0).  When `prev_avg` is 0 the
/// raw `latest` value is returned (seeding the EMA).
fn compute_ema(latest: f64, prev_avg: f64, alpha: f64) -> f64 {
    if prev_avg == 0.0 {
        latest
    } else {
        alpha * latest + (1.0 - alpha) * prev_avg
    }
}

/// Update the dynamic fetch schedule for a repo based on observed delta size.
///
/// Uses an Exponential Moving Average (EMA) over the configured
/// `rolling_window` to smooth out delta observations before comparing against
/// the threshold.  This prevents a single large/small fetch from whipsawing
/// the interval.
///
/// - If the smoothed delta exceeds the configured threshold, the interval is
///   reset to the default (aggressive) value.
/// - If the smoothed delta is below the threshold, the interval is multiplied
///   by the backoff factor, up to `max_interval`.
///
/// Returns the new interval duration.
pub async fn update_fetch_schedule(
    state: &AppState,
    owner_repo: &str,
    delta_bytes: u64,
) -> Result<Duration> {
    let current = crate::coordination::registry::get_fetch_schedule(&state.valkey, owner_repo)
        .await?
        .unwrap_or_default();

    let delta_threshold_cfg = state.config.fetch_schedule.delta_threshold;
    let default_interval = state.config.fetch_schedule.default_interval;
    let backoff_factor = state.config.fetch_schedule.backoff_factor;
    let max_interval_cfg = state.config.fetch_schedule.max_interval;
    let rolling_window = state.config.fetch_schedule.rolling_window;

    // Compute EMA of the delta bytes using the rolling window.
    let effective_interval = if current.current_interval == 0 {
        default_interval
    } else {
        current.current_interval
    };

    let alpha = if rolling_window == 0 {
        1.0
    } else {
        (effective_interval as f64 / rolling_window as f64).min(1.0)
    };

    let smoothed_delta = compute_ema(delta_bytes as f64, current.rolling_avg_delta as f64, alpha);

    let new_interval = if smoothed_delta >= delta_threshold_cfg as f64 {
        // Significant activity -- reset to the default (short) interval.
        debug!(
            repo = %owner_repo,
            delta_bytes,
            smoothed_delta = smoothed_delta as u64,
            new_interval_secs = default_interval,
            "large smoothed delta; resetting fetch interval to default"
        );
        default_interval
    } else {
        // Quiet repo -- back off.
        let backed_off = (effective_interval as f64 * backoff_factor) as u64;
        let clamped = backed_off.min(max_interval_cfg);
        debug!(
            repo = %owner_repo,
            delta_bytes,
            smoothed_delta = smoothed_delta as u64,
            previous_interval = effective_interval,
            new_interval = clamped,
            "small smoothed delta; backing off fetch interval"
        );
        clamped
    };

    let new_schedule = crate::coordination::registry::FetchSchedule {
        current_interval: new_interval,
        rolling_avg_delta: smoothed_delta as u64,
        delta_threshold: current.delta_threshold,
        max_interval: current.max_interval,
        last_delta_bytes: delta_bytes,
    };
    crate::coordination::registry::set_fetch_schedule(&state.valkey, owner_repo, &new_schedule)
        .await?;

    Ok(Duration::from_secs(new_interval))
}

// ---------------------------------------------------------------------------
// Daily consolidation
// ---------------------------------------------------------------------------

/// Collapse hourly bundles into a single daily bundle.
///
/// Runs indefinitely, waking once per minute and performing the consolidation
/// at the configured `daily_consolidation_hour` (UTC).
pub async fn run_daily_consolidation(state: Arc<AppState>) {
    let target_hour = state.config.bundles.daily_consolidation_hour;
    info!(
        target_hour = target_hour,
        "daily bundle consolidation scheduler started"
    );

    let mut last_run_date = None;

    loop {
        let now = Utc::now();
        let today = now.date_naive();

        // Only run once per day at the target hour.
        if now.hour() as u8 == target_hour && last_run_date != Some(today) {
            info!("starting daily bundle consolidation");
            last_run_date = Some(today);

            if let Err(e) = daily_consolidation_tick(&state).await {
                error!(error = %e, "daily consolidation failed");
            }
        }

        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

/// Perform one round of daily consolidation across all repos.
pub(crate) async fn daily_consolidation_tick(state: &AppState) -> Result<()> {
    let repos = crate::coordination::registry::list_all_repos(&state.valkey).await?;
    let lock_ttl = state.config.bundles.bundle_lock_ttl;

    for owner_repo in &repos {
        // Check if bundles are disabled for this repo.
        if let Some(override_cfg) = state.config.repo_overrides.get(owner_repo.as_str())
            && override_cfg.disable_bundles == Some(true)
        {
            debug!(repo = %owner_repo, "bundles disabled for repo; skipping consolidation");
            continue;
        }

        let repo_path = state.cache_manager.repo_path(owner_repo);

        if !repo_path.exists() || !repo_path.join("HEAD").is_file() {
            debug!(repo = %owner_repo, "repo not locally cached; skipping daily consolidation");
            continue;
        }

        let lock_key = format!("forgeproxy:lock:daily-consolidation:{owner_repo}");
        let node_id = crate::coordination::node::node_id();
        let lock_acquired =
            crate::coordination::locks::acquire_lock(&state.valkey, &lock_key, &node_id, lock_ttl)
                .await?;

        if !lock_acquired {
            debug!(
                repo = %owner_repo,
                "another node holds the daily consolidation lock; skipping"
            );
            continue;
        }

        // Generate a new full bundle that replaces the hourly incrementals.
        let result =
            match crate::bundleuri::generator::generate_full_bundle(state, &repo_path, owner_repo)
                .await
            {
                Ok(bundle) => {
                    info!(
                        repo = %owner_repo,
                        creation_token = bundle.creation_token,
                        size_bytes = bundle.size_bytes,
                        "daily consolidation bundle generated"
                    );

                    // Update registry with new bundle info.
                    let repo_key = crate::coordination::registry::repo_key(owner_repo);
                    let s3_key = format!(
                        "{}{}/bundles/daily-{}.bundle",
                        state.config.storage.s3.prefix,
                        owner_repo,
                        Utc::now().format("%Y%m%d"),
                    );
                    HashesInterface::hset::<(), _, _>(
                        &state.valkey,
                        &repo_key,
                        [
                            ("latest_daily_bundle_s3_key", s3_key.as_str()),
                            (
                                "latest_daily_bundle_token",
                                &bundle.creation_token.to_string(),
                            ),
                        ],
                    )
                    .await
                    .unwrap_or_default();

                    // Generate filtered (blobless) bundle variant if configured.
                    if state.config.bundles.generate_filtered_bundles {
                        match crate::bundleuri::generator::generate_filtered_bundle(
                            state, &repo_path, owner_repo,
                        )
                        .await
                        {
                            Ok(filtered) => {
                                let filtered_s3_key = format!(
                                    "{}{}/bundles/daily-{}.filtered.bundle",
                                    state.config.storage.s3.prefix,
                                    owner_repo,
                                    Utc::now().format("%Y%m%d"),
                                );
                                crate::storage::s3::upload_bundle(
                                    &state.s3_client,
                                    &state.config.storage.s3.bucket,
                                    &filtered_s3_key,
                                    &filtered.bundle_path,
                                )
                                .await
                                .unwrap_or_else(|e| {
                                    warn!(
                                        repo = %owner_repo,
                                        error = %e,
                                        "failed to upload filtered daily bundle to S3"
                                    );
                                });
                            }
                            Err(e) => {
                                warn!(
                                    repo = %owner_repo,
                                    error = %e,
                                    "filtered bundle generation failed during daily consolidation"
                                );
                            }
                        }
                    }
                    Ok(())
                }
                Err(e) => {
                    warn!(
                        repo = %owner_repo,
                        error = %e,
                        "daily consolidation bundle generation failed"
                    );
                    Err(e)
                }
            };

        let _ = crate::coordination::locks::release_lock(&state.valkey, &lock_key, &node_id, true)
            .await;

        if let Err(e) = result {
            debug!(
                repo = %owner_repo,
                error = %e,
                "daily consolidation finished with repo-level error"
            );
        }
    }

    info!("daily bundle consolidation complete");
    Ok(())
}

// ---------------------------------------------------------------------------
// Weekly consolidation
// ---------------------------------------------------------------------------

/// Collapse daily bundles into a new base bundle.
///
/// Runs indefinitely, waking once per minute and performing the consolidation
/// on the configured weekday at the `daily_consolidation_hour` (UTC).
pub async fn run_weekly_consolidation(state: Arc<AppState>) {
    let target_day = state.config.bundles.weekly_consolidation_day;
    let target_hour = state.config.bundles.daily_consolidation_hour;
    info!(
        target_day = target_day,
        target_hour = target_hour,
        "weekly bundle consolidation scheduler started"
    );

    let mut last_run_date = None;

    loop {
        let now = Utc::now();
        let today = now.date_naive();

        // ISO weekday: 1=Mon .. 7=Sun.
        let current_weekday = now.weekday().num_days_from_monday() as u8 + 1;

        if current_weekday == target_day
            && now.hour() as u8 == target_hour
            && last_run_date != Some(today)
        {
            info!("starting weekly bundle consolidation");
            last_run_date = Some(today);

            if let Err(e) = weekly_consolidation_tick(&state).await {
                error!(error = %e, "weekly consolidation failed");
            }
        }

        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

/// Perform one round of weekly consolidation across all repos.
pub(crate) async fn weekly_consolidation_tick(state: &AppState) -> Result<()> {
    let repos = crate::coordination::registry::list_all_repos(&state.valkey).await?;
    let lock_ttl = state.config.bundles.bundle_lock_ttl;

    for owner_repo in &repos {
        if let Some(override_cfg) = state.config.repo_overrides.get(owner_repo.as_str())
            && override_cfg.disable_bundles == Some(true)
        {
            continue;
        }

        let repo_path = state.cache_manager.repo_path(owner_repo);

        if !repo_path.exists() || !repo_path.join("HEAD").is_file() {
            continue;
        }

        let lock_key = format!("forgeproxy:lock:weekly-consolidation:{owner_repo}");
        let node_id = crate::coordination::node::node_id();
        let lock_acquired =
            crate::coordination::locks::acquire_lock(&state.valkey, &lock_key, &node_id, lock_ttl)
                .await?;

        if !lock_acquired {
            debug!(
                repo = %owner_repo,
                "another node holds the weekly consolidation lock; skipping"
            );
            continue;
        }

        // Generate a new base (full) bundle.
        let result =
            match crate::bundleuri::generator::generate_full_bundle(state, &repo_path, owner_repo)
                .await
            {
                Ok(bundle) => {
                    info!(
                        repo = %owner_repo,
                        creation_token = bundle.creation_token,
                        size_bytes = bundle.size_bytes,
                        "weekly consolidation (base) bundle generated"
                    );

                    let repo_key = crate::coordination::registry::repo_key(owner_repo);
                    let s3_key = format!(
                        "{}{}/bundles/base-{}.bundle",
                        state.config.storage.s3.prefix,
                        owner_repo,
                        Utc::now().format("%Y%m%d"),
                    );
                    HashesInterface::hset::<(), _, _>(
                        &state.valkey,
                        &repo_key,
                        [
                            ("base_bundle_s3_key", s3_key.as_str()),
                            ("base_bundle_token", &bundle.creation_token.to_string()),
                        ],
                    )
                    .await
                    .unwrap_or_default();
                    Ok(())
                }
                Err(e) => {
                    warn!(
                        repo = %owner_repo,
                        error = %e,
                        "weekly consolidation bundle generation failed"
                    );
                    Err(e)
                }
            };

        let _ = crate::coordination::locks::release_lock(&state.valkey, &lock_key, &node_id, true)
            .await;

        if let Err(e) = result {
            debug!(
                repo = %owner_repo,
                error = %e,
                "weekly consolidation finished with repo-level error"
            );
        }
    }

    info!("weekly bundle consolidation complete");
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ema_seeds_from_zero() {
        // When prev_avg is 0, EMA returns the raw value.
        assert_eq!(compute_ema(100.0, 0.0, 0.5), 100.0);
    }

    #[test]
    fn ema_blends_values() {
        // alpha=0.5: 0.5*200 + 0.5*100 = 150
        let result = compute_ema(200.0, 100.0, 0.5);
        assert!((result - 150.0).abs() < f64::EPSILON);
    }

    #[test]
    fn ema_alpha_one_returns_latest() {
        // alpha=1.0: fully replaces previous average.
        let result = compute_ema(300.0, 100.0, 1.0);
        assert!((result - 300.0).abs() < f64::EPSILON);
    }

    #[test]
    fn ema_alpha_zero_keeps_previous() {
        // alpha=0.0: ignores new value entirely.
        let result = compute_ema(300.0, 100.0, 0.0);
        assert!((result - 100.0).abs() < f64::EPSILON);
    }
}
