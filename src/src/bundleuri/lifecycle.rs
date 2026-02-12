//! Bundle lifecycle scheduler.
//!
//! Runs background tasks on a periodic schedule to:
//!
//! 1. Scan the repo registry for repos that need a background fetch from GHE.
//! 2. Generate incremental bundles after each fetch.
//! 3. Upload bundles to S3 and update the KeyDB registry.
//! 4. Consolidate hourly bundles into daily bundles.
//! 5. Consolidate daily bundles into a new base bundle.
//!
//! The fetch interval for each repo is dynamically adjusted based on the delta
//! size observed in the most recent fetch: large deltas shorten the interval,
//! small deltas lengthen it (exponential backoff up to the configured max).

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::{Datelike, Timelike, Utc};
use fred::interfaces::HashesInterface;
use tracing::{debug, error, info, instrument, warn};

use crate::AppState;

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
async fn tick(state: &AppState) -> Result<()> {
    let repos = crate::coordination::registry::list_all_repos(&state.keydb).await?;
    debug!(repo_count = repos.len(), "lifecycle tick: scanning repos");

    for owner_repo in &repos {
        if let Err(e) = process_repo(state, owner_repo).await {
            warn!(
                repo = %owner_repo,
                error = %e,
                "failed to process repo in lifecycle tick"
            );
        }
    }

    Ok(())
}

/// Process a single repo: check schedule, fetch if needed, generate bundle,
/// upload to S3.
#[instrument(skip(state), fields(%owner_repo))]
async fn process_repo(state: &AppState, owner_repo: &str) -> Result<()> {
    // 1. Read the dynamic fetch schedule for this repo.
    let schedule = crate::coordination::registry::get_fetch_schedule(&state.keydb, owner_repo)
        .await?
        .unwrap_or_default();

    // 2. Check if the repo is due for a fetch.
    // Use the repo info's last_fetch_ts to determine timing.
    let now = Utc::now().timestamp() as u64;
    let repo_info = crate::coordination::registry::get_repo_info(&state.keydb, owner_repo).await?;
    let last_fetch = repo_info
        .as_ref()
        .map(|r| r.last_fetch_ts as u64)
        .unwrap_or(0);
    let interval = effective_interval(state, owner_repo, schedule.current_interval);
    // ^ uses the current_interval from FetchSchedule

    if last_fetch + interval > now {
        debug!(
            repo = %owner_repo,
            next_in_secs = (last_fetch + interval).saturating_sub(now),
            "repo not yet due for fetch"
        );
        return Ok(());
    }

    // 3. Check minimum clone count threshold before investing in bundles.
    let repo_key = crate::coordination::registry::repo_key(owner_repo);
    let clone_count: Option<i64> = HashesInterface::hget(&state.keydb, &repo_key, "clone_count")
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
        return Ok(());
    }

    // 4. Attempt to acquire the distributed fetch/bundle lock.
    let lock_key = format!("forgecache:lock:bundle:{owner_repo}");
    let lock_ttl = state.config.bundles.bundle_lock_ttl;
    let node_id = crate::coordination::node::node_id();
    let lock_acquired =
        crate::coordination::locks::acquire_lock(&state.keydb, &lock_key, &node_id, lock_ttl)
            .await?;

    if !lock_acquired {
        debug!(repo = %owner_repo, "another node holds the bundle lock; skipping");
        return Ok(());
    }

    // 5. Perform the fetch.
    info!(repo = %owner_repo, "starting background fetch for bundle generation");

    let repo_path = state.cache_manager.repo_path(owner_repo);

    let fetch_result = if repo_path.exists() && repo_path.join("HEAD").is_file() {
        // Repo is locally cached -- do an incremental fetch.
        let ghe_url = format!(
            "https://{}/{}.git",
            state.config.upstream.hostname, owner_repo,
        );
        let admin_token = std::env::var(&state.config.upstream.admin_token_env).unwrap_or_default();
        let env_vars = vec![("GIT_TERMINAL_PROMPT".to_string(), "0".to_string())];
        let env_with_auth: Vec<(String, String)> = if admin_token.is_empty() {
            env_vars
        } else {
            let mut v = env_vars;
            v.push(("GIT_ASKPASS".to_string(), "/bin/true".to_string()));
            v
        };

        let url_with_token = if admin_token.is_empty() {
            ghe_url
        } else {
            format!(
                "https://x-access-token:{admin_token}@{}/{}.git",
                state.config.upstream.hostname, owner_repo,
            )
        };

        crate::git::commands::git_fetch(&repo_path, &url_with_token, &env_with_auth).await
    } else {
        debug!(
            repo = %owner_repo,
            "repo not locally cached; skipping bundle generation"
        );
        // Release lock and return.
        let _ = crate::coordination::locks::release_lock(&state.keydb, &lock_key, &node_id).await;
        return Ok(());
    };

    // 6. Record fetch timestamp in repo info.
    crate::coordination::registry::update_repo_field(
        &state.keydb,
        owner_repo,
        "last_fetch_ts",
        &now.to_string(),
    )
    .await?;

    match fetch_result {
        Ok(result) => {
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
            // Read the previously recorded refs (if any) from KeyDB.
            let prev_refs_json: Option<String> =
                HashesInterface::hget(&state.keydb, &repo_key, "prev_refs")
                    .await
                    .unwrap_or(None);

            let prev_refs: std::collections::HashMap<String, String> = prev_refs_json
                .and_then(|json: String| serde_json::from_str(&json).ok())
                .unwrap_or_default();

            let bundle_result = crate::bundleuri::generator::generate_incremental_bundle(
                state, &repo_path, owner_repo, &prev_refs,
            )
            .await;

            match bundle_result {
                Ok(bundle) => {
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

                    crate::storage::s3::upload_bundle(
                        &state.s3_client,
                        &state.config.storage.s3.bucket,
                        &s3_key,
                        &bundle.bundle_path,
                    )
                    .await
                    .unwrap_or_else(|e| {
                        warn!(
                            repo = %owner_repo,
                            s3_key = %s3_key,
                            error = %e,
                            "failed to upload bundle to S3"
                        );
                    });

                    // Record the current refs snapshot for the next incremental.
                    let current_refs = crate::bundleuri::generator::get_refs(&repo_path).await?;
                    let refs_json = serde_json::to_string(&current_refs)?;
                    HashesInterface::hset::<(), _, _>(
                        &state.keydb,
                        &repo_key,
                        [
                            ("prev_refs", refs_json.as_str()),
                            ("latest_bundle_s3_key", s3_key.as_str()),
                            ("latest_bundle_token", &bundle.creation_token.to_string()),
                        ],
                    )
                    .await?;
                }
                Err(e) => {
                    warn!(
                        repo = %owner_repo,
                        error = %e,
                        "bundle generation failed"
                    );
                }
            }
        }
        Err(e) => {
            warn!(
                repo = %owner_repo,
                error = %e,
                "background fetch failed"
            );
        }
    }

    // Release the distributed lock.
    let _ = crate::coordination::locks::release_lock(&state.keydb, &lock_key, &node_id).await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Dynamic schedule
// ---------------------------------------------------------------------------

/// Compute the effective fetch interval for a repo, taking into account
/// per-repo overrides from the configuration.
fn effective_interval(state: &AppState, owner_repo: &str, schedule_secs: u64) -> u64 {
    // Check for a per-repo override.
    if let Some(override_cfg) = state.config.repo_overrides.get(owner_repo) {
        if let Some(interval) = override_cfg.fetch_interval {
            return interval;
        }
    }

    if schedule_secs == 0 {
        return state.config.fetch_schedule.default_interval;
    }

    schedule_secs
}

/// Update the dynamic fetch schedule for a repo based on observed delta size.
///
/// - If the delta exceeds the configured threshold, the interval is reset to
///   the default (aggressive) value.
/// - If the delta is below the threshold, the interval is multiplied by the
///   backoff factor, up to `max_interval`.
///
/// Returns the new interval duration.
pub async fn update_fetch_schedule(
    state: &AppState,
    owner_repo: &str,
    delta_bytes: u64,
) -> Result<Duration> {
    let current = crate::coordination::registry::get_fetch_schedule(&state.keydb, owner_repo)
        .await?
        .unwrap_or_default();

    let delta_threshold_cfg = state.config.fetch_schedule.delta_threshold;
    let default_interval = state.config.fetch_schedule.default_interval;
    let backoff_factor = state.config.fetch_schedule.backoff_factor;
    let max_interval_cfg = state.config.fetch_schedule.max_interval;

    let new_interval = if delta_bytes >= delta_threshold_cfg {
        // Significant activity -- reset to the default (short) interval.
        debug!(
            repo = %owner_repo,
            delta_bytes = delta_bytes,
            new_interval_secs = default_interval,
            "large delta detected; resetting fetch interval to default"
        );
        default_interval
    } else {
        // Quiet repo -- back off.
        let current_interval = if current.current_interval == 0 {
            default_interval
        } else {
            current.current_interval
        };
        let backed_off = (current_interval as f64 * backoff_factor) as u64;
        let clamped = backed_off.min(max_interval_cfg);
        debug!(
            repo = %owner_repo,
            delta_bytes = delta_bytes,
            previous_interval = current_interval,
            new_interval = clamped,
            "small delta; backing off fetch interval"
        );
        clamped
    };

    let new_schedule = crate::coordination::registry::FetchSchedule {
        current_interval: new_interval,
        rolling_avg_delta: current.rolling_avg_delta,
        delta_threshold: current.delta_threshold,
        max_interval: current.max_interval,
        last_delta_bytes: delta_bytes,
    };
    crate::coordination::registry::set_fetch_schedule(&state.keydb, owner_repo, &new_schedule)
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
async fn daily_consolidation_tick(state: &AppState) -> Result<()> {
    let repos = crate::coordination::registry::list_all_repos(&state.keydb).await?;

    for owner_repo in &repos {
        // Check if bundles are disabled for this repo.
        if let Some(override_cfg) = state.config.repo_overrides.get(owner_repo.as_str()) {
            if override_cfg.disable_bundles == Some(true) {
                debug!(repo = %owner_repo, "bundles disabled for repo; skipping consolidation");
                continue;
            }
        }

        let repo_path = state.cache_manager.repo_path(owner_repo);

        if !repo_path.exists() || !repo_path.join("HEAD").is_file() {
            debug!(repo = %owner_repo, "repo not locally cached; skipping daily consolidation");
            continue;
        }

        // Generate a new full bundle that replaces the hourly incrementals.
        match crate::bundleuri::generator::generate_full_bundle(state, &repo_path, owner_repo).await
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
                    &state.keydb,
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
            }
            Err(e) => {
                warn!(
                    repo = %owner_repo,
                    error = %e,
                    "daily consolidation bundle generation failed"
                );
            }
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
async fn weekly_consolidation_tick(state: &AppState) -> Result<()> {
    let repos = crate::coordination::registry::list_all_repos(&state.keydb).await?;

    for owner_repo in &repos {
        if let Some(override_cfg) = state.config.repo_overrides.get(owner_repo.as_str()) {
            if override_cfg.disable_bundles == Some(true) {
                continue;
            }
        }

        let repo_path = state.cache_manager.repo_path(owner_repo);

        if !repo_path.exists() || !repo_path.join("HEAD").is_file() {
            continue;
        }

        // Generate a new base (full) bundle.
        match crate::bundleuri::generator::generate_full_bundle(state, &repo_path, owner_repo).await
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
                    &state.keydb,
                    &repo_key,
                    [
                        ("base_bundle_s3_key", s3_key.as_str()),
                        ("base_bundle_token", &bundle.creation_token.to_string()),
                    ],
                )
                .await
                .unwrap_or_default();
            }
            Err(e) => {
                warn!(
                    repo = %owner_repo,
                    error = %e,
                    "weekly consolidation bundle generation failed"
                );
            }
        }
    }

    info!("weekly bundle consolidation complete");
    Ok(())
}
