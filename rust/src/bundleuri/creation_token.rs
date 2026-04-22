//! Monotonic creation token management for Git bundle-URI.
//!
//! The source of truth for the per-repository generation counter lives in S3 at
//! `.../gen.counter`. We still guard updates with a short Valkey lease so
//! nodes serialise counter allocation even when using S3-compatible backends
//! that do not offer object-level locking primitives.

use std::time::Duration;

use anyhow::{Context, Result, bail};

const CREATION_TOKEN_STEP: u64 = 1000;
const COUNTER_LOCK_RETRY_ATTEMPTS: usize = 20;
const COUNTER_LOCK_RETRY_DELAY: Duration = Duration::from_millis(250);

/// Atomically allocate the next creation token for a repository.
pub async fn next_creation_token(state: &crate::AppState, owner_repo: &str) -> Result<u64> {
    let config = state.config();
    let lock_key = format!("forgeproxy:lock:bundle-counter:{owner_repo}");
    let ttl_secs = config.bundles.bundle_lock_ttl;

    let lease = acquire_counter_lock(state, &lock_key, ttl_secs, owner_repo).await?;
    let counter_key =
        crate::bundleuri::bundle_counter_s3_key(&config.storage.s3.prefix, owner_repo);

    let result = async {
        let current = crate::storage::s3::download_text_if_exists(
            &state.s3_client,
            &state.metrics,
            &config.storage.s3.bucket,
            &counter_key,
        )
        .await?
        .map(|text| text.trim().parse::<u64>())
        .transpose()
        .with_context(|| format!("parse S3 creation counter for {owner_repo}"))?
        .unwrap_or(0);

        let next = current
            .saturating_add(CREATION_TOKEN_STEP)
            .max(CREATION_TOKEN_STEP);
        crate::storage::s3::upload_text(
            &state.s3_client,
            &config.storage.s3.bucket,
            &counter_key,
            &format!("{next}\n"),
        )
        .await
        .with_context(|| format!("write S3 creation counter for {owner_repo}"))?;

        Ok::<u64, anyhow::Error>(next)
    }
    .await;

    let _ = crate::coordination::locks::release_lock_lease(
        &state.valkey,
        &lease,
        true,
        Some(&state.metrics),
    )
    .await;

    result
}

async fn acquire_counter_lock(
    state: &crate::AppState,
    lock_key: &str,
    ttl_secs: u64,
    owner_repo: &str,
) -> Result<crate::coordination::locks::LockLease> {
    for _ in 0..COUNTER_LOCK_RETRY_ATTEMPTS {
        if let Some(lease) = crate::coordination::locks::acquire_lock_lease(
            &state.valkey,
            lock_key,
            &state.node_id,
            ttl_secs,
            Some(&state.metrics),
        )
        .await?
        {
            return Ok(lease);
        }

        tokio::time::sleep(COUNTER_LOCK_RETRY_DELAY).await;
    }

    bail!("timed out waiting for bundle counter lock for {owner_repo}")
}
