use anyhow::{Context, Result};
use fred::interfaces::{ClientLike, KeysInterface};
use fred::types::CustomCommand;
use tracing::trace;

/// Retrieve a cached auth value from KeyDB by key.
/// Returns `Ok(Some(value))` on cache hit, `Ok(None)` on miss.
pub async fn get_cached_auth(pool: &fred::clients::Pool, key: &str) -> Result<Option<String>> {
    let val: Option<String> = pool.get(key).await.context("KeyDB GET failed")?;
    if val.is_some() {
        trace!(key, "auth cache hit");
    }
    Ok(val)
}

/// Store an auth value in KeyDB with a TTL (in seconds).
pub async fn set_cached_auth(
    pool: &fred::clients::Pool,
    key: &str,
    value: &str,
    ttl_secs: u64,
) -> Result<()> {
    let _: () = pool
        .set(
            key,
            value,
            Some(fred::types::Expiration::EX(ttl_secs as i64)),
            None,
            false,
        )
        .await
        .context("KeyDB SET failed")?;
    trace!(key, ttl_secs, "auth cache set");
    Ok(())
}

/// Invalidate all auth cache keys matching a glob pattern.
///
/// Uses the KEYS command to find matching keys, then DELetes each one.
/// For production workloads with very large keyspaces, consider SCAN-based
/// iteration instead. Returns the number of keys deleted.
pub async fn invalidate_auth(pool: &fred::clients::Pool, pattern: &str) -> Result<u64> {
    let keys: Vec<String> = pool
        .custom(CustomCommand::new_static("KEYS", None::<u16>, false), vec![pattern.to_string()])
        .await
        .unwrap_or_default();
    let count = keys.len() as u64;
    for key in &keys {
        let _: () = pool.del(key).await.unwrap_or_default();
    }
    if count > 0 {
        trace!(pattern, count, "auth cache invalidated");
    }
    Ok(count)
}
