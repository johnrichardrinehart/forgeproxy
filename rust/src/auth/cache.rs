use anyhow::{Context, Result};
use fred::interfaces::KeysInterface;
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
/// Uses SCAN-based iteration to avoid blocking the KeyDB server, then
/// DELetes each matching key.  Returns the number of keys deleted.
pub async fn invalidate_auth(pool: &fred::clients::Pool, pattern: &str) -> Result<u64> {
    let mut count: u64 = 0;
    let mut cursor = String::from("0");

    loop {
        let (next_cursor, keys): (String, Vec<String>) = pool
            .scan_page(&cursor, pattern, Some(100), None)
            .await
            .context("KeyDB SCAN failed")?;

        for key in &keys {
            let _: () = pool.del(key).await.unwrap_or_default();
            count += 1;
        }

        if next_cursor == "0" {
            break;
        }
        cursor = next_cursor;
    }

    if count > 0 {
        trace!(pattern, count, "auth cache invalidated");
    }
    Ok(count)
}
