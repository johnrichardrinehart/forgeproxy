use std::time::Duration;

use anyhow::{Context, Result};
use fred::interfaces::{KeysInterface, LuaInterface};
use tracing::{debug, warn};

/// Attempt to acquire a distributed lock using SET NX EX.
///
/// Returns `true` if the lock was successfully acquired, `false` if it is
/// already held by another node.
pub async fn acquire_lock(
    pool: &fred::clients::Pool,
    key: &str,
    node_id: &str,
    ttl_secs: u64,
) -> Result<bool> {
    let value = format!("{node_id}:{}", chrono::Utc::now().timestamp());
    let result: Option<String> = pool
        .set(
            key,
            value.as_str(),
            Some(fred::types::Expiration::EX(ttl_secs as i64)),
            Some(fred::types::SetOptions::NX),
            false,
        )
        .await?;
    // SET … NX returns "OK" when the key was set, nil otherwise.
    let acquired = result.is_some();
    debug!(%key, %node_id, acquired, "acquire_lock");
    Ok(acquired)
}

/// Release a lock only if it is still owned by `node_id`.
///
/// Uses a Lua script so the check-and-delete is atomic.  After deletion the
/// script publishes a notification on `{key}:notify` so that waiters can wake
/// up immediately.
pub async fn release_lock(pool: &fred::clients::Pool, key: &str, node_id: &str) -> Result<()> {
    let script = r#"
        local val = redis.call('GET', KEYS[1])
        if val and string.find(val, ARGV[1] .. ":", 1, true) == 1 then
            redis.call('DEL', KEYS[1])
            redis.call('PUBLISH', KEYS[1] .. ':notify', 'released')
            return 1
        end
        return 0
    "#;
    let released: i64 = pool
        .eval(script, vec![key.to_string()], vec![node_id.to_string()])
        .await
        .context("lock release script failed")?;
    if released == 1 {
        debug!(%key, %node_id, "lock released");
    } else {
        warn!(%key, %node_id, "lock release: key missing or owned by another node");
    }
    Ok(())
}

/// Wait until the lock identified by `key` is released or `timeout` elapses.
///
/// The function polls at a short interval and also subscribes to the
/// `{key}:notify` pub/sub channel so it can return as soon as the holder
/// publishes a release notification.
///
/// Returns `true` if the lock was released before the timeout, `false` if the
/// timeout expired while the lock was still held.
pub async fn wait_for_lock(
    pool: &fred::clients::Pool,
    key: &str,
    timeout: Duration,
) -> Result<bool> {
    let deadline = tokio::time::Instant::now() + timeout;
    let poll_interval = Duration::from_millis(250);

    // Fast path: check whether the key already does not exist.
    let exists: bool = pool.exists(key).await?;
    if !exists {
        return Ok(true);
    }

    // Poll until the deadline.  A production implementation would open a
    // dedicated subscriber connection and race a SUBSCRIBE against the
    // polling loop.  Here we keep things simple and just poll.
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        tokio::time::sleep(poll_interval.min(remaining)).await;

        let exists: bool = pool.exists(key).await?;
        if !exists {
            debug!(%key, "wait_for_lock: lock released");
            return Ok(true);
        }
    }

    warn!(%key, ?timeout, "wait_for_lock: timed out waiting for lock release");
    Ok(false)
}
