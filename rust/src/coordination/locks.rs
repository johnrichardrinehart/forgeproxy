use anyhow::{Context, Result, bail};
use fred::interfaces::{KeysInterface, LuaInterface};
use tracing::{debug, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReleaseStatus {
    Released,
    Expired,
    Missing,
    OwnedByAnotherNode,
}

#[derive(Debug, Clone)]
pub struct SemaphoreLease {
    pub key: String,
    pub token: String,
}

#[derive(Debug, Clone)]
pub struct LockLease {
    pub key: String,
    pub node_id: String,
    pub token: String,
}

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
    let acquired = result.is_some();
    debug!(%key, %node_id, acquired, "acquire_lock");
    Ok(acquired)
}

/// Attempt to acquire a distributed lock backed by a renewable lease.
///
/// The stored value includes a random token so a holder can safely renew or
/// release only the exact lease it acquired.
pub async fn acquire_lock_lease(
    pool: &fred::clients::Pool,
    key: &str,
    node_id: &str,
    ttl_secs: u64,
) -> Result<Option<LockLease>> {
    let token = format!("{node_id}:{}", Uuid::new_v4());
    let result: Option<String> = pool
        .set(
            key,
            token.as_str(),
            Some(fred::types::Expiration::EX(ttl_secs as i64)),
            Some(fred::types::SetOptions::NX),
            false,
        )
        .await?;
    let acquired = result.is_some();
    debug!(%key, %node_id, acquired, "acquire_lock_lease");
    Ok(acquired.then(|| LockLease {
        key: key.to_string(),
        node_id: node_id.to_string(),
        token,
    }))
}

/// Renew a lock lease only if the exact lease token still owns the lock.
pub async fn renew_lock_lease(
    pool: &fred::clients::Pool,
    lease: &LockLease,
    ttl_secs: u64,
) -> Result<bool> {
    let script = r#"
        local val = redis.call('GET', KEYS[1])
        if not val then
            return 0
        end
        if val == ARGV[1] then
            redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
            return 1
        end
        return 0
    "#;
    let renewed: i64 = pool
        .eval(
            script,
            vec![lease.key.clone()],
            vec![lease.token.clone(), ttl_secs.to_string()],
        )
        .await
        .context("lock renewal script failed")?;

    if renewed == 1 {
        debug!(key = %lease.key, node_id = %lease.node_id, ttl_secs, "lock lease renewed");
        Ok(true)
    } else {
        warn!(
            key = %lease.key,
            node_id = %lease.node_id,
            "lock lease could not be renewed because ownership was lost"
        );
        Ok(false)
    }
}

/// Release a lock only if it is still owned by `node_id`.
///
/// `expected_owned` should be `true` when the caller previously observed a
/// successful acquire. That lets us distinguish an expired lock from a missing
/// one that we never owned.
pub async fn release_lock(
    pool: &fred::clients::Pool,
    key: &str,
    node_id: &str,
    expected_owned: bool,
) -> Result<LockReleaseStatus> {
    let script = r#"
        local val = redis.call('GET', KEYS[1])
        if not val then
            return 'missing'
        end
        if string.find(val, ARGV[1] .. ":", 1, true) == 1 then
            redis.call('DEL', KEYS[1])
            redis.call('PUBLISH', KEYS[1] .. ':notify', 'released')
            return 'released'
        end
        return 'owned_by_another_node'
    "#;
    let result: String = pool
        .eval(script, vec![key.to_string()], vec![node_id.to_string()])
        .await
        .context("lock release script failed")?;

    let status = match result.as_str() {
        "released" => LockReleaseStatus::Released,
        "missing" if expected_owned => LockReleaseStatus::Expired,
        "missing" => LockReleaseStatus::Missing,
        "owned_by_another_node" => LockReleaseStatus::OwnedByAnotherNode,
        other => bail!("unexpected lock release result {other:?}"),
    };

    match status {
        LockReleaseStatus::Released => {
            debug!(%key, %node_id, "lock released");
        }
        LockReleaseStatus::Expired => {
            info!(%key, %node_id, "lock expired before release");
        }
        LockReleaseStatus::Missing => {
            warn!(%key, %node_id, "lock release skipped because key was missing");
        }
        LockReleaseStatus::OwnedByAnotherNode => {
            warn!(%key, %node_id, "lock release skipped because key is owned by another node");
        }
    }

    Ok(status)
}

/// Release a renewable lock lease only if the stored token still matches.
pub async fn release_lock_lease(
    pool: &fred::clients::Pool,
    lease: &LockLease,
    expected_owned: bool,
) -> Result<LockReleaseStatus> {
    let script = r#"
        local val = redis.call('GET', KEYS[1])
        if not val then
            return 'missing'
        end
        if val == ARGV[1] then
            redis.call('DEL', KEYS[1])
            redis.call('PUBLISH', KEYS[1] .. ':notify', 'released')
            return 'released'
        end
        return 'owned_by_another_node'
    "#;
    let result: String = pool
        .eval(script, vec![lease.key.clone()], vec![lease.token.clone()])
        .await
        .context("lock lease release script failed")?;

    let status = match result.as_str() {
        "released" => LockReleaseStatus::Released,
        "missing" if expected_owned => LockReleaseStatus::Expired,
        "missing" => LockReleaseStatus::Missing,
        "owned_by_another_node" => LockReleaseStatus::OwnedByAnotherNode,
        other => bail!("unexpected lock release result {other:?}"),
    };

    match status {
        LockReleaseStatus::Released => {
            debug!(key = %lease.key, node_id = %lease.node_id, "lock lease released");
        }
        LockReleaseStatus::Expired => {
            info!(key = %lease.key, node_id = %lease.node_id, "lock lease expired before release");
        }
        LockReleaseStatus::Missing => {
            warn!(
                key = %lease.key,
                node_id = %lease.node_id,
                "lock lease release skipped because key was missing"
            );
        }
        LockReleaseStatus::OwnedByAnotherNode => {
            warn!(
                key = %lease.key,
                node_id = %lease.node_id,
                "lock lease release skipped because key is owned by another node"
            );
        }
    }

    Ok(status)
}

/// Acquire a lease-backed distributed semaphore permit for a single repo.
///
/// Returns `Ok(Some(lease))` when a permit is granted and `Ok(None)` when the
/// semaphore is currently saturated.
pub async fn acquire_semaphore_lease(
    pool: &fred::clients::Pool,
    key: &str,
    node_id: &str,
    limit: usize,
    ttl_secs: u64,
) -> Result<Option<SemaphoreLease>> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let ttl_ms = (ttl_secs as i64) * 1000;
    let token = format!("{node_id}:{}:{}", now_ms, Uuid::new_v4());
    let script = r#"
        local now_ms = tonumber(ARGV[1])
        local ttl_ms = tonumber(ARGV[2])
        local limit = tonumber(ARGV[3])
        local token = ARGV[4]

        redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now_ms)
        local active = redis.call('ZCARD', KEYS[1])
        if active >= limit then
            return 0
        end

        redis.call('ZADD', KEYS[1], now_ms + ttl_ms, token)
        redis.call('PEXPIRE', KEYS[1], ttl_ms)
        return 1
    "#;

    let acquired: i64 = pool
        .eval(
            script,
            vec![key.to_string()],
            vec![
                now_ms.to_string(),
                ttl_ms.to_string(),
                limit.to_string(),
                token.clone(),
            ],
        )
        .await
        .context("semaphore acquire script failed")?;

    if acquired == 1 {
        debug!(%key, %node_id, limit, "distributed semaphore lease acquired");
        Ok(Some(SemaphoreLease {
            key: key.to_string(),
            token,
        }))
    } else {
        debug!(%key, %node_id, limit, "distributed semaphore saturated");
        Ok(None)
    }
}

pub async fn release_semaphore_lease(
    pool: &fred::clients::Pool,
    lease: &SemaphoreLease,
) -> Result<()> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let script = r#"
        local now_ms = tonumber(ARGV[1])
        local token = ARGV[2]

        if redis.call('EXISTS', KEYS[1]) == 0 then
            return 'expired'
        end

        redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now_ms)
        local removed = redis.call('ZREM', KEYS[1], token)
        if removed == 1 then
            if redis.call('ZCARD', KEYS[1]) == 0 then
                redis.call('DEL', KEYS[1])
            end
            return 'released'
        end

        if redis.call('EXISTS', KEYS[1]) == 0 then
            return 'expired'
        end

        return 'missing'
    "#;

    let status: String = pool
        .eval(
            script,
            vec![lease.key.clone()],
            vec![now_ms.to_string(), lease.token.clone()],
        )
        .await
        .context("semaphore release script failed")?;

    match status.as_str() {
        "released" => debug!(key = %lease.key, "distributed semaphore lease released"),
        "expired" => info!(key = %lease.key, "distributed semaphore lease already expired"),
        "missing" => warn!(
            key = %lease.key,
            "distributed semaphore lease missing at release time"
        ),
        other => bail!("unexpected semaphore release result {other:?}"),
    }

    Ok(())
}
