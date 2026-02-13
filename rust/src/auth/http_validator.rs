//! HTTP credential validation against the upstream forge API.
//!
//! Validates an HTTP `Authorization` header by forwarding it to the upstream
//! forge API (via the [`ForgeBackend`] trait) and caching the result in KeyDB.
//! The cache key is derived from a SHA-256 hash of the token so that raw
//! credentials are never stored.

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};
use tracing::debug;

use crate::AppState;
use crate::auth::cache;
use crate::auth::middleware::Permission;

/// Validate an HTTP `Authorization` header value by forwarding it to the
/// upstream forge API and caching the result in KeyDB.
///
/// Returns `Ok(())` if the caller has at least read permission on the
/// repository, or an error otherwise.
pub async fn validate_http_auth(
    state: &AppState,
    auth_header: &str,
    owner: &str,
    repo: &str,
) -> Result<()> {
    // Normalise: callers may pass "repo.git" from the URL path.
    let repo = repo.trim_end_matches(".git");

    // 1. Hash the token for the cache key (never store raw credentials).
    let token_hash = {
        let mut hasher = Sha256::new();
        hasher.update(auth_header.as_bytes());
        hex::encode(hasher.finalize())
    };

    let cache_key = format!("forgecache:http:auth:{token_hash}:{owner}/{repo}");

    // 2. Check KeyDB cache.
    if let Some(cached) = cache::get_cached_auth(&state.keydb, &cache_key).await? {
        let perm = Permission::parse(&cached);
        if perm.has_read() {
            debug!(%owner, %repo, permission = %cached, "http auth cache hit (allowed)");
            return Ok(());
        }
        debug!(%owner, %repo, permission = %cached, "http auth cache hit (denied)");
        bail!("access denied for {owner}/{repo} (cached)");
    }

    // 3. Self-throttle if approaching the upstream rate limit.
    state
        .rate_limit
        .wait_if_needed(state.config.upstream.api_rate_limit_buffer)
        .await;

    // 4. Delegate to the forge backend.
    let perm = state
        .forge
        .validate_http_auth(
            &state.http_client,
            auth_header,
            owner,
            repo,
            &state.rate_limit,
        )
        .await?;

    // 5. Cache the result.
    let ttl = if perm.has_read() {
        state.config.auth.http_cache_ttl
    } else {
        state.config.auth.negative_cache_ttl
    };
    let perm_str = perm.as_str();
    cache::set_cached_auth(&state.keydb, &cache_key, perm_str, ttl)
        .await
        .ok();

    // 6. Decide.
    if perm.has_read() {
        debug!(%owner, %repo, permission = perm_str, "http auth validated (allowed)");
        Ok(())
    } else {
        debug!(%owner, %repo, permission = perm_str, "http auth validated (denied)");
        bail!("access denied for {owner}/{repo}")
    }
}
