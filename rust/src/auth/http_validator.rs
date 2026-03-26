//! HTTP credential validation against the upstream forge API.
//!
//! Validates an HTTP `Authorization` header by forwarding it to the upstream
//! forge API (via the [`ForgeBackend`] trait) and caching the result in Valkey.
//! The cache key is derived from a SHA-256 hash of the token so that raw
//! credentials are never stored.

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};
use tracing::debug;

use crate::AppState;
use crate::auth::cache;
use crate::auth::middleware::Permission;

#[derive(Clone, Debug)]
pub struct HttpAuthContext {
    pub metric_username: String,
}

/// Validate an HTTP `Authorization` header value by forwarding it to the
/// upstream forge API and caching the result in Valkey.
///
/// Returns `Ok(())` if the caller has at least read permission on the
/// repository, or an error otherwise.
pub async fn validate_http_auth(
    state: &AppState,
    auth_header: Option<&str>,
    owner: &str,
    repo: &str,
) -> Result<()> {
    validate_http_auth_with_context(state, auth_header, owner, repo)
        .await
        .map(|_| ())
}

pub async fn validate_http_auth_with_context(
    state: &AppState,
    auth_header: Option<&str>,
    owner: &str,
    repo: &str,
) -> Result<HttpAuthContext> {
    // Normalise: callers may pass "repo.git" from the URL path.
    let repo = repo.trim_end_matches(".git");
    let auth_header = auth_header.filter(|header| !header.trim().is_empty());
    let auth_present = auth_header.is_some();

    // 1. Hash the token for the cache key (never store raw credentials).
    let token_hash = match auth_header {
        Some(header) => {
            let mut hasher = Sha256::new();
            hasher.update(header.as_bytes());
            hex::encode(hasher.finalize())
        }
        None => "anonymous".to_string(),
    };

    let cache_key = format!("forgeproxy:http:auth:{token_hash}:{owner}/{repo}");

    // 2. Check Valkey cache.
    if let Some(cached) = cache::get_cached_auth(&state.valkey, &cache_key).await? {
        let perm = Permission::parse(&cached);
        if perm.has_read() {
            debug!(%owner, %repo, permission = %cached, "http auth cache hit (allowed)");
            let username = resolve_http_user(state, auth_header, &token_hash).await;
            return Ok(HttpAuthContext {
                metric_username: crate::metrics::clone_metric_username(
                    username.as_deref(),
                    auth_present,
                ),
            });
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
    cache::set_cached_auth(&state.valkey, &cache_key, perm_str, ttl)
        .await
        .ok();

    // 6. Decide.
    if perm.has_read() {
        debug!(%owner, %repo, permission = perm_str, "http auth validated (allowed)");
        let username = resolve_http_user(state, auth_header, &token_hash).await;
        Ok(HttpAuthContext {
            metric_username: crate::metrics::clone_metric_username(
                username.as_deref(),
                auth_present,
            ),
        })
    } else {
        debug!(%owner, %repo, permission = perm_str, "http auth validated (denied)");
        bail!("access denied for {owner}/{repo}")
    }
}

async fn resolve_http_user(
    state: &AppState,
    auth_header: Option<&str>,
    token_hash: &str,
) -> Option<String> {
    let auth_header = auth_header?;
    let cache_key = format!("forgeproxy:http:user:{token_hash}");
    if let Ok(Some(cached)) = cache::get_cached_auth(&state.valkey, &cache_key).await {
        debug!(cache_key, username = %cached, "http user resolution cache hit");
        return Some(cached);
    }

    state
        .rate_limit
        .wait_if_needed(state.config.upstream.api_rate_limit_buffer)
        .await;

    match state
        .forge
        .resolve_http_user(&state.http_client, Some(auth_header), &state.rate_limit)
        .await
    {
        Ok(Some(username)) => {
            debug!(username = %username, "resolved HTTP user from upstream API");
            cache::set_cached_auth(
                &state.valkey,
                &cache_key,
                &username,
                state.config.auth.http_cache_ttl,
            )
            .await
            .ok();
            Some(username)
        }
        Ok(None) => {
            debug!("no HTTP user found for presented credentials");
            None
        }
        Err(error) => {
            tracing::warn!(
                error = %error,
                "failed to resolve authenticated HTTP user; continuing without a resolved username label"
            );
            None
        }
    }
}
