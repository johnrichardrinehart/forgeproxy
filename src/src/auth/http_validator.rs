//! HTTP credential validation against upstream GHE.
//!
//! Validates an HTTP `Authorization` header by forwarding it to the upstream
//! GHE API (repos endpoint) and caching the result in KeyDB.  The cache key
//! is derived from a SHA-256 hash of the token so that raw credentials are
//! never stored.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use crate::auth::cache;
use crate::auth::middleware::Permission;
use crate::AppState;

/// Validate an HTTP `Authorization` header value by forwarding it to the
/// upstream GHE API and caching the result in KeyDB.
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
        let perm = parse_permission(&cached);
        if perm.has_read() {
            debug!(%owner, %repo, permission = %cached, "http auth cache hit (allowed)");
            return Ok(());
        }
        debug!(%owner, %repo, permission = %cached, "http auth cache hit (denied)");
        bail!("access denied for {owner}/{repo} (cached)");
    }

    // 3. Call GHE API: GET /repos/{owner}/{repo} with the caller's auth header.
    let url = format!("{}/repos/{owner}/{repo}", state.config.upstream.api_url);

    let resp = state
        .http_client
        .get(&url)
        .header("Authorization", auth_header)
        .header("Accept", state.config.backend_type.accept_header())
        .send()
        .await
        .context("upstream API request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        warn!(%owner, %repo, %status, "GHE API returned non-success for repo check");
        // Cache the denial with negative TTL.
        cache::set_cached_auth(
            &state.keydb,
            &cache_key,
            "none",
            state.config.auth.negative_cache_ttl,
        )
        .await
        .ok();
        bail!("access denied for {owner}/{repo} (upstream returned {status})");
    }

    // 4. Parse permissions from the response JSON.
    let body: serde_json::Value = resp
        .json()
        .await
        .context("failed to parse GHE API response")?;

    let perm = extract_permission(&body);

    // 5. Cache the result.
    let ttl = if perm.has_read() {
        state.config.auth.http_cache_ttl
    } else {
        state.config.auth.negative_cache_ttl
    };
    let perm_str = permission_str(perm);
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

/// Extract the highest permission from the GHE repo response `permissions` object.
fn extract_permission(body: &serde_json::Value) -> Permission {
    let perms = match body.get("permissions") {
        Some(p) => p,
        None => return Permission::None,
    };

    if perms
        .get("admin")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        Permission::Admin
    } else if perms.get("push").and_then(|v| v.as_bool()).unwrap_or(false) {
        Permission::Write
    } else if perms.get("pull").and_then(|v| v.as_bool()).unwrap_or(false) {
        Permission::Read
    } else {
        Permission::None
    }
}

fn parse_permission(s: &str) -> Permission {
    match s {
        "admin" => Permission::Admin,
        "write" | "push" => Permission::Write,
        "read" | "pull" => Permission::Read,
        _ => Permission::None,
    }
}

fn permission_str(p: Permission) -> &'static str {
    match p {
        Permission::Admin => "admin",
        Permission::Write => "write",
        Permission::Read => "read",
        Permission::None => "none",
    }
}
