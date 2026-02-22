use anyhow::Result;
use tracing::{debug, instrument};

use super::middleware::Permission;
use crate::AppState;

/// Resolve SSH fingerprint to upstream username via the forge admin API, with
/// KeyDB cache.
#[instrument(skip(state), fields(fingerprint))]
pub async fn resolve_user_by_fingerprint(
    state: &AppState,
    fingerprint: &str,
) -> Result<Option<String>> {
    // 1. Check KeyDB cache: forgeproxy:ssh:auth:{fingerprint}
    let cache_key = format!("forgeproxy:ssh:auth:{fingerprint}");
    if let Some(cached) = crate::auth::cache::get_cached_auth(&state.keydb, &cache_key).await? {
        debug!(fingerprint, username = %cached, "resolved user from cache");
        return Ok(Some(cached));
    }

    // 2. Self-throttle if approaching the upstream rate limit.
    state
        .rate_limit
        .wait_if_needed(state.config.upstream.api_rate_limit_buffer)
        .await;

    // 3. Delegate to the forge backend.
    let resolved = state
        .forge
        .resolve_ssh_user(&state.http_client, fingerprint, &state.rate_limit)
        .await?;

    if let Some(ref username) = resolved {
        debug!(fingerprint, username = %username, "resolved user from upstream API");
        crate::auth::cache::set_cached_auth(
            &state.keydb,
            &cache_key,
            username,
            state.config.auth.ssh_cache_ttl,
        )
        .await?;
    } else {
        debug!(fingerprint, "no user found for fingerprint");
    }

    Ok(resolved)
}

/// Check SSH user's permission on a repo via the forge API, with KeyDB cache.
#[instrument(skip(state), fields(fingerprint, username, owner, repo))]
pub async fn check_ssh_repo_access(
    state: &AppState,
    fingerprint: &str,
    username: &str,
    owner: &str,
    repo: &str,
) -> Result<Permission> {
    let cache_key = format!("forgeproxy:ssh:access:{fingerprint}:{owner}/{repo}");
    if let Some(cached) = crate::auth::cache::get_cached_auth(&state.keydb, &cache_key).await? {
        debug!(cache_key, permission = %cached, "repo access from cache");
        return Ok(Permission::parse(&cached));
    }

    // Self-throttle if approaching the upstream rate limit.
    state
        .rate_limit
        .wait_if_needed(state.config.upstream.api_rate_limit_buffer)
        .await;

    // Delegate to the forge backend.
    let perm = state
        .forge
        .check_repo_access(&state.http_client, username, owner, repo, &state.rate_limit)
        .await?;

    let perm_str = perm.as_str();
    debug!(
        username,
        owner,
        repo,
        permission = perm_str,
        "resolved repo permission"
    );
    crate::auth::cache::set_cached_auth(
        &state.keydb,
        &cache_key,
        perm_str,
        state.config.auth.ssh_cache_ttl,
    )
    .await?;

    Ok(perm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_permission_admin() {
        assert_eq!(Permission::parse("admin"), Permission::Admin);
    }

    #[test]
    fn test_parse_permission_write() {
        assert_eq!(Permission::parse("write"), Permission::Write);
    }

    #[test]
    fn test_parse_permission_push() {
        assert_eq!(Permission::parse("push"), Permission::Write);
    }

    #[test]
    fn test_parse_permission_read() {
        assert_eq!(Permission::parse("read"), Permission::Read);
    }

    #[test]
    fn test_parse_permission_pull() {
        assert_eq!(Permission::parse("pull"), Permission::Read);
    }

    #[test]
    fn test_parse_permission_none() {
        assert_eq!(Permission::parse("none"), Permission::None);
    }

    #[test]
    fn test_parse_permission_unknown() {
        assert_eq!(Permission::parse("gibberish"), Permission::None);
        assert_eq!(Permission::parse(""), Permission::None);
    }
}
