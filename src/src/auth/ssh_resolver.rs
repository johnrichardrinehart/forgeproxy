use anyhow::{Context, Result};
use tracing::{debug, instrument, warn};

use crate::AppState;
use super::middleware::Permission;

/// Resolve SSH fingerprint to GHE username via admin API, with KeyDB cache.
#[instrument(skip(state), fields(fingerprint))]
pub async fn resolve_user_by_fingerprint(
    state: &AppState,
    fingerprint: &str,
) -> Result<Option<String>> {
    // 1. Check KeyDB cache: gheproxy:ssh:auth:{fingerprint}
    let cache_key = format!("gheproxy:ssh:auth:{fingerprint}");
    if let Some(cached) = crate::auth::cache::get_cached_auth(&state.keydb, &cache_key).await? {
        debug!(fingerprint, username = %cached, "resolved user from cache");
        return Ok(Some(cached));
    }

    // 2. Call GHE admin API: GET /api/v3/admin/ssh-keys?fingerprint={fp}
    let admin_token = std::env::var(&state.config.ghe.admin_token_env).unwrap_or_default();
    let url = format!(
        "{}/admin/ssh-keys?fingerprint={}",
        state.config.ghe.api_url, fingerprint
    );

    let resp = state
        .http_client
        .get(&url)
        .header("Authorization", format!("Bearer {admin_token}"))
        .header("Accept", "application/vnd.github.v3+json")
        .send()
        .await
        .context("GHE admin API request failed")?;

    if !resp.status().is_success() {
        warn!(
            fingerprint,
            status = %resp.status(),
            "GHE admin API returned non-success status"
        );
        return Ok(None);
    }

    let body: serde_json::Value = resp.json().await?;

    // Parse array, extract user.login from the first matching key
    if let Some(arr) = body.as_array() {
        if let Some(first) = arr.first() {
            if let Some(login) = first
                .get("user")
                .and_then(|u| u.get("login"))
                .and_then(|l| l.as_str())
            {
                let username = login.to_string();
                debug!(fingerprint, username = %username, "resolved user from GHE API");
                crate::auth::cache::set_cached_auth(
                    &state.keydb,
                    &cache_key,
                    &username,
                    state.config.auth.ssh_cache_ttl,
                )
                .await?;
                return Ok(Some(username));
            }
        }
    }

    debug!(fingerprint, "no user found for fingerprint");
    Ok(None)
}

/// Check SSH user's permission on a repo via GHE collaborator API, with KeyDB cache.
#[instrument(skip(state), fields(fingerprint, username, owner, repo))]
pub async fn check_ssh_repo_access(
    state: &AppState,
    fingerprint: &str,
    username: &str,
    owner: &str,
    repo: &str,
) -> Result<Permission> {
    let cache_key = format!("gheproxy:ssh:access:{fingerprint}:{owner}/{repo}");
    if let Some(cached) = crate::auth::cache::get_cached_auth(&state.keydb, &cache_key).await? {
        debug!(cache_key, permission = %cached, "repo access from cache");
        return Ok(parse_permission(&cached));
    }

    let admin_token = std::env::var(&state.config.ghe.admin_token_env).unwrap_or_default();
    let url = format!(
        "{}/repos/{owner}/{repo}/collaborators/{username}/permission",
        state.config.ghe.api_url
    );

    let resp = state
        .http_client
        .get(&url)
        .header("Authorization", format!("Bearer {admin_token}"))
        .header("Accept", "application/vnd.github.v3+json")
        .send()
        .await?;

    if !resp.status().is_success() {
        warn!(
            username,
            owner,
            repo,
            status = %resp.status(),
            "GHE collaborator permission check failed"
        );
        return Ok(Permission::None);
    }

    let body: serde_json::Value = resp.json().await?;
    let perm_str = body
        .get("permission")
        .and_then(|p| p.as_str())
        .unwrap_or("none");
    let perm = parse_permission(perm_str);

    debug!(username, owner, repo, permission = perm_str, "resolved repo permission");
    crate::auth::cache::set_cached_auth(
        &state.keydb,
        &cache_key,
        perm_str,
        state.config.auth.ssh_cache_ttl,
    )
    .await?;

    Ok(perm)
}

fn parse_permission(s: &str) -> Permission {
    match s {
        "admin" => Permission::Admin,
        "write" | "push" => Permission::Write,
        "read" | "pull" => Permission::Read,
        _ => Permission::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_permission_admin() {
        assert_eq!(parse_permission("admin"), Permission::Admin);
    }

    #[test]
    fn test_parse_permission_write() {
        assert_eq!(parse_permission("write"), Permission::Write);
    }

    #[test]
    fn test_parse_permission_push() {
        assert_eq!(parse_permission("push"), Permission::Write);
    }

    #[test]
    fn test_parse_permission_read() {
        assert_eq!(parse_permission("read"), Permission::Read);
    }

    #[test]
    fn test_parse_permission_pull() {
        assert_eq!(parse_permission("pull"), Permission::Read);
    }

    #[test]
    fn test_parse_permission_none() {
        assert_eq!(parse_permission("none"), Permission::None);
    }

    #[test]
    fn test_parse_permission_unknown() {
        assert_eq!(parse_permission("gibberish"), Permission::None);
        assert_eq!(parse_permission(""), Permission::None);
    }
}
