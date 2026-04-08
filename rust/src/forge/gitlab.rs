//! GitLab backend implementation.
//!
//! Maps GitLab project API responses and webhook formats to the
//! [`ForgeBackend`] trait.

use anyhow::{Context, Result};
use axum::http::HeaderMap;
use base64::Engine as _;
use tracing::warn;

use crate::auth::middleware::Permission;
use crate::config::Config;

use super::rate_limit::RateLimitState;
use super::{AuthError, ForgeBackend, UpstreamRateLimitResponse, WebhookEvent};

// ---------------------------------------------------------------------------
// Backend struct
// ---------------------------------------------------------------------------

pub struct GitLabBackend {
    api_url: String,
    admin_token_env: String,
}

fn extract_current_username(body: &serde_json::Value) -> Option<String> {
    body.get("username")
        .and_then(|username| username.as_str())
        .map(|username| username.to_string())
}

fn extract_default_branch(body: &serde_json::Value) -> Option<String> {
    body.get("default_branch")
        .and_then(|branch| branch.as_str())
        .map(str::to_string)
}

fn apply_gitlab_api_auth(
    req: reqwest::RequestBuilder,
    auth_header: Option<&str>,
) -> reqwest::RequestBuilder {
    let Some(auth_header) = auth_header
        .map(str::trim)
        .filter(|header| !header.is_empty())
    else {
        return req;
    };

    if auth_header.starts_with("Bearer ") {
        return req.header("Authorization", auth_header);
    }

    if let Some(basic_payload) = auth_header.strip_prefix("Basic ")
        && let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(basic_payload)
        && let Ok(credentials) = String::from_utf8(decoded)
        && let Some((_, token)) = credentials.split_once(':')
        && !token.is_empty()
    {
        return req.header("PRIVATE-TOKEN", token);
    }

    req.header("Authorization", auth_header)
}

impl GitLabBackend {
    pub fn new(config: &Config) -> Self {
        Self {
            api_url: config.upstream.api_url.clone(),
            admin_token_env: config.upstream.admin_token_env.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Trait implementation
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl ForgeBackend for GitLabBackend {
    async fn startup_probe(
        &self,
        http_client: &reqwest::Client,
        rate_limit: &RateLimitState,
    ) -> Result<()> {
        let admin_token = crate::credentials::keyring::resolve_secret(&self.admin_token_env)
            .await
            .unwrap_or_default();
        if admin_token.is_empty() {
            anyhow::bail!(
                "upstream admin token env '{}' is empty or unavailable",
                self.admin_token_env
            );
        }

        let url = format!("{}/user", self.api_url);
        let resp = http_client
            .get(&url)
            .header("PRIVATE-TOKEN", &admin_token)
            .header("Accept", "application/json")
            .send()
            .await
            .context("upstream startup probe request failed")?;

        rate_limit.record_response("GET /user", resp.headers());

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "upstream startup probe GET {url} returned {status}: {}",
                body.trim()
            );
        }

        Ok(())
    }

    async fn validate_http_auth(
        &self,
        http_client: &reqwest::Client,
        auth_header: Option<&str>,
        owner: &str,
        repo: &str,
        rate_limit: &RateLimitState,
    ) -> std::result::Result<Permission, AuthError> {
        // GitLab uses URL-encoded `namespace/project` as the project id.
        let project_path = format!("{owner}%2F{repo}");
        let url = format!("{}/projects/{project_path}", self.api_url);

        let req = apply_gitlab_api_auth(
            http_client.get(&url).header("Accept", "application/json"),
            auth_header,
        );
        let resp = req.send().await.context("upstream API request failed")?;

        rate_limit.record_response("GET /projects/{owner}%2F{repo}", resp.headers());

        if !resp.status().is_success() {
            let status = resp.status();
            if super::rate_limit::is_rate_limited_response(status, resp.headers()) {
                let forwarded_headers =
                    super::rate_limit::forwarded_rate_limit_headers(resp.headers());
                let body = resp.text().await.unwrap_or_default();
                return Err(AuthError::RateLimited(UpstreamRateLimitResponse {
                    status,
                    headers: forwarded_headers,
                    body,
                }));
            }
            warn!(%owner, %repo, %status, "GitLab API returned non-success for project check");
            return Ok(Permission::None);
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .context("failed to parse GitLab API response")
            .map_err(AuthError::from)?;

        Ok(permission_from_project_response(&body))
    }

    async fn resolve_http_user(
        &self,
        http_client: &reqwest::Client,
        auth_header: Option<&str>,
        rate_limit: &RateLimitState,
    ) -> Result<Option<String>> {
        let Some(auth_header) = auth_header.filter(|header| !header.trim().is_empty()) else {
            return Ok(None);
        };

        let url = format!("{}/user", self.api_url);
        let resp = apply_gitlab_api_auth(
            http_client.get(&url).header("Accept", "application/json"),
            Some(auth_header),
        )
        .send()
        .await
        .context("GitLab current-user request failed")?;

        rate_limit.record_response("GET /user", resp.headers());

        if !resp.status().is_success() {
            warn!(
                status = %resp.status(),
                "GitLab current-user API returned non-success"
            );
            return Ok(None);
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .context("failed to parse GitLab current-user response")?;
        Ok(extract_current_username(&body))
    }

    async fn resolve_ssh_user(
        &self,
        http_client: &reqwest::Client,
        fingerprint: &str,
        rate_limit: &RateLimitState,
    ) -> Result<Option<String>> {
        let admin_token = crate::credentials::keyring::resolve_secret(&self.admin_token_env)
            .await
            .unwrap_or_default();
        if admin_token.is_empty() {
            warn!(
                env_var = %self.admin_token_env,
                "admin token env var is empty — SSH key resolution will fail"
            );
        }
        let url = reqwest::Url::parse_with_params(
            &format!("{}/keys", self.api_url),
            &[("fingerprint", fingerprint)],
        )?;

        let resp = http_client
            .get(url)
            .header("PRIVATE-TOKEN", &admin_token)
            .header("Accept", "application/json")
            .send()
            .await
            .context("GitLab admin API request failed")?;

        rate_limit.record_response("GET /keys?fingerprint=...", resp.headers());

        if !resp.status().is_success() {
            warn!(
                fingerprint,
                status = %resp.status(),
                "GitLab admin API returned non-success status"
            );
            return Ok(None);
        }

        let body: serde_json::Value = resp.json().await?;

        Ok(body
            .get("user")
            .and_then(|u| u.get("username"))
            .and_then(|l| l.as_str())
            .map(|s| s.to_string()))
    }

    async fn check_repo_access(
        &self,
        http_client: &reqwest::Client,
        _username: &str,
        owner: &str,
        repo: &str,
        rate_limit: &RateLimitState,
    ) -> Result<Permission> {
        // GitLab: fetch the project with an admin token and read the access level.
        let admin_token = crate::credentials::keyring::resolve_secret(&self.admin_token_env)
            .await
            .unwrap_or_default();
        if admin_token.is_empty() {
            warn!(
                env_var = %self.admin_token_env,
                "admin token env var is empty — project access check will fail"
            );
        }
        let project_path = format!("{owner}%2F{repo}");
        let url = format!("{}/projects/{project_path}", self.api_url);

        let resp = http_client
            .get(&url)
            .header("PRIVATE-TOKEN", &admin_token)
            .header("Accept", "application/json")
            .send()
            .await?;

        rate_limit.record_response("GET /projects/{owner}%2F{repo}", resp.headers());

        if !resp.status().is_success() {
            warn!(
                owner,
                repo,
                status = %resp.status(),
                "GitLab project access check failed"
            );
            return Ok(Permission::None);
        }

        let body: serde_json::Value = resp.json().await?;
        Ok(access_level_to_permission(&body))
    }

    fn verify_webhook_signature(
        &self,
        headers: &HeaderMap,
        _body: &[u8],
        secret: &str,
    ) -> Result<()> {
        // GitLab sends the secret as a plain token in `X-Gitlab-Token`.
        let token = headers
            .get("X-Webhook-Signature")
            .or_else(|| headers.get("X-Gitlab-Token"))
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| anyhow::anyhow!("missing GitLab webhook token header"))?;

        // Constant-time comparison.
        use subtle::ConstantTimeEq;
        if token.as_bytes().ct_eq(secret.as_bytes()).into() {
            Ok(())
        } else {
            anyhow::bail!("GitLab webhook token mismatch")
        }
    }

    fn webhook_event_type(&self, headers: &HeaderMap) -> Option<String> {
        headers
            .get("X-Webhook-Event")
            .or_else(|| headers.get("X-Gitlab-Event"))
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    async fn resolve_ref(
        &self,
        http_client: &reqwest::Client,
        owner: &str,
        repo: &str,
        git_ref: &str,
        auth_header: Option<&str>,
        rate_limit: &RateLimitState,
    ) -> Result<Option<String>> {
        let project_path = format!("{owner}%2F{repo}");
        let url = format!(
            "{}/projects/{project_path}/repository/commits/{git_ref}",
            self.api_url
        );

        let req = apply_gitlab_api_auth(
            http_client.get(&url).header("Accept", "application/json"),
            auth_header,
        );
        let resp = req
            .send()
            .await
            .context("upstream API request failed for ref resolution")?;

        rate_limit.record_response(
            "GET /projects/{owner}%2F{repo}/repository/commits/{git_ref}",
            resp.headers(),
        );

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status();
            warn!(%owner, %repo, %git_ref, %status, "GitLab API returned non-success for ref resolution");
            return Ok(None);
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .context("failed to parse GitLab ref resolution response")?;

        Ok(body
            .get("id")
            .and_then(|s| s.as_str())
            .map(|s| s.to_string()))
    }

    async fn resolve_default_branch(
        &self,
        http_client: &reqwest::Client,
        owner: &str,
        repo: &str,
        auth_header: Option<&str>,
        rate_limit: &RateLimitState,
    ) -> Result<Option<String>> {
        let project_path = format!("{owner}%2F{repo}");
        let url = format!("{}/projects/{project_path}", self.api_url);

        let req = apply_gitlab_api_auth(
            http_client.get(&url).header("Accept", "application/json"),
            auth_header,
        );
        let resp = req
            .send()
            .await
            .context("GitLab API request failed for default branch resolution")?;

        rate_limit.record_response("GET /projects/{owner}%2F{repo}", resp.headers());

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status();
            warn!(%owner, %repo, %status, "GitLab API returned non-success for default branch resolution");
            return Ok(None);
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .context("failed to parse GitLab default branch response")?;

        Ok(extract_default_branch(&body))
    }

    fn parse_webhook_payload(&self, event_type: &str, payload: &serde_json::Value) -> WebhookEvent {
        match event_type {
            // GitLab sends "Member Hook" for group member changes.
            "Member Hook" | "Subgroup Hook" => {
                let group = payload
                    .get("group")
                    .and_then(|g| g.get("path"))
                    .and_then(|p| p.as_str())
                    .unwrap_or("");
                if group.is_empty() {
                    WebhookEvent::NoAction
                } else {
                    WebhookEvent::OrgChange {
                        org: group.to_string(),
                    }
                }
            }
            // Project events carry `project.path_with_namespace`.
            "Project Hook" | "Push Hook" | "Tag Push Hook" => {
                let full_path = payload
                    .get("project")
                    .and_then(|p| p.get("path_with_namespace"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("");
                if full_path.is_empty() {
                    WebhookEvent::NoAction
                } else {
                    WebhookEvent::RepoChange {
                        repo_full_name: full_path.to_string(),
                    }
                }
            }
            _ => WebhookEvent::NoAction,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map a GitLab `permissions.project_access.access_level` to our Permission.
///
/// GitLab access levels:
/// - 10: Guest   → None (no code access)
/// - 20: Reporter → Read
/// - 30: Developer → Write
/// - 40: Maintainer → Admin
/// - 50: Owner   → Admin
fn access_level_to_permission(body: &serde_json::Value) -> Permission {
    let level = body
        .get("permissions")
        .and_then(|p| p.get("project_access"))
        .and_then(|pa| pa.get("access_level"))
        .and_then(|l| l.as_u64())
        .unwrap_or(0);

    match level {
        40..=u64::MAX => Permission::Admin,
        30..=39 => Permission::Write,
        20..=29 => Permission::Read,
        _ => Permission::None,
    }
}

fn permission_from_project_response(body: &serde_json::Value) -> Permission {
    let perm = access_level_to_permission(body);
    if perm.has_read() {
        return perm;
    }
    if body
        .get("visibility")
        .and_then(|v| v.as_str())
        .is_some_and(|v| v.eq_ignore_ascii_case("public"))
    {
        return Permission::Read;
    }
    Permission::None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Access level mapping ────────────────────────────────────────────

    #[test]
    fn access_level_guest() {
        let body = serde_json::json!({
            "permissions": {"project_access": {"access_level": 10}}
        });
        assert_eq!(access_level_to_permission(&body), Permission::None);
    }

    #[test]
    fn access_level_reporter() {
        let body = serde_json::json!({
            "permissions": {"project_access": {"access_level": 20}}
        });
        assert_eq!(access_level_to_permission(&body), Permission::Read);
    }

    #[test]
    fn access_level_developer() {
        let body = serde_json::json!({
            "permissions": {"project_access": {"access_level": 30}}
        });
        assert_eq!(access_level_to_permission(&body), Permission::Write);
    }

    #[test]
    fn access_level_maintainer() {
        let body = serde_json::json!({
            "permissions": {"project_access": {"access_level": 40}}
        });
        assert_eq!(access_level_to_permission(&body), Permission::Admin);
    }

    #[test]
    fn access_level_owner() {
        let body = serde_json::json!({
            "permissions": {"project_access": {"access_level": 50}}
        });
        assert_eq!(access_level_to_permission(&body), Permission::Admin);
    }

    #[test]
    fn access_level_missing() {
        let body = serde_json::json!({"id": 1});
        assert_eq!(access_level_to_permission(&body), Permission::None);
    }

    #[test]
    fn public_project_without_membership_is_readable() {
        let body = serde_json::json!({"visibility": "public"});
        assert_eq!(permission_from_project_response(&body), Permission::Read);
    }

    // ── SSH user extraction ─────────────────────────────────────────────

    #[test]
    fn extract_gitlab_ssh_username() {
        // GitLab /keys endpoint returns a single object, not an array.
        let body = serde_json::json!({
            "id": 1,
            "user": {"username": "alice", "id": 42}
        });
        let username = body
            .get("user")
            .and_then(|u| u.get("username"))
            .and_then(|l| l.as_str())
            .map(|s| s.to_string());
        assert_eq!(username, Some("alice".to_string()));
    }

    #[test]
    fn extract_gitlab_ssh_username_missing() {
        let body = serde_json::json!({"id": 1});
        let username = body
            .get("user")
            .and_then(|u| u.get("username"))
            .and_then(|l| l.as_str())
            .map(|s| s.to_string());
        assert_eq!(username, None);
    }

    // ── Token verification ──────────────────────────────────────────────

    #[test]
    fn verify_gitlab_token_match() {
        let backend = GitLabBackend {
            api_url: String::new(),
            admin_token_env: String::new(),
        };
        let mut headers = HeaderMap::new();
        headers.insert("X-Gitlab-Token", "my-secret".parse().unwrap());
        assert!(
            backend
                .verify_webhook_signature(&headers, b"body", "my-secret")
                .is_ok()
        );
    }

    #[test]
    fn verify_gitlab_token_mismatch() {
        let backend = GitLabBackend {
            api_url: String::new(),
            admin_token_env: String::new(),
        };
        let mut headers = HeaderMap::new();
        headers.insert("X-Gitlab-Token", "wrong-secret".parse().unwrap());
        assert!(
            backend
                .verify_webhook_signature(&headers, b"body", "my-secret")
                .is_err()
        );
    }

    // ── Webhook event parsing ───────────────────────────────────────────

    #[test]
    fn webhook_member_hook() {
        let backend = GitLabBackend {
            api_url: String::new(),
            admin_token_env: String::new(),
        };
        let payload = serde_json::json!({
            "group": {"path": "acme"}
        });
        assert_eq!(
            backend.parse_webhook_payload("Member Hook", &payload),
            WebhookEvent::OrgChange {
                org: "acme".to_string()
            }
        );
    }

    #[test]
    fn webhook_project_hook() {
        let backend = GitLabBackend {
            api_url: String::new(),
            admin_token_env: String::new(),
        };
        let payload = serde_json::json!({
            "project": {"path_with_namespace": "acme/widgets"}
        });
        assert_eq!(
            backend.parse_webhook_payload("Project Hook", &payload),
            WebhookEvent::RepoChange {
                repo_full_name: "acme/widgets".to_string()
            }
        );
    }

    #[test]
    fn webhook_event_type_gitlab_header() {
        let backend = GitLabBackend {
            api_url: String::new(),
            admin_token_env: String::new(),
        };
        let mut headers = HeaderMap::new();
        headers.insert("X-Gitlab-Event", "Push Hook".parse().unwrap());
        assert_eq!(
            backend.webhook_event_type(&headers),
            Some("Push Hook".to_string())
        );
    }

    #[test]
    fn webhook_unknown_event() {
        let backend = GitLabBackend {
            api_url: String::new(),
            admin_token_env: String::new(),
        };
        let payload = serde_json::json!({});
        assert_eq!(
            backend.parse_webhook_payload("Note Hook", &payload),
            WebhookEvent::NoAction
        );
    }

    #[test]
    fn extract_current_username_found() {
        let body = serde_json::json!({ "username": "alice" });
        assert_eq!(extract_current_username(&body), Some("alice".to_string()));
    }

    #[test]
    fn extract_current_username_missing() {
        let body = serde_json::json!({ "id": 1 });
        assert_eq!(extract_current_username(&body), None);
    }

    #[test]
    fn extract_default_branch_found() {
        let body = serde_json::json!({ "default_branch": "main" });
        assert_eq!(extract_default_branch(&body), Some("main".to_string()));
    }

    #[test]
    fn extract_default_branch_missing() {
        let body = serde_json::json!({});
        assert_eq!(extract_default_branch(&body), None);
    }
}
