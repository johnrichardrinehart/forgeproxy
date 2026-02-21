//! GitLab backend implementation.
//!
//! Maps GitLab project API responses and webhook formats to the
//! [`ForgeBackend`] trait.

use anyhow::{Context, Result};
use axum::http::HeaderMap;
use tracing::warn;

use crate::auth::middleware::Permission;
use crate::config::Config;

use super::rate_limit::RateLimitState;
use super::{ForgeBackend, WebhookEvent};

// ---------------------------------------------------------------------------
// Backend struct
// ---------------------------------------------------------------------------

pub struct GitLabBackend {
    api_url: String,
    admin_token_env: String,
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
    async fn validate_http_auth(
        &self,
        http_client: &reqwest::Client,
        auth_header: &str,
        owner: &str,
        repo: &str,
        rate_limit: &RateLimitState,
    ) -> Result<Permission> {
        // GitLab uses URL-encoded `namespace/project` as the project id.
        let project_path = format!("{owner}%2F{repo}");
        let url = format!("{}/projects/{project_path}", self.api_url);

        let resp = http_client
            .get(&url)
            .header("Authorization", auth_header)
            .header("Accept", "application/json")
            .send()
            .await
            .context("upstream API request failed")?;

        rate_limit.update_from_headers(resp.headers());

        if !resp.status().is_success() {
            let status = resp.status();
            warn!(%owner, %repo, %status, "GitLab API returned non-success for project check");
            return Ok(Permission::None);
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .context("failed to parse GitLab API response")?;

        Ok(access_level_to_permission(&body))
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

        rate_limit.update_from_headers(resp.headers());

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

        rate_limit.update_from_headers(resp.headers());

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
        auth_header: &str,
        rate_limit: &RateLimitState,
    ) -> Result<Option<String>> {
        let project_path = format!("{owner}%2F{repo}");
        let url = format!(
            "{}/projects/{project_path}/repository/commits/{git_ref}",
            self.api_url
        );

        let resp = http_client
            .get(&url)
            .header("Authorization", auth_header)
            .header("Accept", "application/json")
            .send()
            .await
            .context("upstream API request failed for ref resolution")?;

        rate_limit.update_from_headers(resp.headers());

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
}
