//! GitHub / GitHub Enterprise backend implementation.
//!
//! Extracted from the inline API calls previously spread across
//! `auth/http_validator.rs`, `auth/ssh_resolver.rs`, `auth/webhook.rs`, and
//! `ssh/session.rs`.  No behavioural changes — just moved behind the
//! [`ForgeBackend`] trait.

use anyhow::{Context, Result};
use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::warn;

use crate::auth::middleware::Permission;
use crate::config::Config;

use super::rate_limit::RateLimitState;
use super::{ForgeBackend, WebhookEvent};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Backend struct
// ---------------------------------------------------------------------------

pub struct GitHubBackend {
    api_url: String,
    admin_token_env: String,
    accept: &'static str,
}

impl GitHubBackend {
    pub fn new(config: &Config) -> Self {
        Self {
            api_url: config.upstream.api_url.clone(),
            admin_token_env: config.upstream.admin_token_env.clone(),
            accept: config.backend_type.accept_header(),
        }
    }
}

// ---------------------------------------------------------------------------
// Trait implementation
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl ForgeBackend for GitHubBackend {
    async fn validate_http_auth(
        &self,
        http_client: &reqwest::Client,
        auth_header: &str,
        owner: &str,
        repo: &str,
        rate_limit: &RateLimitState,
    ) -> Result<Permission> {
        let url = format!("{}/repos/{owner}/{repo}", self.api_url);

        let resp = http_client
            .get(&url)
            .header("Authorization", auth_header)
            .header("Accept", self.accept)
            .send()
            .await
            .context("upstream API request failed")?;

        rate_limit.update_from_headers(resp.headers());

        if !resp.status().is_success() {
            let status = resp.status();
            warn!(%owner, %repo, %status, "upstream API returned non-success for repo check");
            return Ok(Permission::None);
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .context("failed to parse upstream API response")?;

        Ok(super::extract_permission(&body))
    }

    async fn resolve_ssh_user(
        &self,
        http_client: &reqwest::Client,
        fingerprint: &str,
        rate_limit: &RateLimitState,
    ) -> Result<Option<String>> {
        let admin_token = std::env::var(&self.admin_token_env).unwrap_or_default();
        let url = format!(
            "{}/admin/ssh-keys?fingerprint={}",
            self.api_url, fingerprint
        );

        let resp = http_client
            .get(&url)
            .header("Authorization", format!("Bearer {admin_token}"))
            .header("Accept", self.accept)
            .send()
            .await
            .context("upstream admin API request failed")?;

        rate_limit.update_from_headers(resp.headers());

        if !resp.status().is_success() {
            warn!(
                fingerprint,
                status = %resp.status(),
                "upstream admin API returned non-success status"
            );
            return Ok(None);
        }

        let body: serde_json::Value = resp.json().await?;

        Ok(extract_ssh_user_login(&body))
    }

    async fn check_repo_access(
        &self,
        http_client: &reqwest::Client,
        username: &str,
        owner: &str,
        repo: &str,
        rate_limit: &RateLimitState,
    ) -> Result<Permission> {
        let admin_token = std::env::var(&self.admin_token_env).unwrap_or_default();
        let url = format!(
            "{}/repos/{owner}/{repo}/collaborators/{username}/permission",
            self.api_url
        );

        let resp = http_client
            .get(&url)
            .header("Authorization", format!("Bearer {admin_token}"))
            .header("Accept", self.accept)
            .send()
            .await?;

        rate_limit.update_from_headers(resp.headers());

        if !resp.status().is_success() {
            warn!(
                username,
                owner,
                repo,
                status = %resp.status(),
                "collaborator permission check failed"
            );
            return Ok(Permission::None);
        }

        let body: serde_json::Value = resp.json().await?;
        let perm_str = body
            .get("permission")
            .and_then(|p| p.as_str())
            .unwrap_or("none");

        Ok(Permission::parse(perm_str))
    }

    fn verify_webhook_signature(
        &self,
        headers: &HeaderMap,
        body: &[u8],
        secret: &str,
    ) -> Result<()> {
        let sig_header = headers
            .get("X-Webhook-Signature")
            .or_else(|| headers.get("X-Hub-Signature-256"))
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| anyhow::anyhow!("missing webhook signature header"))?;

        let sig_hex = sig_header
            .strip_prefix("sha256=")
            .ok_or_else(|| anyhow::anyhow!("signature does not start with sha256="))?;

        let sig_bytes =
            hex::decode(sig_hex).map_err(|e| anyhow::anyhow!("invalid hex in signature: {e}"))?;

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|e| anyhow::anyhow!("HMAC key error: {e}"))?;
        mac.update(body);

        mac.verify_slice(&sig_bytes)
            .map_err(|_| anyhow::anyhow!("HMAC signature mismatch"))?;

        Ok(())
    }

    fn webhook_event_type(&self, headers: &HeaderMap) -> Option<String> {
        headers
            .get("X-Webhook-Event")
            .or_else(|| headers.get("X-GitHub-Event"))
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    fn parse_webhook_payload(&self, event_type: &str, payload: &serde_json::Value) -> WebhookEvent {
        super::parse_webhook_payload_github_style(event_type, payload)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the SSH user login from the GitHub admin API response array.
fn extract_ssh_user_login(body: &serde_json::Value) -> Option<String> {
    body.as_array()?
        .first()?
        .get("user")?
        .get("login")?
        .as_str()
        .map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Permission extraction ───────────────────────────────────────────

    #[test]
    fn extract_permission_admin() {
        let body = serde_json::json!({
            "permissions": {"admin": true, "push": true, "pull": true}
        });
        assert_eq!(crate::forge::extract_permission(&body), Permission::Admin);
    }

    #[test]
    fn extract_permission_write() {
        let body = serde_json::json!({
            "permissions": {"admin": false, "push": true, "pull": true}
        });
        assert_eq!(crate::forge::extract_permission(&body), Permission::Write);
    }

    #[test]
    fn extract_permission_read() {
        let body = serde_json::json!({
            "permissions": {"admin": false, "push": false, "pull": true}
        });
        assert_eq!(crate::forge::extract_permission(&body), Permission::Read);
    }

    #[test]
    fn extract_permission_none() {
        let body = serde_json::json!({
            "permissions": {"admin": false, "push": false, "pull": false}
        });
        assert_eq!(crate::forge::extract_permission(&body), Permission::None);
    }

    #[test]
    fn extract_permission_missing_permissions_key() {
        let body = serde_json::json!({"id": 1});
        assert_eq!(crate::forge::extract_permission(&body), Permission::None);
    }

    // ── SSH user extraction ─────────────────────────────────────────────

    #[test]
    fn extract_ssh_user_from_array() {
        let body = serde_json::json!([
            {"id": 1, "user": {"login": "alice", "id": 42}}
        ]);
        assert_eq!(extract_ssh_user_login(&body), Some("alice".to_string()));
    }

    #[test]
    fn extract_ssh_user_empty_array() {
        let body = serde_json::json!([]);
        assert_eq!(extract_ssh_user_login(&body), None);
    }

    #[test]
    fn extract_ssh_user_missing_login() {
        let body = serde_json::json!([{"id": 1, "user": {}}]);
        assert_eq!(extract_ssh_user_login(&body), None);
    }

    // ── Collaborator permission parsing ─────────────────────────────────

    #[test]
    fn parse_collaborator_permission_write() {
        assert_eq!(Permission::parse("write"), Permission::Write);
    }

    #[test]
    fn parse_collaborator_permission_admin() {
        assert_eq!(Permission::parse("admin"), Permission::Admin);
    }

    #[test]
    fn parse_collaborator_permission_read() {
        assert_eq!(Permission::parse("read"), Permission::Read);
    }

    #[test]
    fn parse_collaborator_permission_unknown() {
        assert_eq!(Permission::parse("maintain"), Permission::None);
    }

    // ── HMAC verification ───────────────────────────────────────────────

    #[test]
    fn verify_webhook_valid_signature() {
        use hmac::Mac;

        let secret = "test-secret";
        let body = b"hello world";

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        let sig = hex::encode(mac.finalize().into_bytes());

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Hub-Signature-256",
            format!("sha256={sig}").parse().unwrap(),
        );

        let backend = GitHubBackend {
            api_url: String::new(),
            admin_token_env: String::new(),
            accept: "application/json",
        };

        assert!(backend
            .verify_webhook_signature(&headers, body, secret)
            .is_ok());
    }

    #[test]
    fn verify_webhook_invalid_signature() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Hub-Signature-256",
            "sha256=0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap(),
        );

        let backend = GitHubBackend {
            api_url: String::new(),
            admin_token_env: String::new(),
            accept: "application/json",
        };

        assert!(backend
            .verify_webhook_signature(&headers, b"body", "secret")
            .is_err());
    }

    // ── Webhook event dispatch ──────────────────────────────────────────

    #[test]
    fn webhook_membership_event() {
        let backend = GitHubBackend {
            api_url: String::new(),
            admin_token_env: String::new(),
            accept: "application/json",
        };
        let payload = serde_json::json!({
            "organization": {"login": "acme"}
        });
        assert_eq!(
            backend.parse_webhook_payload("membership", &payload),
            WebhookEvent::OrgChange {
                org: "acme".to_string()
            }
        );
    }

    #[test]
    fn webhook_team_event() {
        let backend = GitHubBackend {
            api_url: String::new(),
            admin_token_env: String::new(),
            accept: "application/json",
        };
        let payload = serde_json::json!({
            "organization": {"login": "acme"}
        });
        assert_eq!(
            backend.parse_webhook_payload("team", &payload),
            WebhookEvent::OrgChange {
                org: "acme".to_string()
            }
        );
    }

    #[test]
    fn webhook_repository_event() {
        let backend = GitHubBackend {
            api_url: String::new(),
            admin_token_env: String::new(),
            accept: "application/json",
        };
        let payload = serde_json::json!({
            "repository": {"full_name": "acme/widgets"}
        });
        assert_eq!(
            backend.parse_webhook_payload("repository", &payload),
            WebhookEvent::RepoChange {
                repo_full_name: "acme/widgets".to_string()
            }
        );
    }

    #[test]
    fn webhook_unknown_event() {
        let backend = GitHubBackend {
            api_url: String::new(),
            admin_token_env: String::new(),
            accept: "application/json",
        };
        let payload = serde_json::json!({});
        assert_eq!(
            backend.parse_webhook_payload("ping", &payload),
            WebhookEvent::NoAction
        );
    }

    #[test]
    fn webhook_event_type_github_header() {
        let backend = GitHubBackend {
            api_url: String::new(),
            admin_token_env: String::new(),
            accept: "application/json",
        };
        let mut headers = HeaderMap::new();
        headers.insert("X-GitHub-Event", "push".parse().unwrap());
        assert_eq!(
            backend.webhook_event_type(&headers),
            Some("push".to_string())
        );
    }

    #[test]
    fn webhook_event_type_normalized_header() {
        let backend = GitHubBackend {
            api_url: String::new(),
            admin_token_env: String::new(),
            accept: "application/json",
        };
        let mut headers = HeaderMap::new();
        headers.insert("X-Webhook-Event", "push".parse().unwrap());
        headers.insert("X-GitHub-Event", "ignored".parse().unwrap());
        assert_eq!(
            backend.webhook_event_type(&headers),
            Some("push".to_string())
        );
    }
}
