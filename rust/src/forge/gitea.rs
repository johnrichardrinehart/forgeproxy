//! Gitea / Forgejo backend implementation.
//!
//! Gitea is largely GitHub-API-compatible.  The key differences are the webhook
//! signature header names (`X-Gitea-Signature` / `X-Forgejo-Signature` without
//! the `sha256=` prefix) and event header names.

use anyhow::{Context, Result};
use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::warn;

use crate::auth::middleware::Permission;
use crate::config::{BackendType, Config};

use super::rate_limit::RateLimitState;
use super::{ForgeBackend, WebhookEvent};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Backend struct
// ---------------------------------------------------------------------------

pub struct GiteaBackend {
    api_url: String,
    admin_token_env: String,
    accept: &'static str,
    is_forgejo: bool,
}

impl GiteaBackend {
    pub fn new(config: &Config) -> Self {
        Self {
            api_url: config.upstream.api_url.clone(),
            admin_token_env: config.upstream.admin_token_env.clone(),
            accept: config.backend_type.accept_header(),
            is_forgejo: config.backend_type == BackendType::Forgejo,
        }
    }

    /// Return the appropriate signature header name for this backend.
    fn signature_header(&self) -> &'static str {
        if self.is_forgejo {
            "X-Forgejo-Signature"
        } else {
            "X-Gitea-Signature"
        }
    }

    /// Return the appropriate event header name for this backend.
    fn event_header(&self) -> &'static str {
        if self.is_forgejo {
            "X-Forgejo-Event"
        } else {
            "X-Gitea-Event"
        }
    }
}

// ---------------------------------------------------------------------------
// Trait implementation
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl ForgeBackend for GiteaBackend {
    async fn validate_http_auth(
        &self,
        http_client: &reqwest::Client,
        auth_header: &str,
        owner: &str,
        repo: &str,
        rate_limit: &RateLimitState,
    ) -> Result<Permission> {
        // Gitea uses the same GitHub-compatible repo endpoint.
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
            warn!(%owner, %repo, %status, "Gitea API returned non-success for repo check");
            return Ok(Permission::None);
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .context("failed to parse Gitea API response")?;

        Ok(crate::forge::extract_permission(&body))
    }

    async fn resolve_ssh_user(
        &self,
        http_client: &reqwest::Client,
        fingerprint: &str,
        rate_limit: &RateLimitState,
    ) -> Result<Option<String>> {
        let admin_token = std::env::var(&self.admin_token_env).unwrap_or_default();
        if admin_token.is_empty() {
            warn!(
                env_var = %self.admin_token_env,
                "admin token env var is empty — SSH key resolution will fail"
            );
        }
        let url = reqwest::Url::parse_with_params(
            &format!("{}/admin/ssh-keys", self.api_url),
            &[("fingerprint", fingerprint)],
        )?;

        let resp = http_client
            .get(url)
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
                "Gitea admin API returned non-success status"
            );
            return Ok(None);
        }

        let body: serde_json::Value = resp.json().await?;

        // Same shape as GitHub: array of key objects with user.login.
        Ok(body
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|obj| obj.get("user"))
            .and_then(|u| u.get("login"))
            .and_then(|l| l.as_str())
            .map(|s| s.to_string()))
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
        if admin_token.is_empty() {
            warn!(
                env_var = %self.admin_token_env,
                "admin token env var is empty — collaborator permission check will fail"
            );
        }
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
                "Gitea collaborator permission check failed"
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
        // Gitea/Forgejo sends the raw hex HMAC-SHA256 without the `sha256=` prefix.
        let sig_header = headers
            .get("X-Webhook-Signature")
            .or_else(|| headers.get(self.signature_header()))
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| anyhow::anyhow!("missing webhook signature header"))?;

        let sig_bytes = hex::decode(sig_header)
            .map_err(|e| anyhow::anyhow!("invalid hex in signature: {e}"))?;

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
            .or_else(|| headers.get(self.event_header()))
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    fn parse_webhook_payload(&self, event_type: &str, payload: &serde_json::Value) -> WebhookEvent {
        // Gitea/Forgejo use the same event names as GitHub.
        super::parse_webhook_payload_github_style(event_type, payload)
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
        // Gitea uses the same endpoint as GitHub.
        let url = format!("{}/repos/{owner}/{repo}/commits/{git_ref}", self.api_url);

        let resp = http_client
            .get(&url)
            .header("Authorization", auth_header)
            .header("Accept", self.accept)
            .send()
            .await
            .context("upstream API request failed for ref resolution")?;

        rate_limit.update_from_headers(resp.headers());

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status();
            warn!(%owner, %repo, %git_ref, %status, "Gitea API returned non-success for ref resolution");
            return Ok(None);
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .context("failed to parse Gitea ref resolution response")?;

        Ok(body
            .get("sha")
            .and_then(|s| s.as_str())
            .map(|s| s.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Permission extraction (same shape as GitHub) ────────────────────

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

    // ── Gitea HMAC verification (no sha256= prefix) ────────────────────

    #[test]
    fn verify_gitea_signature_valid() {
        use hmac::Mac;

        let secret = "gitea-secret";
        let body = b"test payload";

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        let sig = hex::encode(mac.finalize().into_bytes());

        let mut headers = HeaderMap::new();
        // No sha256= prefix — just raw hex.
        headers.insert("X-Gitea-Signature", sig.parse().unwrap());

        let backend = GiteaBackend {
            api_url: String::new(),
            admin_token_env: String::new(),
            accept: "application/json",
            is_forgejo: false,
        };

        assert!(
            backend
                .verify_webhook_signature(&headers, body, secret)
                .is_ok()
        );
    }

    #[test]
    fn verify_gitea_signature_invalid() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Gitea-Signature",
            "0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap(),
        );

        let backend = GiteaBackend {
            api_url: String::new(),
            admin_token_env: String::new(),
            accept: "application/json",
            is_forgejo: false,
        };

        assert!(
            backend
                .verify_webhook_signature(&headers, b"body", "secret")
                .is_err()
        );
    }

    // ── Forgejo variant header ──────────────────────────────────────────

    #[test]
    fn verify_forgejo_signature_valid() {
        use hmac::Mac;

        let secret = "forgejo-secret";
        let body = b"test payload";

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        let sig = hex::encode(mac.finalize().into_bytes());

        let mut headers = HeaderMap::new();
        headers.insert("X-Forgejo-Signature", sig.parse().unwrap());

        let backend = GiteaBackend {
            api_url: String::new(),
            admin_token_env: String::new(),
            accept: "application/json",
            is_forgejo: true,
        };

        assert!(
            backend
                .verify_webhook_signature(&headers, body, secret)
                .is_ok()
        );
    }

    #[test]
    fn forgejo_event_header() {
        let backend = GiteaBackend {
            api_url: String::new(),
            admin_token_env: String::new(),
            accept: "application/json",
            is_forgejo: true,
        };
        let mut headers = HeaderMap::new();
        headers.insert("X-Forgejo-Event", "push".parse().unwrap());
        assert_eq!(
            backend.webhook_event_type(&headers),
            Some("push".to_string())
        );
    }

    #[test]
    fn gitea_event_header() {
        let backend = GiteaBackend {
            api_url: String::new(),
            admin_token_env: String::new(),
            accept: "application/json",
            is_forgejo: false,
        };
        let mut headers = HeaderMap::new();
        headers.insert("X-Gitea-Event", "push".parse().unwrap());
        assert_eq!(
            backend.webhook_event_type(&headers),
            Some("push".to_string())
        );
    }

    // ── Webhook event parsing (same as GitHub) ──────────────────────────

    #[test]
    fn webhook_repository_event() {
        let backend = GiteaBackend {
            api_url: String::new(),
            admin_token_env: String::new(),
            accept: "application/json",
            is_forgejo: false,
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
    fn webhook_org_event() {
        let backend = GiteaBackend {
            api_url: String::new(),
            admin_token_env: String::new(),
            accept: "application/json",
            is_forgejo: false,
        };
        let payload = serde_json::json!({
            "organization": {"login": "acme"}
        });
        assert_eq!(
            backend.parse_webhook_payload("organization", &payload),
            WebhookEvent::OrgChange {
                org: "acme".to_string()
            }
        );
    }
}
