//! GitHub / GitHub Enterprise backend implementation.
//!
//! Extracted from the inline API calls previously spread across
//! `auth/http_validator.rs`, `auth/ssh_resolver.rs`, `auth/webhook.rs`, and
//! `ssh/session.rs`.  No behavioural changes — just moved behind the
//! [`ForgeBackend`] trait.

use anyhow::{Context, Result, anyhow};
use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{debug, warn};

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
    /// When `Some`, SSH fingerprint resolution calls this sidecar instead of
    /// the built-in GHE admin endpoint.
    key_lookup_url: Option<String>,
}

impl GitHubBackend {
    pub fn new(config: &Config) -> Self {
        Self {
            api_url: config.upstream.api_url.clone(),
            admin_token_env: config.upstream.admin_token_env.clone(),
            accept: config.backend_type.accept_header(),
            key_lookup_url: config.upstream.key_lookup_url.clone(),
        }
    }
}

fn permission_from_repo_response(body: &serde_json::Value) -> Permission {
    let perm = super::extract_permission(body);
    if perm.has_read() {
        return perm;
    }

    // Anonymous public repos are readable even when "permissions" is absent.
    if body
        .get("private")
        .and_then(|v| v.as_bool())
        .is_some_and(|is_private| !is_private)
    {
        return Permission::Read;
    }

    Permission::None
}

// ---------------------------------------------------------------------------
// Trait implementation
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl ForgeBackend for GitHubBackend {
    async fn validate_http_auth(
        &self,
        http_client: &reqwest::Client,
        auth_header: Option<&str>,
        owner: &str,
        repo: &str,
        rate_limit: &RateLimitState,
    ) -> Result<Permission> {
        let url = format!("{}/repos/{owner}/{repo}", self.api_url);

        let mut req = http_client.get(&url).header("Accept", self.accept);
        if let Some(header) = auth_header
            && !header.trim().is_empty()
        {
            req = req.header("Authorization", header);
        }
        let resp = req.send().await.context("upstream API request failed")?;

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

        Ok(permission_from_repo_response(&body))
    }

    async fn resolve_ssh_user(
        &self,
        http_client: &reqwest::Client,
        fingerprint: &str,
        _rate_limit: &RateLimitState,
    ) -> Result<Option<String>> {
        // Neither GitHub.com nor GitHub Enterprise Server expose a usable HTTP
        // API for fingerprint-to-username resolution.  Without a ghe-key-lookup
        // sidecar we cannot identify the connecting user; return None so the
        // caller falls back to an anonymous (unauthenticated) upstream clone.
        let Some(base_url) = self.key_lookup_url.as_deref() else {
            warn!(
                fingerprint,
                "no ghe-key-lookup sidecar configured; SSH key resolution unavailable, \
                 proceeding as anonymous"
            );
            return Ok(None);
        };

        let url = reqwest::Url::parse_with_params(
            &format!("{}/api/v3/users/keys/lookup", base_url),
            &[("fingerprint", fingerprint)],
        )?;

        debug!(fingerprint, %url, "querying ghe-key-lookup sidecar");
        let resp = http_client
            .get(url)
            .send()
            .await
            .context("ghe-key-lookup sidecar request failed")?;

        if !resp.status().is_success() {
            warn!(
                fingerprint,
                status = %resp.status(),
                "ghe-key-lookup sidecar returned non-success status"
            );
            return Ok(None);
        }

        let body: serde_json::Value = resp.json().await?;
        Ok(extract_key_lookup_login(&body))
    }

    async fn check_repo_access(
        &self,
        http_client: &reqwest::Client,
        username: &str,
        owner: &str,
        repo: &str,
        rate_limit: &RateLimitState,
    ) -> Result<Permission> {
        let admin_token = crate::credentials::keyring::resolve_secret(&self.admin_token_env)
            .await
            .unwrap_or_default();
        if admin_token.is_empty() {
            warn!(
                env_var = %self.admin_token_env,
                "admin token env var is empty — collaborator permission check will fail"
            );
        }
        let url = format!(
            "{}/repos/{owner}/{repo}/collaborators/{username}",
            self.api_url
        );

        let resp = http_client
            .get(&url)
            .header("Authorization", format!("Bearer {admin_token}"))
            .header("Accept", self.accept)
            .send()
            .await?;

        rate_limit.update_from_headers(resp.headers());

        match resp.status() {
            reqwest::StatusCode::NO_CONTENT => Ok(Permission::Read),
            reqwest::StatusCode::NOT_FOUND => Ok(Permission::None),
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => Err(anyhow!(
                "collaborator access check unauthorized for {owner}/{repo} user {username}: {}",
                resp.status()
            )),
            status => {
                warn!(
                    username,
                    owner,
                    repo,
                    status = %status,
                    "collaborator check returned unexpected status"
                );
                Ok(Permission::None)
            }
        }
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

    async fn resolve_ref(
        &self,
        http_client: &reqwest::Client,
        owner: &str,
        repo: &str,
        git_ref: &str,
        auth_header: Option<&str>,
        rate_limit: &RateLimitState,
    ) -> Result<Option<String>> {
        let url = format!("{}/repos/{owner}/{repo}/commits/{git_ref}", self.api_url);

        let mut req = http_client.get(&url).header("Accept", self.accept);
        if let Some(header) = auth_header
            && !header.trim().is_empty()
        {
            req = req.header("Authorization", header);
        }
        let resp = req
            .send()
            .await
            .context("upstream API request failed for ref resolution")?;

        rate_limit.update_from_headers(resp.headers());

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status();
            warn!(%owner, %repo, %git_ref, %status, "upstream API returned non-success for ref resolution");
            return Ok(None);
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .context("failed to parse ref resolution response")?;

        Ok(body
            .get("sha")
            .and_then(|s| s.as_str())
            .map(|s| s.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the SSH user login from a `ghe-key-lookup` sidecar response array.
///
/// Sidecar format: `[{"login": "<name>", ...}]` — no nested `user` object.
fn extract_key_lookup_login(body: &serde_json::Value) -> Option<String> {
    body.as_array()?
        .first()?
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

    #[test]
    fn public_repo_without_permissions_is_readable() {
        let body = serde_json::json!({"private": false});
        assert_eq!(permission_from_repo_response(&body), Permission::Read);
    }

    // ── ghe-key-lookup sidecar login extraction ─────────────────────────

    #[test]
    fn extract_key_lookup_login_found() {
        let body = serde_json::json!([
            {"id": 1, "login": "alice", "key": "ssh-ed25519 AAAA..."}
        ]);
        assert_eq!(extract_key_lookup_login(&body), Some("alice".to_string()));
    }

    #[test]
    fn extract_key_lookup_login_empty_array() {
        let body = serde_json::json!([]);
        assert_eq!(extract_key_lookup_login(&body), None);
    }

    #[test]
    fn extract_key_lookup_login_missing_field() {
        let body = serde_json::json!([{"id": 1}]);
        assert_eq!(extract_key_lookup_login(&body), None);
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
            key_lookup_url: None,
        };

        assert!(
            backend
                .verify_webhook_signature(&headers, body, secret)
                .is_ok()
        );
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
            key_lookup_url: None,
        };

        assert!(
            backend
                .verify_webhook_signature(&headers, b"body", "secret")
                .is_err()
        );
    }

    // ── Webhook event dispatch ──────────────────────────────────────────

    #[test]
    fn webhook_membership_event() {
        let backend = GitHubBackend {
            api_url: String::new(),
            admin_token_env: String::new(),
            accept: "application/json",
            key_lookup_url: None,
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
            key_lookup_url: None,
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
            key_lookup_url: None,
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
            key_lookup_url: None,
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
            key_lookup_url: None,
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
            key_lookup_url: None,
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
