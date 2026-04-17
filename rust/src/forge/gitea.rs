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
use super::{AuthError, ForgeBackend, UpstreamRateLimitResponse, WebhookEvent};

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

fn permission_from_repo_response(body: &serde_json::Value) -> Permission {
    let perm = crate::forge::extract_permission(body);
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

fn extract_current_user_username(body: &serde_json::Value) -> Option<String> {
    body.get("login")
        .or_else(|| body.get("username"))
        .and_then(|username| username.as_str())
        .map(|username| username.to_string())
}

fn extract_default_branch(body: &serde_json::Value) -> Option<String> {
    body.get("default_branch")
        .and_then(|branch| branch.as_str())
        .map(str::to_string)
}

fn repo_full_name_matches(owner: &str, repo: &str, body: &serde_json::Value) -> bool {
    let Some(full_name) = body.get("full_name").and_then(|name| name.as_str()) else {
        return true;
    };
    crate::repo_identity::RepoIdentity::new(owner, repo).matches_upstream_full_name(full_name)
}

// ---------------------------------------------------------------------------
// Trait implementation
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl ForgeBackend for GiteaBackend {
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
            .header("Authorization", format!("Bearer {admin_token}"))
            .header("Accept", self.accept)
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
        // Gitea uses the same GitHub-compatible repo endpoint.
        let url = format!("{}/repos/{owner}/{repo}", self.api_url);

        let mut req = http_client.get(&url).header("Accept", self.accept);
        if let Some(header) = auth_header
            && !header.trim().is_empty()
        {
            req = req.header("Authorization", header);
        }
        let resp = req.send().await.context("upstream API request failed")?;

        rate_limit.record_response("GET /repos/{owner}/{repo}", resp.headers());

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
            warn!(%owner, %repo, %status, "Gitea API returned non-success for repo check");
            return Ok(Permission::None);
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .context("failed to parse Gitea API response")
            .map_err(AuthError::from)?;

        if !repo_full_name_matches(owner, repo, &body) {
            warn!(
                %owner,
                %repo,
                upstream_full_name = body.get("full_name").and_then(|name| name.as_str()).unwrap_or(""),
                "Gitea repository canonical path did not match requested path"
            );
            return Ok(Permission::None);
        }

        Ok(permission_from_repo_response(&body))
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
        let resp = http_client
            .get(&url)
            .header("Authorization", auth_header)
            .header("Accept", self.accept)
            .send()
            .await
            .context("upstream current-user request failed")?;

        rate_limit.record_response("GET /user", resp.headers());

        if !resp.status().is_success() {
            warn!(
                status = %resp.status(),
                "Gitea current-user API returned non-success"
            );
            return Ok(None);
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .context("failed to parse Gitea current-user response")?;
        Ok(extract_current_user_username(&body))
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

        rate_limit.record_response("GET /admin/ssh-keys?fingerprint=...", resp.headers());

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
        let admin_token = crate::credentials::keyring::resolve_secret(&self.admin_token_env)
            .await
            .unwrap_or_default();
        if admin_token.is_empty() {
            warn!(
                env_var = %self.admin_token_env,
                "admin token env var is empty — collaborator permission check will fail"
            );
        }
        let repo_url = format!("{}/repos/{owner}/{repo}", self.api_url);
        let repo_resp = http_client
            .get(&repo_url)
            .header("Authorization", format!("Bearer {admin_token}"))
            .header("Accept", self.accept)
            .send()
            .await?;
        rate_limit.record_response("GET /repos/{owner}/{repo}", repo_resp.headers());
        if !repo_resp.status().is_success() {
            warn!(%owner, %repo, status = %repo_resp.status(), "Gitea repo identity check failed before collaborator check");
            return Ok(Permission::None);
        }
        let repo_body: serde_json::Value = repo_resp.json().await?;
        if !repo_full_name_matches(owner, repo, &repo_body) {
            warn!(
                %owner,
                %repo,
                upstream_full_name = repo_body.get("full_name").and_then(|name| name.as_str()).unwrap_or(""),
                "Gitea repository canonical path did not match requested path"
            );
            return Ok(Permission::None);
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

        rate_limit.record_response(
            "GET /repos/{owner}/{repo}/collaborators/{username}/permission",
            resp.headers(),
        );

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
        auth_header: Option<&str>,
        rate_limit: &RateLimitState,
    ) -> Result<Option<String>> {
        // Gitea uses the same endpoint as GitHub.
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

        rate_limit.record_response(
            "GET /repos/{owner}/{repo}/commits/{git_ref}",
            resp.headers(),
        );

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

    async fn resolve_default_branch(
        &self,
        http_client: &reqwest::Client,
        owner: &str,
        repo: &str,
        auth_header: Option<&str>,
        rate_limit: &RateLimitState,
    ) -> Result<Option<String>> {
        let url = format!("{}/repos/{owner}/{repo}", self.api_url);

        let mut req = http_client.get(&url).header("Accept", self.accept);
        if let Some(header) = auth_header
            && !header.trim().is_empty()
        {
            req = req.header("Authorization", header);
        }
        let resp = req
            .send()
            .await
            .context("Gitea API request failed for default branch resolution")?;

        rate_limit.record_response("GET /repos/{owner}/{repo}", resp.headers());

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status();
            warn!(%owner, %repo, %status, "Gitea API returned non-success for default branch resolution");
            return Ok(None);
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .context("failed to parse Gitea default branch response")?;

        Ok(extract_default_branch(&body))
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

    #[test]
    fn public_repo_without_permissions_is_readable() {
        let body = serde_json::json!({"private": false});
        assert_eq!(permission_from_repo_response(&body), Permission::Read);
    }

    #[test]
    fn extract_current_user_username_login_field() {
        let body = serde_json::json!({ "login": "alice" });
        assert_eq!(
            extract_current_user_username(&body),
            Some("alice".to_string())
        );
    }

    #[test]
    fn extract_current_user_username_username_field() {
        let body = serde_json::json!({ "username": "alice" });
        assert_eq!(
            extract_current_user_username(&body),
            Some("alice".to_string())
        );
    }

    #[test]
    fn extract_current_user_username_missing() {
        let body = serde_json::json!({ "id": 1 });
        assert_eq!(extract_current_user_username(&body), None);
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
