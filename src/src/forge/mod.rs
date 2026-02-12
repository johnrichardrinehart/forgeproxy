//! Forge backend abstraction layer.
//!
//! Provides the [`ForgeBackend`] trait that encapsulates all forge-specific API
//! interaction (GitHub, GitLab, Gitea/Forgejo).  Callers in the auth and SSH
//! subsystems dispatch through this trait so that no forge-specific URL
//! construction or response parsing leaks outside this module.

pub mod gitea;
pub mod github;
pub mod gitlab;
pub mod rate_limit;

use anyhow::Result;
use axum::http::HeaderMap;

use crate::auth::middleware::Permission;
use crate::config::Config;

use self::rate_limit::RateLimitState;

// ---------------------------------------------------------------------------
// Webhook event
// ---------------------------------------------------------------------------

/// Describes the cache-invalidation effect of a webhook event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookEvent {
    /// Invalidate all auth cache entries for an org.
    OrgChange { org: String },
    /// Invalidate auth cache entries for a specific repo.
    RepoChange { repo_full_name: String },
    /// No cache invalidation needed.
    NoAction,
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Abstraction over forge-specific API endpoints and webhook formats.
#[async_trait::async_trait]
pub trait ForgeBackend: Send + Sync {
    /// Validate an HTTP Authorization header by calling the upstream repo API.
    async fn validate_http_auth(
        &self,
        http_client: &reqwest::Client,
        auth_header: &str,
        owner: &str,
        repo: &str,
        rate_limit: &RateLimitState,
    ) -> Result<Permission>;

    /// Resolve an SSH key fingerprint to a username via the upstream admin API.
    async fn resolve_ssh_user(
        &self,
        http_client: &reqwest::Client,
        fingerprint: &str,
        rate_limit: &RateLimitState,
    ) -> Result<Option<String>>;

    /// Check a user's permission on a repository via the upstream API.
    async fn check_repo_access(
        &self,
        http_client: &reqwest::Client,
        username: &str,
        owner: &str,
        repo: &str,
        rate_limit: &RateLimitState,
    ) -> Result<Permission>;

    /// Verify a webhook signature/token.
    fn verify_webhook_signature(
        &self,
        headers: &HeaderMap,
        body: &[u8],
        secret: &str,
    ) -> Result<()>;

    /// Extract the event type string from webhook headers.
    fn webhook_event_type(&self, headers: &HeaderMap) -> Option<String>;

    /// Parse a webhook payload into a cache-invalidation action.
    fn parse_webhook_payload(&self, event_type: &str, payload: &serde_json::Value) -> WebhookEvent;
}

// ---------------------------------------------------------------------------
// Shared helpers (GitHub & Gitea use the same JSON schemas)
// ---------------------------------------------------------------------------

/// Extract the highest permission from a `{admin, push, pull}` booleans
/// object — the format used by both GitHub and Gitea/Forgejo.
pub(crate) fn extract_permission(body: &serde_json::Value) -> Permission {
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

/// Parse webhook payloads that follow the GitHub/Gitea event schema
/// (`membership`, `team`, `organization`, `repository`).
pub(crate) fn parse_webhook_payload_github_style(
    event_type: &str,
    payload: &serde_json::Value,
) -> WebhookEvent {
    match event_type {
        "membership" | "team" | "organization" => {
            let org = payload
                .get("organization")
                .and_then(|o| o.get("login"))
                .and_then(|l| l.as_str())
                .unwrap_or("");
            if org.is_empty() {
                WebhookEvent::NoAction
            } else {
                WebhookEvent::OrgChange {
                    org: org.to_string(),
                }
            }
        }
        "repository" => {
            let full_name = payload
                .get("repository")
                .and_then(|r| r.get("full_name"))
                .and_then(|n| n.as_str())
                .unwrap_or("");
            if full_name.is_empty() {
                WebhookEvent::NoAction
            } else {
                WebhookEvent::RepoChange {
                    repo_full_name: full_name.to_string(),
                }
            }
        }
        _ => WebhookEvent::NoAction,
    }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

use crate::config::BackendType;

/// Build the appropriate [`ForgeBackend`] implementation for the configured
/// backend type.
pub fn build_backend(config: &Config) -> Box<dyn ForgeBackend> {
    match config.backend_type {
        BackendType::GithubEnterprise | BackendType::Github => {
            Box::new(github::GitHubBackend::new(config))
        }
        BackendType::Gitlab => Box::new(gitlab::GitLabBackend::new(config)),
        BackendType::Gitea | BackendType::Forgejo => Box::new(gitea::GiteaBackend::new(config)),
    }
}
