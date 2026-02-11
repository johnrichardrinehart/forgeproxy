//! GitHub webhook receiver for cache invalidation and event processing.
//!
//! Validates the HMAC-SHA256 signature from GitHub, parses the event type,
//! and invalidates the appropriate KeyDB auth cache entries so that
//! permission changes take effect without waiting for TTL expiry.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{debug, info, warn};

use crate::auth::cache;
use crate::AppState;

type HmacSha256 = Hmac<Sha256>;

/// Process an incoming GitHub webhook payload.
///
/// 1. Verify the HMAC-SHA256 signature.
/// 2. Parse the event type from `X-GitHub-Event`.
/// 3. Dispatch to per-event handlers that invalidate auth cache entries.
pub async fn handle_webhook_payload(
    state: &AppState,
    headers: &HeaderMap,
    body: &Bytes,
) -> anyhow::Result<Response> {
    // 1. Verify HMAC signature.
    if let Err(e) = verify_signature(state, headers, body) {
        warn!(error = %e, "webhook signature verification failed");
        return Ok((StatusCode::UNAUTHORIZED, "invalid signature").into_response());
    }

    // 2. Extract event type (prefer normalized header from nginx, fall back to GitHub-specific).
    let event_type = headers
        .get("X-Webhook-Event")
        .or_else(|| headers.get("X-GitHub-Event"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    info!(event = %event_type, "processing webhook event");

    // 3. Parse body as JSON.
    let payload: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| anyhow::anyhow!("failed to parse webhook JSON: {e}"))?;

    // 4. Dispatch by event type.
    match event_type {
        "membership" => handle_membership(state, &payload).await,
        "team" => handle_team(state, &payload).await,
        "organization" => handle_organization(state, &payload).await,
        "repository" => handle_repository(state, &payload).await,
        _ => {
            debug!(event = %event_type, "ignoring unhandled webhook event type");
        }
    }

    Ok(StatusCode::OK.into_response())
}

/// Verify the HMAC-SHA256 signature from the webhook signature header.
///
/// Checks the normalized `X-Webhook-Signature` header first (set by nginx for
/// non-GitHub backends), then falls back to `X-Hub-Signature-256`.
fn verify_signature(state: &AppState, headers: &HeaderMap, body: &Bytes) -> anyhow::Result<()> {
    let secret = std::env::var(&state.config.auth.webhook_secret_env)
        .map_err(|_| anyhow::anyhow!("webhook secret env var not set"))?;

    let sig_header = headers
        .get("X-Webhook-Signature")
        .or_else(|| headers.get("X-Hub-Signature-256"))
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("missing webhook signature header"))?;

    let sig_hex = sig_header
        .strip_prefix("sha256=")
        .ok_or_else(|| anyhow::anyhow!("X-Hub-Signature-256 does not start with sha256="))?;

    let sig_bytes =
        hex::decode(sig_hex).map_err(|e| anyhow::anyhow!("invalid hex in signature: {e}"))?;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| anyhow::anyhow!("HMAC key error: {e}"))?;
    mac.update(body);

    mac.verify_slice(&sig_bytes)
        .map_err(|_| anyhow::anyhow!("HMAC signature mismatch"))?;

    Ok(())
}

/// `membership` event: a user was added to or removed from a team.
async fn handle_membership(state: &AppState, payload: &serde_json::Value) {
    let org = payload
        .get("organization")
        .and_then(|o| o.get("login"))
        .and_then(|l| l.as_str())
        .unwrap_or("");

    if org.is_empty() {
        return;
    }

    invalidate_org_auth(state, org).await;
}

/// `team` event: team permissions or repos changed.
async fn handle_team(state: &AppState, payload: &serde_json::Value) {
    let org = payload
        .get("organization")
        .and_then(|o| o.get("login"))
        .and_then(|l| l.as_str())
        .unwrap_or("");

    if org.is_empty() {
        return;
    }

    invalidate_org_auth(state, org).await;
}

/// `organization` event: member added/removed from org.
async fn handle_organization(state: &AppState, payload: &serde_json::Value) {
    let org = payload
        .get("organization")
        .and_then(|o| o.get("login"))
        .and_then(|l| l.as_str())
        .unwrap_or("");

    if org.is_empty() {
        return;
    }

    invalidate_org_auth(state, org).await;
}

/// `repository` event: repo visibility, transfer, or access changes.
async fn handle_repository(state: &AppState, payload: &serde_json::Value) {
    let full_name = payload
        .get("repository")
        .and_then(|r| r.get("full_name"))
        .and_then(|n| n.as_str())
        .unwrap_or("");

    if full_name.is_empty() {
        return;
    }

    // Invalidate all auth entries for this specific repo.
    let http_pattern = format!("forgecache:http:auth:*:{full_name}");
    let ssh_pattern = format!("forgecache:ssh:access:*:{full_name}");

    let http_count = cache::invalidate_auth(&state.keydb, &http_pattern)
        .await
        .unwrap_or(0);
    let ssh_count = cache::invalidate_auth(&state.keydb, &ssh_pattern)
        .await
        .unwrap_or(0);

    info!(
        repo = %full_name,
        http_invalidated = http_count,
        ssh_invalidated = ssh_count,
        "invalidated auth cache for repository event"
    );
}

/// Invalidate all auth cache entries for an entire organization.
async fn invalidate_org_auth(state: &AppState, org: &str) {
    let http_pattern = format!("forgecache:http:auth:*:{org}/*");
    let ssh_pattern = format!("forgecache:ssh:access:*:{org}/*");

    let http_count = cache::invalidate_auth(&state.keydb, &http_pattern)
        .await
        .unwrap_or(0);
    let ssh_count = cache::invalidate_auth(&state.keydb, &ssh_pattern)
        .await
        .unwrap_or(0);

    info!(
        org = %org,
        http_invalidated = http_count,
        ssh_invalidated = ssh_count,
        "invalidated auth cache for org event"
    );
}
