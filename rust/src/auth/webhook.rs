//! Webhook receiver for cache invalidation and event processing.
//!
//! Validates the webhook signature via the [`ForgeBackend`] trait, parses the
//! event type, and invalidates the appropriate KeyDB auth cache entries so that
//! permission changes take effect without waiting for TTL expiry.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use tracing::{debug, info, warn};

use crate::AppState;
use crate::auth::cache;
use crate::forge::WebhookEvent;

/// Process an incoming webhook payload.
///
/// 1. Verify the signature via the forge backend.
/// 2. Parse the event type from forge-specific headers.
/// 3. Dispatch to cache-invalidation handlers.
pub async fn handle_webhook_payload(
    state: &AppState,
    headers: &HeaderMap,
    body: &Bytes,
) -> anyhow::Result<Response> {
    // 1. Verify signature.
    let secret = crate::credentials::keyring::resolve_secret(&state.config.auth.webhook_secret_env)
        .await
        .ok_or_else(|| anyhow::anyhow!("webhook secret not found in keyring or env"))?;

    if let Err(e) = state.forge.verify_webhook_signature(headers, body, &secret) {
        warn!(error = %e, "webhook signature verification failed");
        return Ok((StatusCode::UNAUTHORIZED, "invalid signature").into_response());
    }

    // 2. Extract event type.
    let event_type = state.forge.webhook_event_type(headers).unwrap_or_default();

    info!(event = %event_type, "processing webhook event");

    // 3. Parse body as JSON.
    let payload: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| anyhow::anyhow!("failed to parse webhook JSON: {e}"))?;

    // 4. Dispatch by parsed event.
    let event = state.forge.parse_webhook_payload(&event_type, &payload);

    match event {
        WebhookEvent::OrgChange { org } => invalidate_org_auth(state, &org).await,
        WebhookEvent::RepoChange { repo_full_name } => {
            invalidate_repo_auth(state, &repo_full_name).await
        }
        WebhookEvent::NoAction => {
            debug!(event = %event_type, "ignoring unhandled webhook event type");
        }
    }

    Ok(StatusCode::OK.into_response())
}

/// Invalidate all auth cache entries for a specific repository.
async fn invalidate_repo_auth(state: &AppState, full_name: &str) {
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
