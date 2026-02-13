//! Main axum router and HTTP request handlers for the caching proxy.
//!
//! Routes:
//! - `GET  /:owner/:repo/info/refs`       - Smart HTTP info/refs (upload-pack only)
//! - `POST /:owner/:repo/git-upload-pack`  - Pack negotiation / data transfer
//! - `POST /:owner/:repo/git-receive-pack` - Always rejected (403)
//! - `GET  /bundles/:owner/:repo/bundle-list` - Bundle-list for bundle-uri
//! - `POST /webhook`                       - GitHub webhook receiver
//! - `GET  /healthz`                       - Health check
//! - `GET  /metrics`                       - Prometheus metrics

use std::sync::Arc;

use anyhow::Context as _;
use axum::{
    Router,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bytes::Bytes;
use serde::Deserialize;
use tokio::process::Command;
use tokio_util::io::ReaderStream;
use tracing::{debug, error, info, instrument, warn};

use crate::AppState;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the axum [`Router`] with all HTTP routes and shared state.
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Git smart HTTP protocol endpoints
        .route("/{owner}/{repo}/info/refs", get(handle_info_refs))
        .route("/{owner}/{repo}/git-upload-pack", post(handle_upload_pack))
        .route(
            "/{owner}/{repo}/git-receive-pack",
            post(handle_receive_pack),
        )
        // Bundle-URI endpoint
        .route(
            "/bundles/{owner}/{repo}/bundle-list",
            get(handle_bundle_list),
        )
        // Archive pass-through
        .route(
            "/{owner}/{repo}/archive/{*rest}",
            get(super::archive::handle_archive),
        )
        // Webhook, health, metrics
        .route("/webhook", post(handle_webhook))
        .route("/healthz", get(handle_health))
        .route("/metrics", get(handle_metrics))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Query parameter types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct InfoRefsQuery {
    service: Option<String>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /:owner/:repo/info/refs?service=git-upload-pack`
///
/// Validates authentication, rejects pushes, and proxies info/refs from the
/// upstream forge.  For `git-upload-pack` requests the response is
/// intercepted so that we can inject the `bundle-uri` protocol-v2 capability.
#[instrument(skip(state, headers), fields(%owner, %repo))]
async fn handle_info_refs(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<InfoRefsQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // 1. Validate path segments.
    validate_path_segment(&owner, "owner")?;
    validate_path_segment(&repo, "repo")?;

    // 2. Extract and validate the Authorization header.
    let auth_header = extract_auth_header(&headers)?;
    crate::auth::http_validator::validate_http_auth(&state, &auth_header, &owner, &repo)
        .await
        .map_err(|e| {
            // If rate-limited, return 503 with Retry-After.
            let remaining = state.rate_limit.remaining();
            if remaining < state.config.upstream.api_rate_limit_buffer as u64
                && remaining != u64::MAX
            {
                let retry = state.rate_limit.retry_after_secs();
                warn!(error = %e, retry_after = retry, "auth failed due to rate limiting");
                return AppError::RateLimited {
                    retry_after_secs: retry,
                };
            }
            warn!(error = %e, "auth validation failed");
            AppError::Unauthorized(e.to_string())
        })?;

    let service = query.service.unwrap_or_default();
    if service == "git-receive-pack" {
        return Ok((
            StatusCode::FORBIDDEN,
            "Push (git-receive-pack) is not supported through the caching proxy",
        )
            .into_response());
    }

    if service != "git-upload-pack" {
        return Ok((
            StatusCode::BAD_REQUEST,
            format!("Unsupported service: {service}"),
        )
            .into_response());
    }

    // Proxy the info/refs request to the upstream forge.
    let upstream_url = format!(
        "https://{}/{}/{}/info/refs?service=git-upload-pack",
        state.config.upstream.hostname, owner, repo,
    );

    debug!(%upstream_url, "proxying info/refs to upstream forge");

    let upstream_resp = state
        .http_client
        .get(&upstream_url)
        .header(header::AUTHORIZATION, &auth_header)
        .header("Git-Protocol", "version=2")
        .send()
        .await
        .context("failed to reach upstream forge")?;

    if !upstream_resp.status().is_success() {
        let status = upstream_resp.status();
        let body = upstream_resp
            .text()
            .await
            .unwrap_or_else(|_| String::from("<unreadable>"));
        warn!(%status, "upstream forge returned error for info/refs");
        return Ok((
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            body,
        )
            .into_response());
    }

    // 4. Read the upstream body and inject bundle-uri capability.
    let upstream_bytes = upstream_resp
        .bytes()
        .await
        .context("failed to read upstream info/refs body")?;

    let bundle_list_url = format!(
        "{}/bundles/{}/{}/bundle-list",
        state.config.proxy.bundle_uri_base_url, owner, repo,
    );

    let modified_body =
        crate::http::protocolv2::inject_bundle_uri(&upstream_bytes, &bundle_list_url);

    // 5. Return the modified response.
    Ok((
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "application/x-git-upload-pack-advertisement",
        )],
        modified_body,
    )
        .into_response())
}

/// `POST /:owner/:repo/git-upload-pack`
///
/// If the repository is cached locally and fresh, runs a local `git upload-pack`
/// process.  Otherwise proxies the request to the upstream forge and spawns a
/// background task to clone the repo for future requests.
#[instrument(skip(state, headers, body), fields(%owner, %repo))]
async fn handle_upload_pack(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    // 1. Validate path segments.
    validate_path_segment(&owner, "owner")?;
    validate_path_segment(&repo, "repo")?;

    // 2. Validate auth.
    let auth_header = extract_auth_header(&headers)?;
    crate::auth::http_validator::validate_http_auth(&state, &auth_header, &owner, &repo)
        .await
        .map_err(|e| AppError::Unauthorized(e.to_string()))?;

    // Check if repo is cached locally and fresh.
    let repo_slug = format!("{}/{}", owner, repo);
    let cached = crate::coordination::registry::is_repo_cached_and_fresh(&state, &repo_slug)
        .await
        .unwrap_or(false);

    if cached {
        info!("serving upload-pack from local cache");
        return serve_local_upload_pack(&state, &owner, &repo, &body).await;
    }

    // Proxy to upstream forge.
    info!("proxying upload-pack to upstream forge");
    let response = proxy_upload_pack_to_upstream(&state, &owner, &repo, &auth_header, body).await?;

    // 4. Spawn background clone so future requests can be served locally.
    {
        let state = Arc::clone(&state);
        let owner = owner.clone();
        let repo = repo.clone();
        let auth = auth_header.clone();
        tokio::spawn(async move {
            if let Err(e) =
                crate::coordination::registry::ensure_repo_cloned(&state, &owner, &repo, &auth)
                    .await
            {
                warn!(
                    error = %e,
                    repo = %format!("{}/{}", owner, repo),
                    "background clone failed"
                );
            }
        });
    }

    Ok(response)
}

/// `POST /:owner/:repo/git-receive-pack`
///
/// Pushes are unconditionally rejected.  The proxy is read-only.
#[instrument(skip(_state, _headers))]
async fn handle_receive_pack(
    State(_state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    _headers: HeaderMap,
) -> Response {
    if validate_path_segment(&owner, "owner").is_err()
        || validate_path_segment(&repo, "repo").is_err()
    {
        return (StatusCode::UNAUTHORIZED, "invalid owner or repo").into_response();
    }

    warn!(%owner, %repo, "rejected git-receive-pack (push)");
    (
        StatusCode::FORBIDDEN,
        "Push (git-receive-pack) is not supported through the caching proxy.\n\
         Please push directly to the upstream forge.",
    )
        .into_response()
}

/// `GET /bundles/:owner/:repo/bundle-list`
///
/// Serves the Git bundle-list document with pre-signed S3 URLs.
#[instrument(skip(state, headers), fields(%owner, %repo))]
async fn handle_bundle_list(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    validate_path_segment(&owner, "owner")?;
    validate_path_segment(&repo, "repo")?;

    let auth_header = extract_auth_header(&headers)?;
    crate::http::bundle_serve::handle_bundle_list(&state, &owner, &repo, &auth_header)
        .await
        .map_err(AppError::Internal)
}

/// `POST /webhook`
///
/// Receives GitHub webhook payloads and forwards them to the auth/webhook
/// handler for cache invalidation and other side-effects.
#[instrument(skip(state, headers, body))]
async fn handle_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    crate::auth::webhook::handle_webhook_payload(&state, &headers, &body)
        .await
        .map_err(AppError::Internal)
}

/// `GET /healthz`
async fn handle_health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let health_state = crate::health::HealthState {
        config: Arc::clone(&state.config),
        keydb: state.keydb.clone(),
        http_client: state.http_client.clone(),
    };
    crate::health::health_handler(axum::extract::State(health_state)).await
}

/// `GET /metrics`
///
/// Returns Prometheus metrics collected by the proxy.
async fn handle_metrics(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    let mut buf = String::new();
    prometheus_client::encoding::text::encode(&mut buf, &state.metrics.registry)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("metrics encoding failed: {e}")))?;

    Ok((
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )],
        buf,
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Validate that an owner or repo path segment is safe (no path traversal).
///
/// Rejects segments containing `..`, `/`, `\`, null bytes, or that are empty.
pub(crate) fn validate_path_segment(segment: &str, label: &str) -> Result<(), AppError> {
    if segment.is_empty() {
        return Err(AppError::Unauthorized(format!("{label} must not be empty")));
    }
    if segment.contains('/')
        || segment.contains('\\')
        || segment.contains('\0')
        || segment == ".."
        || segment.starts_with("../")
        || segment.ends_with("/..")
        || segment.contains("/../")
    {
        return Err(AppError::Unauthorized(format!(
            "invalid {label}: {segment:?}"
        )));
    }
    Ok(())
}

/// Extract the `Authorization` header value, returning an error if absent.
pub(crate) fn extract_auth_header(headers: &HeaderMap) -> Result<String, AppError> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
        .ok_or_else(|| AppError::Unauthorized("missing Authorization header".into()))
}

/// Run a local `git upload-pack` process and stream its output as the HTTP
/// response body.
async fn serve_local_upload_pack(
    state: &AppState,
    owner: &str,
    repo: &str,
    request_body: &[u8],
) -> Result<Response, AppError> {
    let repo_path = state.cache_manager.repo_path(&format!("{owner}/{repo}"));

    let mut child = Command::new("git")
        .arg("upload-pack")
        .arg("--stateless-rpc")
        .arg(&repo_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn git upload-pack")?;

    // Write the request body to stdin.
    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(request_body).await.ok();
        // Drop stdin to signal EOF.
    }

    let stdout = child
        .stdout
        .take()
        .context("failed to capture git upload-pack stdout")?;

    // Stream stdout as the response body.
    let stream = ReaderStream::new(stdout);
    let body = Body::from_stream(stream);

    // Reap the child in the background so we don't leak processes.
    tokio::spawn(async move {
        match child.wait().await {
            Ok(status) if !status.success() => {
                warn!(%status, "git upload-pack exited with non-zero status");
            }
            Err(e) => {
                error!(error = %e, "failed to wait on git upload-pack");
            }
            _ => {}
        }
    });

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/x-git-upload-pack-result")],
        body,
    )
        .into_response())
}

/// Proxy a `git-upload-pack` POST to the upstream forge and stream the response.
async fn proxy_upload_pack_to_upstream(
    state: &AppState,
    owner: &str,
    repo: &str,
    auth_header: &str,
    body: Bytes,
) -> Result<Response, AppError> {
    let upstream_url = format!(
        "https://{}/{}/{}/git-upload-pack",
        state.config.upstream.hostname, owner, repo,
    );

    let upstream_resp = state
        .http_client
        .post(&upstream_url)
        .header(header::AUTHORIZATION, auth_header)
        .header(
            header::CONTENT_TYPE,
            "application/x-git-upload-pack-request",
        )
        .header("Git-Protocol", "version=2")
        .body(body)
        .send()
        .await
        .context("failed to reach upstream forge for upload-pack")?;

    if !upstream_resp.status().is_success() {
        let status = upstream_resp.status();
        let text = upstream_resp
            .text()
            .await
            .unwrap_or_else(|_| String::from("<unreadable>"));
        return Ok((
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            text,
        )
            .into_response());
    }

    // Stream the upstream body back to the client without buffering.
    let byte_stream = upstream_resp.bytes_stream();
    let body = Body::from_stream(byte_stream);

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/x-git-upload-pack-result")],
        body,
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Application-level error type that maps cleanly to HTTP responses.
#[derive(Debug)]
pub enum AppError {
    /// The caller is not authenticated or not authorised.
    Unauthorized(String),
    /// Upstream rate limit reached — include `Retry-After` header.
    RateLimited { retry_after_secs: u64 },
    /// An unexpected internal error.
    Internal(anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Unauthorized(msg) => (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Basic realm=\"forgecache\"")],
                msg,
            )
                .into_response(),
            AppError::RateLimited { retry_after_secs } => (
                StatusCode::SERVICE_UNAVAILABLE,
                [(
                    "Retry-After",
                    retry_after_secs.to_string().as_str().to_owned(),
                )],
                "Upstream API rate limit reached. Please retry later.\n",
            )
                .into_response(),
            AppError::Internal(err) => {
                error!(error = %err, "internal server error");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error\n").into_response()
            }
        }
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::Internal(err)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_path_segment_rejects_empty() {
        assert!(validate_path_segment("", "owner").is_err());
    }

    #[test]
    fn validate_path_segment_rejects_dotdot() {
        assert!(validate_path_segment("..", "owner").is_err());
    }

    #[test]
    fn validate_path_segment_rejects_dotdot_prefix() {
        assert!(validate_path_segment("../etc", "owner").is_err());
    }

    #[test]
    fn validate_path_segment_rejects_dotdot_suffix() {
        assert!(validate_path_segment("foo/..", "owner").is_err());
    }

    #[test]
    fn validate_path_segment_rejects_dotdot_middle() {
        assert!(validate_path_segment("foo/../bar", "owner").is_err());
    }

    #[test]
    fn validate_path_segment_rejects_slash() {
        assert!(validate_path_segment("foo/bar", "owner").is_err());
    }

    #[test]
    fn validate_path_segment_rejects_backslash() {
        assert!(validate_path_segment("foo\\bar", "owner").is_err());
    }

    #[test]
    fn validate_path_segment_rejects_null_byte() {
        assert!(validate_path_segment("foo\0bar", "owner").is_err());
    }

    #[test]
    fn validate_path_segment_accepts_normal_names() {
        assert!(validate_path_segment("acme-corp", "owner").is_ok());
        assert!(validate_path_segment("my_repo.v2", "repo").is_ok());
        assert!(validate_path_segment("123", "owner").is_ok());
        assert!(validate_path_segment("a", "owner").is_ok());
    }

    #[test]
    fn validate_path_segment_accepts_dots_that_are_not_traversal() {
        assert!(validate_path_segment(".", "owner").is_ok());
        assert!(validate_path_segment(".hidden", "owner").is_ok());
        assert!(validate_path_segment("name.git", "repo").is_ok());
    }
}
