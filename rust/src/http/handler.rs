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
use futures::{Stream, StreamExt};
use serde::Deserialize;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::ReaderStream;
use tracing::{debug, error, info, instrument, warn};

use crate::AppState;
use crate::coordination::registry::{
    LocalServeDecision, LocalServeRepoLease, LocalServeRepoSource,
};

struct LeasedReaderStream<S> {
    inner: S,
    lease: Option<LocalServeRepoLease>,
}

impl<S> LeasedReaderStream<S> {
    fn new(inner: S, lease: LocalServeRepoLease) -> Self {
        Self {
            inner,
            lease: Some(lease),
        }
    }
}

impl<S> Stream for LeasedReaderStream<S>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Unpin,
{
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let poll = Pin::new(&mut self.inner).poll_next(cx);
        if matches!(poll, Poll::Ready(None)) {
            self.lease.take();
        }
        poll
    }
}

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

    // 2. Validate auth (optional for public repos).
    let auth_header = extract_optional_auth_header(&headers);
    crate::auth::http_validator::validate_http_auth(&state, auth_header.as_deref(), &owner, &repo)
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

    let mut upstream_req = state
        .http_client
        .get(&upstream_url)
        .header("Git-Protocol", "version=2");
    if let Some(header) = auth_header.as_deref() {
        upstream_req = upstream_req.header(header::AUTHORIZATION, header);
    }
    let upstream_resp = upstream_req
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

    state.recent_info_refs_advertisements.lock().await.insert(
        format!("{owner}/{repo}"),
        crate::RecentInfoRefsAdvertisement {
            captured_at: std::time::Instant::now(),
            payload: upstream_bytes.to_vec(),
        },
    );

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
/// If the repository is cached locally and contains the requested objects,
/// runs a local `git upload-pack` process. Otherwise proxies the request to
/// the upstream forge and spawns a background task to clone the repo for
/// future requests.
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

    // 2. Validate auth (optional for public repos).
    let auth_header = extract_optional_auth_header(&headers);
    crate::auth::http_validator::validate_http_auth(&state, auth_header.as_deref(), &owner, &repo)
        .await
        .map_err(|e| AppError::Unauthorized(e.to_string()))?;

    let repo_slug = format!("{}/{}", owner, repo);
    let git_protocol = headers
        .get("Git-Protocol")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let wants = crate::tee_hydration::parse_fetch_request_metadata(&body)
        .map(|meta| meta.want_oids)
        .unwrap_or_default();
    let want_sample = wants
        .iter()
        .take(5)
        .map(|want| want.chars().take(12).collect::<String>())
        .collect::<Vec<String>>()
        .join(",");
    let initial_local_decision =
        match crate::coordination::registry::classify_local_wants_satisfaction(
            &state, &repo_slug, &wants,
        )
        .await
        {
            Ok(decision) => decision,
            Err(error) => {
                warn!(
                    repo = %repo_slug,
                    wants = wants.len(),
                    want_sample,
                    error = %error,
                    "failed to classify local upload-pack serveability; proxying upstream"
                );
                LocalServeDecision::Unavailable {
                    had_local_repo_before_check: state.cache_manager.has_repo(&repo_slug),
                    restored_from_s3_for_request: false,
                }
            }
        };
    let local_decision = if matches!(
        initial_local_decision,
        LocalServeDecision::MissingWantedObjects { .. }
    ) {
        match crate::coordination::registry::wait_for_local_catch_up(
            &state,
            &owner,
            &repo,
            auth_header.as_deref(),
            &wants,
        )
        .await
        {
            Ok(decision) => decision,
            Err(error) => {
                warn!(
                    repo = %repo_slug,
                    wants = wants.len(),
                    want_sample,
                    error = %error,
                    "failed while waiting for local upload-pack catch-up; proxying upstream"
                );
                initial_local_decision
            }
        }
    } else {
        initial_local_decision
    };

    match &local_decision {
        LocalServeDecision::SatisfiesWants {
            serve_from,
            restored_from_s3_for_request,
            want_count,
            ..
        } => {
            info!(
                repo = %repo_slug,
                serve_from = ?serve_from,
                wants = *want_count,
                want_sample,
                restored_from_s3_for_request = *restored_from_s3_for_request,
                "serving upload-pack directly from local disk"
            );
            return serve_local_upload_pack(
                &state,
                &owner,
                &repo,
                *serve_from,
                &body,
                git_protocol.as_deref(),
            )
            .await;
        }
        LocalServeDecision::Unavailable {
            had_local_repo_before_check,
            restored_from_s3_for_request,
        } => {
            info!(
                repo = %repo_slug,
                wants = wants.len(),
                want_sample,
                had_local_repo_before_check = *had_local_repo_before_check,
                restored_from_s3_for_request = *restored_from_s3_for_request,
                "cannot serve upload-pack from local disk; no local published repo or request-time S3 restore is available"
            );
        }
        LocalServeDecision::MissingWantedObjects {
            had_local_repo_before_check,
            restored_from_s3_for_request,
            want_count,
            missing_wants,
        } => {
            let missing_sample = missing_wants
                .iter()
                .take(5)
                .map(|want| want.chars().take(12).collect::<String>())
                .collect::<Vec<String>>()
                .join(",");
            info!(
                repo = %repo_slug,
                wants = *want_count,
                missing_wants = missing_wants.len(),
                want_sample,
                missing_sample,
                had_local_repo_before_check = *had_local_repo_before_check,
                restored_from_s3_for_request = *restored_from_s3_for_request,
                "local disk can only partially satisfy upload-pack request; proxying upstream for missing objects or completeness"
            );
        }
    }

    // Proxy to upstream forge.
    info!(repo = %repo_slug, "proxying upload-pack to upstream forge");
    let response =
        proxy_upload_pack_to_upstream(&state, &owner, &repo, auth_header.as_deref(), body).await?;

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

    let auth_header = extract_optional_auth_header(&headers);
    crate::http::bundle_serve::handle_bundle_list(&state, &owner, &repo, auth_header.as_deref())
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
        valkey: state.valkey.clone(),
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

/// Extract the `Authorization` header value when present.
pub(crate) fn extract_optional_auth_header(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned)
}

/// Run a local `git upload-pack` process and stream its output as the HTTP
/// response body.
async fn serve_local_upload_pack(
    state: &AppState,
    owner: &str,
    repo: &str,
    serve_from: LocalServeRepoSource,
    request_body: &[u8],
    git_protocol: Option<&str>,
) -> Result<Response, AppError> {
    let owner_repo = format!("{owner}/{repo}");
    let repo_lease = crate::coordination::registry::acquire_local_serve_repo_lease(
        state,
        &owner_repo,
        serve_from,
    )
    .await?;
    let repo_path = repo_lease.repo_path().to_path_buf();

    let mut cmd = Command::new("git");
    cmd.arg("upload-pack")
        .arg("--stateless-rpc")
        .arg("--strict")
        .arg(&repo_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(proto) = git_protocol {
        cmd.env("GIT_PROTOCOL", proto);
    }

    let mut child = cmd.spawn().context("failed to spawn git upload-pack")?;

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
    let mut stderr = child
        .stderr
        .take()
        .context("failed to capture git upload-pack stderr")?;

    // Stream stdout as the response body.
    let stream = LeasedReaderStream::new(ReaderStream::new(stdout), repo_lease);
    let body = Body::from_stream(stream);

    // Reap the child in the background so we don't leak processes.
    tokio::spawn(async move {
        use tokio::io::AsyncReadExt;

        let mut stderr_buf = Vec::new();
        let _ = stderr.read_to_end(&mut stderr_buf).await;
        match child.wait().await {
            Ok(status) if !status.success() => {
                warn!(
                    %status,
                    stderr = %String::from_utf8_lossy(&stderr_buf),
                    "git upload-pack exited with non-zero status"
                );
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
    auth_header: Option<&str>,
    body: Bytes,
) -> Result<Response, AppError> {
    let upstream_url = format!(
        "https://{}/{}/{}/git-upload-pack",
        state.config.upstream.hostname, owner, repo,
    );

    let mut req = state.http_client.post(&upstream_url).header(
        header::CONTENT_TYPE,
        "application/x-git-upload-pack-request",
    );
    if let Some(header) = auth_header {
        req = req.header(header::AUTHORIZATION, header);
    }
    let capture_body = body.clone();
    let upstream_resp = req
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
        let owner_repo = format!("{owner}/{repo}");
        let wants = crate::tee_hydration::parse_fetch_request_metadata(&capture_body)
            .map(|meta| meta.want_oids)
            .unwrap_or_default();
        let want_sample = wants
            .iter()
            .take(5)
            .map(|want| want.chars().take(12).collect::<String>())
            .collect::<Vec<String>>()
            .join(",");
        error!(
            repo = %owner_repo,
            status = %status,
            wants = wants.len(),
            want_sample,
            "cannot satisfy HTTP upload-pack request from local disk and upstream upload-pack failed"
        );
        return Ok((
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            text,
        )
            .into_response());
    }

    let owner_repo = format!("{owner}/{repo}");
    let mut hydration_permits =
        match crate::coordination::registry::try_acquire_clone_hydration_permits(state, &owner_repo)
            .await
        {
            Ok(Some(permits)) => Some(permits),
            Ok(None) => {
                info!(
                    repo = %owner_repo,
                    per_instance_limit = state.config.clone.max_concurrent_upstream_clones_per_repo_per_instance,
                    cross_instance_limit = state.config.clone.max_concurrent_upstream_clones_per_repo_across_instances,
                    lease_ttl_secs = state.config.clone.lock_ttl,
                    "skipping tee hydration because the repo clone semaphore is saturated"
                );
                None
            }
            Err(e) => {
                warn!(
                    repo = %owner_repo,
                    error = %e,
                    "failed to acquire clone hydration permits for HTTP miss"
                );
                None
            }
        };

    let mut capture = if hydration_permits.is_some() {
        match crate::tee_hydration::TeeCapture::start(
            &state.cache_manager.base_path,
            &owner_repo,
            "https",
        )
        .await
        {
            Ok(capture) => Some(capture),
            Err(e) => {
                warn!(repo = %owner_repo, error = %e, "failed to start tee capture for HTTP miss");
                None
            }
        }
    } else {
        None
    };

    if let Some(active_capture) = capture.as_ref() {
        let recent_info_refs = state
            .recent_info_refs_advertisements
            .lock()
            .await
            .get(&owner_repo)
            .cloned();
        if let Some(recent_info_refs) = recent_info_refs
            && recent_info_refs.captured_at.elapsed() <= std::time::Duration::from_secs(60)
            && let Err(e) = active_capture
                .write_info_refs_advertisement(&recent_info_refs.payload)
                .await
        {
            warn!(
                repo = %owner_repo,
                error = %e,
                "failed to record recent HTTP info/refs advertisement in tee capture"
            );
        }
    }

    let request_capture_failed = if let Some(active_capture) = capture.as_mut() {
        if let Err(e) = active_capture.write_request(&capture_body).await {
            warn!(repo = %owner_repo, error = %e, "failed to record HTTP tee request");
            true
        } else {
            false
        }
    } else {
        false
    };
    if request_capture_failed {
        capture = None;
    }
    let capture = capture.map(crate::tee_hydration::BufferedTeeCapture::new);
    if capture.is_none()
        && let Some(permits) = hydration_permits.take()
        && let Err(e) =
            crate::coordination::registry::release_clone_hydration_permits(state, permits).await
    {
        warn!(
            repo = %owner_repo,
            error = %e,
            "failed to release clone hydration permits after HTTP tee capture setup failure"
        );
    }

    let (tx, rx) = mpsc::channel::<Result<Bytes, reqwest::Error>>(8);
    let state = state.clone();
    let owner = owner.to_string();
    let repo = repo.to_string();
    let auth_header = auth_header.map(str::to_string);
    tokio::spawn(async move {
        let mut stream = upstream_resp.bytes_stream();
        let mut capture = capture;
        let mut hydration_permits = hydration_permits;

        while let Some(item) = stream.next().await {
            match item {
                Ok(chunk) => {
                    if let Some(mut active_capture) = capture.take() {
                        if let Err(e) = active_capture.try_write_response_chunk(chunk.clone()) {
                            warn!(
                                repo = %owner_repo,
                                error = %e,
                                buffer_bytes = crate::tee_hydration::CAPTURE_BUFFER_BYTES,
                                "dropping HTTP tee capture because disk capture fell behind the client stream"
                            );
                            if let Err(cleanup_error) = active_capture.abort().await {
                                warn!(
                                    repo = %owner_repo,
                                    error = %cleanup_error,
                                    "failed to clean up aborted HTTP tee capture"
                                );
                            }
                        } else {
                            capture = Some(active_capture);
                        }
                    }

                    if tx.send(Ok(chunk)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    if let Some(active_capture) = capture.take()
                        && let Err(cleanup_error) = active_capture.abort().await
                    {
                        warn!(
                            repo = %owner_repo,
                            error = %cleanup_error,
                            "failed to clean up aborted HTTP tee capture after proxy error"
                        );
                    }
                    if let Some(permits) = hydration_permits.take()
                        && let Err(release_error) =
                            crate::coordination::registry::release_clone_hydration_permits(
                                &state, permits,
                            )
                            .await
                    {
                        warn!(
                            repo = %owner_repo,
                            error = %release_error,
                            "failed to release clone hydration permits after HTTP proxy error"
                        );
                    }
                    let _ = tx.send(Err(e)).await;
                    return;
                }
            }
        }

        if let Some(active_capture) = capture {
            match active_capture.finish_success().await {
                Ok(Some(capture_dir)) => {
                    let state_bg = state.clone();
                    let owner_bg = owner.clone();
                    let repo_bg = repo.clone();
                    let owner_repo_bg = owner_repo.clone();
                    let auth_bg = auth_header.clone();
                    if let Some(permits) = hydration_permits.take() {
                        tokio::spawn(async move {
                            if let Err(e) =
                                crate::coordination::registry::try_ensure_repo_cloned_from_tee_with_permits(
                                    &state_bg,
                                    &owner_bg,
                                    &repo_bg,
                                    auth_bg.as_deref(),
                                    capture_dir,
                                    permits,
                                )
                                .await
                            {
                                warn!(
                                    repo = %owner_repo_bg,
                                    error = %e,
                                    error_chain = %format!("{e:#}"),
                                    "tee hydration after HTTP miss failed"
                                );
                            }
                        });
                    } else {
                        tokio::spawn(async move {
                            if let Err(e) =
                                crate::coordination::registry::try_ensure_repo_cloned_from_tee(
                                    &state_bg,
                                    &owner_bg,
                                    &repo_bg,
                                    auth_bg.as_deref(),
                                    capture_dir,
                                )
                                .await
                            {
                                warn!(
                                    repo = %owner_repo_bg,
                                    error = %e,
                                    error_chain = %format!("{e:#}"),
                                    "tee hydration after HTTP miss failed"
                                );
                            }
                        });
                    }
                }
                Ok(None) => {
                    if let Some(permits) = hydration_permits.take()
                        && let Err(release_error) =
                            crate::coordination::registry::release_clone_hydration_permits(
                                &state, permits,
                            )
                            .await
                    {
                        warn!(
                            repo = %owner_repo,
                            error = %release_error,
                            "failed to release clone hydration permits after dropping HTTP tee capture"
                        );
                    }
                    let state_bg = state.clone();
                    let owner_bg = owner.clone();
                    let repo_bg = repo.clone();
                    let owner_repo_bg = owner_repo.clone();
                    let auth_bg = auth_header.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            crate::coordination::registry::ensure_repo_cloned_from_upstream(
                                &state_bg,
                                &owner_bg,
                                &repo_bg,
                                auth_bg.as_deref(),
                            )
                            .await
                        {
                            warn!(
                                repo = %owner_repo_bg,
                                error = %e,
                                error_chain = %format!("{e:#}"),
                                "background upstream hydration after HTTP miss completed without tee capture failed"
                            );
                        }
                    });
                }
                Err(error) => {
                    warn!(
                        repo = %owner_repo,
                        error = %error,
                        "failed to finalize buffered HTTP tee capture"
                    );
                    if let Some(permits) = hydration_permits.take()
                        && let Err(release_error) =
                            crate::coordination::registry::release_clone_hydration_permits(
                                &state, permits,
                            )
                            .await
                    {
                        warn!(
                            repo = %owner_repo,
                            error = %release_error,
                            "failed to release clone hydration permits after HTTP tee finalization failure"
                        );
                    }
                    let state_bg = state.clone();
                    let owner_bg = owner.clone();
                    let repo_bg = repo.clone();
                    let owner_repo_bg = owner_repo.clone();
                    let auth_bg = auth_header.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            crate::coordination::registry::ensure_repo_cloned_from_upstream(
                                &state_bg,
                                &owner_bg,
                                &repo_bg,
                                auth_bg.as_deref(),
                            )
                            .await
                        {
                            warn!(
                                repo = %owner_repo_bg,
                                error = %e,
                                error_chain = %format!("{e:#}"),
                                "background upstream hydration after HTTP tee finalization failure failed"
                            );
                        }
                    });
                }
            }
        } else {
            let state_bg = state.clone();
            let owner_bg = owner.clone();
            let repo_bg = repo.clone();
            let owner_repo_bg = owner_repo.clone();
            let auth_bg = auth_header.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::coordination::registry::ensure_repo_cloned_from_upstream(
                    &state_bg,
                    &owner_bg,
                    &repo_bg,
                    auth_bg.as_deref(),
                )
                .await
                {
                    warn!(
                        repo = %owner_repo_bg,
                        error = %e,
                        error_chain = %format!("{e:#}"),
                        "background upstream hydration after HTTP miss completed without tee capture failed"
                    );
                }
            });
        }
    });

    let body = Body::from_stream(ReceiverStream::new(rx));

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
                [(header::WWW_AUTHENTICATE, "Basic realm=\"forgeproxy\"")],
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
                error!(error = %format!("{err:#}"), "internal server error");
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
