//! Main axum router and HTTP request handlers for the caching proxy.
//!
//! Routes:
//! - `GET  /:owner/:repo/info/refs`       - Smart HTTP info/refs (upload-pack only)
//! - `POST /:owner/:repo/git-upload-pack`  - Pack negotiation / data transfer
//! - `POST /:owner/:repo/git-receive-pack` - Always rejected (403)
//! - `GET  /bundles/:owner/:repo/bundle-list` - Bundle-list for bundle-uri
//! - `POST /webhook`                       - GitHub webhook receiver
//! - `GET  /healthz`                       - Liveness check
//! - `GET  /readyz`                        - Readiness check
//! - `GET  /metrics`                       - Prometheus metrics

use std::sync::Arc;
use std::time::Instant;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use anyhow::Context as _;
use axum::{
    Router,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bytes::Bytes;
use futures::{Stream, StreamExt};
use prometheus_client::metrics::counter::Counter;
use serde::Deserialize;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::ReaderStream;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::AppState;
use crate::clone_support::{
    CloneCompletion, LocalUploadPackMode, UpstreamHydrationRequest, UpstreamHydrationTracker,
    spawn_local_upload_pack, wait_for_local_upload_pack_exit,
};
use crate::coordination::registry::{
    LocalServeDecision, LocalServeRepoLease, LocalServeRepoSource,
};
use crate::metrics::{
    CacheStatus, CloneDownstreamBytesLabels, ClonePhase, CloneSource, CloneUpstreamBytesLabels,
    Protocol,
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

struct CountingBytesStream<S> {
    inner: S,
    counter: Counter,
}

impl<S> CountingBytesStream<S> {
    fn new(inner: S, counter: Counter) -> Self {
        Self { inner, counter }
    }
}

impl<S, E> Stream for CountingBytesStream<S>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
{
    type Item = Result<Bytes, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let poll = Pin::new(&mut self.inner).poll_next(cx);
        if let Poll::Ready(Some(Ok(bytes))) = &poll {
            self.counter.inc_by(bytes.len() as u64);
        }
        poll
    }
}

struct CloneCompletionStream<S> {
    inner: S,
    metrics: crate::metrics::MetricsRegistry,
    protocol: Protocol,
    completion: CloneCompletion,
    recorded: bool,
}

impl<S> CloneCompletionStream<S> {
    fn new(
        inner: S,
        metrics: crate::metrics::MetricsRegistry,
        protocol: Protocol,
        completion: CloneCompletion,
    ) -> Self {
        Self {
            inner,
            metrics,
            protocol,
            completion,
            recorded: false,
        }
    }

    fn record_once(&mut self) {
        if self.recorded {
            return;
        }
        self.recorded = true;
        self.completion
            .record_success(&self.metrics, self.protocol.clone());
    }
}

impl<S, E> Stream for CloneCompletionStream<S>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
{
    type Item = Result<Bytes, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let poll = Pin::new(&mut self.inner).poll_next(cx);
        if matches!(poll, Poll::Ready(None)) {
            self.record_once();
        }
        poll
    }
}

impl<S> Drop for CloneCompletionStream<S> {
    fn drop(&mut self) {
        self.record_once();
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
        .route("/readyz", get(handle_ready))
        .route("/metrics", get(handle_metrics))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            reject_new_requests_while_draining,
        ))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Query parameter types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct InfoRefsQuery {
    service: Option<String>,
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
}

fn http_git_client_fingerprint(
    headers: &HeaderMap,
    metric_username: &str,
    owner: &str,
    repo: &str,
) -> String {
    let forwarded_for = header_value(headers, "x-forwarded-for").unwrap_or("");
    let real_ip = header_value(headers, "x-real-ip").unwrap_or("");
    let user_agent = header_value(headers, "user-agent").unwrap_or("");
    let git_protocol = header_value(headers, "Git-Protocol").unwrap_or("");

    let mut hasher = DefaultHasher::new();
    owner.hash(&mut hasher);
    repo.hash(&mut hasher);
    metric_username.hash(&mut hasher);
    forwarded_for.hash(&mut hasher);
    real_ip.hash(&mut hasher);
    user_agent.hash(&mut hasher);
    git_protocol.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn request_scheme(headers: &HeaderMap) -> &str {
    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("http")
}

fn request_host(headers: &HeaderMap) -> Result<&str, AppError> {
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::BadRequest("missing Host header".to_string()))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /:owner/:repo/info/refs?service=git-upload-pack`
///
/// Rejects pushes, proxies `info/refs` from the upstream forge, and only
/// rewrites successful `git-upload-pack` advertisements to inject the
/// `bundle-uri` protocol-v2 capability. Upstream authentication challenges
/// and non-success responses are forwarded transparently.
///
/// For `git-upload-pack` requests the response is
/// intercepted so that we can inject the `bundle-uri` protocol-v2 capability.
#[instrument(
    skip(state, headers),
    fields(
        %owner,
        %repo,
        git_request_id = tracing::field::Empty,
        git_session_id = tracing::field::Empty,
        git_phase = tracing::field::Empty,
        client_fingerprint = tracing::field::Empty,
    )
)]
async fn handle_info_refs(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<InfoRefsQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let _active_connection = state.begin_active_connection(Protocol::Https);
    // 1. Validate path segments.
    validate_path_segment(&owner, "owner")?;
    validate_path_segment(&repo, "repo")?;

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

    let auth_header = extract_optional_auth_header(&headers);
    let metric_username = crate::auth::http_validator::metric_username_for_http_request(
        &state,
        auth_header.as_deref(),
    )
    .await;
    let client_fingerprint = http_git_client_fingerprint(&headers, &metric_username, &owner, &repo);
    let git_request_id = format!("http-{}", Uuid::new_v4().simple());
    let git_session_id = format!("http-{}", Uuid::new_v4().simple());
    let span = tracing::Span::current();
    span.record("git_request_id", tracing::field::display(&git_request_id));
    span.record("git_session_id", tracing::field::display(&git_session_id));
    span.record("git_phase", tracing::field::display("info-refs"));
    span.record(
        "client_fingerprint",
        tracing::field::display(&client_fingerprint),
    );

    // Proxy the info/refs request to the upstream forge.
    let upstream_url = format!(
        "https://{}/{}/{}/info/refs?service=git-upload-pack",
        state.config.upstream.hostname, owner, repo,
    );

    debug!(%upstream_url, "proxying info/refs to upstream forge");

    let upstream_req =
        apply_forwarded_request_headers(state.http_client.get(&upstream_url), &headers);
    let upstream_resp = upstream_req
        .send()
        .await
        .context("failed to reach upstream forge")?;

    if !upstream_resp.status().is_success() {
        let status = upstream_resp.status();
        warn!(%status, "upstream forge returned error for info/refs");
        return forward_upstream_response(upstream_resp).await;
    }

    let status = upstream_resp.status();
    let forwarded_headers = collect_forwarded_response_headers(upstream_resp.headers());

    // 4. Read the upstream body and inject bundle-uri capability.
    let upstream_bytes = upstream_resp
        .bytes()
        .await
        .context("failed to read upstream info/refs body")?;

    let bundle_list_url = format!(
        "{}://{}/bundles/{}/{}/bundle-list",
        request_scheme(&headers),
        request_host(&headers)?,
        owner,
        repo,
    );

    let modified_body =
        crate::http::protocolv2::inject_bundle_uri(&upstream_bytes, &bundle_list_url);

    state
        .metrics
        .metrics
        .clone_upstream_bytes
        .get_or_create(&CloneUpstreamBytesLabels {
            protocol: Protocol::Https,
            phase: ClonePhase::InfoRefs,
            username: metric_username.clone(),
            repo: format!("{owner}/{repo}"),
        })
        .inc_by(upstream_bytes.len() as u64);
    state
        .metrics
        .metrics
        .clone_downstream_bytes
        .get_or_create(&CloneDownstreamBytesLabels {
            protocol: Protocol::Https,
            phase: ClonePhase::InfoRefs,
            source: CloneSource::Upstream,
            username: metric_username,
            repo: format!("{owner}/{repo}"),
        })
        .inc_by(modified_body.len() as u64);

    state
        .remember_recent_advertised_refs(
            format!("{owner}/{repo}"),
            &client_fingerprint,
            &git_session_id,
            crate::coordination::registry::RequestAdvertisedRefs {
                info_refs_advertisement: Some(upstream_bytes.to_vec()),
                ..Default::default()
            },
        )
        .await;

    // 5. Return the modified response.
    Ok(response_from_upstream_parts(
        status,
        forwarded_headers,
        Body::from(modified_body),
    ))
}

/// `POST /:owner/:repo/git-upload-pack`
///
/// If the repository is cached locally and contains the requested objects,
/// runs a local `git upload-pack` process after a lightweight upstream
/// read-access probe confirms the presented client credentials may clone the
/// repo. Otherwise it proxies the request to the upstream forge and preserves
/// the upstream HTTP response semantics.
#[instrument(
    skip(state, headers, body),
    fields(
        %owner,
        %repo,
        git_request_id = tracing::field::Empty,
        git_session_id = tracing::field::Empty,
        git_phase = tracing::field::Empty,
        client_fingerprint = tracing::field::Empty,
        client_session_id = tracing::field::Empty,
        git_client_agent = tracing::field::Empty,
    )
)]
async fn handle_upload_pack(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let _active_connection = state.begin_active_connection(Protocol::Https);
    let started_at = Instant::now();
    // 1. Validate path segments.
    validate_path_segment(&owner, "owner")?;
    validate_path_segment(&repo, "repo")?;

    let auth_header = extract_optional_auth_header(&headers);
    let metric_username = crate::auth::http_validator::metric_username_for_http_request(
        &state,
        auth_header.as_deref(),
    )
    .await;

    let repo_slug = format!("{}/{}", owner, repo);
    let git_protocol = headers
        .get("Git-Protocol")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let request_metadata =
        crate::tee_hydration::parse_upload_pack_request_metadata(&body, git_protocol.as_deref())
            .unwrap_or_default();
    let wants = request_metadata.want_oids.clone();
    let want_sample = wants
        .iter()
        .take(5)
        .map(|want| want.chars().take(12).collect::<String>())
        .collect::<Vec<String>>()
        .join(",");
    let local_authz_confirmed =
        local_http_clone_access_confirmed(&state, auth_header.as_deref(), &owner, &repo).await;
    let client_fingerprint = http_git_client_fingerprint(&headers, &metric_username, &owner, &repo);
    let recent_advertised_refs = state
        .recent_advertised_refs(&repo_slug, &client_fingerprint)
        .await;
    let advertised_refs = recent_advertised_refs
        .as_ref()
        .map(|recent| recent.advertised_refs.clone());
    let git_request_id = format!("http-{}", Uuid::new_v4().simple());
    let git_session_id = recent_advertised_refs
        .as_ref()
        .map(|recent| recent.session_id.clone())
        .unwrap_or_else(|| format!("http-{}", Uuid::new_v4().simple()));
    let request_phase = request_metadata.request_phase.to_string();
    let span = tracing::Span::current();
    span.record("git_request_id", tracing::field::display(&git_request_id));
    span.record("git_session_id", tracing::field::display(&git_session_id));
    span.record("git_phase", tracing::field::display(&request_phase));
    span.record(
        "client_fingerprint",
        tracing::field::display(&client_fingerprint),
    );
    span.record(
        "client_session_id",
        tracing::field::display(request_metadata.client_session_id.as_deref().unwrap_or("")),
    );
    span.record(
        "git_client_agent",
        tracing::field::display(request_metadata.agent.as_deref().unwrap_or("")),
    );
    info!(
        repo = %repo_slug,
        wants = wants.len(),
        want_sample,
        "received git-upload-pack request"
    );
    let local_decision = crate::coordination::registry::resolve_local_fetch_serveability(
        &state,
        &repo_slug,
        &wants,
        auth_header.as_deref(),
        advertised_refs.as_ref(),
        "http",
        local_authz_confirmed,
    )
    .await;
    let effective_cache_status = if local_authz_confirmed {
        crate::coordination::registry::clone_cache_status(&local_decision)
    } else {
        CacheStatus::Cold
    };
    let expects_local_pack_serve = request_metadata.request_phase.expects_local_pack_serve();

    if !local_authz_confirmed {
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
                    "skipping local upload-pack serve because presented HTTP auth was missing or could not be confirmed; proxying upstream"
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
                    "skipping local upload-pack catch-up because presented HTTP auth was missing or could not be confirmed; proxying upstream"
                );
            }
            LocalServeDecision::Unavailable { .. } => {}
        }
    }

    if local_authz_confirmed {
        match &local_decision {
            LocalServeDecision::SatisfiesWants {
                serve_from,
                restored_from_s3_for_request: _,
                want_count: _,
                ..
            } => {
                return serve_local_upload_pack(
                    &state,
                    &owner,
                    &repo,
                    *serve_from,
                    &body,
                    git_protocol.as_deref(),
                    CloneCompletion {
                        cache_status: effective_cache_status.clone(),
                        started_at,
                        metric_username: metric_username.clone(),
                        metric_repo: repo_slug.clone(),
                    },
                )
                .await;
            }
            LocalServeDecision::Unavailable {
                had_local_repo_before_check,
                restored_from_s3_for_request,
            } => {
                if expects_local_pack_serve {
                    info!(
                        repo = %repo_slug,
                        wants = wants.len(),
                        want_sample,
                        had_local_repo_before_check = *had_local_repo_before_check,
                        restored_from_s3_for_request = *restored_from_s3_for_request,
                        "cannot serve upload-pack from local disk; no local published repo or request-time S3 restore is available"
                    );
                }
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
    }

    // Proxy to upstream forge.
    info!(repo = %repo_slug, "proxying upload-pack to upstream forge");
    let response = proxy_upload_pack_to_upstream(
        &state,
        &owner,
        &repo,
        auth_header.as_deref(),
        body,
        CloneCompletion {
            cache_status: effective_cache_status,
            started_at,
            metric_username,
            metric_repo: repo_slug,
        },
        &headers,
        request_metadata,
        git_session_id,
        client_fingerprint,
    )
    .await?;

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
    crate::health::health_handler(axum::extract::State(health_state))
        .await
        .into_response()
}

/// `GET /readyz`
async fn handle_ready(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if state.is_draining() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "forgeproxy is draining and not accepting new requests\n",
        )
            .into_response();
    }

    let health_state = crate::health::HealthState {
        config: Arc::clone(&state.config),
        valkey: state.valkey.clone(),
        http_client: state.http_client.clone(),
    };
    crate::health::health_handler(axum::extract::State(health_state))
        .await
        .into_response()
}

/// `GET /metrics`
///
/// Returns Prometheus metrics collected by the proxy.
async fn handle_metrics(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    state.refresh_live_metrics();
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

async fn reject_new_requests_while_draining(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let allow_during_drain = matches!(path, "/healthz" | "/readyz" | "/metrics");
    if state.is_draining() && !allow_during_drain {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "forgeproxy is draining and not accepting new requests\n",
        )
            .into_response();
    }

    next.run(request).await
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

fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn should_forward_request_header(name: &HeaderName) -> bool {
    !is_hop_by_hop_header(name) && *name != header::HOST && *name != header::CONTENT_LENGTH
}

fn should_forward_response_header(name: &HeaderName) -> bool {
    !is_hop_by_hop_header(name) && *name != header::CONTENT_LENGTH
}

fn apply_forwarded_request_headers(
    mut request: reqwest::RequestBuilder,
    headers: &HeaderMap,
) -> reqwest::RequestBuilder {
    for (name, value) in headers {
        if should_forward_request_header(name) {
            request = request.header(name, value);
        }
    }
    request
}

fn collect_forwarded_response_headers(
    headers: &reqwest::header::HeaderMap,
) -> Vec<(HeaderName, HeaderValue)> {
    headers
        .iter()
        .filter(|(name, _)| should_forward_response_header(name))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

fn response_from_upstream_parts(
    status: StatusCode,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: Body,
) -> Response {
    let mut response = (status, body).into_response();
    for (name, value) in headers {
        response.headers_mut().append(name, value);
    }
    response
}

async fn forward_upstream_response(upstream_resp: reqwest::Response) -> Result<Response, AppError> {
    let status = upstream_resp.status();
    let headers = collect_forwarded_response_headers(upstream_resp.headers());
    let body = upstream_resp
        .bytes()
        .await
        .context("failed to read upstream response body")?;
    Ok(response_from_upstream_parts(
        status,
        headers,
        Body::from(body),
    ))
}

async fn local_http_clone_access_confirmed(
    state: &AppState,
    auth_header: Option<&str>,
    owner: &str,
    repo: &str,
) -> bool {
    let auth_header = auth_header.filter(|header| !header.trim().is_empty());
    let auth_kind = if auth_header.is_some() {
        "presented client Authorization header"
    } else {
        "anonymous access"
    };

    match crate::auth::http_validator::validate_http_auth(state, auth_header, owner, repo).await {
        Ok(()) => true,
        Err(AppError::Unauthorized(message)) => {
            info!(
                %owner,
                %repo,
                %message,
                auth_kind,
                "local HTTP clone access probe denied; proxying upstream"
            );
            false
        }
        Err(AppError::UpstreamRateLimited { status, .. }) => {
            warn!(
                %owner,
                %repo,
                %status,
                auth_kind,
                "local HTTP clone access probe was rate limited; proxying upstream"
            );
            false
        }
        Err(AppError::Internal(error)) => {
            warn!(
                %owner,
                %repo,
                %error,
                auth_kind,
                "local HTTP clone access probe failed; proxying upstream"
            );
            false
        }
        Err(AppError::BadRequest(message)) => {
            warn!(
                %owner,
                %repo,
                %message,
                auth_kind,
                "local HTTP clone access probe rejected malformed input; proxying upstream"
            );
            false
        }
    }
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
    completion: CloneCompletion,
) -> Result<Response, AppError> {
    let owner_repo = format!("{owner}/{repo}");
    let mut process = spawn_local_upload_pack(
        state,
        &owner_repo,
        "http",
        serve_from,
        LocalUploadPackMode::StatelessRpc,
        git_protocol,
    )
    .await?;

    // Write the request body to stdin.
    if let Some(mut stdin) = process.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(request_body).await.ok();
        // Drop stdin to signal EOF.
    }

    let stdout = process
        .stdout
        .context("failed to capture git upload-pack stdout")?;
    let mut stderr = process
        .stderr
        .context("failed to capture git upload-pack stderr")?;
    let mut child = process.child;
    let repo_lease = process._lease;

    // Stream stdout as the response body.
    let downstream_counter = state
        .metrics
        .metrics
        .clone_downstream_bytes
        .get_or_create(&CloneDownstreamBytesLabels {
            protocol: Protocol::Https,
            phase: ClonePhase::UploadPack,
            source: CloneSource::Local,
            username: completion.metric_username.clone(),
            repo: completion.metric_repo.clone(),
        })
        .clone();
    let stream = CloneCompletionStream::new(
        LeasedReaderStream::new(
            CountingBytesStream::new(ReaderStream::new(stdout), downstream_counter),
            repo_lease,
        ),
        state.metrics.clone(),
        Protocol::Https,
        completion,
    );
    let body = Body::from_stream(stream);

    // Reap the child in the background so we don't leak processes.
    tokio::spawn(async move {
        match wait_for_local_upload_pack_exit(&mut child, &mut stderr).await {
            Ok(exit) if !exit.status.success() => {
                warn!(
                    status = %exit.status,
                    stderr = %String::from_utf8_lossy(&exit.stderr),
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
    completion: CloneCompletion,
    request_headers: &HeaderMap,
    request_metadata: crate::tee_hydration::CapturedFetchMetadata,
    git_session_id: String,
    client_fingerprint: String,
) -> Result<Response, AppError> {
    let upstream_url = format!(
        "https://{}/{}/{}/git-upload-pack",
        state.config.upstream.hostname, owner, repo,
    );

    let req =
        apply_forwarded_request_headers(state.http_client.post(&upstream_url), request_headers);
    let capture_body = body.clone();
    let upstream_resp = req
        .body(body)
        .send()
        .await
        .context("failed to reach upstream forge for upload-pack")?;

    if !upstream_resp.status().is_success() {
        let status = upstream_resp.status();
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
        return forward_upstream_response(upstream_resp).await;
    }

    let status = upstream_resp.status();
    let forwarded_headers = collect_forwarded_response_headers(upstream_resp.headers());

    let owner_repo = format!("{owner}/{repo}");
    let (tx, rx) = mpsc::channel::<Result<Bytes, reqwest::Error>>(8);
    let completion_metrics = state.metrics.clone();
    let state = state.clone();
    let owner = owner.to_string();
    let repo = repo.to_string();
    let owner_repo_for_cache = owner_repo.clone();
    let auth_header = auth_header.map(ToOwned::to_owned);
    let request_phase = request_metadata.request_phase.clone();
    let ls_refs_request_body = capture_body.clone();
    let upstream_counter = state
        .metrics
        .metrics
        .clone_upstream_bytes
        .get_or_create(&CloneUpstreamBytesLabels {
            protocol: Protocol::Https,
            phase: ClonePhase::UploadPack,
            username: completion.metric_username.clone(),
            repo: owner_repo.clone(),
        })
        .clone();
    let downstream_counter = state
        .metrics
        .metrics
        .clone_downstream_bytes
        .get_or_create(&CloneDownstreamBytesLabels {
            protocol: Protocol::Https,
            phase: ClonePhase::UploadPack,
            source: CloneSource::Upstream,
            username: completion.metric_username.clone(),
            repo: owner_repo.clone(),
        })
        .clone();
    let recent_advertised_refs = state
        .recent_advertised_refs(
            &owner_repo,
            &http_git_client_fingerprint(
                request_headers,
                &completion.metric_username,
                &owner,
                &repo,
            ),
        )
        .await;
    let advertised_refs = recent_advertised_refs
        .as_ref()
        .map(|recent| recent.advertised_refs.clone());
    tokio::spawn(async move {
        let mut stream = upstream_resp.bytes_stream();
        let mut ls_refs_response =
            if request_phase == crate::tee_hydration::UploadPackRequestPhase::V2LsRefs {
                Some(Vec::new())
            } else {
                None
            };
        let mut stream_completed = true;
        let mut hydration = UpstreamHydrationTracker::start(
            &state,
            &owner,
            &repo,
            auth_header.as_deref(),
            "http",
            UpstreamHydrationRequest {
                advertised_refs: advertised_refs.as_ref(),
                request_body: &capture_body,
                enable_hydration: true,
            },
        )
        .await;

        while let Some(item) = stream.next().await {
            match item {
                Ok(chunk) => {
                    let chunk_len = chunk.len() as u64;
                    upstream_counter.inc_by(chunk_len);
                    if let Some(response_buf) = ls_refs_response.as_mut() {
                        response_buf.extend_from_slice(&chunk);
                    }
                    hydration.record_response_chunk(chunk.clone()).await;

                    if tx.send(Ok(chunk)).await.is_err() {
                        stream_completed = false;
                        break;
                    }
                    downstream_counter.inc_by(chunk_len);
                }
                Err(e) => {
                    hydration.handle_stream_error().await;
                    let _ = tx.send(Err(e)).await;
                    return;
                }
            }
        }
        if stream_completed && let Some(ls_refs_response) = ls_refs_response {
            state
                .merge_recent_advertised_refs(
                    owner_repo_for_cache,
                    client_fingerprint,
                    git_session_id,
                    crate::coordination::registry::RequestAdvertisedRefs {
                        ls_refs_request: Some(ls_refs_request_body.to_vec()),
                        ls_refs_response: Some(ls_refs_response),
                        ..Default::default()
                    },
                )
                .await;
        }
        hydration.finish().await;
    });

    let body = Body::from_stream(CloneCompletionStream::new(
        ReceiverStream::new(rx),
        completion_metrics,
        Protocol::Https,
        completion,
    ));

    Ok(response_from_upstream_parts(
        status,
        forwarded_headers,
        body,
    ))
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Application-level error type that maps cleanly to HTTP responses.
#[derive(Debug)]
pub enum AppError {
    /// The caller is not authenticated or not authorised.
    Unauthorized(String),
    /// The request is malformed.
    BadRequest(String),
    /// Forward an upstream rate-limit response to the client.
    UpstreamRateLimited {
        status: StatusCode,
        headers: Vec<(String, String)>,
        body: String,
    },
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
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
            AppError::UpstreamRateLimited {
                status,
                headers,
                body,
            } => {
                let response_body = if body.trim().is_empty() {
                    "Upstream API rate limit reached. Please retry later.\n".to_string()
                } else {
                    body
                };
                let mut response = (status, response_body).into_response();
                for (name, value) in headers {
                    let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
                        continue;
                    };
                    let Ok(value) = HeaderValue::from_str(&value) else {
                        continue;
                    };
                    response.headers_mut().insert(name, value);
                }
                response
            }
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
