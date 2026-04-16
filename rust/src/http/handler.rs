//! Main axum router and HTTP request handlers for the caching proxy.
//!
//! Routes:
//! - `GET  /:owner/:repo/info/refs`       - Smart HTTP info/refs
//! - `POST /:owner/:repo/git-upload-pack`  - Pack negotiation / data transfer
//! - `POST /:owner/:repo/git-receive-pack` - Proxied write-through push
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
    io::{Cursor, Read},
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
use brotli::Decompressor;
use bytes::Bytes;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use futures::{Stream, StreamExt};
use prometheus_client::metrics::counter::Counter;
use serde::Deserialize;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::ReaderStream;
use tracing::{Instrument, debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::AppState;
use crate::clone_support::{
    CloneCompletion, LocalUploadPackMode, UpstreamHydrationRequest, UpstreamHydrationTracker,
    spawn_local_upload_pack_with_lease, wait_for_local_upload_pack_exit,
};
use crate::coordination::registry::{
    LocalServeDecision, LocalServeRepoLease, LocalServeRepoSource,
    try_finish_pack_cache_delta_composite,
};
use crate::metrics::{
    ActiveCloneGuard, CacheStatus, CloneDownstreamBytesLabels, ClonePhase, CloneSource,
    CloneUpstreamBytesLabels, Protocol,
};
use crate::observability::GitRequestObservation;

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
    upload_pack_source: Option<CloneSource>,
    _active_clone_guard: ActiveCloneGuard,
    recorded: bool,
}

impl<S> CloneCompletionStream<S> {
    fn new(
        inner: S,
        metrics: crate::metrics::MetricsRegistry,
        protocol: Protocol,
        completion: CloneCompletion,
        upload_pack_source: Option<CloneSource>,
        active_clone_guard: ActiveCloneGuard,
    ) -> Self {
        Self {
            inner,
            metrics,
            protocol,
            completion,
            upload_pack_source,
            _active_clone_guard: active_clone_guard,
            recorded: false,
        }
    }

    fn record_once(&mut self) {
        if self.recorded {
            return;
        }
        self.recorded = true;
        if let Some(source) = self.upload_pack_source.clone() {
            crate::metrics::observe_upload_pack_duration(
                &self.metrics,
                self.protocol.clone(),
                source,
                &self.completion.metric_repo,
                self.completion.started_at.elapsed(),
            );
        }
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
        .route(
            "/repos/{owner}/{repo}/tarball",
            get(super::archive::handle_tarball_redirect_without_ref),
        )
        .route(
            "/repos/{owner}/{repo}/tarball/{*git_ref}",
            get(super::archive::handle_tarball_redirect_with_ref),
        )
        .route(
            "/repos/{owner}/{repo}/zipball",
            get(super::archive::handle_zipball_redirect_without_ref),
        )
        .route(
            "/repos/{owner}/{repo}/zipball/{*git_ref}",
            get(super::archive::handle_zipball_redirect_with_ref),
        )
        .route(
            "/api/v3/repos/{owner}/{repo}/tarball",
            get(super::archive::handle_tarball_redirect_without_ref),
        )
        .route(
            "/api/v3/repos/{owner}/{repo}/tarball/{*git_ref}",
            get(super::archive::handle_tarball_redirect_with_ref),
        )
        .route(
            "/api/v3/repos/{owner}/{repo}/zipball",
            get(super::archive::handle_zipball_redirect_without_ref),
        )
        .route(
            "/api/v3/repos/{owner}/{repo}/zipball/{*git_ref}",
            get(super::archive::handle_zipball_redirect_with_ref),
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

fn normalized_upload_pack_request_body(
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<Bytes, AppError> {
    let encoding = header_value(headers, "Content-Encoding").unwrap_or("");
    if encoding.trim().is_empty() {
        return Ok(body.clone());
    }

    let encodings = encoding
        .split(',')
        .map(|part| {
            part.trim()
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .filter(|part| !part.is_empty() && part != "identity")
        .collect::<Vec<_>>();
    if encodings.is_empty() {
        return Ok(body.clone());
    }

    let mut decoded = body.to_vec();
    for content_coding in encodings.iter().rev() {
        decoded = decode_upload_pack_body(&decoded, content_coding)?;
    }
    Ok(Bytes::from(decoded))
}

fn decode_upload_pack_body(body: &[u8], content_coding: &str) -> Result<Vec<u8>, AppError> {
    match content_coding {
        "gzip" | "x-gzip" => {
            let mut decoder = GzDecoder::new(Cursor::new(body));
            let mut decoded = Vec::new();
            decoder.read_to_end(&mut decoded).map_err(|error| {
                AppError::BadRequest(format!("invalid gzip upload-pack body: {error}"))
            })?;
            Ok(decoded)
        }
        "deflate" => {
            let mut decoded = Vec::new();
            match ZlibDecoder::new(Cursor::new(body)).read_to_end(&mut decoded) {
                Ok(_) => Ok(decoded),
                Err(zlib_error) => {
                    let mut fallback = Vec::new();
                    DeflateDecoder::new(Cursor::new(body))
                        .read_to_end(&mut fallback)
                        .map_err(|raw_error| {
                            AppError::BadRequest(format!(
                                "invalid deflate upload-pack body: zlib={zlib_error}; raw={raw_error}"
                            ))
                        })?;
                    Ok(fallback)
                }
            }
        }
        "br" => {
            let mut decoder = Decompressor::new(Cursor::new(body), 4096);
            let mut decoded = Vec::new();
            decoder.read_to_end(&mut decoded).map_err(|error| {
                AppError::BadRequest(format!("invalid brotli upload-pack body: {error}"))
            })?;
            Ok(decoded)
        }
        "zstd" | "x-zstd" => zstd::decode_all(Cursor::new(body)).map_err(|error| {
            AppError::BadRequest(format!("invalid zstd upload-pack body: {error}"))
        }),
        other => Err(AppError::BadRequest(format!(
            "unsupported Content-Encoding for upload-pack: {other}"
        ))),
    }
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

/// `GET /:owner/:repo/info/refs?service=<git-service>`
///
/// Proxies `info/refs` from the upstream forge. Successful
/// `git-upload-pack` advertisements are rewritten to inject the `bundle-uri`
/// protocol-v2 capability. `git-receive-pack` advertisements are forwarded
/// transparently so HTTP pushes can flow straight through to the upstream.
/// Upstream authentication challenges and non-success responses are preserved.
///
/// `git-upload-pack` responses are intercepted so that we can inject the
/// `bundle-uri` protocol-v2 capability.
#[instrument(
    skip(state, headers),
    fields(
        %owner,
        %repo,
        owner_repo = tracing::field::Empty,
        username = tracing::field::Empty,
        forge_backend = tracing::field::Empty,
        git_protocol = tracing::field::Empty,
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
        info!(service = %service, "proxying git info/refs request to upstream forge");
        return proxy_info_refs_to_upstream(&state, &owner, &repo, &service, &headers).await;
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
    let observation = GitRequestObservation::new(
        &state.config,
        &owner,
        &repo,
        &metric_username,
        None,
        &client_fingerprint,
        "http",
        None,
    );
    let git_session_id = observation.git_session_id.clone();
    let span = tracing::Span::current();
    observation.record_span(&span, "info-refs");

    // Proxy the info/refs request to the upstream forge.
    let upstream_url = format!(
        "{}/{}/{}/info/refs?service=git-upload-pack",
        state.config.upstream.git_url_base(),
        owner,
        repo,
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

    let (modified_body, bundle_uri_result) =
        crate::http::protocolv2::inject_bundle_uri_with_result(&upstream_bytes, &bundle_list_url);
    let repo_slug = format!("{owner}/{repo}");
    let bundle_uri_result_label = bundle_uri_result.as_metric_label();
    crate::metrics::inc_bundle_uri_advertisement(
        &state.metrics,
        &repo_slug,
        bundle_uri_result_label,
    );
    info!(
        repo = %repo_slug,
        result = bundle_uri_result_label,
        bundle_list_url = %bundle_list_url,
        upstream_bytes = upstream_bytes.len(),
        downstream_bytes = modified_body.len(),
        "processed bundle-uri advertisement"
    );

    state
        .metrics
        .metrics
        .clone_upstream_bytes
        .get_or_create(&CloneUpstreamBytesLabels {
            protocol: Protocol::Https,
            phase: ClonePhase::InfoRefs,
            username: metric_username.clone(),
            repo: repo_slug.clone(),
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
            repo: repo_slug.clone(),
        })
        .inc_by(modified_body.len() as u64);

    state
        .remember_recent_advertised_refs(
            repo_slug,
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
        owner_repo = tracing::field::Empty,
        username = tracing::field::Empty,
        forge_backend = tracing::field::Empty,
        git_protocol = tracing::field::Empty,
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
    let decoded_body = normalized_upload_pack_request_body(&headers, &body)?;
    let request_metadata = crate::tee_hydration::parse_upload_pack_request_metadata(
        &decoded_body,
        git_protocol.as_deref(),
    )
    .unwrap_or_default();
    let wants = request_metadata.want_oids.clone();
    let want_sample = wants
        .iter()
        .take(5)
        .map(|want| want.chars().take(12).collect::<String>())
        .collect::<Vec<String>>()
        .join(",");
    let local_http_access =
        local_http_clone_access(&state, auth_header.as_deref(), &owner, &repo).await;
    let local_authz_confirmed = local_http_access == LocalHttpAccess::Confirmed;
    let client_fingerprint = http_git_client_fingerprint(&headers, &metric_username, &owner, &repo);
    let recent_advertised_refs = state
        .recent_advertised_refs(&repo_slug, &client_fingerprint)
        .await;
    let advertised_refs = recent_advertised_refs
        .as_ref()
        .map(|recent| recent.advertised_refs.clone());
    let git_session_id = recent_advertised_refs
        .as_ref()
        .map(|recent| recent.session_id.clone())
        .unwrap_or_else(|| format!("http-{}", Uuid::new_v4().simple()));
    let request_phase = request_metadata.request_phase.to_string();
    let observation = GitRequestObservation::new(
        &state.config,
        &owner,
        &repo,
        &metric_username,
        git_protocol.as_deref(),
        &client_fingerprint,
        "http",
        Some(git_session_id.clone()),
    );
    let span = tracing::Span::current();
    observation.record_span(&span, &request_phase);
    info!(
        repo = %repo_slug,
        wants = wants.len(),
        want_sample,
        "received git-upload-pack request"
    );
    span.record(
        "client_session_id",
        tracing::field::display(request_metadata.client_session_id.as_deref().unwrap_or("")),
    );
    span.record(
        "git_client_agent",
        tracing::field::display(request_metadata.agent.as_deref().unwrap_or("")),
    );

    if matches!(
        &request_metadata.request_phase,
        crate::tee_hydration::UploadPackRequestPhase::V2Command(command) if command == "bundle-uri"
    ) {
        match local_http_access {
            LocalHttpAccess::Confirmed => {}
            LocalHttpAccess::Denied => {
                crate::metrics::inc_bundle_uri_command(&state.metrics, "auth_failed");
                return Err(AppError::Unauthorized(
                    "HTTP authorization is required before serving bundle URIs.\n".to_string(),
                ));
            }
            LocalHttpAccess::Indeterminate => {
                crate::metrics::inc_bundle_uri_command(&state.metrics, "auth_indeterminate");
                return Ok((
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/x-git-upload-pack-result")],
                    Body::from("0000"),
                )
                    .into_response());
            }
        }
        match crate::http::bundle_serve::bundle_uri_command_response(&state, &repo_slug).await {
            Ok(Some(body)) => {
                crate::metrics::inc_bundle_uri_command(&state.metrics, "served");
                return Ok((
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/x-git-upload-pack-result")],
                    Body::from(body),
                )
                    .into_response());
            }
            Ok(None) => {
                crate::metrics::inc_bundle_uri_command(&state.metrics, "missing_metadata");
                return Ok((
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/x-git-upload-pack-result")],
                    Body::from("0000"),
                )
                    .into_response());
            }
            Err(error) => {
                crate::metrics::inc_bundle_uri_command(&state.metrics, "failed");
                warn!(
                    repo = %repo_slug,
                    error = %error,
                    "bundle-uri command failed; returning empty response so fetch can continue"
                );
                return Ok((
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/x-git-upload-pack-result")],
                    Body::from("0000"),
                )
                    .into_response());
            }
        }
    }

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
                    serve_from = %serve_from,
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
                    &decoded_body,
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
        decoded_body,
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
/// Pushes are written through to the upstream forge without mutating the local
/// cache or forcing immediate mirror updates.
#[instrument(skip(state, headers, body))]
async fn handle_receive_pack(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let _active_connection = state.begin_active_connection(Protocol::Https);
    validate_path_segment(&owner, "owner")?;
    validate_path_segment(&repo, "repo")?;

    info!(
        %owner,
        %repo,
        request_bytes = body.len(),
        "proxying git-receive-pack to upstream forge"
    );

    proxy_receive_pack_to_upstream(&state, &owner, &repo, body, &headers).await
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

fn stream_upstream_response(upstream_resp: reqwest::Response) -> Response {
    let status = upstream_resp.status();
    let headers = collect_forwarded_response_headers(upstream_resp.headers());
    let body = Body::from_stream(upstream_resp.bytes_stream());
    response_from_upstream_parts(status, headers, body)
}

async fn proxy_info_refs_to_upstream(
    state: &AppState,
    owner: &str,
    repo: &str,
    service: &str,
    request_headers: &HeaderMap,
) -> Result<Response, AppError> {
    let upstream_url = format!(
        "{}/{}/{}/info/refs?service={service}",
        state.config.upstream.git_url_base(),
        owner,
        repo,
    );

    let upstream_req =
        apply_forwarded_request_headers(state.http_client.get(&upstream_url), request_headers);
    let upstream_resp = upstream_req
        .send()
        .await
        .context("failed to reach upstream forge for info/refs")?;

    Ok(stream_upstream_response(upstream_resp))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalHttpAccess {
    Confirmed,
    Denied,
    Indeterminate,
}

async fn local_http_clone_access(
    state: &AppState,
    auth_header: Option<&str>,
    owner: &str,
    repo: &str,
) -> LocalHttpAccess {
    let auth_header = auth_header.filter(|header| !header.trim().is_empty());
    let auth_kind = if auth_header.is_some() {
        "presented client Authorization header"
    } else {
        "anonymous access"
    };

    match crate::auth::http_validator::validate_http_auth(state, auth_header, owner, repo).await {
        Ok(()) => LocalHttpAccess::Confirmed,
        Err(AppError::Unauthorized(message)) => {
            info!(
                %owner,
                %repo,
                %message,
                auth_kind,
                "local HTTP clone access probe denied; proxying upstream"
            );
            LocalHttpAccess::Denied
        }
        Err(AppError::UpstreamRateLimited { status, .. }) => {
            warn!(
                %owner,
                %repo,
                %status,
                auth_kind,
                "local HTTP clone access probe was rate limited; proxying upstream"
            );
            LocalHttpAccess::Indeterminate
        }
        Err(AppError::Internal(error)) => {
            warn!(
                %owner,
                %repo,
                %error,
                auth_kind,
                "local HTTP clone access probe failed; proxying upstream"
            );
            LocalHttpAccess::Indeterminate
        }
        Err(AppError::BadRequest(message)) => {
            warn!(
                %owner,
                %repo,
                %message,
                auth_kind,
                "local HTTP clone access probe rejected malformed input; proxying upstream"
            );
            LocalHttpAccess::Indeterminate
        }
        Err(AppError::NotFound(message)) => {
            info!(
                %owner,
                %repo,
                %message,
                auth_kind,
                "local HTTP clone access probe found no upstream repo metadata; proxying upstream"
            );
            LocalHttpAccess::Indeterminate
        }
        Err(AppError::UpstreamFallback(message)) => {
            warn!(
                %owner,
                %repo,
                %message,
                auth_kind,
                "local HTTP clone access probe was capacity-limited; proxying upstream"
            );
            LocalHttpAccess::Indeterminate
        }
    }
}

/// Run a local `git upload-pack` process and stream its output as the HTTP
/// response body.
async fn serve_http_pack_cache_hit_response(
    state: &AppState,
    hit: crate::pack_cache::PackCacheHit,
    completion: CloneCompletion,
) -> Result<Response, anyhow::Error> {
    let source_stream: Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>> =
        match hit.artifact {
            crate::pack_cache::PackCacheArtifact::Full => {
                let file = tokio::fs::File::open(&hit.path)
                    .await
                    .with_context(|| format!("open pack cache artifact {}", hit.path.display()))?;
                Box::pin(ReaderStream::new(file))
            }
            crate::pack_cache::PackCacheArtifact::Composite { .. } => {
                Box::pin(state.pack_cache.stream_composite_response(&hit)?)
            }
        };

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
    let active_clone_guard =
        state.begin_active_clone(Protocol::Https, completion.cache_status.clone());
    let stream = CloneCompletionStream::new(
        CountingBytesStream::new(source_stream, downstream_counter),
        state.metrics.clone(),
        Protocol::Https,
        completion,
        None,
        active_clone_guard,
    );
    let body = Body::from_stream(stream);
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/x-git-upload-pack-result")],
        body,
    )
        .into_response())
}

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
    let repo_lease = crate::coordination::registry::acquire_local_serve_repo_lease(
        state,
        &owner_repo,
        serve_from,
    )
    .await?;
    let mut pack_cache_lookup = match state.pack_cache.key_for_fresh_clone(
        &owner_repo,
        repo_lease.repo_path(),
        request_body,
        git_protocol,
    ) {
        Ok(key) => Some(
            state
                .pack_cache
                .lookup_or_reserve(Protocol::Https, key)
                .await
                .map_err(AppError::Internal)?,
        ),
        Err(reason) => {
            if state.pack_cache.enabled() && reason != "disabled" {
                crate::metrics::inc_pack_cache_request(
                    &state.metrics,
                    Protocol::Https,
                    "bypass",
                    reason,
                );
            }
            None
        }
    };

    match pack_cache_lookup.take() {
        Some(crate::pack_cache::PackCacheLookup::Hit(hit)) => {
            match serve_http_pack_cache_hit_response(state, hit, completion.clone()).await {
                Ok(response) => return Ok(response),
                Err(error) => {
                    warn!(
                        error = %error,
                        "pack cache artifact disappeared before HTTP replay; falling back to local upload-pack"
                    );
                    crate::metrics::inc_pack_cache_request(
                        &state.metrics,
                        Protocol::Https,
                        "bypass",
                        "artifact_open_failed",
                    );
                }
            }
        }
        other => pack_cache_lookup = other,
    }

    let pack_cache_writer = match pack_cache_lookup {
        Some(crate::pack_cache::PackCacheLookup::Generate(writer)) => {
            match try_finish_pack_cache_delta_composite(
                state,
                &owner_repo,
                repo_lease.repo_path(),
                writer,
            )
            .await
            {
                Ok(hit) => {
                    match serve_http_pack_cache_hit_response(state, hit, completion.clone()).await {
                        Ok(response) => return Ok(response),
                        Err(error) => {
                            warn!(
                                error = %error,
                                "on-demand pack cache composite could not be replayed; falling back without cache writer"
                            );
                            None
                        }
                    }
                }
                Err(miss) => {
                    if miss.reason != "no_base"
                        && miss.reason != "missing_request_wants"
                        && miss.reason != "same_tips"
                    {
                        crate::metrics::inc_pack_cache_request(
                            &state.metrics,
                            Protocol::Https,
                            "bypass",
                            miss.reason,
                        );
                    }
                    miss.writer
                }
            }
        }
        Some(crate::pack_cache::PackCacheLookup::BypassAfterWait) | None => None,
        Some(crate::pack_cache::PackCacheLookup::Hit(_)) => unreachable!(),
    };

    let mut process = spawn_local_upload_pack_with_lease(
        state,
        &owner_repo,
        Protocol::Https,
        serve_from,
        repo_lease,
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
    let stderr = process
        .stderr
        .context("failed to capture git upload-pack stderr")?;
    let crate::clone_support::LocalUploadPackProcess {
        child,
        upload_pack_guard,
        _global_upload_pack_permit: global_upload_pack_permit,
        _repo_upload_pack_permit: repo_upload_pack_permit,
        _lease: repo_lease,
        ..
    } = process;

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
    let active_clone_guard =
        state.begin_active_clone(Protocol::Https, completion.cache_status.clone());
    let upload_pack_cpu_metrics = state.metrics.clone();
    let stream: Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>> = if let Some(
        pack_cache_writer,
    ) =
        pack_cache_writer
    {
        let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(8);
        tokio::spawn(
            async move {
                let _repo_lease = repo_lease;
                let _upload_pack_guard = upload_pack_guard;
                let _global_upload_pack_permit = global_upload_pack_permit;
                let _repo_upload_pack_permit = repo_upload_pack_permit;
                let mut child = child;
                let mut stderr = stderr;
                let mut stdout_stream = ReaderStream::new(stdout);
                let mut writer = Some(pack_cache_writer);
                let mut downstream_open = true;

                while let Some(item) = stdout_stream.next().await {
                    match item {
                        Ok(bytes) => {
                            if let Some(active_writer) = writer.as_mut()
                                && let Err(error) = active_writer.write_chunk(&bytes).await
                            {
                                warn!(
                                    error = %error,
                                    "pack cache write failed; continuing client stream without caching artifact"
                                );
                                if let Some(active_writer) = writer.take() {
                                    active_writer.abort().await;
                                }
                            }
                            if downstream_open && tx.send(Ok(bytes)).await.is_err() {
                                downstream_open = false;
                            }
                        }
                        Err(error) => {
                            if let Some(active_writer) = writer.take() {
                                active_writer.abort().await;
                            }
                            if downstream_open {
                                let _ = tx.send(Err(error)).await;
                            }
                            let _ = child.kill().await;
                            if let Ok(exit) =
                                wait_for_local_upload_pack_exit(&mut child, &mut stderr).await
                            {
                                crate::metrics::inc_upload_pack_cpu_seconds(
                                    &upload_pack_cpu_metrics,
                                    Protocol::Https,
                                    "pack_cache_generation",
                                    exit.cpu_seconds,
                                );
                            }
                            return;
                        }
                    }
                }

                match wait_for_local_upload_pack_exit(&mut child, &mut stderr).await {
                    Ok(exit) if exit.status.success() => {
                        crate::metrics::inc_upload_pack_cpu_seconds(
                            &upload_pack_cpu_metrics,
                            Protocol::Https,
                            "pack_cache_generation",
                            exit.cpu_seconds,
                        );
                        if let Some(active_writer) = writer.take()
                            && let Err(error) = active_writer.finish().await
                        {
                            warn!(error = %error, "failed to finalize pack cache artifact");
                        }
                    }
                    Ok(exit) => {
                        crate::metrics::inc_upload_pack_cpu_seconds(
                            &upload_pack_cpu_metrics,
                            Protocol::Https,
                            "pack_cache_generation",
                            exit.cpu_seconds,
                        );
                        if let Some(active_writer) = writer.take() {
                            active_writer.abort().await;
                        }
                        warn!(
                            status = %exit.status,
                            stderr = %String::from_utf8_lossy(&exit.stderr),
                            "git upload-pack exited with non-zero status; discarding pack cache artifact"
                        );
                    }
                    Err(error) => {
                        if let Some(active_writer) = writer.take() {
                            active_writer.abort().await;
                        }
                        error!(error = %error, "failed to wait on git upload-pack");
                    }
                }
            }
            .instrument(tracing::Span::current()),
        );
        Box::pin(ReceiverStream::new(rx))
    } else {
        let mut child = child;
        let mut stderr = stderr;
        let upload_pack_cpu_metrics = upload_pack_cpu_metrics.clone();
        tokio::spawn(
            async move {
                let _upload_pack_guard = upload_pack_guard;
                let _global_upload_pack_permit = global_upload_pack_permit;
                let _repo_upload_pack_permit = repo_upload_pack_permit;
                match wait_for_local_upload_pack_exit(&mut child, &mut stderr).await {
                    Ok(exit) if !exit.status.success() => {
                        crate::metrics::inc_upload_pack_cpu_seconds(
                            &upload_pack_cpu_metrics,
                            Protocol::Https,
                            "local",
                            exit.cpu_seconds,
                        );
                        warn!(
                            status = %exit.status,
                            stderr = %String::from_utf8_lossy(&exit.stderr),
                            "git upload-pack exited with non-zero status"
                        );
                    }
                    Ok(exit) => {
                        crate::metrics::inc_upload_pack_cpu_seconds(
                            &upload_pack_cpu_metrics,
                            Protocol::Https,
                            "local",
                            exit.cpu_seconds,
                        );
                    }
                    Err(e) => {
                        error!(error = %e, "failed to wait on git upload-pack");
                    }
                }
            }
            .instrument(tracing::Span::current()),
        );
        Box::pin(LeasedReaderStream::new(
            ReaderStream::new(stdout),
            repo_lease,
        ))
    };
    let stream = CloneCompletionStream::new(
        CountingBytesStream::new(stream, downstream_counter),
        state.metrics.clone(),
        Protocol::Https,
        completion,
        Some(CloneSource::Local),
        active_clone_guard,
    );
    let body = Body::from_stream(stream);

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/x-git-upload-pack-result")],
        body,
    )
        .into_response())
}

/// Proxy a `git-upload-pack` POST to the upstream forge and stream the response.
#[allow(clippy::too_many_arguments)]
async fn proxy_upload_pack_to_upstream(
    state: &AppState,
    owner: &str,
    repo: &str,
    auth_header: Option<&str>,
    body: Bytes,
    decoded_body: Bytes,
    completion: CloneCompletion,
    request_headers: &HeaderMap,
    request_metadata: crate::tee_hydration::CapturedFetchMetadata,
    git_session_id: String,
    client_fingerprint: String,
) -> Result<Response, AppError> {
    let owner_repo = format!("{owner}/{repo}");
    let upstream_url = format!(
        "{}/{}/{}/git-upload-pack",
        state.config.upstream.git_url_base(),
        owner,
        repo,
    );
    let upstream_clone_permits =
        match crate::coordination::registry::try_acquire_clone_hydration_permits(state, &owner_repo)
            .await
            .map_err(AppError::Internal)?
        {
            Ok(permits) => permits,
            Err(reason) => {
                warn!(
                    repo = %owner_repo,
                    reason = reason.as_metric_reason(),
                    "upstream upload-pack proxy is saturated; asking nginx to fall back to upstream"
                );
                crate::metrics::inc_upstream_fallback(
                    &state.metrics,
                    Protocol::Https,
                    reason.as_metric_reason(),
                );
                return Err(AppError::UpstreamFallback(
                    "Upstream clone capacity is saturated. Please retry later.\n".to_string(),
                ));
            }
        };

    let req =
        apply_forwarded_request_headers(state.http_client.post(&upstream_url), request_headers);
    let capture_body = decoded_body.clone();
    let upstream_resp = match req.body(body).send().await {
        Ok(response) => response,
        Err(error) => {
            crate::coordination::registry::release_clone_hydration_permits(
                state,
                upstream_clone_permits,
            )
            .await
            .map_err(AppError::Internal)?;
            return Err(AppError::Internal(
                anyhow::Error::new(error).context("failed to reach upstream forge for upload-pack"),
            ));
        }
    };

    if !upstream_resp.status().is_success() {
        let status = upstream_resp.status();
        let wants = request_metadata.want_oids.clone();
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
        crate::coordination::registry::release_clone_hydration_permits(
            state,
            upstream_clone_permits,
        )
        .await
        .map_err(AppError::Internal)?;
        return forward_upstream_response(upstream_resp).await;
    }

    let status = upstream_resp.status();
    let forwarded_headers = collect_forwarded_response_headers(upstream_resp.headers());

    let (tx, rx) = mpsc::channel::<Result<Bytes, reqwest::Error>>(8);
    let completion_metrics = state.metrics.clone();
    let active_clone_guard =
        state.begin_active_clone(Protocol::Https, completion.cache_status.clone());
    let state_for_stream = state.clone();
    let owner = owner.to_string();
    let repo = repo.to_string();
    let owner_repo_for_cache = owner_repo.clone();
    let auth_header = auth_header.map(ToOwned::to_owned);
    let request_phase = request_metadata.request_phase.clone();
    let ls_refs_request_body = capture_body.clone();
    let upstream_counter = state_for_stream
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
    let downstream_counter = state_for_stream
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
    let recent_advertised_refs = state_for_stream
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
    tokio::spawn(
        async move {
            let mut upstream_clone_permits = Some(upstream_clone_permits);
            let mut stream = upstream_resp.bytes_stream();
            let mut ls_refs_response =
                if request_phase == crate::tee_hydration::UploadPackRequestPhase::V2LsRefs {
                    Some(Vec::new())
                } else {
                    None
                };
            let mut hydration = UpstreamHydrationTracker::start(
                &state_for_stream,
                &owner,
                &repo,
                auth_header.as_deref(),
                "http",
                UpstreamHydrationRequest {
                    advertised_refs: advertised_refs.as_ref(),
                    request_body: &capture_body,
                    enable_hydration: request_phase.expects_local_pack_serve(),
                },
            )
            .await;

            while let Some(item) = stream.next().await {
                match item {
                    Ok(chunk) => {
                        let chunk_len = chunk.len() as u64;
                        upstream_counter.inc_by(chunk_len);
                        let capture_chunk = chunk.clone();

                        if tx.send(Ok(chunk)).await.is_err() {
                            hydration.handle_stream_error().await;
                            if let Some(permits) = upstream_clone_permits.take()
                                && let Err(error) =
                                    crate::coordination::registry::release_clone_hydration_permits(
                                        &state_for_stream,
                                        permits,
                                    )
                                    .await
                            {
                                warn!(
                                    repo = %owner_repo_for_cache,
                                    error = %error,
                                    "failed to release upstream upload-pack proxy permits after client disconnect"
                                );
                            }
                            return;
                        }
                        downstream_counter.inc_by(chunk_len);

                        if let Some(response_buf) = ls_refs_response.as_mut() {
                            response_buf.extend_from_slice(&capture_chunk);
                        }
                        hydration.record_response_chunk(capture_chunk).await;
                    }
                    Err(e) => {
                        hydration.handle_stream_error().await;
                        let _ = tx.send(Err(e)).await;
                        if let Some(permits) = upstream_clone_permits.take()
                            && let Err(error) =
                                crate::coordination::registry::release_clone_hydration_permits(
                                    &state_for_stream,
                                    permits,
                                )
                                .await
                        {
                            warn!(
                                repo = %owner_repo_for_cache,
                                error = %error,
                                "failed to release upstream upload-pack proxy permits after upstream stream error"
                            );
                        }
                        return;
                    }
                }
            }
            if let Some(ls_refs_response) = ls_refs_response {
                state_for_stream
                    .merge_recent_advertised_refs(
                        owner_repo_for_cache.clone(),
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
            if let Some(permits) = upstream_clone_permits.take()
                && let Err(error) = crate::coordination::registry::release_clone_hydration_permits(
                    &state_for_stream,
                    permits,
                )
                .await
            {
                warn!(
                    repo = %owner_repo_for_cache,
                    error = %error,
                    "failed to release upstream upload-pack proxy permits"
                );
            }
        }
        .instrument(tracing::Span::current()),
    );

    let body = Body::from_stream(CloneCompletionStream::new(
        ReceiverStream::new(rx),
        completion_metrics,
        Protocol::Https,
        completion,
        Some(CloneSource::Upstream),
        active_clone_guard,
    ));

    Ok(response_from_upstream_parts(
        status,
        forwarded_headers,
        body,
    ))
}

async fn proxy_receive_pack_to_upstream(
    state: &AppState,
    owner: &str,
    repo: &str,
    body: Bytes,
    request_headers: &HeaderMap,
) -> Result<Response, AppError> {
    let upstream_url = format!(
        "{}/{}/{}/git-receive-pack",
        state.config.upstream.git_url_base(),
        owner,
        repo,
    );

    let upstream_req =
        apply_forwarded_request_headers(state.http_client.post(&upstream_url), request_headers);
    let upstream_resp = upstream_req
        .body(body)
        .send()
        .await
        .context("failed to reach upstream forge for receive-pack")?;

    Ok(stream_upstream_response(upstream_resp))
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Application-level error type that maps cleanly to HTTP responses.
#[derive(Debug)]
pub enum AppError {
    /// The caller is not authenticated or not authorised.
    Unauthorized(String),
    /// The requested resource does not exist.
    NotFound(String),
    /// The request is malformed.
    BadRequest(String),
    /// Forward an upstream rate-limit response to the client.
    UpstreamRateLimited {
        status: StatusCode,
        headers: Vec<(String, String)>,
        body: String,
    },
    /// Ask the fronting proxy to retry this Git request directly against the
    /// upstream forge.
    UpstreamFallback(String),
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
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg).into_response(),
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
            AppError::UpstreamFallback(msg) => {
                let status = StatusCode::from_u16(530).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
                let mut response = (status, msg).into_response();
                response.headers_mut().insert(
                    HeaderName::from_static("x-forgeproxy-upstream-fallback"),
                    HeaderValue::from_static("1"),
                );
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
    use brotli::CompressorWriter;
    use flate2::Compression;
    use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
    use std::io::Write;

    fn sample_v2_fetch_request() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&crate::http::protocolv2::encode_pkt_line(
            b"command=fetch\n",
        ));
        body.extend_from_slice(&crate::http::protocolv2::encode_pkt_line(
            b"agent=git/2.51.2-Linux\n",
        ));
        body.extend_from_slice(&crate::http::protocolv2::encode_pkt_line(
            b"want 0123456789abcdef0123456789abcdef01234567\n",
        ));
        body.extend_from_slice(b"0000");
        body
    }

    fn gzip_body(body: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(body).unwrap();
        encoder.finish().unwrap()
    }

    fn zlib_body(body: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(body).unwrap();
        encoder.finish().unwrap()
    }

    fn deflate_body(body: &[u8]) -> Vec<u8> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(body).unwrap();
        encoder.finish().unwrap()
    }

    fn brotli_body(body: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::new();
        {
            let mut encoder = CompressorWriter::new(&mut encoded, 4096, 5, 22);
            encoder.write_all(body).unwrap();
            encoder.flush().unwrap();
        }
        encoded
    }

    fn assert_decoded_fetch(headers: HeaderMap, encoded: Vec<u8>) {
        let decoded = normalized_upload_pack_request_body(&headers, &Bytes::from(encoded)).unwrap();
        let metadata =
            crate::tee_hydration::parse_upload_pack_request_metadata(&decoded, Some("version=2"))
                .unwrap();

        assert_eq!(
            metadata.request_phase,
            crate::tee_hydration::UploadPackRequestPhase::V2Fetch
        );
        assert_eq!(
            metadata.want_oids,
            vec!["0123456789abcdef0123456789abcdef01234567".to_string()]
        );
    }

    #[test]
    fn normalized_upload_pack_request_body_decodes_gzip() {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Encoding", HeaderValue::from_static("gzip"));
        assert_decoded_fetch(headers, gzip_body(&sample_v2_fetch_request()));
    }

    #[test]
    fn normalized_upload_pack_request_body_decodes_zlib_deflate() {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Encoding", HeaderValue::from_static("deflate"));
        assert_decoded_fetch(headers, zlib_body(&sample_v2_fetch_request()));
    }

    #[test]
    fn normalized_upload_pack_request_body_decodes_raw_deflate() {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Encoding", HeaderValue::from_static("deflate"));
        assert_decoded_fetch(headers, deflate_body(&sample_v2_fetch_request()));
    }

    #[test]
    fn normalized_upload_pack_request_body_decodes_brotli() {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Encoding", HeaderValue::from_static("br"));
        assert_decoded_fetch(headers, brotli_body(&sample_v2_fetch_request()));
    }

    #[test]
    fn normalized_upload_pack_request_body_decodes_zstd() {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Encoding", HeaderValue::from_static("zstd"));
        assert_decoded_fetch(
            headers,
            zstd::encode_all(Cursor::new(sample_v2_fetch_request()), 1).unwrap(),
        );
    }

    #[test]
    fn normalized_upload_pack_request_body_decodes_stacked_encodings() {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Encoding", HeaderValue::from_static("br, gzip"));
        let once = brotli_body(&sample_v2_fetch_request());
        let twice = gzip_body(&once);
        assert_decoded_fetch(headers, twice);
    }

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
