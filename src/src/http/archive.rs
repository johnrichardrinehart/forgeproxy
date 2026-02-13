//! Archive / tarball pass-through proxy handler.
//!
//! When nginx's cache layer has a miss for an archive request (e.g.
//! `/:owner/:repo/archive/:ref.tar.gz`), the request falls through to this
//! handler.  We validate the caller's credentials against GHE and then stream
//! the archive directly from upstream without buffering the entire payload.

use std::sync::Arc;

use anyhow::Context as _;
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode, header},
    response::{IntoResponse, Response},
};
use tracing::{debug, instrument, warn};

use super::handler::AppError;
use crate::AppState;

/// Handle an archive request that missed the nginx cache.
///
/// 1. Validate the `Authorization` header against the upstream GHE API.
/// 2. Forward the full request to GHE.
/// 3. Stream the response back to the client without buffering.
#[instrument(skip_all)]
pub async fn handle_archive(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Result<Response, AppError> {
    let headers = req.headers().clone();
    let uri = req.uri().clone();

    // ---------- auth ----------
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
        .ok_or_else(|| AppError::Unauthorized("missing Authorization header".into()))?;

    // We cannot easily extract owner/repo from every possible archive URL
    // shape, so we validate at the GHE level by proxying with the caller's
    // token.  GHE itself will return 404 if the user lacks access.

    // ---------- proxy to upstream ----------
    let upstream_url = format!(
        "https://{}{}",
        state.config.upstream.hostname,
        uri.path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or(uri.path()),
    );

    debug!(%upstream_url, "proxying archive request to GHE");

    let upstream_resp = state
        .http_client
        .get(&upstream_url)
        .header(header::AUTHORIZATION, &auth_header)
        .send()
        .await
        .context("failed to reach upstream GHE for archive")?;

    let status = upstream_resp.status();
    if !status.is_success() {
        let body_text = upstream_resp
            .text()
            .await
            .unwrap_or_else(|_| String::from("<unreadable>"));
        warn!(%status, "upstream GHE returned error for archive request");
        return Ok((
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            body_text,
        )
            .into_response());
    }

    // ---------- stream response ----------
    // Forward relevant headers from upstream.
    let mut resp_headers = HeaderMap::new();

    if let Some(ct) = upstream_resp.headers().get(header::CONTENT_TYPE) {
        resp_headers.insert(header::CONTENT_TYPE, ct.clone());
    }
    if let Some(cd) = upstream_resp.headers().get(header::CONTENT_DISPOSITION) {
        resp_headers.insert(header::CONTENT_DISPOSITION, cd.clone());
    }
    if let Some(cl) = upstream_resp.headers().get(header::CONTENT_LENGTH) {
        resp_headers.insert(header::CONTENT_LENGTH, cl.clone());
    }

    let body = Body::from_stream(upstream_resp.bytes_stream());

    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::OK;
    *response.headers_mut() = resp_headers;

    Ok(response)
}
