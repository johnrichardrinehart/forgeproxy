//! Archive / tarball caching proxy handler.
//!
//! Serves archive requests (`/:owner/:repo/archive/*rest`) with a three-tier
//! cache: local disk → S3 → upstream forge.  Mutable refs (branches, tags) are
//! resolved to their commit SHA via the forge API so that cache keys are
//! stable for the same content.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use axum::{
    body::Body,
    extract::{Path as AxumPath, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::ReaderStream;
use tracing::{debug, info, instrument, warn};

use super::handler::{AppError, extract_optional_auth_header, validate_path_segment};
use crate::AppState;
use crate::cache::archive::{
    archive_local_path, archive_s3_key, download_from_s3, parse_archive_rest, s3_cache_hit,
    tee_upstream_to_cache,
};

/// Validate that the `rest` segment of an archive URL is safe.
///
/// Rejects path traversal attempts and null bytes.
fn validate_archive_rest(rest: &str) -> Result<(), AppError> {
    if rest.is_empty() {
        return Err(AppError::Unauthorized(
            "archive ref must not be empty".into(),
        ));
    }
    if rest.contains('\0') || rest.contains("..") {
        return Err(AppError::Unauthorized(format!(
            "invalid archive ref: {rest:?}"
        )));
    }
    Ok(())
}

fn archive_rest(ref_name: &str, ext: &str) -> String {
    format!("{ref_name}{ext}")
}

fn archive_redirect_path(owner: &str, repo: &str, ref_name: &str, ext: &str) -> String {
    format!("/{owner}/{repo}/archive/{}", archive_rest(ref_name, ext))
}

fn archive_download_filename(repo: &str, ref_name: &str, ext: &str) -> String {
    format!("{}-{}{}", repo, ref_name.replace('/', "-"), ext)
}

#[allow(clippy::too_many_arguments)]
fn apply_archive_response_headers(
    response: &mut Response,
    repo: &str,
    ref_name: &str,
    ext: &str,
    content_length: Option<u64>,
    content_disposition: Option<&str>,
    cache_control: Option<&str>,
    etag: Option<&str>,
    last_modified: Option<&str>,
) {
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        content_type_for_ext(ext).parse().unwrap(),
    );
    if let Some(length) = content_length
        && let Ok(length) = HeaderValue::from_str(&length.to_string())
    {
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, length);
    }
    let disposition = content_disposition.map(str::to_string).unwrap_or_else(|| {
        format!(
            "attachment; filename=\"{}\"",
            archive_download_filename(repo, ref_name, ext)
        )
    });
    if let Ok(disposition) = HeaderValue::from_str(&disposition) {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, disposition);
    }
    if let Some(cache_control) = cache_control
        && let Ok(cache_control) = HeaderValue::from_str(cache_control)
    {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, cache_control);
    }
    if let Some(etag) = etag
        && let Ok(etag) = HeaderValue::from_str(etag)
    {
        response.headers_mut().insert(header::ETAG, etag);
    }
    if let Some(last_modified) = last_modified
        && let Ok(last_modified) = HeaderValue::from_str(last_modified)
    {
        response
            .headers_mut()
            .insert(header::LAST_MODIFIED, last_modified);
    }
}

async fn resolve_archive_ref_name(
    state: &AppState,
    owner: &str,
    repo: &str,
    auth_header: Option<&str>,
    requested_ref: Option<&str>,
) -> Result<String, AppError> {
    if let Some(git_ref) = requested_ref {
        if git_ref.is_empty() {
            return Err(AppError::Unauthorized(
                "archive ref must not be empty".into(),
            ));
        }
        return Ok(git_ref.to_string());
    }

    state
        .forge
        .resolve_default_branch(
            &state.http_client,
            owner,
            repo,
            auth_header,
            &state.rate_limit,
        )
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound(format!("default branch not found for {owner}/{repo}")))
}

/// Handle an archive request with three-tier caching.
///
/// 1. Validate inputs and authenticate the caller.
/// 2. Parse the ref name and extension from the URL rest segment.
/// 3. Resolve the ref to a commit SHA via the forge API.
/// 4. Check local disk cache, then S3, then fetch from upstream.
/// 5. Stream the response back to the client.
#[instrument(skip(state, headers), fields(%owner, %repo, %rest))]
pub async fn handle_archive(
    State(state): State<Arc<AppState>>,
    AxumPath((owner, repo, rest)): AxumPath<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // ---------- validation ----------
    validate_path_segment(&owner, "owner")?;
    validate_path_segment(&repo, "repo")?;
    validate_archive_rest(&rest)?;

    // ---------- auth ----------
    let auth_header = extract_optional_auth_header(&headers);
    crate::auth::http_validator::validate_http_auth(&state, auth_header.as_deref(), &owner, &repo)
        .await?;

    // ---------- parse rest → (ref_name, ext) ----------
    let (ref_name, ext) = parse_archive_rest(&rest)
        .ok_or_else(|| AppError::NotFound(format!("unrecognised archive format: {rest}")))?;

    // ---------- resolve ref → SHA ----------
    let sha = state
        .forge
        .resolve_ref(
            &state.http_client,
            &owner,
            &repo,
            &ref_name,
            auth_header.as_deref(),
            &state.rate_limit,
        )
        .await
        .map_err(|e| {
            warn!(error = %e, %ref_name, "ref resolution failed");
            AppError::Internal(e)
        })?
        .ok_or_else(|| AppError::NotFound(format!("ref not found: {ref_name}")))?;

    debug!(%ref_name, %sha, "resolved archive ref");

    // ---------- cache paths ----------
    let local_path = archive_local_path(
        &state.cache_manager.base_path,
        &owner,
        &repo,
        &ref_name,
        &sha,
        &ext,
    );
    let config = state.config();
    let s3_key = archive_s3_key(
        &config.storage.s3.prefix,
        &owner,
        &repo,
        &ref_name,
        &sha,
        &ext,
    );
    let bucket = &config.storage.s3.bucket;

    // ---------- 1. Local disk hit ----------
    if local_path.exists() {
        info!(path = %local_path.display(), "archive cache hit (local)");
        state.metrics.metrics.archive_cache_hits_local.inc();
        return serve_local_file(&local_path, &repo, &ref_name, &ext).await;
    }

    // ---------- 2. S3 hit ----------
    if s3_cache_hit(&state.s3_client, bucket, &s3_key).await {
        info!(%s3_key, "archive cache hit (S3)");
        state.metrics.metrics.archive_cache_hits_s3.inc();

        if let Err(e) = download_from_s3(&state.s3_client, bucket, &s3_key, &local_path).await {
            warn!(error = %e, "S3 download failed, falling through to upstream");
        } else {
            return serve_local_file(&local_path, &repo, &ref_name, &ext).await;
        }
    }

    // ---------- 3. Cache miss → fetch from upstream ----------
    info!("archive cache miss, fetching from upstream");
    state.metrics.metrics.archive_cache_misses.inc();

    let upstream_url = format!(
        "https://{}/{}/{}/archive/{}",
        state.config().upstream.hostname,
        owner,
        repo,
        rest,
    );

    debug!(%upstream_url, "proxying archive request to upstream forge");

    let mut upstream_req = state.http_client.get(&upstream_url);
    if let Some(header) = auth_header.as_deref() {
        upstream_req = upstream_req.header(header::AUTHORIZATION, header);
    }
    let upstream_resp = upstream_req
        .send()
        .await
        .context("failed to reach upstream forge for archive")?;

    let status = upstream_resp.status();
    if !status.is_success() {
        let body_text = upstream_resp
            .text()
            .await
            .unwrap_or_else(|_| String::from("<unreadable>"));
        warn!(%status, "upstream forge returned error for archive request");
        return Ok((
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            body_text,
        )
            .into_response());
    }

    let content_length = upstream_resp.content_length();
    let content_disposition = upstream_resp
        .headers()
        .get(header::CONTENT_DISPOSITION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let cache_control = upstream_resp
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let etag = upstream_resp
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let last_modified = upstream_resp
        .headers()
        .get(header::LAST_MODIFIED)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    // Tee the upstream response to both the client and the local disk cache.
    let (rx, tee_handle) = tee_upstream_to_cache(upstream_resp, local_path.clone());

    let body = Body::from_stream(ReceiverStream::new(rx));

    // Background: after the tee completes, upload to S3.
    let s3_client = state.s3_client.clone();
    let metrics = state.metrics.clone();
    let s3_bucket = bucket.clone();
    let s3_key_owned = s3_key.clone();
    let local_path_bg = local_path.clone();
    tokio::spawn(async move {
        // Wait for the tee to finish writing.
        if let Err(e) = tee_handle.await {
            warn!(error = %e, "tee task panicked");
            return;
        }
        // Upload to S3 if the file was written successfully.
        if local_path_bg.exists() {
            if let Err(e) = crate::storage::s3::upload_bundle(
                &s3_client,
                &metrics,
                &s3_bucket,
                &s3_key_owned,
                &local_path_bg,
            )
            .await
            {
                warn!(error = %e, "background S3 upload for archive failed");
            } else {
                debug!(key = %s3_key_owned, "archive uploaded to S3");
            }
        }
    });

    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::OK;
    apply_archive_response_headers(
        &mut response,
        &repo,
        &ref_name,
        &ext,
        content_length,
        content_disposition.as_deref(),
        cache_control.as_deref(),
        etag.as_deref(),
        last_modified.as_deref(),
    );

    Ok(response)
}

#[instrument(skip(state, headers), fields(%owner, %repo, %ext))]
pub async fn handle_api_archive_redirect(
    State(state): State<Arc<AppState>>,
    AxumPath((owner, repo, requested_ref)): AxumPath<(String, String, Option<String>)>,
    headers: HeaderMap,
    ext: &'static str,
) -> Result<Response, AppError> {
    validate_path_segment(&owner, "owner")?;
    validate_path_segment(&repo, "repo")?;

    let auth_header = extract_optional_auth_header(&headers);
    crate::auth::http_validator::validate_http_auth(&state, auth_header.as_deref(), &owner, &repo)
        .await?;

    let ref_name = resolve_archive_ref_name(
        &state,
        &owner,
        &repo,
        auth_header.as_deref(),
        requested_ref.as_deref(),
    )
    .await?;
    let rest = archive_rest(&ref_name, ext);
    validate_archive_rest(&rest)?;

    Ok((
        StatusCode::FOUND,
        [(
            header::LOCATION,
            archive_redirect_path(&owner, &repo, &ref_name, ext),
        )],
    )
        .into_response())
}

pub async fn handle_tarball_redirect_without_ref(
    state: State<Arc<AppState>>,
    AxumPath((owner, repo)): AxumPath<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    handle_api_archive_redirect(state, AxumPath((owner, repo, None)), headers, ".tar.gz").await
}

pub async fn handle_tarball_redirect_with_ref(
    state: State<Arc<AppState>>,
    AxumPath((owner, repo, git_ref)): AxumPath<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    handle_api_archive_redirect(
        state,
        AxumPath((owner, repo, Some(git_ref))),
        headers,
        ".tar.gz",
    )
    .await
}

pub async fn handle_zipball_redirect_without_ref(
    state: State<Arc<AppState>>,
    AxumPath((owner, repo)): AxumPath<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    handle_api_archive_redirect(state, AxumPath((owner, repo, None)), headers, ".zip").await
}

pub async fn handle_zipball_redirect_with_ref(
    state: State<Arc<AppState>>,
    AxumPath((owner, repo, git_ref)): AxumPath<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    handle_api_archive_redirect(
        state,
        AxumPath((owner, repo, Some(git_ref))),
        headers,
        ".zip",
    )
    .await
}

/// Serve a cached archive file from local disk.
async fn serve_local_file(
    path: &Path,
    repo: &str,
    ref_name: &str,
    ext: &str,
) -> Result<Response, AppError> {
    let file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("open cached archive: {}", path.display()))?;
    let metadata = tokio::fs::metadata(path)
        .await
        .with_context(|| format!("stat cached archive: {}", path.display()))?;

    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::OK;
    apply_archive_response_headers(
        &mut response,
        repo,
        ref_name,
        ext,
        Some(metadata.len()),
        None,
        None,
        None,
        None,
    );

    Ok(response)
}

/// Map an archive extension to an appropriate Content-Type.
fn content_type_for_ext(ext: &str) -> &'static str {
    match ext {
        ".tar.gz" | ".tgz" => "application/gzip",
        ".tar.bz2" => "application/x-bzip2",
        ".tar.xz" => "application/x-xz",
        ".tar" => "application/x-tar",
        ".zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_archive_rest_accepts_normal() {
        assert!(validate_archive_rest("main.tar.gz").is_ok());
        assert!(validate_archive_rest("refs/heads/main.tar.gz").is_ok());
        assert!(validate_archive_rest("v1.2.3.zip").is_ok());
    }

    #[test]
    fn validate_archive_rest_rejects_empty() {
        assert!(validate_archive_rest("").is_err());
    }

    #[test]
    fn validate_archive_rest_rejects_traversal() {
        assert!(validate_archive_rest("../../etc/passwd.tar.gz").is_err());
        assert!(validate_archive_rest("main/../other.tar.gz").is_err());
    }

    #[test]
    fn validate_archive_rest_rejects_null_byte() {
        assert!(validate_archive_rest("main\0.tar.gz").is_err());
    }

    #[test]
    fn api_archive_redirect_path_uses_archive_route() {
        assert_eq!(
            archive_redirect_path("acme", "widgets", "refs/heads/main", ".tar.gz"),
            "/acme/widgets/archive/refs/heads/main.tar.gz"
        );
    }

    #[test]
    fn archive_download_filename_sanitizes_ref_name() {
        assert_eq!(
            archive_download_filename("widgets", "refs/heads/main", ".tar.gz"),
            "widgets-refs-heads-main.tar.gz"
        );
    }

    #[test]
    fn content_type_mapping() {
        assert_eq!(content_type_for_ext(".tar.gz"), "application/gzip");
        assert_eq!(content_type_for_ext(".tgz"), "application/gzip");
        assert_eq!(content_type_for_ext(".zip"), "application/zip");
        assert_eq!(content_type_for_ext(".tar"), "application/x-tar");
        assert_eq!(content_type_for_ext(".tar.bz2"), "application/x-bzip2");
        assert_eq!(content_type_for_ext(".tar.xz"), "application/x-xz");
        assert_eq!(content_type_for_ext(".unknown"), "application/octet-stream");
    }
}
