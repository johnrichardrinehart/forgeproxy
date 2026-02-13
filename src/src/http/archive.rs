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
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::ReaderStream;
use tracing::{debug, info, instrument, warn};

use super::handler::{AppError, extract_auth_header, validate_path_segment};
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
    let auth_header = extract_auth_header(&headers)?;
    crate::auth::http_validator::validate_http_auth(&state, &auth_header, &owner, &repo)
        .await
        .map_err(|e| {
            warn!(error = %e, "archive auth validation failed");
            AppError::Unauthorized(e.to_string())
        })?;

    // ---------- parse rest → (ref_name, ext) ----------
    let (ref_name, ext) = parse_archive_rest(&rest)
        .ok_or_else(|| AppError::Unauthorized(format!("unrecognised archive format: {rest}")))?;

    // ---------- resolve ref → SHA ----------
    let sha = state
        .forge
        .resolve_ref(
            &state.http_client,
            &owner,
            &repo,
            &ref_name,
            &auth_header,
            &state.rate_limit,
        )
        .await
        .map_err(|e| {
            warn!(error = %e, %ref_name, "ref resolution failed");
            AppError::Internal(e)
        })?
        .ok_or_else(|| AppError::Unauthorized(format!("ref not found: {ref_name}")))?;

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
    let s3_key = archive_s3_key(
        &state.config.storage.s3.prefix,
        &owner,
        &repo,
        &ref_name,
        &sha,
        &ext,
    );
    let bucket = &state.config.storage.s3.bucket;

    // ---------- 1. Local disk hit ----------
    if local_path.exists() {
        info!(path = %local_path.display(), "archive cache hit (local)");
        state.metrics.metrics.archive_cache_hits_local.inc();
        return serve_local_file(&local_path, &ext).await;
    }

    // ---------- 2. S3 hit ----------
    if s3_cache_hit(&state.s3_client, bucket, &s3_key).await {
        info!(%s3_key, "archive cache hit (S3)");
        state.metrics.metrics.archive_cache_hits_s3.inc();

        if let Err(e) = download_from_s3(&state.s3_client, bucket, &s3_key, &local_path).await {
            warn!(error = %e, "S3 download failed, falling through to upstream");
        } else {
            return serve_local_file(&local_path, &ext).await;
        }
    }

    // ---------- 3. Cache miss → fetch from upstream ----------
    info!("archive cache miss, fetching from upstream");
    state.metrics.metrics.archive_cache_misses.inc();

    let upstream_url = format!(
        "https://{}/{}/{}/archive/{}",
        state.config.upstream.hostname, owner, repo, rest,
    );

    debug!(%upstream_url, "proxying archive request to upstream forge");

    let upstream_resp = state
        .http_client
        .get(&upstream_url)
        .header(header::AUTHORIZATION, &auth_header)
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

    // Tee the upstream response to both the client and the local disk cache.
    let (rx, tee_handle) = tee_upstream_to_cache(upstream_resp, local_path.clone());

    let body = Body::from_stream(ReceiverStream::new(rx));

    // Background: after the tee completes, upload to S3.
    let s3_client = state.s3_client.clone();
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
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        content_type_for_ext(&ext).parse().unwrap(),
    );

    Ok(response)
}

/// Serve a cached archive file from local disk.
async fn serve_local_file(path: &Path, ext: &str) -> Result<Response, AppError> {
    let file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("open cached archive: {}", path.display()))?;

    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        content_type_for_ext(ext).parse().unwrap(),
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
