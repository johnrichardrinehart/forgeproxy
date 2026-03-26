//! Bundle-list serving for the Git `bundle-uri` protocol extension.
//!
//! When a Git client sees the `bundle-uri` capability in the protocol v2
//! info/refs response it will fetch the advertised bundle-list URL.  This
//! module generates that document on-the-fly from the current node's published
//! bundle metadata in S3, replacing the raw S3 keys with short-lived
//! pre-signed download URLs.
//!
//! # Bundle-list format
//!
//! ```text
//! [bundle]
//!     version = 1
//!     mode = all
//!     heuristic = creationToken
//!
//! [bundle "base"]
//!     uri = <presigned-url>
//!     creationToken = 1000
//!
//! [bundle "incremental-20240101"]
//!     uri = <presigned-url>
//!     creationToken = 1001
//! ```
//!
//! See `gitformat-bundle-uri(5)` for the full specification.

use std::fmt::Write as _;

use anyhow::{Context, Result};
use axum::{
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use tracing::{debug, instrument};

use crate::AppState;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Produce a Git bundle-list response for the given repository.
///
/// Returns `404 Not Found` if this node has not published a bundle for the
/// repo.
#[instrument(skip(state, auth_token), fields(%owner, %repo))]
pub async fn handle_bundle_list(
    state: &AppState,
    owner: &str,
    repo: &str,
    auth_token: Option<&str>,
) -> Result<Response> {
    // 1. Validate that the caller has at least read access.
    crate::auth::http_validator::validate_http_auth(state, auth_token, owner, repo)
        .await
        .context("bundle-list auth validation failed")?;

    let owner_repo = format!("{owner}/{repo}");
    let Some(metadata) =
        crate::coordination::registry::load_current_node_bundle_metadata(state, &owner_repo)
            .await
            .with_context(|| format!("failed to read bundle metadata for {owner_repo}"))?
    else {
        debug!(
            repo = %owner_repo,
            publisher_id = %state.bundle_publisher_id,
            "no bundle metadata published for this node"
        );
        return Ok((
            StatusCode::NOT_FOUND,
            "No bundles available for this repository.\n",
        )
            .into_response());
    };

    let presigned_ttl_secs = 60u64; // short-lived; clients fetch immediately
    let presigned_url = crate::storage::s3::generate_presigned_url(
        &state.s3_client,
        &state.config.storage.s3.bucket,
        &metadata.bundle_s3_key,
        presigned_ttl_secs,
    )
    .await
    .with_context(|| format!("failed to generate presigned URL for {owner_repo}"))?;

    let mut body = String::with_capacity(512);
    writeln!(body, "[bundle]")?;
    writeln!(body, "\tversion = 1")?;
    writeln!(body, "\tmode = all")?;
    writeln!(body, "\theuristic = creationToken")?;
    writeln!(body)?;
    writeln!(body, "[bundle \"{}\"]", metadata.publisher_id)?;
    writeln!(body, "\turi = {presigned_url}")?;
    writeln!(body, "\tcreationToken = {}", metadata.creation_token)?;

    debug!(
        repo = %owner_repo,
        publisher_id = %metadata.publisher_id,
        creation_token = metadata.creation_token,
        "generated bundle-list for {owner}/{repo}"
    );

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
        .into_response())
}
