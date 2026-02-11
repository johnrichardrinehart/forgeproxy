//! Bundle-list serving for the Git `bundle-uri` protocol extension.
//!
//! When a Git client sees the `bundle-uri` capability in the protocol v2
//! info/refs response it will fetch the advertised bundle-list URL.  This
//! module generates that document on-the-fly from the bundle registry stored
//! in KeyDB, replacing the raw S3 keys with short-lived pre-signed download
//! URLs.
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
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use fred::interfaces::{HashesInterface, SortedSetsInterface};
use tracing::{debug, instrument};

use crate::AppState;

// ---------------------------------------------------------------------------
// KeyDB schema constants
// ---------------------------------------------------------------------------

/// KeyDB hash key that stores the bundle registry for a repository.
///
/// Structure: `HGETALL bundles:{owner}/{repo}` returns a map of
/// `bundle_name -> s3_object_key`.
fn bundle_registry_key(owner: &str, repo: &str) -> String {
    format!("bundles:{owner}/{repo}")
}

/// KeyDB sorted-set key that stores creation tokens (ordering) for bundles.
///
/// Structure: `ZSCORE bundle_tokens:{owner}/{repo} <bundle_name>` returns the
/// creation token.
fn bundle_tokens_key(owner: &str, repo: &str) -> String {
    format!("bundle_tokens:{owner}/{repo}")
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Produce a Git bundle-list response for the given repository.
///
/// Returns `404 Not Found` if no bundles are registered for the repo.
#[instrument(skip(state, auth_token), fields(%owner, %repo))]
pub async fn handle_bundle_list(
    state: &AppState,
    owner: &str,
    repo: &str,
    auth_token: &str,
) -> Result<Response> {
    // 1. Validate that the caller has at least read access.
    crate::auth::http_validator::validate_http_auth(state, auth_token, owner, repo)
        .await
        .context("bundle-list auth validation failed")?;

    // 2. Fetch the bundle registry from KeyDB.
    let registry: std::collections::HashMap<String, String> =
        HashesInterface::hgetall(&state.keydb, bundle_registry_key(owner, repo))
            .await
            .context("failed to read bundle registry from KeyDB")?;

    if registry.is_empty() {
        debug!("no bundles registered for {owner}/{repo}");
        return Ok((StatusCode::NOT_FOUND, "No bundles available for this repository.\n")
            .into_response());
    }

    // 3. Fetch creation tokens for ordering.
    let token_key = bundle_tokens_key(owner, repo);
    let bundle_names: Vec<String> = registry.keys().cloned().collect();

    // Retrieve tokens in bulk.  We build a map of name -> creationToken.
    let mut creation_tokens: std::collections::HashMap<String, u64> =
        std::collections::HashMap::new();

    for name in &bundle_names {
        let score: Option<f64> = SortedSetsInterface::zscore(&state.keydb, &token_key, name)
            .await
            .unwrap_or(None);
        let token = score.map(|s| s as u64).unwrap_or(0);
        creation_tokens.insert(name.clone(), token);
    }

    // 4. Sort bundles by creation token (ascending) so that the base bundle
    //    comes first.
    let mut sorted_bundles: Vec<(&String, &String)> = registry.iter().collect();
    sorted_bundles.sort_by_key(|(name, _)| creation_tokens.get(*name).copied().unwrap_or(0));

    // 5. Generate pre-signed S3 URLs for each bundle.
    let presigned_ttl_secs = 60u64; // short-lived; clients fetch immediately

    let mut body = String::with_capacity(512);
    writeln!(body, "[bundle]")?;
    writeln!(body, "\tversion = 1")?;
    writeln!(body, "\tmode = all")?;
    writeln!(body, "\theuristic = creationToken")?;

    for (name, s3_key) in &sorted_bundles {
        let presigned_url = crate::storage::s3::generate_presigned_url(
            &state.s3_client,
            &state.config.storage.s3.bucket,
            s3_key,
            presigned_ttl_secs,
        )
        .await
        .with_context(|| format!("failed to generate presigned URL for bundle {name}"))?;

        let token = creation_tokens.get(*name).copied().unwrap_or(0);

        writeln!(body)?;
        writeln!(body, "[bundle \"{name}\"]")?;
        writeln!(body, "\turi = {presigned_url}")?;
        writeln!(body, "\tcreationToken = {token}")?;
    }

    debug!(
        bundles = sorted_bundles.len(),
        "generated bundle-list for {owner}/{repo}"
    );

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
        .into_response())
}
