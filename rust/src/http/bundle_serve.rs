//! Bundle-list serving for the Git `bundle-uri` protocol extension.
//!
//! When a Git client sees the `bundle-uri` capability in the protocol v2
//! info/refs response it will fetch the advertised bundle-list URL.  This
//! module generates that document on-the-fly from repo-global bundle manifest
//! metadata in S3, replacing the raw S3 keys with short-lived pre-signed
//! download URLs.
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

use anyhow::Context;
use axum::{
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use tracing::{debug, info, instrument};

use crate::AppState;
use crate::http::handler::AppError;

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
) -> Result<Response, AppError> {
    let owner_repo = crate::repo_identity::canonical_owner_repo(owner, repo);
    if state.config().repository_is_delegated(&owner_repo) {
        info!(
            repo = %owner_repo,
            "repository is delegated to upstream; refusing local bundle-list"
        );
        crate::metrics::inc_bundle_list_request(&state.metrics, &owner_repo, "delegated");
        return Ok((
            StatusCode::NOT_FOUND,
            "No bundles available for this repository.\n",
        )
            .into_response());
    }

    let org_credential_status =
        crate::credentials::org_policy::local_acceleration_status_for_repo(state, owner, repo)
            .await;
    if !org_credential_status.is_eligible() {
        crate::credentials::org_policy::log_local_acceleration_bypass(
            &org_credential_status,
            &owner_repo,
            "http",
            "bundle-list",
        );
        crate::metrics::inc_bundle_list_request(&state.metrics, &owner_repo, "not_managed");
        return Ok((
            StatusCode::NOT_FOUND,
            "No bundles available for this repository.\n",
        )
            .into_response());
    }

    // 1. Validate that the caller has at least read access.
    if let Err(error) =
        crate::auth::http_validator::validate_http_auth(state, auth_token, owner, repo).await
    {
        crate::metrics::inc_bundle_list_request(&state.metrics, &owner_repo, "auth_failed");
        debug!(error = ?error, "bundle-list auth validation failed");
        info!(
            repo = %owner_repo,
            result = "auth_failed",
            "bundle-list request completed"
        );
        return Err(error);
    }

    let Some(body) = bundle_list_body(state, &owner_repo)
        .await
        .with_context(|| format!("failed to build bundle list for {owner_repo}"))
        .map_err(|error| {
            crate::metrics::inc_bundle_list_request(
                &state.metrics,
                &owner_repo,
                "metadata_load_failed",
            );
            AppError::Internal(error)
        })?
    else {
        crate::metrics::inc_bundle_list_request(&state.metrics, &owner_repo, "missing_metadata");
        debug!(
            repo = %owner_repo,
            publisher_id = %state.bundle_publisher_id,
            "no bundle metadata published for this node"
        );
        info!(
            repo = %owner_repo,
            result = "missing_metadata",
            publisher_id = %state.bundle_publisher_id,
            "bundle-list request completed"
        );
        return Ok((
            StatusCode::NOT_FOUND,
            "No bundles available for this repository.\n",
        )
            .into_response());
    };

    crate::metrics::inc_bundle_list_request(&state.metrics, &owner_repo, "served");
    info!(
        repo = %owner_repo,
        result = "served",
        "bundle-list request completed"
    );

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
        .into_response())
}

pub async fn bundle_list_body(
    state: &AppState,
    owner_repo: &str,
) -> anyhow::Result<Option<String>> {
    let Some(manifest) =
        crate::coordination::registry::load_repo_bundle_manifest(state, owner_repo).await?
    else {
        return Ok(None);
    };
    if manifest.entries.is_empty() {
        return Ok(None);
    }

    let presigned_ttl_secs = 60u64; // short-lived; clients fetch immediately
    let config = state.config();
    let mut body = String::with_capacity(512);
    writeln!(body, "[bundle]")?;
    writeln!(body, "\tversion = 1")?;
    writeln!(body, "\tmode = all")?;
    writeln!(body, "\theuristic = creationToken")?;
    writeln!(body)?;
    for entry in &manifest.entries {
        let presigned_url = crate::storage::s3::generate_presigned_url(
            &state.s3_client,
            &config.storage.s3.bucket,
            &entry.bundle_s3_key,
            presigned_ttl_secs,
        )
        .await
        .with_context(|| format!("failed to generate presigned URL for {owner_repo}"))?;
        crate::metrics::inc_bundle_presign(&state.metrics, "success");

        writeln!(body)?;
        writeln!(body, "[bundle \"{}\"]", entry.id)?;
        writeln!(body, "\turi = {presigned_url}")?;
        writeln!(body, "\tcreationToken = {}", entry.creation_token)?;
        if let Some(filter) = entry.filter.as_deref() {
            writeln!(body, "\tfilter = {filter}")?;
        }
    }

    record_manifest_metrics(state, &manifest);
    info!(
        repo = %owner_repo,
        entries = manifest.entries.len(),
        "built bundle-list body"
    );

    Ok(Some(body))
}

pub async fn bundle_uri_command_response(
    state: &AppState,
    owner_repo: &str,
) -> anyhow::Result<Option<Vec<u8>>> {
    let Some(manifest) =
        crate::coordination::registry::load_repo_bundle_manifest(state, owner_repo).await?
    else {
        return Ok(None);
    };
    if manifest.entries.is_empty() {
        return Ok(None);
    }

    let mut body = Vec::new();
    let config = state.config();
    let mut lines = vec![
        "bundle.version=1\n".to_string(),
        "bundle.mode=all\n".to_string(),
        "bundle.heuristic=creationToken\n".to_string(),
    ];
    for entry in &manifest.entries {
        let presigned_url = crate::storage::s3::generate_presigned_url(
            &state.s3_client,
            &config.storage.s3.bucket,
            &entry.bundle_s3_key,
            60,
        )
        .await
        .with_context(|| format!("failed to generate presigned URL for {owner_repo}"))?;
        crate::metrics::inc_bundle_presign(&state.metrics, "success");
        lines.push(format!("bundle.{}.uri={presigned_url}\n", entry.id));
        lines.push(format!(
            "bundle.{}.creationToken={}\n",
            entry.id, entry.creation_token
        ));
        if let Some(filter) = entry.filter.as_deref() {
            lines.push(format!("bundle.{}.filter={filter}\n", entry.id));
        }
    }
    for line in lines {
        body.extend_from_slice(&crate::http::protocolv2::encode_pkt_line(line.as_bytes()));
    }
    body.extend_from_slice(b"0000");
    record_manifest_metrics(state, &manifest);
    Ok(Some(body))
}

fn record_manifest_metrics(state: &AppState, manifest: &crate::bundleuri::BundleManifest) {
    let full_entries = manifest
        .entries
        .iter()
        .filter(|entry| entry.filter.is_none())
        .count();
    let filtered_entries = manifest
        .entries
        .iter()
        .filter(|entry| entry.filter.is_some())
        .count();
    crate::metrics::set_bundle_manifest_entries(&state.metrics, "full", full_entries);
    crate::metrics::set_bundle_manifest_entries(&state.metrics, "filtered", filtered_entries);
}
