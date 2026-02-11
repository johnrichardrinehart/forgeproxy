//! Hydrate local bare repos from S3 bundles.
//!
//! When a repo exists in S3 (warm cache) but not locally, the hydrator
//! downloads the bundle-list, fetches all referenced bundles in creation-token
//! order, initialises a bare repo, and unbundles them.

use std::path::PathBuf;

use anyhow::{Context, Result};
use tracing::{debug, info, instrument};

use crate::bundleuri::bundlelist::{parse_bundle_list, BundleEntry};
use crate::git::{bare_repo, commands};
use crate::storage::s3;
use crate::AppState;

/// Hydrate a local bare repository from S3-stored bundles.
///
/// 1. Download the bundle-list manifest from S3.
/// 2. Parse it to get individual bundle entries.
/// 3. Download each bundle in creation-token order (base first).
/// 4. Init a bare repo and unbundle each in order.
/// 5. Set the remote to the upstream GHE URL.
///
/// Returns the path to the hydrated bare repo.
#[instrument(skip(state), fields(%owner_repo))]
pub async fn hydrate_from_s3(state: &AppState, owner_repo: &str) -> Result<PathBuf> {
    let repo_path = state.cache_manager.ensure_repo_dir(owner_repo)?;

    // 1. Determine the S3 key for the bundle-list.
    let bundle_list_key = format!("{owner_repo}/bundle-list");

    // 2. Download bundle-list content.
    let bundle_list_tmp =
        tempfile::NamedTempFile::new().context("failed to create temp file for bundle-list")?;

    s3::download_bundle(
        &state.s3_client,
        &state.config.storage.s3.bucket,
        &bundle_list_key,
        bundle_list_tmp.path(),
    )
    .await
    .with_context(|| format!("failed to download bundle-list for {owner_repo}"))?;

    let bundle_list_content = tokio::fs::read_to_string(bundle_list_tmp.path())
        .await
        .context("failed to read bundle-list file")?;

    let mut entries =
        parse_bundle_list(&bundle_list_content).context("failed to parse bundle-list")?;

    if entries.is_empty() {
        anyhow::bail!("bundle-list for {owner_repo} contains no entries");
    }

    // Sort by creation token ascending (base bundle first).
    entries.sort_by_key(|e| e.creation_token);

    info!(
        owner_repo,
        bundles = entries.len(),
        "hydrating repo from S3 bundles"
    );

    // 3. Init the bare repo.
    bare_repo::init_bare_repo(&repo_path).await?;

    // 4. Download and unbundle each entry.
    let tmp_dir = tempfile::tempdir().context("failed to create temp dir for bundles")?;

    for (i, entry) in entries.iter().enumerate() {
        let bundle_file = tmp_dir.path().join(format!("bundle-{i}.bundle"));

        // The URI in the bundle-list may be a presigned S3 URL or an S3 key.
        // For hydration we use the S3 key directly (we have credentials).
        let s3_key = extract_s3_key_from_entry(owner_repo, entry);

        debug!(
            owner_repo,
            bundle = %entry.name,
            s3_key = %s3_key,
            "downloading bundle"
        );

        s3::download_bundle(
            &state.s3_client,
            &state.config.storage.s3.bucket,
            &s3_key,
            &bundle_file,
        )
        .await
        .with_context(|| format!("failed to download bundle {}", entry.name))?;

        commands::git_bundle_unbundle(&bundle_file, &repo_path)
            .await
            .with_context(|| format!("failed to unbundle {}", entry.name))?;

        debug!(
            owner_repo,
            bundle = %entry.name,
            "unbundled successfully"
        );
    }

    // 5. Set the remote origin.
    let (clone_url, _credential) = crate::credentials::upstream::get_clone_url(
        &state.config,
        owner_repo.split('/').next().unwrap_or(""),
        owner_repo.split('/').nth(1).unwrap_or(""),
    )?;

    bare_repo::set_remote(&repo_path, "origin", &clone_url).await?;

    info!(owner_repo, "repo hydrated from S3");

    Ok(repo_path)
}

/// Best-effort extraction of the S3 object key from a bundle entry.
///
/// If the entry URI is a presigned URL, we strip the query string and
/// extract the path component.  Otherwise we build the key from the
/// owner/repo and bundle name.
fn extract_s3_key_from_entry(owner_repo: &str, entry: &BundleEntry) -> String {
    // If the URI contains '?', it's likely a presigned URL.  Try to
    // extract the path.
    if let Some(path_part) = entry.uri.split('?').next() {
        if let Ok(url) = url::Url::parse(path_part) {
            let path = url.path().trim_start_matches('/');
            if !path.is_empty() {
                return path.to_string();
            }
        }
    }

    // Fallback: construct from owner_repo and bundle name.
    format!("{owner_repo}/{}.bundle", entry.name)
}
