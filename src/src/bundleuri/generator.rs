//! Bundle generation utilities.
//!
//! Produces full, incremental, and filtered Git bundles from bare repositories
//! using the `git bundle create` command. Bundles are written to temporary
//! files via the `tempfile` crate so that partially-written artifacts never
//! appear in the final storage path.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::{debug, info, instrument, warn};

use crate::git::commands;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Result of a bundle-creation operation.
#[derive(Debug, Clone)]
pub struct BundleResult {
    /// Path to the generated `.bundle` file on local disk.
    pub bundle_path: PathBuf,
    /// Monotonic creation token assigned to this bundle.
    pub creation_token: u64,
    /// Size of the bundle file in bytes.
    pub size_bytes: u64,
    /// Number of refs included in the bundle.
    pub ref_count: usize,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate an incremental bundle containing only the refs that changed since
/// `since_refs`.
///
/// If `since_refs` is empty this behaves identically to
/// [`generate_full_bundle`].
#[instrument(skip(state, since_refs), fields(%owner_repo))]
pub async fn generate_incremental_bundle(
    state: &crate::AppState,
    repo_path: &Path,
    owner_repo: &str,
    since_refs: &HashMap<String, String>,
) -> Result<BundleResult> {
    let current_refs = get_refs(repo_path).await?;

    // Determine which refs are new or updated.
    let mut new_refs: Vec<String> = Vec::new();
    let mut old_oids: Vec<String> = Vec::new();

    for (refname, oid) in &current_refs {
        match since_refs.get(refname) {
            Some(prev_oid) if prev_oid == oid => {
                // Ref unchanged -- skip.
            }
            Some(prev_oid) => {
                // Ref was updated.
                new_refs.push(refname.clone());
                old_oids.push(prev_oid.clone());
            }
            None => {
                // Brand-new ref.
                new_refs.push(refname.clone());
            }
        }
    }

    if new_refs.is_empty() {
        debug!(owner_repo, "no new refs; generating full bundle instead");
        return generate_full_bundle(state, repo_path, owner_repo).await;
    }

    let tmp_dir = tempfile::tempdir().context("failed to create temp dir for bundle")?;
    let bundle_path = tmp_dir.path().join(format!(
        "{}.incremental.bundle",
        owner_repo.replace('/', "_")
    ));

    let not_refs: Vec<String> = old_oids;

    info!(
        owner_repo,
        new = new_refs.len(),
        excluded = not_refs.len(),
        "creating incremental bundle"
    );

    commands::git_bundle_create(
        repo_path,
        &bundle_path,
        Some(&new_refs),
        if not_refs.is_empty() {
            None
        } else {
            Some(&not_refs)
        },
    )
    .await
    .with_context(|| format!("git bundle create failed for {owner_repo}"))?;

    let metadata = tokio::fs::metadata(&bundle_path)
        .await
        .context("failed to stat bundle file")?;

    let creation_token =
        crate::bundleuri::creation_token::next_creation_token(state, owner_repo).await?;

    state.metrics.metrics.bundle_generation_total.inc();

    Ok(BundleResult {
        bundle_path,
        creation_token,
        size_bytes: metadata.len(),
        ref_count: new_refs.len(),
    })
}

/// Generate a full bundle of **all** refs in the bare repository.
#[instrument(skip(state), fields(%owner_repo))]
pub async fn generate_full_bundle(
    state: &crate::AppState,
    repo_path: &Path,
    owner_repo: &str,
) -> Result<BundleResult> {
    let current_refs = get_refs(repo_path).await?;

    let tmp_dir = tempfile::tempdir().context("failed to create temp dir for bundle")?;
    let bundle_path = tmp_dir
        .path()
        .join(format!("{}.full.bundle", owner_repo.replace('/', "_")));

    info!(
        owner_repo,
        refs = current_refs.len(),
        "creating full bundle"
    );

    // --all includes every ref.
    commands::git_bundle_create(repo_path, &bundle_path, None, None)
        .await
        .with_context(|| format!("git bundle create (full) failed for {owner_repo}"))?;

    let metadata = tokio::fs::metadata(&bundle_path)
        .await
        .context("failed to stat bundle file")?;

    let creation_token =
        crate::bundleuri::creation_token::next_creation_token(state, owner_repo).await?;

    state.metrics.metrics.bundle_generation_total.inc();

    Ok(BundleResult {
        bundle_path,
        creation_token,
        size_bytes: metadata.len(),
        ref_count: current_refs.len(),
    })
}

/// Generate a filtered bundle (e.g. `blob:none` for blobless clones).
///
/// This is a placeholder for future use; the `filter` string is passed
/// directly to `git bundle create --filter=<filter>`.
#[instrument(fields(%owner_repo, %filter))]
pub async fn generate_filtered_bundle(
    repo_path: &Path,
    owner_repo: &str,
    filter: &str,
) -> Result<BundleResult> {
    let current_refs = get_refs(repo_path).await?;

    let tmp_dir = tempfile::tempdir().context("failed to create temp dir for bundle")?;
    let bundle_path = tmp_dir
        .path()
        .join(format!("{}.filtered.bundle", owner_repo.replace('/', "_")));

    info!(
        owner_repo,
        filter,
        refs = current_refs.len(),
        "creating filtered bundle"
    );

    // Build a custom command to include the --filter flag.
    let status = tokio::process::Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .arg("bundle")
        .arg("create")
        .arg(&bundle_path)
        .arg("--all")
        .arg(format!("--filter={filter}"))
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .status()
        .await
        .context("failed to spawn git bundle create")?;

    if !status.success() {
        anyhow::bail!(
            "git bundle create --filter={filter} exited with status {status} for {owner_repo}"
        );
    }

    let metadata = tokio::fs::metadata(&bundle_path)
        .await
        .context("failed to stat filtered bundle file")?;

    // Filtered bundles currently get a token of 0; the caller is responsible
    // for assigning a real token if needed.
    warn!(
        owner_repo,
        "filtered bundle generated with placeholder creation_token=0"
    );

    Ok(BundleResult {
        bundle_path,
        creation_token: 0,
        size_bytes: metadata.len(),
        ref_count: current_refs.len(),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Enumerate all refs in a bare repository by running
/// `git for-each-ref --format='%(refname) %(objectname)'`.
///
/// Returns a map of `refname -> object_id`.
#[instrument]
pub async fn get_refs(repo_path: &Path) -> Result<HashMap<String, String>> {
    commands::git_for_each_ref(repo_path).await
}
