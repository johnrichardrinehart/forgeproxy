//! Bundle generation utilities.
//!
//! Produces full and incremental Git bundles from bare repositories using the
//! `git bundle create` command. Bundles are written to temporary files via the
//! `tempfile` crate so that partially-written artifacts never appear in the
//! final storage path.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use tracing::{debug, info, instrument, warn};

use crate::git::commands;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Result of a bundle-creation operation.
#[derive(Debug)]
pub struct BundleResult {
    /// Keep the temporary directory alive until upload/publish is complete.
    _temp_dir: tempfile::TempDir,
    /// Path to the generated `.bundle` file on local disk.
    pub bundle_path: PathBuf,
    /// Monotonic creation token assigned to this bundle.
    pub creation_token: u64,
    /// Size of the bundle file in bytes.
    pub size_bytes: u64,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a full bundle of **all** refs in the bare repository.
#[instrument(skip(state), fields(%owner_repo))]
pub async fn generate_full_bundle(
    state: &crate::AppState,
    repo_path: &Path,
    owner_repo: &str,
) -> Result<BundleResult> {
    let started_at = Instant::now();
    let current_refs = get_refs(repo_path).await?;

    let tmp_dir = create_bundle_tempdir(state, "bundle")?;
    let bundle_path = tmp_dir
        .path()
        .join(format!("{}.full.bundle", owner_repo.replace('/', "_")));

    info!(
        owner_repo,
        refs = current_refs.len(),
        "creating full bundle"
    );

    // --all includes every ref.
    let _bundle_generation_permit = state
        .bundle_generation_semaphore
        .clone()
        .acquire_owned()
        .await
        .context("bundle generation semaphore closed")?;
    debug!(
        owner_repo,
        pack_threads = state.bundle_pack_threads,
        max_concurrent_generations = state.bundle_max_concurrency,
        "acquired bundle generation permit"
    );
    commands::git_bundle_create(
        repo_path,
        &bundle_path,
        None,
        None,
        state.bundle_pack_threads,
    )
    .await
    .with_context(|| format!("git bundle create (full) failed for {owner_repo}"))?;
    let included_refs: Vec<String> = current_refs.keys().cloned().collect();
    verify_bundle_or_log(
        repo_path,
        &bundle_path,
        owner_repo,
        "full",
        Some(&included_refs),
        0,
    )
    .await?;

    let metadata = tokio::fs::metadata(&bundle_path)
        .await
        .context("failed to stat bundle file")?;

    let creation_token =
        crate::bundleuri::creation_token::next_creation_token(state, owner_repo).await?;

    state.metrics.metrics.bundle_generation_total.inc();
    state
        .metrics
        .metrics
        .bundle_generation_duration_seconds
        .observe(started_at.elapsed().as_secs_f64());

    Ok(BundleResult {
        _temp_dir: tmp_dir,
        bundle_path,
        creation_token,
        size_bytes: metadata.len(),
    })
}

/// Generate a filtered (blobless) bundle of all refs.
///
/// Uses `git bundle create --filter=blob:none` which requires Git 2.40+.
/// On failure (e.g., Git version too old), logs a warning and returns the
/// error without panicking.
#[instrument(skip(state), fields(%owner_repo))]
pub async fn generate_filtered_bundle(
    state: &crate::AppState,
    repo_path: &Path,
    owner_repo: &str,
) -> Result<BundleResult> {
    let started_at = Instant::now();
    let current_refs = get_refs(repo_path).await?;
    let tmp_dir = create_bundle_tempdir(state, "filtered bundle")?;
    let bundle_path = tmp_dir
        .path()
        .join(format!("{}.filtered.bundle", owner_repo.replace('/', "_")));

    info!(owner_repo, "creating filtered (blob:none) bundle");

    let _bundle_generation_permit = state
        .bundle_generation_semaphore
        .clone()
        .acquire_owned()
        .await
        .context("bundle generation semaphore closed")?;
    debug!(
        owner_repo,
        pack_threads = state.bundle_pack_threads,
        max_concurrent_generations = state.bundle_max_concurrency,
        "acquired bundle generation permit"
    );
    commands::git_bundle_create_filtered(
        repo_path,
        &bundle_path,
        "blob:none",
        state.bundle_pack_threads,
    )
    .await
    .with_context(|| format!("filtered bundle create failed for {owner_repo}"))?;
    let included_refs: Vec<String> = current_refs.keys().cloned().collect();
    verify_bundle_or_log(
        repo_path,
        &bundle_path,
        owner_repo,
        "filtered",
        Some(&included_refs),
        0,
    )
    .await?;

    let metadata = tokio::fs::metadata(&bundle_path)
        .await
        .context("failed to stat filtered bundle file")?;

    let creation_token =
        crate::bundleuri::creation_token::next_creation_token(state, owner_repo).await?;

    state.metrics.metrics.bundle_generation_total.inc();
    state
        .metrics
        .metrics
        .bundle_generation_duration_seconds
        .observe(started_at.elapsed().as_secs_f64());

    Ok(BundleResult {
        _temp_dir: tmp_dir,
        bundle_path,
        creation_token,
        size_bytes: metadata.len(),
    })
}

/// Generate an incremental bundle containing objects reachable from current
/// refs but not reachable from the supplied base ref tips.
#[instrument(skip(state, base_refs), fields(%owner_repo, base_refs = base_refs.len()))]
pub async fn generate_incremental_bundle(
    state: &crate::AppState,
    repo_path: &Path,
    owner_repo: &str,
    base_refs: &HashMap<String, String>,
) -> Result<Option<BundleResult>> {
    let started_at = Instant::now();
    let current_refs = get_refs(repo_path).await?;
    if current_refs.is_empty() || current_refs == *base_refs {
        return Ok(None);
    }

    let mut refs = current_refs.keys().cloned().collect::<Vec<_>>();
    refs.sort();
    let mut not_refs = base_refs.values().cloned().collect::<Vec<_>>();
    not_refs.sort();
    not_refs.dedup();

    if refs.is_empty() || not_refs.is_empty() {
        return Ok(None);
    }

    let tmp_dir = create_bundle_tempdir(state, "incremental bundle")?;
    let bundle_path = tmp_dir.path().join(format!(
        "{}.incremental.bundle",
        owner_repo.replace('/', "_")
    ));

    info!(
        owner_repo,
        refs = refs.len(),
        not_refs = not_refs.len(),
        "creating incremental bundle"
    );

    let _bundle_generation_permit = state
        .bundle_generation_semaphore
        .clone()
        .acquire_owned()
        .await
        .context("bundle generation semaphore closed")?;
    commands::git_bundle_create(
        repo_path,
        &bundle_path,
        Some(&refs),
        Some(&not_refs),
        state.bundle_pack_threads,
    )
    .await
    .with_context(|| format!("git bundle create (incremental) failed for {owner_repo}"))?;
    verify_bundle_or_log(
        repo_path,
        &bundle_path,
        owner_repo,
        "incremental",
        Some(&refs),
        not_refs.len(),
    )
    .await?;

    let metadata = tokio::fs::metadata(&bundle_path)
        .await
        .context("failed to stat incremental bundle file")?;

    let creation_token =
        crate::bundleuri::creation_token::next_creation_token(state, owner_repo).await?;

    state.metrics.metrics.bundle_generation_total.inc();
    state
        .metrics
        .metrics
        .bundle_generation_duration_seconds
        .observe(started_at.elapsed().as_secs_f64());

    Ok(Some(BundleResult {
        _temp_dir: tmp_dir,
        bundle_path,
        creation_token,
        size_bytes: metadata.len(),
    }))
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

fn create_bundle_tempdir(state: &crate::AppState, context: &str) -> Result<tempfile::TempDir> {
    let cache_root = Path::new(&state.config.storage.local.path);
    let tmp_root = crate::cache::layout::state_bundle_tmp_root(cache_root);

    std::fs::create_dir_all(&tmp_root)
        .with_context(|| format!("failed to create bundle temp root {}", tmp_root.display()))?;

    let tmp_dir = tempfile::Builder::new()
        .prefix("forgeproxy-bundle-")
        .tempdir_in(&tmp_root)
        .with_context(|| format!("failed to create temp dir for {context}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(tmp_dir.path(), std::fs::Permissions::from_mode(0o770))
            .with_context(|| {
                format!(
                    "failed to set permissions on bundle temp dir {}",
                    tmp_dir.path().display()
                )
            })?;
    }

    Ok(tmp_dir)
}

async fn verify_bundle_or_log(
    repo_path: &Path,
    bundle_path: &Path,
    owner_repo: &str,
    bundle_kind: &str,
    included_refs: Option<&[String]>,
    excluded_object_count: usize,
) -> Result<()> {
    match commands::git_bundle_verify(repo_path, bundle_path).await {
        Ok(()) => Ok(()),
        Err(error) => {
            let bundle_size = tokio::fs::metadata(bundle_path)
                .await
                .map(|meta| meta.len())
                .unwrap_or_default();
            let included_ref_count = included_refs.map_or(0, <[String]>::len);
            let included_ref_sample = included_refs
                .map(|refs| {
                    refs.iter()
                        .take(5)
                        .cloned()
                        .collect::<Vec<String>>()
                        .join(",")
                })
                .unwrap_or_default();
            warn!(
                owner_repo,
                bundle_kind,
                bundle_path = %bundle_path.display(),
                bundle_size,
                included_ref_count,
                excluded_object_count,
                included_ref_sample,
                error = %error,
                error_debug = ?error,
                "git bundle verify failed"
            );
            Err(error).with_context(|| format!("git bundle verify failed for {owner_repo}"))
        }
    }
}
