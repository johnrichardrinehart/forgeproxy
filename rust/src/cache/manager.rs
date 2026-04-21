//! On-disk bare-repo cache manager with water-mark-based eviction.
//!
//! Repos are exposed to readers under
//! `{base_path}/published/{owner}/{repo}.git`, with mutable mirrors and other
//! operational state stored in sibling subtrees. When disk usage exceeds the
//! configured high-water mark for the filesystem-relative cache budget, repos
//! that have an S3 bundle backup are evicted until usage drops below the
//! low-water mark.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use fred::interfaces::HashesInterface;
use tracing::{debug, info, warn};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use crate::AppState;
use crate::cache::layout;
use crate::config::{EvictionPolicy, LocalStorageConfig};

use super::{lfu, lru};

// ---------------------------------------------------------------------------
// CacheManager
// ---------------------------------------------------------------------------

/// Manages the local bare-repo cache on EBS-backed storage.
#[derive(Debug, Clone)]
pub struct CacheManager {
    /// Root directory for forgeproxy cache state (e.g. `/var/cache/forgeproxy`).
    pub base_path: PathBuf,
    /// Fraction of the backing filesystem capacity usable by forgeproxy cache state.
    pub max_percent: f64,
    /// Eviction starts when usage fraction exceeds this value (0.0 .. 1.0).
    pub high_water: f64,
    /// Eviction stops when usage fraction drops to or below this value.
    pub low_water: f64,
    /// Active eviction policy.
    pub eviction_policy: EvictionPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheMetricsSnapshot {
    pub total_apparent_usage_bytes: u64,
    pub total_physical_usage_bytes: u64,
    pub repo_count: usize,
    pub mirror_apparent_sizes: Vec<(String, u64)>,
    pub mirror_physical_sizes: Vec<(String, u64)>,
    pub subtree_apparent_sizes: Vec<(String, u64)>,
    pub subtree_physical_sizes: Vec<(String, u64)>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DiskUsage {
    pub apparent_bytes: u64,
    pub physical_bytes: u64,
}

impl CacheManager {
    /// Create a new [`CacheManager`] from the local storage configuration.
    pub fn new(config: &LocalStorageConfig) -> Self {
        Self {
            base_path: PathBuf::from(&config.path),
            max_percent: config.max_percent,
            high_water: config.high_water_mark,
            low_water: config.low_water_mark,
            eviction_policy: config.eviction_policy,
        }
    }

    /// Return the on-disk path for a repository identified by `owner/repo`.
    ///
    /// This is the stable published entry path exposed to readers. In the
    /// generation-based layout it is typically a symlink to an immutable
    /// generation directory under `.state/generations/`.
    pub fn repo_path(&self, owner_repo: &str) -> PathBuf {
        layout::reader_repo_path(&self.base_path, owner_repo)
    }

    /// Return the directory under which immutable generations are stored for a repo.
    pub fn repo_generations_dir(&self, owner_repo: &str) -> PathBuf {
        layout::state_generation_repo_dir(&self.base_path, owner_repo)
    }

    /// Return the persistent writer-owned mirror path for a repository.
    pub fn repo_mirror_path(&self, owner_repo: &str) -> PathBuf {
        layout::mirror_repo_path(&self.base_path, owner_repo)
    }

    /// Create a fresh delta workspace path for an incremental repo update.
    pub fn create_delta_repo_path(&self, owner_repo: &str) -> Result<PathBuf> {
        let delta_root = self.repo_delta_dir(owner_repo);
        std::fs::create_dir_all(&delta_root).with_context(|| {
            format!(
                "failed to create repo delta-work directory: {}",
                delta_root.display()
            )
        })?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        Ok(delta_root.join(format!("delta-{now}-{}.git", std::process::id())))
    }

    /// Create a fresh staging path for a new immutable generation.
    pub fn create_staging_repo_path(&self, owner_repo: &str) -> Result<PathBuf> {
        let generations_dir = self.repo_generations_dir(owner_repo);
        std::fs::create_dir_all(&generations_dir).with_context(|| {
            format!(
                "failed to create repo generations directory: {}",
                generations_dir.display()
            )
        })?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        Ok(generations_dir.join(format!("gen-{now}-{}.git", std::process::id())))
    }

    /// List immutable generation directories for a repository.
    pub fn list_generation_dirs(&self, owner_repo: &str) -> Result<Vec<PathBuf>> {
        let generations_dir = self.repo_generations_dir(owner_repo);
        if !generations_dir.exists() {
            return Ok(Vec::new());
        }

        let mut paths = Vec::new();
        for entry in std::fs::read_dir(&generations_dir).with_context(|| {
            format!(
                "failed to read repo generations directory: {}",
                generations_dir.display()
            )
        })? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                paths.push(path);
            }
        }

        paths.sort();
        Ok(paths)
    }

    /// Atomically publish a staged generation as the current repo entry.
    ///
    /// The staged generation becomes the new reader-visible snapshot. The most
    /// recent previously-published generation may remain as a retiring snapshot
    /// so in-flight readers can continue on the old target while new readers
    /// pick up the new one. Pruning is lease-aware and happens outside this
    /// method.
    pub fn publish_staged_repo(&self, owner_repo: &str, staged_repo_path: &Path) -> Result<()> {
        let published_path = self.repo_path(owner_repo);
        if let Some(parent) = published_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create published repo parent directory: {}",
                    parent.display()
                )
            })?;
        }

        if published_path.exists() {
            let metadata = std::fs::symlink_metadata(&published_path).with_context(|| {
                format!(
                    "failed to stat published repo path: {}",
                    published_path.display()
                )
            })?;

            if metadata.file_type().is_symlink() {
            } else {
                std::fs::remove_dir_all(&published_path).with_context(|| {
                    format!(
                        "failed to remove non-symlink published repo at {}",
                        published_path.display()
                    )
                })?;
            }
        }

        let temp_link = published_path.with_extension(format!(
            "git.tmp-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::os::unix::fs::symlink(staged_repo_path, &temp_link).with_context(|| {
            format!(
                "failed to create temporary published repo symlink {} -> {}",
                temp_link.display(),
                staged_repo_path.display()
            )
        })?;
        std::fs::rename(&temp_link, &published_path).with_context(|| {
            format!(
                "failed to publish staged repo {} at {}",
                staged_repo_path.display(),
                published_path.display()
            )
        })?;

        Ok(())
    }

    /// Resolve the concrete published generation currently exposed to readers.
    pub fn current_repo_target(&self, owner_repo: &str) -> Result<Option<PathBuf>> {
        let published_path = self.repo_path(owner_repo);
        if !published_path.exists() {
            return Ok(None);
        }

        let metadata = std::fs::symlink_metadata(&published_path).with_context(|| {
            format!(
                "failed to stat published repo path while resolving current target: {}",
                published_path.display()
            )
        })?;

        if metadata.file_type().is_symlink() {
            Ok(std::fs::read_link(&published_path).ok())
        } else {
            Ok(None)
        }
    }

    /// Remove every generation except the explicitly retained paths.
    ///
    /// Most publication paths should not need this directly now that
    /// [`publish_staged_repo`] retains only the current and retiring reader
    /// snapshots by default.
    pub fn prune_generations_except(&self, owner_repo: &str, retain: &[PathBuf]) -> Result<()> {
        let generations_dir = self.repo_generations_dir(owner_repo);
        if !generations_dir.exists() {
            return Ok(());
        }

        for path in self.list_generation_dirs(owner_repo)? {
            if retain.iter().any(|keep| keep == &path) {
                continue;
            }

            std::fs::remove_dir_all(&path).with_context(|| {
                format!(
                    "failed to remove stale repo generation at {}",
                    path.display()
                )
            })?;
        }

        Ok(())
    }

    /// Remove the published repo entry and all stored generations.
    pub async fn remove_repo_all(&self, owner_repo: &str) -> Result<()> {
        let published_path = self.repo_path(owner_repo);
        if published_path.exists() {
            let metadata = tokio::fs::symlink_metadata(&published_path)
                .await
                .with_context(|| {
                    format!(
                        "failed to stat published repo path for removal: {}",
                        published_path.display()
                    )
                })?;
            if metadata.file_type().is_symlink() {
                tokio::fs::remove_file(&published_path)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to remove published repo symlink: {}",
                            published_path.display()
                        )
                    })?;
            } else {
                tokio::fs::remove_dir_all(&published_path)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to remove invalid non-symlink published repo path: {}",
                            published_path.display()
                        )
                    })?;
            }
        }

        let generations_dir = self.repo_generations_dir(owner_repo);
        if generations_dir.exists() {
            tokio::fs::remove_dir_all(&generations_dir)
                .await
                .with_context(|| {
                    format!(
                        "failed to remove repo generations directory: {}",
                        generations_dir.display()
                    )
                })?;
        }

        let mirror_path = self.repo_mirror_path(owner_repo);
        if mirror_path.exists() {
            tokio::fs::remove_dir_all(&mirror_path)
                .await
                .with_context(|| {
                    format!(
                        "failed to remove repo mirror directory: {}",
                        mirror_path.display()
                    )
                })?;
        }

        let delta_dir = self.repo_delta_dir(owner_repo);
        if delta_dir.exists() {
            tokio::fs::remove_dir_all(&delta_dir)
                .await
                .with_context(|| {
                    format!(
                        "failed to remove repo delta-work directory: {}",
                        delta_dir.display()
                    )
                })?;
        }

        Ok(())
    }

    /// Remove the published repo entry and all stored generations, but keep
    /// the writer-owned mirror and transient workspaces intact.
    pub async fn remove_published_repo_generations(&self, owner_repo: &str) -> Result<()> {
        let published_path = self.repo_path(owner_repo);
        if published_path.exists() {
            let metadata = tokio::fs::symlink_metadata(&published_path)
                .await
                .with_context(|| {
                    format!(
                        "failed to stat published repo path for removal: {}",
                        published_path.display()
                    )
                })?;
            if metadata.file_type().is_symlink() {
                tokio::fs::remove_file(&published_path)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to remove published repo symlink: {}",
                            published_path.display()
                        )
                    })?;
            } else {
                tokio::fs::remove_dir_all(&published_path)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to remove invalid non-symlink published repo path: {}",
                            published_path.display()
                        )
                    })?;
            }
        }

        let generations_dir = self.repo_generations_dir(owner_repo);
        if generations_dir.exists() {
            tokio::fs::remove_dir_all(&generations_dir)
                .await
                .with_context(|| {
                    format!(
                        "failed to remove repo generations directory: {}",
                        generations_dir.display()
                    )
                })?;
        }

        Ok(())
    }

    /// Check whether a cached bare repo exists for `owner/repo` and looks
    /// like a usable bare Git repository.
    ///
    /// A `HEAD` file alone is not enough: partially initialised clone targets
    /// can contain the bare repo skeleton without any refs that `upload-pack`
    /// can actually serve. Reader-visible published state is only considered
    /// available when the writer-owned mirror exists too.
    pub fn has_repo(&self, owner_repo: &str) -> bool {
        is_usable_bare_repo(&self.repo_path(owner_repo)) && self.has_repo_mirror(owner_repo)
    }

    /// Check whether an arbitrary on-disk bare repo path looks usable.
    pub fn has_repo_at(&self, repo_path: &Path) -> bool {
        is_usable_bare_repo(repo_path)
    }

    /// Check whether the persistent writer-owned mirror exists and is usable.
    pub fn has_repo_mirror(&self, owner_repo: &str) -> bool {
        is_usable_bare_repo(&self.repo_mirror_path(owner_repo))
    }

    /// Walk [`base_path`] and return the physical bytes allocated by unique files.
    pub fn total_physical_usage_bytes(&self) -> Result<u64> {
        Ok(dir_usage(&self.base_path)?.physical_bytes)
    }

    pub(crate) fn total_usage_bytes(&self) -> Result<DiskUsage> {
        dir_usage(&self.base_path)
    }

    pub fn metrics_snapshot(&self) -> Result<CacheMetricsSnapshot> {
        let subtree_paths = [
            ("mirrors", layout::mirrors_root(&self.base_path)),
            ("snapshots", layout::snapshots_root(&self.base_path)),
            (
                "state_generations",
                layout::state_generations_root(&self.base_path),
            ),
            ("state_delta", layout::state_delta_root(&self.base_path)),
            ("state_tee", layout::state_tee_root(&self.base_path)),
        ];

        let mut subtree_apparent_sizes = Vec::with_capacity(subtree_paths.len());
        let mut subtree_physical_sizes = Vec::with_capacity(subtree_paths.len());
        for (subtree, path) in subtree_paths {
            let usage = dir_usage(&path)?;
            subtree_apparent_sizes.push((subtree.to_string(), usage.apparent_bytes));
            subtree_physical_sizes.push((subtree.to_string(), usage.physical_bytes));
        }
        let total_usage = self.total_usage_bytes()?;

        let mut mirror_apparent_sizes = Vec::new();
        let mut mirror_physical_sizes = Vec::new();
        for (owner_repo, repo_path) in self.list_mirror_repo_dirs()? {
            let usage = dir_usage(&repo_path)?;
            mirror_apparent_sizes.push((owner_repo.clone(), usage.apparent_bytes));
            mirror_physical_sizes.push((owner_repo, usage.physical_bytes));
        }
        let mirror_apparent_sizes = mirror_apparent_sizes;
        let mirror_physical_sizes = mirror_physical_sizes;

        Ok(CacheMetricsSnapshot {
            total_apparent_usage_bytes: total_usage.apparent_bytes,
            total_physical_usage_bytes: total_usage.physical_bytes,
            repo_count: self.list_repos()?.len(),
            mirror_apparent_sizes,
            mirror_physical_sizes,
            subtree_apparent_sizes,
            subtree_physical_sizes,
        })
    }

    pub fn budget_bytes(&self) -> Result<u64> {
        super::capacity::budget_bytes_for_path(&self.base_path, self.max_percent)
    }

    /// Return the current physical cache usage as a fraction of the
    /// filesystem-relative cache budget.
    pub fn physical_usage_fraction(&self) -> Result<f64> {
        let used = self.total_physical_usage_bytes()?;
        let budget = self.budget_bytes()?;
        Ok(used as f64 / budget as f64)
    }

    /// Return `true` when physical cache usage exceeds the high-water mark and
    /// eviction should be triggered.
    pub fn needs_eviction(&self) -> Result<bool> {
        let fraction = self.physical_usage_fraction()?;
        Ok(fraction > self.high_water)
    }

    /// Evict least-frequently-used repos until usage drops to or below the
    /// low-water mark.
    ///
    /// Only repos that have a confirmed S3 bundle backup are eligible for
    /// eviction -- repos without a bundle are skipped so they are not lost.
    ///
    /// Returns the number of repos evicted.
    pub async fn run_eviction(
        &self,
        state: &AppState,
        telemetry: Option<&super::telemetry::TelemetryBuffer>,
    ) -> Result<usize> {
        let repos = self.list_repos()?;
        if repos.is_empty() {
            return Ok(0);
        }

        // Select candidates using the configured eviction policy.
        let candidates = match self.eviction_policy {
            EvictionPolicy::Lfu => {
                lfu::get_eviction_candidates(&state.valkey, &repos, repos.len()).await?
            }
            EvictionPolicy::Lru => {
                lru::get_eviction_candidates(&state.valkey, &repos, repos.len()).await?
            }
        };

        let mut evicted: usize = 0;
        let mut repo_details: Vec<super::telemetry::RepoDetail> = Vec::new();

        for owner_repo in &candidates {
            // Collect metadata for telemetry before we possibly evict.
            let info = crate::coordination::registry::get_repo_info(&state.valkey, owner_repo)
                .await
                .ok()
                .flatten();

            // Re-check whether we still need to evict.
            let fraction = self.physical_usage_fraction()?;
            if fraction <= self.low_water {
                let usage = self.total_usage_bytes().unwrap_or_default();
                info!(
                    evicted,
                    physical_usage_fraction = fraction,
                    apparent_usage_bytes = usage.apparent_bytes,
                    physical_usage_bytes = usage.physical_bytes,
                    "eviction complete: reached low-water mark"
                );
                // Record remaining candidates as not-evicted.
                if telemetry.is_some() {
                    repo_details.push(super::telemetry::RepoDetail {
                        name: owner_repo.clone(),
                        clone_count: info.as_ref().map_or(0, |i| i.clone_count),
                        last_bundle_ts: info.as_ref().map_or(0, |i| i.last_bundle_ts),
                        size_bytes: info.as_ref().map_or(0, |i| i.size_bytes),
                        evicted: false,
                    });
                }
                break;
            }

            // Safety: never evict a repo that has no S3 bundle backup.
            let bundle_key = format!("forgeproxy:repo:{owner_repo}");
            let has_bundle: Option<String> =
                HashesInterface::hget(&state.valkey, &bundle_key, "bundle_list_key")
                    .await
                    .unwrap_or(None);

            if has_bundle.is_none() {
                warn!(
                    repo = %owner_repo,
                    "skipping eviction: no S3 bundle backup recorded in Valkey"
                );
                if telemetry.is_some() {
                    repo_details.push(super::telemetry::RepoDetail {
                        name: owner_repo.clone(),
                        clone_count: info.as_ref().map_or(0, |i| i.clone_count),
                        last_bundle_ts: info.as_ref().map_or(0, |i| i.last_bundle_ts),
                        size_bytes: info.as_ref().map_or(0, |i| i.size_bytes),
                        evicted: false,
                    });
                }
                continue;
            }

            // Remove the repo directory.
            let path = self.repo_path(owner_repo);
            self.remove_repo_all(owner_repo).await?;
            debug!(repo = %owner_repo, path = %path.display(), "evicted repo from local cache");

            // Update Valkey registry: mark repo as not locally cached.
            let registry_key = format!("forgeproxy:repo:{owner_repo}");
            HashesInterface::hset::<(), _, _>(
                &state.valkey,
                &registry_key,
                [("local_cached", "false")],
            )
            .await
            .unwrap_or_default();

            if telemetry.is_some() {
                repo_details.push(super::telemetry::RepoDetail {
                    name: owner_repo.clone(),
                    clone_count: info.as_ref().map_or(0, |i| i.clone_count),
                    last_bundle_ts: info.as_ref().map_or(0, |i| i.last_bundle_ts),
                    size_bytes: info.as_ref().map_or(0, |i| i.size_bytes),
                    evicted: true,
                });
            }

            evicted += 1;
        }

        // Record telemetry event.
        if let Some(buf) = telemetry {
            let policy_name = match self.eviction_policy {
                EvictionPolicy::Lfu => "lfu",
                EvictionPolicy::Lru => "lru",
            };
            buf.record(super::telemetry::EvictionEvent {
                ts: chrono::Utc::now().timestamp(),
                policy: policy_name.to_string(),
                candidates: candidates.len(),
                evicted,
                repos: repo_details,
            })
            .await;
        }

        let usage = self.total_usage_bytes().unwrap_or_default();
        info!(
            evicted,
            apparent_usage_bytes = usage.apparent_bytes,
            physical_usage_bytes = usage.physical_bytes,
            "eviction sweep finished"
        );
        Ok(evicted)
    }

    /// List all `owner/repo` slugs currently present in the local cache.
    ///
    /// Scans `{base_path}/published/{owner}/{repo}.git` directories.
    pub fn list_repos(&self) -> Result<Vec<String>> {
        let mut repos = Vec::new();
        for (owner_repo, repo_path) in self.list_repo_dirs()? {
            if is_usable_bare_repo(&repo_path) {
                repos.push(owner_repo);
            }
        }

        Ok(repos)
    }

    /// List all on-disk bare repo directory candidates, including partial repos.
    ///
    /// Scans `{base_path}/published/{owner}/{repo}.git` directories and returns any repo
    /// directory with a `.git` suffix, regardless of current validity.
    pub fn list_repo_dirs(&self) -> Result<Vec<(String, PathBuf)>> {
        list_repo_dirs_under(
            &layout::generations_root(&self.base_path),
            "reader-visible generation directory",
        )
    }

    pub fn list_mirror_repo_dirs(&self) -> Result<Vec<(String, PathBuf)>> {
        list_repo_dirs_under(&layout::mirrors_root(&self.base_path), "mirror directory")
    }

    /// Evict snapshot files from `{base_path}/snapshots/` until disk usage
    /// drops below the low-water mark.
    ///
    /// Files are sorted by modification time (oldest first) and deleted in
    /// order.  No S3 backup check is needed because the upstream forge is
    /// the authoritative source for archives.
    ///
    /// Returns the number of files evicted.
    pub async fn run_archive_eviction(&self) -> Result<usize> {
        let archive_dir = layout::snapshots_root(&self.base_path);
        if !archive_dir.exists() {
            return Ok(0);
        }

        // Collect all files with their modification times.
        let mut files: Vec<(PathBuf, std::time::SystemTime)> = Vec::new();
        let mut stack = vec![archive_dir.clone()];
        while let Some(current) = stack.pop() {
            let entries = match std::fs::read_dir(&current) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries {
                let entry = match entry {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                let meta = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if meta.is_dir() {
                    stack.push(entry.path());
                } else {
                    let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
                    files.push((entry.path(), mtime));
                }
            }
        }

        // Sort oldest first.
        files.sort_by_key(|(_, mtime)| *mtime);

        let mut evicted: usize = 0;
        for (path, _) in &files {
            let fraction = self.physical_usage_fraction()?;
            if fraction <= self.low_water {
                break;
            }
            if let Err(e) = tokio::fs::remove_file(path).await {
                warn!(path = %path.display(), error = %e, "failed to evict archive file");
            } else {
                debug!(path = %path.display(), "evicted archive file");
                evicted += 1;
            }
        }

        if evicted > 0 {
            let usage = self.total_usage_bytes().unwrap_or_default();
            info!(
                evicted,
                apparent_usage_bytes = usage.apparent_bytes,
                physical_usage_bytes = usage.physical_bytes,
                "archive eviction sweep finished"
            );
        }

        Ok(evicted)
    }

    /// Ensure the parent directories for a repo path exist and return the
    /// full path to the bare repo directory.
    pub fn ensure_repo_dir(&self, owner_repo: &str) -> Result<PathBuf> {
        let path = self.repo_path(owner_repo);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create parent directory: {}", parent.display())
            })?;
        }
        Ok(path)
    }

    /// Ensure the parent directories for a repo mirror path exist and return
    /// the full path to the bare repo mirror directory.
    pub fn ensure_repo_mirror_dir(&self, owner_repo: &str) -> Result<PathBuf> {
        let path = self.repo_mirror_path(owner_repo);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create repo mirror parent directory: {}",
                    parent.display()
                )
            })?;
        }
        Ok(path)
    }

    fn repo_delta_dir(&self, owner_repo: &str) -> PathBuf {
        layout::delta_repo_dir(&self.base_path, owner_repo)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Recursively compute de-duplicated apparent and physical file usage.
pub(crate) fn dir_usage(dir: &Path) -> Result<DiskUsage> {
    let mut usage = DiskUsage::default();

    if !dir.exists() {
        return Ok(usage);
    }

    let mut seen = HashSet::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = match std::fs::read_dir(&current) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                stack.push(entry.path());
            } else if meta.is_file() {
                add_file_usage(&mut usage, &mut seen, &meta);
            }
        }
    }

    Ok(usage)
}

#[cfg(unix)]
fn add_file_usage(usage: &mut DiskUsage, seen: &mut HashSet<(u64, u64)>, meta: &std::fs::Metadata) {
    if !seen.insert((meta.dev(), meta.ino())) {
        return;
    }
    let file_usage = file_disk_usage(meta);
    usage.apparent_bytes = usage
        .apparent_bytes
        .saturating_add(file_usage.apparent_bytes);
    usage.physical_bytes = usage
        .physical_bytes
        .saturating_add(file_usage.physical_bytes);
}

#[cfg(not(unix))]
fn add_file_usage(usage: &mut DiskUsage, seen: &mut HashSet<PathBuf>, meta: &std::fs::Metadata) {
    let _ = seen;
    let file_usage = file_disk_usage(meta);
    usage.apparent_bytes = usage
        .apparent_bytes
        .saturating_add(file_usage.apparent_bytes);
    usage.physical_bytes = usage
        .physical_bytes
        .saturating_add(file_usage.physical_bytes);
}

pub(crate) fn file_disk_usage(meta: &std::fs::Metadata) -> DiskUsage {
    DiskUsage {
        apparent_bytes: meta.len(),
        physical_bytes: physical_file_bytes(meta),
    }
}

#[cfg(unix)]
fn physical_file_bytes(meta: &std::fs::Metadata) -> u64 {
    meta.blocks().saturating_mul(512)
}

#[cfg(not(unix))]
fn physical_file_bytes(meta: &std::fs::Metadata) -> u64 {
    meta.len()
}

pub(crate) fn is_usable_bare_repo(path: &Path) -> bool {
    path.is_dir()
        && path.join("HEAD").is_file()
        && (has_packed_refs(path) || has_loose_refs(&path.join("refs")))
}

fn has_packed_refs(path: &Path) -> bool {
    let packed_refs = path.join("packed-refs");
    let contents = match std::fs::read_to_string(&packed_refs) {
        Ok(contents) => contents,
        Err(_) => return false,
    };

    contents.lines().any(|line| {
        let trimmed = line.trim();
        !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with('^')
    })
}

fn has_loose_refs(refs_dir: &Path) -> bool {
    let entries = match std::fs::read_dir(refs_dir) {
        Ok(entries) => entries,
        Err(_) => return false,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };

        if file_type.is_dir() {
            if has_loose_refs(&path) {
                return true;
            }
            continue;
        }

        if file_type.is_file() {
            return true;
        }
    }

    false
}

fn list_repo_dirs_under(root: &Path, root_description: &str) -> Result<Vec<(String, PathBuf)>> {
    let mut repos = Vec::new();
    if !root.exists() {
        return Ok(repos);
    }

    let owners = std::fs::read_dir(root)
        .with_context(|| format!("failed to read {root_description}: {}", root.display()))?;

    for owner_entry in owners {
        let owner_entry = owner_entry?;
        if !owner_entry.file_type()?.is_dir() {
            continue;
        }
        let owner_name = owner_entry.file_name();
        let owner_str = owner_name.to_string_lossy();

        let repo_entries = std::fs::read_dir(owner_entry.path()).with_context(|| {
            format!(
                "failed to read repo entries under {}",
                owner_entry.path().display()
            )
        })?;

        for repo_entry in repo_entries {
            let repo_entry = repo_entry?;
            let repo_path = repo_entry.path();
            if !repo_path.is_dir() {
                continue;
            }
            let repo_name = repo_entry.file_name();
            let repo_str = repo_name.to_string_lossy();
            if !repo_str.ends_with(".git") {
                continue;
            }

            repos.push((
                crate::repo_identity::canonical_owner_repo(&owner_str, &repo_str),
                repo_path,
            ));
        }
    }

    Ok(repos)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use tempfile::tempdir;

    use super::*;

    fn test_manager(base_path: &Path) -> CacheManager {
        CacheManager {
            base_path: base_path.to_path_buf(),
            max_percent: 1.0,
            high_water: 0.90,
            low_water: 0.75,
            eviction_policy: EvictionPolicy::Lfu,
        }
    }

    fn create_minimal_bare_repo(path: &Path) {
        fs::create_dir_all(path.join("refs").join("heads")).unwrap();
        fs::write(path.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(path.join("refs").join("heads").join("main"), "deadbeef\n").unwrap();
    }

    #[test]
    fn repo_path_splits_owner_and_repo() {
        let mgr = test_manager(Path::new("/var/cache/forgeproxy"));

        let path = mgr.repo_path("acme-corp/my-service");
        assert_eq!(
            path,
            PathBuf::from("/var/cache/forgeproxy/published/acme-corp/my-service.git")
        );
    }

    #[test]
    fn repo_path_normalizes_git_suffix() {
        let mgr = test_manager(Path::new("/var/cache/forgeproxy"));

        // With and without .git should resolve to the same path.
        let without = mgr.repo_path("acme-corp/my-service");
        let with = mgr.repo_path("acme-corp/my-service.git");
        assert_eq!(without, with);
        assert_eq!(
            without,
            PathBuf::from("/var/cache/forgeproxy/published/acme-corp/my-service.git")
        );
    }

    #[test]
    fn bare_repo_without_refs_is_not_usable() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path().join("acme").join("widgets.git");
        fs::create_dir_all(repo.join("refs")).unwrap();
        fs::write(repo.join("HEAD"), "ref: refs/heads/main\n").unwrap();

        assert!(!is_usable_bare_repo(&repo));
        assert!(!has_packed_refs(&repo));
        assert!(!has_loose_refs(&repo.join("refs")));
    }

    #[test]
    fn bare_repo_with_loose_refs_is_usable() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path().join("acme").join("widgets.git");
        fs::create_dir_all(repo.join("refs").join("heads")).unwrap();
        fs::write(repo.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(repo.join("refs").join("heads").join("main"), "deadbeef\n").unwrap();

        assert!(is_usable_bare_repo(&repo));
    }

    #[test]
    fn bare_repo_with_packed_refs_is_usable() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path().join("acme").join("widgets.git");
        fs::create_dir_all(&repo).unwrap();
        fs::write(repo.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(
            repo.join("packed-refs"),
            "# pack-refs with: peeled fully-peeled sorted\n\
deadbeef refs/heads/main\n",
        )
        .unwrap();

        assert!(is_usable_bare_repo(&repo));
    }

    #[test]
    fn publish_staged_repo_leaves_pruning_to_the_caller() {
        let tmp = tempdir().unwrap();
        let mgr = test_manager(tmp.path());
        let owner_repo = "acme/widgets";

        let first = mgr.create_staging_repo_path(owner_repo).unwrap();
        create_minimal_bare_repo(&first);
        mgr.publish_staged_repo(owner_repo, &first).unwrap();

        let second = mgr.create_staging_repo_path(owner_repo).unwrap();
        create_minimal_bare_repo(&second);
        mgr.publish_staged_repo(owner_repo, &second).unwrap();

        let third = mgr.create_staging_repo_path(owner_repo).unwrap();
        create_minimal_bare_repo(&third);
        mgr.publish_staged_repo(owner_repo, &third).unwrap();

        let published = mgr.repo_path(owner_repo);
        assert!(
            fs::symlink_metadata(&published)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(&published).unwrap(), third);
        assert!(first.exists());
        assert!(second.exists());
        assert!(third.exists());
    }

    #[test]
    fn prune_generations_except_removes_unretained_generations() {
        let tmp = tempdir().unwrap();
        let mgr = test_manager(tmp.path());
        let owner_repo = "acme/widgets";

        let first = mgr.create_staging_repo_path(owner_repo).unwrap();
        create_minimal_bare_repo(&first);
        mgr.publish_staged_repo(owner_repo, &first).unwrap();

        fs::remove_file(mgr.repo_path(owner_repo)).unwrap();

        let second = mgr.create_staging_repo_path(owner_repo).unwrap();
        create_minimal_bare_repo(&second);
        mgr.publish_staged_repo(owner_repo, &second).unwrap();

        assert!(first.exists());
        assert!(second.exists());
        mgr.prune_generations_except(owner_repo, std::slice::from_ref(&second))
            .unwrap();

        assert!(!first.exists());
        assert!(second.exists());
    }

    #[tokio::test]
    async fn remove_published_repo_generations_keeps_mirror() {
        let tmp = tempdir().unwrap();
        let mgr = test_manager(tmp.path());
        let owner_repo = "acme/widgets";

        let mirror = mgr.ensure_repo_mirror_dir(owner_repo).unwrap();
        create_minimal_bare_repo(&mirror);

        let staged = mgr.create_staging_repo_path(owner_repo).unwrap();
        create_minimal_bare_repo(&staged);
        mgr.publish_staged_repo(owner_repo, &staged).unwrap();

        mgr.remove_published_repo_generations(owner_repo)
            .await
            .unwrap();

        assert!(!mgr.repo_path(owner_repo).exists());
        assert!(!mgr.repo_generations_dir(owner_repo).exists());
        assert!(mirror.exists());
    }

    #[test]
    fn has_repo_requires_published_snapshot_and_mirror() {
        let tmp = tempdir().unwrap();
        let mgr = test_manager(tmp.path());
        let owner_repo = "acme/widgets";

        let staged = mgr.create_staging_repo_path(owner_repo).unwrap();
        create_minimal_bare_repo(&staged);
        mgr.publish_staged_repo(owner_repo, &staged).unwrap();

        assert!(!mgr.has_repo(owner_repo));

        let mirror = mgr.ensure_repo_mirror_dir(owner_repo).unwrap();
        create_minimal_bare_repo(&mirror);

        assert!(mgr.has_repo(owner_repo));
    }

    #[test]
    fn metrics_snapshot_reports_cache_subtrees_and_mirror_sizes() {
        let tmp = tempdir().unwrap();
        let mgr = test_manager(tmp.path());
        let owner_repo = "acme/widgets";

        let mirror = mgr.ensure_repo_mirror_dir(owner_repo).unwrap();
        create_minimal_bare_repo(&mirror);
        fs::create_dir_all(mirror.join("objects")).unwrap();
        fs::write(mirror.join("objects").join("blob.pack"), vec![0_u8; 11]).unwrap();

        let snapshot_dir = crate::cache::layout::snapshot_repo_dir(tmp.path(), "acme", "widgets");
        fs::create_dir_all(&snapshot_dir).unwrap();
        fs::write(snapshot_dir.join("main.tar.gz"), vec![0_u8; 7]).unwrap();

        let generation_dir = mgr.create_staging_repo_path(owner_repo).unwrap();
        create_minimal_bare_repo(&generation_dir);
        fs::create_dir_all(generation_dir.join("objects")).unwrap();
        fs::write(
            generation_dir.join("objects").join("pack.pack"),
            vec![0_u8; 5],
        )
        .unwrap();

        let delta_dir = crate::cache::layout::delta_repo_dir(tmp.path(), owner_repo);
        fs::create_dir_all(&delta_dir).unwrap();
        fs::write(delta_dir.join("fetch.log"), vec![0_u8; 3]).unwrap();

        let tee_dir = crate::cache::layout::tee_repo_dir(tmp.path(), owner_repo);
        fs::create_dir_all(&tee_dir).unwrap();
        fs::write(tee_dir.join("request.bin"), vec![0_u8; 2]).unwrap();

        let snapshot = mgr.metrics_snapshot().unwrap();

        assert_eq!(snapshot.repo_count, 0);
        assert!(
            snapshot
                .mirror_apparent_sizes
                .iter()
                .any(|(repo, size)| repo == owner_repo && *size >= 11)
        );
        assert!(
            snapshot
                .mirror_physical_sizes
                .iter()
                .any(|(repo, size)| repo == owner_repo && *size > 0)
        );
        assert!(
            snapshot
                .subtree_apparent_sizes
                .iter()
                .any(|(subtree, size)| subtree == "mirrors" && *size >= 11)
        );
        assert!(
            snapshot
                .subtree_apparent_sizes
                .iter()
                .any(|(subtree, size)| subtree == "snapshots" && *size >= 7)
        );
        assert!(
            snapshot
                .subtree_apparent_sizes
                .iter()
                .any(|(subtree, size)| subtree == "state_generations" && *size >= 5)
        );
        assert!(
            snapshot
                .subtree_apparent_sizes
                .iter()
                .any(|(subtree, size)| subtree == "state_delta" && *size >= 3)
        );
        assert!(
            snapshot
                .subtree_apparent_sizes
                .iter()
                .any(|(subtree, size)| subtree == "state_tee" && *size >= 2)
        );
        assert_eq!(
            snapshot.total_apparent_usage_bytes,
            snapshot
                .subtree_apparent_sizes
                .iter()
                .map(|(_, size)| *size)
                .sum::<u64>()
        );
    }

    #[test]
    fn disk_usage_deduplicates_hardlinks_for_physical_usage() {
        let tmp = tempdir().unwrap();
        let original = tmp.path().join("pack");
        let hardlink = tmp.path().join("pack.link");
        fs::write(&original, vec![1_u8; 4096]).unwrap();
        fs::hard_link(&original, &hardlink).unwrap();

        let usage = dir_usage(tmp.path()).unwrap();
        assert_eq!(usage.apparent_bytes, 4096);
        assert_eq!(
            usage.physical_bytes,
            file_disk_usage(&fs::metadata(&original).unwrap()).physical_bytes
        );
    }
}
