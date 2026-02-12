//! On-disk bare-repo cache manager with water-mark-based eviction.
//!
//! Repos are stored as bare Git repositories under
//! `{base_path}/{owner}/{repo}.git`.  When disk usage exceeds the configured
//! high-water mark, the least-frequently-used repos (that have an S3 bundle
//! backup) are evicted until usage drops below the low-water mark.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use fred::interfaces::HashesInterface;
use tracing::{debug, info, warn};

use crate::config::LocalStorageConfig;
use crate::AppState;

use super::lfu;

// ---------------------------------------------------------------------------
// CacheManager
// ---------------------------------------------------------------------------

/// Manages the local bare-repo cache on EBS-backed storage.
#[derive(Debug, Clone)]
pub struct CacheManager {
    /// Root directory for cached bare repos (e.g. `/var/cache/forgecache/repos`).
    pub base_path: PathBuf,
    /// Hard ceiling for total cache usage in bytes.
    pub max_bytes: u64,
    /// Eviction starts when usage fraction exceeds this value (0.0 .. 1.0).
    pub high_water: f64,
    /// Eviction stops when usage fraction drops to or below this value.
    pub low_water: f64,
    /// Name of the active eviction policy (informational).
    pub eviction_policy: String,
}

impl CacheManager {
    /// Create a new [`CacheManager`] from the local storage configuration.
    pub fn new(config: &LocalStorageConfig) -> Self {
        Self {
            base_path: PathBuf::from(&config.path),
            max_bytes: config.max_bytes,
            high_water: config.high_water_mark,
            low_water: config.low_water_mark,
            eviction_policy: format!("{:?}", config.eviction_policy).to_lowercase(),
        }
    }

    /// Return the on-disk path for a repository identified by `owner/repo`.
    ///
    /// The resulting path is `{base_path}/{owner}/{repo}.git`.
    pub fn repo_path(&self, owner_repo: &str) -> PathBuf {
        let parts: Vec<&str> = owner_repo.splitn(2, '/').collect();
        if parts.len() == 2 {
            self.base_path
                .join(parts[0])
                .join(format!("{}.git", parts[1]))
        } else {
            // Fallback: treat the whole string as a single component.
            self.base_path.join(format!("{}.git", owner_repo))
        }
    }

    /// Check whether a cached bare repo exists for `owner/repo` and looks
    /// like a valid bare Git repository (contains a `HEAD` file).
    pub fn has_repo(&self, owner_repo: &str) -> bool {
        let path = self.repo_path(owner_repo);
        path.is_dir() && path.join("HEAD").is_file()
    }

    /// Walk [`base_path`] and return the total size of all files in bytes.
    pub fn total_size_bytes(&self) -> Result<u64> {
        dir_size(&self.base_path)
    }

    /// Return the current cache usage as a fraction of `max_bytes`.
    pub fn usage_fraction(&self) -> Result<f64> {
        if self.max_bytes == 0 {
            return Ok(0.0);
        }
        let used = self.total_size_bytes()?;
        Ok(used as f64 / self.max_bytes as f64)
    }

    /// Return `true` when cache usage exceeds the high-water mark and
    /// eviction should be triggered.
    pub fn needs_eviction(&self) -> Result<bool> {
        let fraction = self.usage_fraction()?;
        Ok(fraction > self.high_water)
    }

    /// Evict least-frequently-used repos until usage drops to or below the
    /// low-water mark.
    ///
    /// Only repos that have a confirmed S3 bundle backup are eligible for
    /// eviction -- repos without a bundle are skipped so they are not lost.
    ///
    /// Returns the number of repos evicted.
    pub async fn run_eviction(&self, state: &AppState) -> Result<usize> {
        let repos = self.list_repos()?;
        if repos.is_empty() {
            return Ok(0);
        }

        // Ask LFU for candidates ordered by ascending clone count.
        let candidates = lfu::get_eviction_candidates(&state.keydb, &repos, repos.len()).await?;

        let mut evicted: usize = 0;

        for owner_repo in &candidates {
            // Re-check whether we still need to evict.
            let fraction = self.usage_fraction()?;
            if fraction <= self.low_water {
                info!(
                    evicted,
                    usage_fraction = fraction,
                    "eviction complete: reached low-water mark"
                );
                break;
            }

            // Safety: never evict a repo that has no S3 bundle backup.
            let bundle_key = format!("forgecache:repo:{owner_repo}");
            let has_bundle: Option<String> =
                HashesInterface::hget(&state.keydb, &bundle_key, "bundle_list_key")
                    .await
                    .unwrap_or(None);

            if has_bundle.is_none() {
                warn!(
                    repo = %owner_repo,
                    "skipping eviction: no S3 bundle backup recorded in KeyDB"
                );
                continue;
            }

            // Remove the repo directory.
            let path = self.repo_path(owner_repo);
            if path.exists() {
                tokio::fs::remove_dir_all(&path).await.with_context(|| {
                    format!("failed to remove cached repo at {}", path.display())
                })?;
                debug!(repo = %owner_repo, path = %path.display(), "evicted repo from local cache");
            }

            // Update KeyDB registry: mark repo as not locally cached.
            let registry_key = format!("forgecache:repo:{owner_repo}");
            HashesInterface::hset::<(), _, _>(
                &state.keydb,
                &registry_key,
                [("local_cached", "false")],
            )
            .await
            .unwrap_or_default();

            evicted += 1;
        }

        info!(evicted, "eviction sweep finished");
        Ok(evicted)
    }

    /// List all `owner/repo` slugs currently present in the local cache.
    ///
    /// Scans `{base_path}/{owner}/{repo}.git` directories.
    pub fn list_repos(&self) -> Result<Vec<String>> {
        let mut repos = Vec::new();

        if !self.base_path.exists() {
            return Ok(repos);
        }

        let owners = std::fs::read_dir(&self.base_path).with_context(|| {
            format!(
                "failed to read cache directory: {}",
                self.base_path.display()
            )
        })?;

        for owner_entry in owners {
            let owner_entry = owner_entry?;
            if !owner_entry.file_type()?.is_dir() {
                continue;
            }
            let owner_name = owner_entry.file_name();
            let owner_str = owner_name.to_string_lossy();

            let repo_entries = std::fs::read_dir(owner_entry.path())?;
            for repo_entry in repo_entries {
                let repo_entry = repo_entry?;
                if !repo_entry.file_type()?.is_dir() {
                    continue;
                }
                let repo_name = repo_entry.file_name();
                let repo_str = repo_name.to_string_lossy();

                // Strip the `.git` suffix if present.
                let repo_clean = repo_str.strip_suffix(".git").unwrap_or(&repo_str);

                // Quick validity check: bare repos contain a HEAD file.
                if repo_entry.path().join("HEAD").is_file() {
                    repos.push(format!("{}/{}", owner_str, repo_clean));
                }
            }
        }

        Ok(repos)
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
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Recursively compute the total size of all files under `dir`.
pub(crate) fn dir_size(dir: &Path) -> Result<u64> {
    let mut total: u64 = 0;

    if !dir.exists() {
        return Ok(0);
    }

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
            } else {
                total += meta.len();
            }
        }
    }

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_path_splits_owner_and_repo() {
        let mgr = CacheManager {
            base_path: PathBuf::from("/var/cache/forgecache/repos"),
            max_bytes: 100_000_000_000,
            high_water: 0.90,
            low_water: 0.75,
            eviction_policy: "lfu".to_string(),
        };

        let path = mgr.repo_path("acme-corp/my-service");
        assert_eq!(
            path,
            PathBuf::from("/var/cache/forgecache/repos/acme-corp/my-service.git")
        );
    }
}
