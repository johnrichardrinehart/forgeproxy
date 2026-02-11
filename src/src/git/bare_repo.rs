//! Bare Git repository lifecycle management.
//!
//! Provides helpers for initialising, validating, sizing, configuring remotes,
//! and removing bare Git repositories on the local filesystem.  All file-system
//! operations are async (via Tokio) or wrapped in `spawn_blocking` where
//! needed.

use std::path::Path;

use anyhow::{bail, Context, Result};
use tokio::process::Command;
use tracing::{debug, instrument, warn};

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

/// Initialise a new bare Git repository at `path`.
///
/// Creates the directory (and any missing parents) and runs
/// `git init --bare`.  If the directory already exists and contains a valid
/// bare repo (i.e. has a `HEAD` file), this is a no-op.
#[instrument(fields(path = %path.display()))]
pub async fn init_bare_repo(path: &Path) -> Result<()> {
    // If it already looks like a valid bare repo, skip the init.
    if path.exists() && path.join("HEAD").is_file() {
        debug!("bare repo already exists; skipping init");
        return Ok(());
    }

    // Ensure parent directories exist.
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| {
                format!(
                    "failed to create parent directory: {}",
                    parent.display(),
                )
            })?;
    }

    let output = Command::new("git")
        .arg("init")
        .arg("--bare")
        .arg(path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .context("failed to spawn git init --bare")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git init --bare failed (status {}): {}",
            output.status,
            stderr.trim(),
        );
    }

    debug!("bare repo initialised");
    Ok(())
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

/// Check whether `path` looks like a valid bare Git repository.
///
/// A bare repo must be a directory that contains a `HEAD` file.  This is a
/// lightweight heuristic, not a full integrity check.
#[instrument(fields(path = %path.display()))]
pub async fn validate_bare_repo(path: &Path) -> Result<bool> {
    let is_dir = tokio::fs::metadata(path)
        .await
        .map(|m| m.is_dir())
        .unwrap_or(false);

    if !is_dir {
        debug!("path does not exist or is not a directory");
        return Ok(false);
    }

    let head_exists = tokio::fs::metadata(path.join("HEAD"))
        .await
        .map(|m| m.is_file())
        .unwrap_or(false);

    if !head_exists {
        debug!("HEAD file not found; not a valid bare repo");
        return Ok(false);
    }

    // Optional: check for the `objects` and `refs` directories.
    let objects_ok = tokio::fs::metadata(path.join("objects"))
        .await
        .map(|m| m.is_dir())
        .unwrap_or(false);

    let refs_ok = tokio::fs::metadata(path.join("refs"))
        .await
        .map(|m| m.is_dir())
        .unwrap_or(false);

    if !objects_ok || !refs_ok {
        warn!(
            path = %path.display(),
            "HEAD exists but objects/ or refs/ directory is missing"
        );
        // Still return true since HEAD exists; the repo may be intact
        // but with packed refs.
    }

    Ok(true)
}

// ---------------------------------------------------------------------------
// Remove
// ---------------------------------------------------------------------------

/// Recursively remove a bare repository at `path`.
///
/// This is a destructive operation -- the entire directory tree is deleted.
/// If the path does not exist, this is a no-op.
#[instrument(fields(path = %path.display()))]
pub async fn remove_repo(path: &Path) -> Result<()> {
    if !path.exists() {
        debug!("path does not exist; nothing to remove");
        return Ok(());
    }

    tokio::fs::remove_dir_all(path)
        .await
        .with_context(|| {
            format!("failed to remove repo directory: {}", path.display())
        })?;

    debug!("repo directory removed");
    Ok(())
}

// ---------------------------------------------------------------------------
// Size
// ---------------------------------------------------------------------------

/// Compute the total size (in bytes) of all files under `path` by
/// recursively walking the directory tree.
///
/// Symlinks are not followed; only regular file sizes are counted.
#[instrument(fields(path = %path.display()))]
pub async fn repo_size_bytes(path: &Path) -> Result<u64> {
    let path = path.to_path_buf();

    // File-system walking is synchronous; run it in a blocking task to
    // avoid starving the Tokio runtime.
    let size = tokio::task::spawn_blocking(move || dir_size_sync(&path))
        .await
        .context("blocking task panicked")?
        .context("failed to compute repo size")?;

    debug!(size_bytes = size, "computed repo size");
    Ok(size)
}

/// Synchronous recursive directory size computation.
fn dir_size_sync(dir: &Path) -> Result<u64> {
    let mut total: u64 = 0;

    if !dir.exists() {
        return Ok(0);
    }

    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = match std::fs::read_dir(&current) {
            Ok(e) => e,
            Err(err) => {
                warn!(
                    path = %current.display(),
                    error = %err,
                    "failed to read directory during size computation"
                );
                continue;
            }
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
                total += meta.len();
            }
            // Ignore symlinks and other special files.
        }
    }

    Ok(total)
}

// ---------------------------------------------------------------------------
// Remote configuration
// ---------------------------------------------------------------------------

/// Set (or update) a named remote on a bare repo.
///
/// Runs `git remote add <name> <url>` or, if the remote already exists,
/// `git remote set-url <name> <url>`.
#[instrument(fields(repo = %repo_path.display(), %name, %url))]
pub async fn set_remote(repo_path: &Path, name: &str, url: &str) -> Result<()> {
    // First, try `git remote add`.
    let add_output = Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .arg("remote")
        .arg("add")
        .arg(name)
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .context("failed to spawn git remote add")?;

    if add_output.status.success() {
        debug!("remote added");
        return Ok(());
    }

    // If `add` failed, the remote likely already exists.  Try `set-url`.
    let stderr = String::from_utf8_lossy(&add_output.stderr);
    if stderr.contains("already exists") {
        debug!("remote already exists; updating URL");

        let set_output = Command::new("git")
            .arg("-C")
            .arg(repo_path)
            .arg("remote")
            .arg("set-url")
            .arg(name)
            .arg(url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .await
            .context("failed to spawn git remote set-url")?;

        if !set_output.status.success() {
            let set_stderr = String::from_utf8_lossy(&set_output.stderr);
            bail!(
                "git remote set-url failed (status {}): {}",
                set_output.status,
                set_stderr.trim(),
            );
        }

        debug!("remote URL updated");
        return Ok(());
    }

    // Some other error from `git remote add`.
    bail!(
        "git remote add failed (status {}): {}",
        add_output.status,
        stderr.trim(),
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn validate_nonexistent_path() {
        let result = validate_bare_repo(Path::new("/tmp/nonexistent_gheproxy_test_repo"))
            .await
            .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn repo_size_nonexistent_is_zero() {
        let size = repo_size_bytes(Path::new("/tmp/nonexistent_gheproxy_test_repo"))
            .await
            .unwrap();
        assert_eq!(size, 0);
    }

    #[tokio::test]
    async fn remove_nonexistent_is_noop() {
        // Should not error.
        remove_repo(Path::new("/tmp/nonexistent_gheproxy_test_repo"))
            .await
            .unwrap();
    }

    #[test]
    fn dir_size_sync_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let size = dir_size_sync(tmp.path()).unwrap();
        assert_eq!(size, 0);
    }

    #[test]
    fn dir_size_sync_with_files() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("test.txt");
        std::fs::write(&file_path, "hello world").unwrap(); // 11 bytes
        let size = dir_size_sync(tmp.path()).unwrap();
        assert_eq!(size, 11);
    }

    #[test]
    fn dir_size_sync_nested() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(tmp.path().join("a.txt"), "aaa").unwrap(); // 3
        std::fs::write(sub.join("b.txt"), "bbbbb").unwrap(); // 5
        let size = dir_size_sync(tmp.path()).unwrap();
        assert_eq!(size, 8);
    }
}
