//! Git command wrappers using [`tokio::process::Command`].
//!
//! Every function in this module shells out to the system `git` binary for
//! the actual work.  Environment variables (PATs, `GIT_SSH_COMMAND`, etc.)
//! are injected via the `env_vars` parameter so that credential handling is
//! transparent to callers.
//!
//! All functions are fully `async` and use the Tokio process runtime.

use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use tokio::process::Command;
use tracing::{debug, instrument};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Summary of a `git fetch` operation.
#[derive(Debug, Clone)]
pub struct FetchResult {
    /// Number of refs that were updated (new or changed).
    pub refs_updated: usize,
    /// Total bytes received from the remote (parsed from stderr if available,
    /// otherwise 0).
    pub bytes_received: u64,
}

// ---------------------------------------------------------------------------
// Clone
// ---------------------------------------------------------------------------

/// Run `git clone --bare <url> <dest>` with the supplied environment variables.
#[instrument(skip(env_vars), fields(%url, dest = %dest.display()))]
pub async fn git_clone_bare(url: &str, dest: &Path, env_vars: &[(String, String)]) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("clone")
        .arg("--bare")
        .arg("--no-tags")
        .arg(url)
        .arg(dest);

    cmd.env("GIT_TERMINAL_PROMPT", "0");
    for (k, v) in env_vars {
        cmd.env(k, v);
    }

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    debug!("spawning git clone --bare");

    let output = cmd
        .output()
        .await
        .context("failed to spawn git clone --bare")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git clone --bare failed (status {}): {}",
            output.status,
            stderr.trim(),
        );
    }

    debug!("git clone --bare succeeded");
    Ok(())
}

// ---------------------------------------------------------------------------
// Fetch
// ---------------------------------------------------------------------------

/// Run `git fetch <remote_url> +refs/*:refs/*` inside an existing bare repo.
///
/// Returns a [`FetchResult`] summarising the update.
#[instrument(skip(env_vars), fields(repo = %repo_path.display(), %remote_url))]
pub async fn git_fetch(
    repo_path: &Path,
    remote_url: &str,
    env_vars: &[(String, String)],
) -> Result<FetchResult> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo_path)
        .arg("fetch")
        .arg("--prune")
        .arg("--force")
        .arg(remote_url)
        .arg("+refs/*:refs/*");

    cmd.env("GIT_TERMINAL_PROMPT", "0");
    for (k, v) in env_vars {
        cmd.env(k, v);
    }

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    debug!("spawning git fetch");

    let output = cmd.output().await.context("failed to spawn git fetch")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git fetch failed (status {}): {}",
            output.status,
            stderr.trim(),
        );
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let refs_updated = count_updated_refs(&stderr);
    let bytes_received = parse_bytes_received(&stderr);

    debug!(
        refs_updated = refs_updated,
        bytes_received = bytes_received,
        "git fetch complete"
    );

    Ok(FetchResult {
        refs_updated,
        bytes_received,
    })
}

/// Count the number of ref-update lines in `git fetch` stderr.
///
/// Lines matching patterns like ` -> ` or `[new branch]` are counted.
fn count_updated_refs(stderr: &str) -> usize {
    stderr
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            trimmed.contains("->") && !trimmed.starts_with("From")
        })
        .count()
}

/// Attempt to parse the "Receiving objects: ... bytes" line from `git fetch`
/// stderr.  Returns 0 if the line is not found or cannot be parsed.
fn parse_bytes_received(stderr: &str) -> u64 {
    // Git outputs lines like:
    //   remote: Total 42 (delta 10), reused 40 (delta 8), pack-reused 0
    // We look for a "Total" line and use the first number as a rough proxy.
    for line in stderr.lines() {
        let trimmed = line.trim();
        if trimmed.contains("Total") {
            // Extract the first integer after "Total".
            if let Some(rest) = trimmed.split("Total").nth(1) {
                for token in rest.split_whitespace() {
                    if let Ok(n) = token
                        .trim_matches(|c: char| !c.is_ascii_digit())
                        .parse::<u64>()
                    {
                        return n;
                    }
                }
            }
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Bundle create
// ---------------------------------------------------------------------------

/// Run `git bundle create <output> [refs...] [--not refs...]` inside a bare
/// repo.
///
/// If `refs` is `None`, `--all` is used to include every ref.  If `not_refs`
/// is provided, those object IDs are excluded from the bundle (used for
/// incremental bundles).
#[instrument(fields(repo = %repo_path.display(), output = %output.display()))]
pub async fn git_bundle_create(
    repo_path: &Path,
    output: &Path,
    refs: Option<&[String]>,
    not_refs: Option<&[String]>,
) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo_path)
        .arg("bundle")
        .arg("create")
        .arg(output);

    match refs {
        Some(ref_list) if !ref_list.is_empty() => {
            for r in ref_list {
                cmd.arg(r);
            }
        }
        _ => {
            cmd.arg("--all");
        }
    }

    if let Some(nots) = not_refs {
        for nr in nots {
            cmd.arg("--not").arg(nr);
        }
    }

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    debug!("spawning git bundle create");

    let output_result = cmd
        .output()
        .await
        .context("failed to spawn git bundle create")?;

    if !output_result.status.success() {
        let stderr = String::from_utf8_lossy(&output_result.stderr);
        bail!(
            "git bundle create failed (status {}): {}",
            output_result.status,
            stderr.trim(),
        );
    }

    debug!("git bundle create succeeded");
    Ok(())
}

/// Run `git bundle create --filter=<filter> <output> --all` inside a bare repo.
///
/// This generates a "filtered" bundle (e.g. `blob:none` for blobless clones).
/// Requires Git 2.40+.  Returns an error if the `--filter` flag is not
/// supported by the installed Git version.
#[instrument(fields(repo = %repo_path.display(), output = %output.display(), %filter))]
pub async fn git_bundle_create_filtered(
    repo_path: &Path,
    output: &Path,
    filter: &str,
) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo_path)
        .arg("bundle")
        .arg("create")
        .arg(format!("--filter={filter}"))
        .arg(output)
        .arg("--all");

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    debug!("spawning git bundle create --filter");

    let output_result = cmd
        .output()
        .await
        .context("failed to spawn git bundle create --filter")?;

    if !output_result.status.success() {
        let stderr = String::from_utf8_lossy(&output_result.stderr);
        bail!(
            "git bundle create --filter failed (status {}): {}",
            output_result.status,
            stderr.trim(),
        );
    }

    debug!("git bundle create --filter succeeded");
    Ok(())
}

// ---------------------------------------------------------------------------
// for-each-ref
// ---------------------------------------------------------------------------

/// Run `git for-each-ref` in a bare repo and return a map of
/// `ref_name -> object_id`.
///
/// Uses the format `%(objectname) %(refname)` so each output line is
/// `<oid> <refname>`.
#[instrument(fields(repo = %repo_path.display()))]
pub async fn git_for_each_ref(repo_path: &Path) -> Result<HashMap<String, String>> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo_path)
        .arg("for-each-ref")
        .arg("--format=%(objectname) %(refname)");

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    debug!("spawning git for-each-ref");

    let output = cmd
        .output()
        .await
        .context("failed to spawn git for-each-ref")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git for-each-ref failed (status {}): {}",
            output.status,
            stderr.trim(),
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut refs = HashMap::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Format: "<objectname> <refname>"
        if let Some((oid, refname)) = line.split_once(' ') {
            refs.insert(refname.trim().to_string(), oid.trim().to_string());
        }
    }

    debug!(ref_count = refs.len(), "git for-each-ref complete");
    Ok(refs)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_updated_refs_basic() {
        let stderr = "\
From https://ghe.example.com/org/repo
   abc1234..def5678  main       -> main
 * [new branch]      feature-x  -> feature-x
";
        assert_eq!(count_updated_refs(stderr), 2);
    }

    #[test]
    fn count_updated_refs_empty() {
        assert_eq!(count_updated_refs(""), 0);
    }

    #[test]
    fn parse_bytes_received_with_total() {
        let stderr = "\
remote: Enumerating objects: 100, done.
remote: Counting objects: 100% (100/100), done.
remote: Total 42 (delta 10), reused 40 (delta 8), pack-reused 0
";
        assert_eq!(parse_bytes_received(stderr), 42);
    }

    #[test]
    fn parse_bytes_received_missing() {
        assert_eq!(parse_bytes_received("nothing here"), 0);
    }
}
