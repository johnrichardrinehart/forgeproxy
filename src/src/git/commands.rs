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

use anyhow::{bail, Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tracing::{debug, instrument, warn};

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
// Upload-pack (buffered)
// ---------------------------------------------------------------------------

/// Run `git upload-pack --stateless-rpc <repo_path>`, piping `input` to
/// stdin and returning the complete stdout as bytes.
#[instrument(fields(repo = %repo_path.display()))]
pub async fn git_upload_pack(repo_path: &Path, input: &[u8]) -> Result<Vec<u8>> {
    let mut cmd = Command::new("git");
    cmd.arg("upload-pack").arg("--stateless-rpc").arg(repo_path);

    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().context("failed to spawn git upload-pack")?;

    // Write input to stdin, then close it to signal EOF.
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input)
            .await
            .context("failed to write to git upload-pack stdin")?;
        drop(stdin);
    }

    let output = child
        .wait_with_output()
        .await
        .context("git upload-pack failed")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(
            status = %output.status,
            stderr = %stderr,
            "git upload-pack exited with non-zero status"
        );
    }

    Ok(output.stdout)
}

// ---------------------------------------------------------------------------
// Upload-pack (streamed)
// ---------------------------------------------------------------------------

/// Spawn `git upload-pack --stateless-rpc <repo_path>` and return the
/// [`Child`] process handle.
///
/// The caller is responsible for writing to `child.stdin` and reading from
/// `child.stdout`.  This is intended for streaming large pack files without
/// buffering the entire output in memory.
#[instrument(fields(repo = %repo_path.display()))]
pub async fn git_upload_pack_streamed(repo_path: &Path) -> Result<Child> {
    let mut cmd = Command::new("git");
    cmd.arg("upload-pack").arg("--stateless-rpc").arg(repo_path);

    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let child = cmd
        .spawn()
        .context("failed to spawn git upload-pack (streamed)")?;

    Ok(child)
}

// ---------------------------------------------------------------------------
// Upload-pack bytes (remote URL)
// ---------------------------------------------------------------------------

/// Run `git upload-pack` against a remote URL by fetching into a temporary
/// bare repo and then running upload-pack locally.
///
/// This is a convenience wrapper for the SSH upstream proxy path.
#[instrument(fields(%remote_url))]
pub async fn git_upload_pack_bytes(remote_url: &str, input: &[u8]) -> Result<Vec<u8>> {
    // If input is empty, just return the ref advertisement.
    if input.is_empty() {
        let mut cmd = Command::new("git");
        cmd.arg("ls-remote").arg(remote_url);
        cmd.env("GIT_TERMINAL_PROMPT", "0");
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let output = cmd
            .output()
            .await
            .context("failed to spawn git ls-remote")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("git ls-remote failed: {}", stderr.trim());
        }

        return Ok(output.stdout);
    }

    // For non-empty input, create a temporary bare repo, fetch from the
    // remote, then serve upload-pack locally.
    let tmp_dir = tempfile::tempdir().context("failed to create temp dir for upload-pack-bytes")?;
    let tmp_repo = tmp_dir.path().join("repo.git");

    // Init bare repo.
    let init_output = Command::new("git")
        .arg("init")
        .arg("--bare")
        .arg(&tmp_repo)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("failed to init temp bare repo")?;

    if !init_output.status.success() {
        let stderr = String::from_utf8_lossy(&init_output.stderr);
        bail!("git init --bare failed: {}", stderr.trim());
    }

    // Fetch all refs from remote.
    let fetch_output = Command::new("git")
        .arg("-C")
        .arg(&tmp_repo)
        .arg("fetch")
        .arg(remote_url)
        .arg("+refs/*:refs/*")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("failed to fetch from remote for upload-pack-bytes")?;

    if !fetch_output.status.success() {
        let stderr = String::from_utf8_lossy(&fetch_output.stderr);
        bail!("git fetch failed: {}", stderr.trim());
    }

    // Serve upload-pack from the temp repo.
    git_upload_pack(&tmp_repo, input).await
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

// ---------------------------------------------------------------------------
// Bundle unbundle
// ---------------------------------------------------------------------------

/// Run `git bundle unbundle <bundle_path>` inside a bare repo.
///
/// This applies the bundle contents to the target repository, updating its
/// refs to include those from the bundle.
#[instrument(fields(bundle = %bundle_path.display(), repo = %repo_path.display()))]
pub async fn git_bundle_unbundle(bundle_path: &Path, repo_path: &Path) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo_path)
        .arg("bundle")
        .arg("unbundle")
        .arg(bundle_path);

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    debug!("spawning git bundle unbundle");

    let output = cmd
        .output()
        .await
        .context("failed to spawn git bundle unbundle")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git bundle unbundle failed (status {}): {}",
            output.status,
            stderr.trim(),
        );
    }

    debug!("git bundle unbundle succeeded");
    Ok(())
}

// ---------------------------------------------------------------------------
// ls-remote
// ---------------------------------------------------------------------------

/// Run `git ls-remote <url>` and parse the output into a map of
/// `ref_name -> object_id`.
#[instrument(fields(%url))]
pub async fn git_ls_remote(
    url: &str,
    env_vars: &[(String, String)],
) -> Result<HashMap<String, String>> {
    let mut cmd = Command::new("git");
    cmd.arg("ls-remote").arg(url);

    cmd.env("GIT_TERMINAL_PROMPT", "0");
    for (k, v) in env_vars {
        cmd.env(k, v);
    }

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    debug!("spawning git ls-remote");

    let output = cmd
        .output()
        .await
        .context("failed to spawn git ls-remote")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git ls-remote failed (status {}): {}",
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
        // Format: "<oid>\t<refname>"
        if let Some((oid, refname)) = line.split_once('\t') {
            refs.insert(refname.trim().to_string(), oid.trim().to_string());
        }
    }

    debug!(ref_count = refs.len(), "git ls-remote complete");
    Ok(refs)
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
