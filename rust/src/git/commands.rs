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
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing::{debug, info, instrument};

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

/// Run `git init --bare <dest>`.
#[instrument(fields(dest = %dest.display()))]
pub async fn git_init_bare(dest: &Path) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("init").arg("--bare").arg(dest);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    debug!("spawning git init --bare");

    let output = cmd
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

    debug!("git init --bare succeeded");
    Ok(())
}

/// Run `git clone --bare <url> <dest>` with the supplied environment variables.
#[instrument(skip(env_vars), fields(dest = %dest.display()))]
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

/// Run `git clone --bare --no-local <source> <dest>` for a local bare repo.
#[instrument(fields(source = %source.display(), dest = %dest.display()))]
pub async fn git_clone_bare_local(source: &Path, dest: &Path) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("clone")
        .arg("--bare")
        .arg("--no-local")
        .arg(source)
        .arg(dest);

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    debug!("spawning git clone --bare --no-local");

    let output = cmd
        .output()
        .await
        .context("failed to spawn git clone --bare --no-local")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git clone --bare --no-local failed (status {}): {}",
            output.status,
            stderr.trim(),
        );
    }

    debug!("git clone --bare --no-local succeeded");
    Ok(())
}

// ---------------------------------------------------------------------------
// Fetch
// ---------------------------------------------------------------------------

/// Run `git fetch <remote_url> +refs/*:refs/*` inside an existing bare repo.
///
/// Returns a [`FetchResult`] summarising the update.
#[instrument(skip(env_vars), fields(repo = %repo_path.display()))]
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

pub fn redact_url_secret(url: &str, unmask_chars: usize) -> String {
    let Ok(mut parsed) = url::Url::parse(url) else {
        return url.to_string();
    };

    let Some(password) = parsed.password() else {
        return url.to_string();
    };

    let masked = redact_secret(password, unmask_chars);
    let _ = parsed.set_password(Some(&masked));
    parsed.to_string()
}

fn redact_secret(secret: &str, unmask_chars: usize) -> String {
    if secret.is_empty() {
        return String::new();
    }

    let chars: Vec<char> = secret.chars().collect();
    if unmask_chars == 0 || chars.len() <= unmask_chars.saturating_mul(2) {
        return "*".repeat(chars.len());
    }

    let prefix: String = chars.iter().take(unmask_chars).collect();
    let suffix: String = chars
        .iter()
        .rev()
        .take(unmask_chars)
        .copied()
        .collect::<Vec<char>>()
        .into_iter()
        .rev()
        .collect();
    let masked_len = chars.len().saturating_sub(unmask_chars * 2);

    format!("{prefix}{}{suffix}", "*".repeat(masked_len))
}

/// Run `git fetch <bundle_path> +refs/*:refs/*` inside an existing bare repo.
#[instrument(fields(repo = %repo_path.display(), bundle = %bundle_path.display()))]
pub async fn git_fetch_bundle(repo_path: &Path, bundle_path: &Path) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo_path)
        .arg("fetch")
        .arg("--force")
        .arg(bundle_path)
        .arg("+refs/*:refs/*");

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    debug!("spawning git fetch from bundle");

    let output = cmd
        .output()
        .await
        .context("failed to spawn git fetch from bundle")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git fetch from bundle failed (status {}): {}",
            output.status,
            stderr.trim(),
        );
    }

    debug!("git fetch from bundle succeeded");
    Ok(())
}

/// Run `git index-pack --fix-thin` in a bare repo, reading a pack stream from a
/// local file and writing a normal pack into `objects/pack`.
#[instrument(fields(repo = %repo_path.display(), pack = %pack_path.display()))]
pub async fn git_index_pack(repo_path: &Path, pack_path: &Path) -> Result<()> {
    let pack_file = std::fs::File::open(pack_path)
        .with_context(|| format!("open pack file {}", pack_path.display()))?;
    let input_pack_size = pack_file.metadata().map(|m| m.len()).unwrap_or_default();

    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo_path)
        .arg("index-pack")
        .arg("--stdin")
        .arg("-v")
        .arg("--fix-thin");

    cmd.stdin(Stdio::from(pack_file));
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::piped());

    debug!("spawning git index-pack");

    let mut child = cmd.spawn().context("failed to spawn git index-pack")?;
    let pid = child.id().unwrap_or_default();
    let started_at = std::time::Instant::now();
    let stderr = child
        .stderr
        .take()
        .context("failed to capture git index-pack stderr")?;
    let mut stderr_lines = BufReader::new(stderr).lines();
    let mut stderr_buf = String::new();
    let mut progress_interval = tokio::time::interval(std::time::Duration::from_secs(60));
    progress_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    info!(
        repo = %repo_path.display(),
        pack = %pack_path.display(),
        pid,
        input_pack_size,
        "git index-pack started"
    );

    let wait_fut = child.wait();
    tokio::pin!(wait_fut);
    let status = loop {
        tokio::select! {
            status = &mut wait_fut => {
                break status.context("failed to wait on git index-pack")?;
            }
            line = stderr_lines.next_line() => {
                if let Some(line) = line.context("failed to read git index-pack stderr")? {
                    if !stderr_buf.is_empty() {
                        stderr_buf.push('\n');
                    }
                    stderr_buf.push_str(&line);
                    debug!(
                        repo = %repo_path.display(),
                        pid,
                        progress = %line,
                        "git index-pack progress"
                    );
                }
            }
            _ = progress_interval.tick() => {
                let pack_dir = repo_path.join("objects").join("pack");
                let pack_dir_bytes = std::fs::read_dir(&pack_dir)
                    .ok()
                    .into_iter()
                    .flat_map(|entries| entries.filter_map(|e| e.ok()))
                    .filter_map(|entry| entry.metadata().ok())
                    .filter(|meta| meta.is_file())
                    .map(|meta| meta.len())
                    .sum::<u64>();
                info!(
                    repo = %repo_path.display(),
                    pack = %pack_path.display(),
                    pid,
                    elapsed_secs = started_at.elapsed().as_secs(),
                    input_pack_size,
                    pack_dir_bytes,
                    "git index-pack still running"
                );
            }
        }
    };

    if !status.success() {
        bail!(
            "git index-pack failed (status {}): {}",
            status,
            stderr_buf.trim(),
        );
    }

    info!(
        repo = %repo_path.display(),
        pack = %pack_path.display(),
        pid,
        elapsed_secs = started_at.elapsed().as_secs(),
        input_pack_size,
        "git index-pack finished"
    );
    Ok(())
}

/// Run `git fsck --connectivity-only` in a bare repo.
#[instrument(fields(repo = %repo_path.display()))]
pub async fn git_fsck_connectivity_only(repo_path: &Path) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo_path)
        .arg("fsck")
        .arg("--connectivity-only");

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    debug!("spawning git fsck --connectivity-only");

    let output = cmd
        .output()
        .await
        .context("failed to spawn git fsck --connectivity-only")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git fsck --connectivity-only failed (status {}): {}",
            output.status,
            stderr.trim(),
        );
    }

    debug!("git fsck --connectivity-only succeeded");
    Ok(())
}

/// Check whether a bare repo already contains the requested object ID.
#[instrument(fields(repo = %repo_path.display(), %oid))]
pub async fn git_has_object(repo_path: &Path, oid: &str) -> Result<bool> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo_path)
        .arg("cat-file")
        .arg("-e")
        .arg(format!("{oid}^{{object}}"));

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::piped());

    let output = cmd
        .output()
        .await
        .context("failed to spawn git cat-file -e")?;

    if output.status.success() {
        return Ok(true);
    }

    if output.status.code() == Some(1) {
        return Ok(false);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    bail!(
        "git cat-file -e failed (status {}): {}",
        output.status,
        stderr.trim(),
    );
}

/// Run `git symbolic-ref HEAD <target>` in a bare repo.
#[instrument(fields(repo = %repo_path.display(), %target))]
pub async fn git_set_head_symbolic_ref(repo_path: &Path, target: &str) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo_path)
        .arg("symbolic-ref")
        .arg("HEAD")
        .arg(target);

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    debug!("spawning git symbolic-ref HEAD");

    let output = cmd
        .output()
        .await
        .context("failed to spawn git symbolic-ref HEAD")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git symbolic-ref HEAD failed (status {}): {}",
            output.status,
            stderr.trim(),
        );
    }

    debug!("git symbolic-ref HEAD succeeded");
    Ok(())
}

/// Run `git bundle verify <bundle_path>`.
#[instrument(fields(bundle = %bundle_path.display()))]
pub async fn git_bundle_verify(bundle_path: &Path) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("bundle").arg("verify").arg(bundle_path);

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    debug!("spawning git bundle verify");

    let output = cmd
        .output()
        .await
        .context("failed to spawn git bundle verify")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git bundle verify failed (status {}): {}",
            output.status,
            stderr.trim(),
        );
    }

    debug!("git bundle verify succeeded");
    Ok(())
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

    #[test]
    fn redact_url_secret_masks_password_with_visible_edges() {
        let redacted = redact_url_secret(
            "https://x-access-token:ghp_abcdefghijklmnopqrstuvwxyz@ghe.example.com/org/repo.git",
            4,
        );
        assert!(redacted.starts_with("https://x-access-token:ghp_"));
        assert!(redacted.ends_with("wxyz@ghe.example.com/org/repo.git"));
        assert!(!redacted.contains("abcdefghijklmnopqrstuvwxyz"));
    }

    #[test]
    fn redact_url_secret_masks_entire_short_secret() {
        let redacted = redact_url_secret(
            "https://x-access-token:abcd@ghe.example.com/org/repo.git",
            4,
        );
        assert_eq!(
            redacted,
            "https://x-access-token:****@ghe.example.com/org/repo.git"
        );
    }
}
