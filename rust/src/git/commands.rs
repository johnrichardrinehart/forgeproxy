//! Git command wrappers using [`tokio::process::Command`].
//!
//! Every function in this module shells out to the system `git` binary for
//! the actual work.  Environment variables (PATs, `GIT_SSH_COMMAND`, etc.)
//! are injected via the `env_vars` parameter so that credential handling is
//! transparent to callers.
//!
//! All functions are fully `async` and use the Tokio process runtime.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tracing::{debug, info, instrument, warn};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GitProcessPriority {
    Normal,
    Background,
}

fn git_command(priority: GitProcessPriority) -> Command {
    let mut cmd = Command::new("git");
    if priority == GitProcessPriority::Background {
        apply_background_process_priority(&mut cmd);
    }
    cmd
}

#[cfg(unix)]
fn apply_background_process_priority(cmd: &mut Command) {
    unsafe {
        cmd.pre_exec(|| {
            // Best-effort equivalent of `nice -n 10 ionice -c2 -n7` without
            // depending on those binaries being present in Nix test sandboxes.
            libc::setpriority(libc::PRIO_PROCESS, 0, 10);
            libc::syscall(
                libc::SYS_ioprio_set,
                1, // IOPRIO_WHO_PROCESS
                0,
                (2 << 13) | 7, // IOPRIO_CLASS_BE, priority 7
            );
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn apply_background_process_priority(_cmd: &mut Command) {
    // Non-Unix platforms keep normal priority.
}

/// Summary of a `git fetch` operation.
#[derive(Debug, Clone)]
pub struct FetchResult {
    /// Number of refs that were updated (new or changed).
    pub refs_updated: usize,
    /// Total bytes received from the remote (parsed from stderr if available,
    /// otherwise 0).
    pub bytes_received: u64,
}

/// Result of a selected-ref fetch that may have skipped refs which vanished
/// between advertisement and fetch time.
#[derive(Debug, Clone)]
pub struct SelectedFetchResult {
    pub fetch_result: FetchResult,
    pub fetched_refspecs: Vec<String>,
    pub missing_remote_refspecs: Vec<String>,
}

#[derive(Debug)]
pub struct GitFetchError {
    status: std::process::ExitStatus,
    stderr: String,
}

impl GitFetchError {
    pub fn stderr(&self) -> &str {
        &self.stderr
    }
}

impl fmt::Display for GitFetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "git fetch failed (status {}): {}",
            self.status, self.stderr
        )
    }
}

impl Error for GitFetchError {}

const FETCH_REFSPECS_STDIN_THRESHOLD: usize = 100;

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

/// Run `git clone --bare --local <source> <dest>` for a local bare repo.
///
/// This snapshots a local repository cheaply by letting Git hard-link object
/// files when possible, while still copying refs into an independent bare repo.
/// We use this for published generations so the reader-visible snapshot remains
/// stable without paying the full cost of a byte-for-byte local object copy.
#[instrument(fields(source = %source.display(), dest = %dest.display()))]
pub async fn git_clone_bare_local(source: &Path, dest: &Path) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("clone")
        .arg("--bare")
        .arg("--local")
        .arg(source)
        .arg(dest);

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    debug!("spawning git clone --bare --local");

    let output = cmd
        .output()
        .await
        .context("failed to spawn git clone --bare --local")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git clone --bare --local failed (status {}): {}",
            output.status,
            stderr.trim(),
        );
    }

    debug!("git clone --bare --local succeeded");
    Ok(())
}

/// Snapshot a local bare repo by copying mutable metadata and hard-linking
/// object payloads when possible, falling back to `git clone --bare --local`.
#[instrument(fields(source = %source.display(), dest = %dest.display()))]
pub async fn git_snapshot_bare_local(source: &Path, dest: &Path) -> Result<()> {
    let source = source.to_path_buf();
    let dest = dest.to_path_buf();
    let snapshot_result = tokio::task::spawn_blocking({
        let source = source.clone();
        let dest = dest.clone();
        move || hardlink_bare_repo_snapshot(&source, &dest)
    })
    .await
    .context("bare repo hardlink snapshot task join failed")?;

    match snapshot_result {
        Ok(()) => {
            debug!("bare repo hardlink snapshot succeeded");
            Ok(())
        }
        Err(error) => {
            warn!(
                source = %source.display(),
                dest = %dest.display(),
                error = %error,
                "bare repo hardlink snapshot failed; falling back to git clone --bare --local"
            );
            if dest.exists() {
                tokio::fs::remove_dir_all(&dest).await.with_context(|| {
                    format!("remove partial bare repo snapshot {}", dest.display())
                })?;
            }
            git_clone_bare_local(&source, &dest).await
        }
    }
}

fn hardlink_bare_repo_snapshot(source: &Path, dest: &Path) -> Result<()> {
    if dest.exists() {
        bail!("destination already exists: {}", dest.display());
    }
    std::fs::create_dir_all(dest)
        .with_context(|| format!("create bare repo snapshot {}", dest.display()))?;
    snapshot_bare_repo_dir(source, dest, source, false)
}

fn snapshot_bare_repo_dir(
    source: &Path,
    dest: &Path,
    root: &Path,
    under_objects: bool,
) -> Result<()> {
    for entry in
        std::fs::read_dir(source).with_context(|| format!("read bare repo {}", source.display()))?
    {
        let entry = entry.with_context(|| format!("read bare repo entry {}", source.display()))?;
        let source_path = entry.path();
        let dest_path = dest.join(entry.file_name());
        let file_type = entry
            .file_type()
            .with_context(|| format!("stat bare repo entry {}", source_path.display()))?;
        let relative = source_path.strip_prefix(root).unwrap_or(&source_path);
        if skip_snapshot_path(relative) {
            continue;
        }

        if file_type.is_dir() {
            std::fs::create_dir_all(&dest_path).with_context(|| {
                format!("create bare repo snapshot dir {}", dest_path.display())
            })?;
            snapshot_bare_repo_dir(
                &source_path,
                &dest_path,
                root,
                under_objects || relative == Path::new("objects"),
            )?;
        } else if file_type.is_file() {
            if should_hardlink_bare_object_file(relative, under_objects) {
                std::fs::hard_link(&source_path, &dest_path).with_context(|| {
                    format!(
                        "hard-link bare repo object {} to {}",
                        source_path.display(),
                        dest_path.display()
                    )
                })?;
            } else {
                std::fs::copy(&source_path, &dest_path).with_context(|| {
                    format!(
                        "copy bare repo metadata {} to {}",
                        source_path.display(),
                        dest_path.display()
                    )
                })?;
            }
        } else {
            bail!(
                "unsupported bare repo entry type: {}",
                source_path.display()
            );
        }
    }
    Ok(())
}

fn skip_snapshot_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".lock") || name.starts_with("tmp_"))
}

fn should_hardlink_bare_object_file(path: &Path, under_objects: bool) -> bool {
    if !under_objects {
        return false;
    }
    let mut components = path.components();
    if components
        .next()
        .and_then(|component| component.as_os_str().to_str())
        != Some("objects")
    {
        return false;
    }
    let Some(first) = components
        .next()
        .and_then(|component| component.as_os_str().to_str())
    else {
        return false;
    };

    if first.len() == 2 && first.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return true;
    }
    first == "pack"
        && path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| matches!(extension, "pack" | "idx" | "bitmap" | "rev"))
}

/// Run `git clone --bare --shared <source> <dest>` for a local bare repo.
///
/// This creates a lightweight workspace that borrows objects from `source`
/// through Git alternates, avoiding a full local object copy before the
/// workspace fetches its own delta from upstream.
#[instrument(fields(source = %source.display(), dest = %dest.display()))]
pub async fn git_clone_bare_shared_local(source: &Path, dest: &Path) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("clone")
        .arg("--bare")
        .arg("--shared")
        .arg(source)
        .arg(dest);

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    debug!("spawning git clone --bare --shared");

    let output = cmd
        .output()
        .await
        .context("failed to spawn git clone --bare --shared")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git clone --bare --shared failed (status {}): {}",
            output.status,
            stderr.trim(),
        );
    }

    debug!("git clone --bare --shared succeeded");
    Ok(())
}

/// Prepare a bare generation so local `git upload-pack` can use object lookup
/// and reachability bitmaps through the multi-pack-index path.
///
/// Avoid a full `git repack -a -d`, which rewrites all pack data on every
/// published generation. MIDX writes keep existing packs in place and only
/// rebuild the index/bitmap metadata that upload-pack needs for fast serving.
#[instrument(fields(repo = %repo_path.display(), pack_threads))]
pub async fn git_prepare_published_generation_indexes(
    repo_path: &Path,
    pack_threads: usize,
) -> Result<()> {
    if !repo_has_pack_files(repo_path)? {
        info!(
            repo = %repo_path.display(),
            "skipping published generation bitmap/MIDX indexes because the repo has no pack files"
        );
        return Ok(());
    }

    let started_at = std::time::Instant::now();

    run_git_multi_pack_index_write(repo_path, false, pack_threads).await?;
    if repo_uses_object_alternates(repo_path)? {
        info!(
            repo = %repo_path.display(),
            pack_threads,
            elapsed_ms = started_at.elapsed().as_millis(),
            "prepared published generation MIDX without bitmap because the object database uses alternates"
        );
        return Ok(());
    }
    run_git_multi_pack_index_write(repo_path, true, pack_threads).await?;

    info!(
        repo = %repo_path.display(),
        pack_threads,
        elapsed_ms = started_at.elapsed().as_millis(),
        "prepared published generation bitmap/MIDX indexes"
    );
    Ok(())
}

fn repo_uses_object_alternates(repo_path: &Path) -> Result<bool> {
    let alternates_path = repo_path.join("objects").join("info").join("alternates");
    let contents = match std::fs::read_to_string(&alternates_path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read {}", alternates_path.display()));
        }
    };
    Ok(contents.lines().any(|line| !line.trim().is_empty()))
}

fn repo_has_pack_files(repo_path: &Path) -> Result<bool> {
    let pack_dir = repo_path.join("objects").join("pack");
    if !pack_dir.is_dir() {
        return Ok(false);
    }

    for entry in std::fs::read_dir(&pack_dir)
        .with_context(|| format!("failed to read pack directory {}", pack_dir.display()))?
    {
        let entry = entry?;
        if entry
            .path()
            .extension()
            .is_some_and(|extension| extension == "pack")
        {
            return Ok(true);
        }
    }

    Ok(false)
}

async fn run_git_multi_pack_index_write(
    repo_path: &Path,
    bitmap: bool,
    pack_threads: usize,
) -> Result<()> {
    git_multi_pack_index_write_for_object_dir(&repo_path.join("objects"), bitmap, pack_threads)
        .await
}

#[instrument(fields(object_dir = %object_dir.display(), bitmap, pack_threads))]
pub async fn git_multi_pack_index_write_for_object_dir(
    object_dir: &Path,
    bitmap: bool,
    pack_threads: usize,
) -> Result<()> {
    let git_dir = object_dir.parent().with_context(|| {
        format!(
            "multi-pack-index object dir {} has no parent git dir",
            object_dir.display()
        )
    })?;
    let mut cmd = git_command(GitProcessPriority::Background);
    cmd.current_dir(git_dir)
        .env("GIT_DIR", git_dir)
        .arg("-c")
        .arg(format!("pack.threads={pack_threads}"))
        .arg("multi-pack-index")
        .arg(format!("--object-dir={}", object_dir.display()))
        .arg("write");
    if bitmap {
        cmd.arg("--bitmap");
    }

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    debug!(bitmap, "spawning git multi-pack-index write");

    let output = cmd.output().await.with_context(|| {
        format!(
            "failed to spawn git multi-pack-index write bitmap={bitmap} object_dir={}",
            object_dir.display()
        )
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git multi-pack-index write bitmap={} object_dir={} failed (status {}): {}",
            bitmap,
            object_dir.display(),
            output.status,
            stderr.trim(),
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Fetch
// ---------------------------------------------------------------------------

/// Run `git fetch <remote_url> +refs/*:refs/*` inside an existing bare repo.
///
/// Emits start/progress/finish logs for long-running fetches and returns a
/// [`FetchResult`] summarising the update.
#[instrument(skip(env_vars, remote_url), fields(repo = %repo_path.display()))]
pub async fn git_fetch(
    repo_path: &Path,
    remote_url: &str,
    env_vars: &[(String, String)],
) -> Result<FetchResult> {
    git_fetch_with_context(repo_path, remote_url, env_vars, None).await
}

pub async fn git_fetch_with_context(
    repo_path: &Path,
    remote_url: &str,
    env_vars: &[(String, String)],
    fetch_priority: Option<&str>,
) -> Result<FetchResult> {
    git_fetch_refspecs_with_context(
        repo_path,
        remote_url,
        env_vars,
        &["+refs/*:refs/*".to_string()],
        true,
        fetch_priority,
    )
    .await
}

/// Run `git fetch <remote_url> <refspec>...` inside an existing bare repo.
///
/// When `prune` is true, Git will drop refs that disappeared from the remote.
/// Narrow request-time catch-up fetches should typically disable pruning so a
/// partial refspec update does not delete unrelated refs.
#[instrument(skip(env_vars, remote_url, refspecs), fields(repo = %repo_path.display()))]
pub async fn git_fetch_refspecs_with_context(
    repo_path: &Path,
    remote_url: &str,
    env_vars: &[(String, String)],
    refspecs: &[String],
    prune: bool,
    fetch_priority: Option<&str>,
) -> Result<FetchResult> {
    if refspecs.is_empty() {
        bail!("git fetch requires at least one refspec");
    }

    let use_stdin = should_feed_fetch_refspecs_on_stdin(refspecs);

    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(repo_path).arg("fetch").arg("--force");
    if prune {
        cmd.arg("--prune");
    }
    if use_stdin {
        cmd.arg("--stdin");
    }
    cmd.arg(remote_url);
    if !use_stdin {
        for refspec in refspecs {
            cmd.arg(refspec);
        }
    }

    cmd.env("GIT_TERMINAL_PROMPT", "0");
    for (k, v) in env_vars {
        cmd.env(k, v);
    }

    cmd.stdin(if use_stdin {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::piped());

    debug!("spawning git fetch");

    let mut child = cmd.spawn().context("failed to spawn git fetch")?;
    let pid = child.id().unwrap_or_default();
    let started_at = std::time::Instant::now();
    let stdin_writer = if use_stdin {
        let mut stdin = child
            .stdin
            .take()
            .context("failed to capture git fetch stdin")?;
        let input = encode_fetch_refspecs_stdin(refspecs);
        Some(tokio::spawn(async move {
            stdin
                .write_all(&input)
                .await
                .context("failed to write refspecs to git fetch stdin")?;
            stdin
                .shutdown()
                .await
                .context("failed to close git fetch stdin")?;
            Ok::<(), anyhow::Error>(())
        }))
    } else {
        None
    };
    let stderr = child
        .stderr
        .take()
        .context("failed to capture git fetch stderr")?;
    let mut stderr_lines = BufReader::new(stderr).lines();
    let mut stderr_buf = String::new();
    let mut progress_interval = tokio::time::interval(std::time::Duration::from_secs(60));
    progress_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    info!(
        repo = %repo_path.display(),
        pid,
        remote = %redact_url_secret(remote_url, 4),
        refspec_mode = if refspecs.len() == 1 && refspecs[0] == "+refs/*:refs/*" {
            "all"
        } else {
            "selected"
        },
        fetch_priority = fetch_priority.unwrap_or("unspecified"),
        refspec_count = refspecs.len(),
        prune,
        "git fetch started"
    );

    let wait_fut = child.wait();
    tokio::pin!(wait_fut);
    let status = loop {
        tokio::select! {
            status = &mut wait_fut => {
                break status.context("failed to wait on git fetch")?;
            }
            line = stderr_lines.next_line() => {
                if let Some(line) = line.context("failed to read git fetch stderr")? {
                    if !stderr_buf.is_empty() {
                        stderr_buf.push('\n');
                    }
                    stderr_buf.push_str(&line);
                    debug!(
                        repo = %repo_path.display(),
                        pid,
                        progress = %line,
                        "git fetch progress"
                    );
                }
            }
            _ = progress_interval.tick() => {
                info!(
                    repo = %repo_path.display(),
                    pid,
                    elapsed_secs = started_at.elapsed().as_secs(),
                    "git fetch still running"
                );
            }
        }
    };

    let stdin_writer_result = if let Some(stdin_writer) = stdin_writer {
        Some(
            stdin_writer
                .await
                .context("git fetch stdin writer task join failed"),
        )
    } else {
        None
    };

    while let Some(line) = stderr_lines
        .next_line()
        .await
        .context("failed to read remaining git fetch stderr")?
    {
        if !stderr_buf.is_empty() {
            stderr_buf.push('\n');
        }
        stderr_buf.push_str(&line);
        debug!(
            repo = %repo_path.display(),
            pid,
            progress = %line,
            "git fetch progress"
        );
    }

    if !status.success() {
        return Err(GitFetchError {
            status,
            stderr: stderr_buf.trim().to_string(),
        }
        .into());
    }
    if let Some(result) = stdin_writer_result {
        result??;
    }

    let refs_updated = count_updated_refs(&stderr_buf);
    let bytes_received = parse_bytes_received(&stderr_buf);

    info!(
        refs_updated = refs_updated,
        bytes_received = bytes_received,
        elapsed_secs = started_at.elapsed().as_secs(),
        pid,
        "git fetch complete"
    );

    Ok(FetchResult {
        refs_updated,
        bytes_received,
    })
}

/// Run a selected-ref fetch and retry after dropping refs that disappeared
/// from the remote between advertisement and fetch time.
pub async fn git_fetch_refspecs_allow_missing_remote_refs_with_context(
    repo_path: &Path,
    remote_url: &str,
    env_vars: &[(String, String)],
    refspecs: &[String],
    prune: bool,
    fetch_priority: Option<&str>,
) -> Result<SelectedFetchResult> {
    if refspecs.is_empty() {
        bail!("git fetch requires at least one refspec");
    }

    let mut pending_refspecs = refspecs.to_vec();
    let mut missing_remote_refspecs = Vec::new();

    loop {
        match git_fetch_refspecs_with_context(
            repo_path,
            remote_url,
            env_vars,
            &pending_refspecs,
            prune,
            fetch_priority,
        )
        .await
        {
            Ok(fetch_result) => {
                return Ok(SelectedFetchResult {
                    fetch_result,
                    fetched_refspecs: pending_refspecs,
                    missing_remote_refspecs,
                });
            }
            Err(error) => {
                let missing_remote_refs = {
                    let Some(fetch_error) = error.downcast_ref::<GitFetchError>() else {
                        return Err(error);
                    };
                    missing_remote_refs_from_fetch_stderr(fetch_error.stderr())
                };
                if missing_remote_refs.is_empty() {
                    return Err(error);
                }

                let before_len = pending_refspecs.len();
                let mut next_refspecs = Vec::with_capacity(before_len);
                for refspec in pending_refspecs {
                    if missing_remote_refs.contains(refspec_source_ref(&refspec)) {
                        missing_remote_refspecs.push(refspec);
                    } else {
                        next_refspecs.push(refspec);
                    }
                }

                if next_refspecs.len() == before_len {
                    return Err(error);
                }
                if next_refspecs.is_empty() {
                    return Ok(SelectedFetchResult {
                        fetch_result: FetchResult {
                            refs_updated: 0,
                            bytes_received: 0,
                        },
                        fetched_refspecs: Vec::new(),
                        missing_remote_refspecs,
                    });
                }

                info!(
                    repo = %repo_path.display(),
                    missing_remote_refspecs = missing_remote_refspecs.len(),
                    remaining_refspecs = next_refspecs.len(),
                    fetch_priority = fetch_priority.unwrap_or("unspecified"),
                    "retrying selected git fetch after dropping refs that disappeared from the remote"
                );
                pending_refspecs = next_refspecs;
            }
        }
    }
}

fn should_feed_fetch_refspecs_on_stdin(refspecs: &[String]) -> bool {
    refspecs.len() > FETCH_REFSPECS_STDIN_THRESHOLD
}

fn encode_fetch_refspecs_stdin(refspecs: &[String]) -> Vec<u8> {
    let mut input = Vec::with_capacity(refspecs.iter().map(|refspec| refspec.len() + 1).sum());
    for refspec in refspecs {
        input.extend_from_slice(refspec.as_bytes());
        input.push(b'\n');
    }
    input
}

fn refspec_source_ref(refspec: &str) -> &str {
    let refspec = refspec.strip_prefix('+').unwrap_or(refspec);
    refspec
        .split_once(':')
        .map(|(source, _)| source)
        .unwrap_or(refspec)
}

fn missing_remote_refs_from_fetch_stderr(stderr: &str) -> BTreeSet<&str> {
    stderr
        .lines()
        .filter_map(|line| {
            line.split_once("couldn't find remote ref ")
                .map(|(_, remote_ref)| remote_ref.trim())
        })
        .filter(|remote_ref| !remote_ref.is_empty())
        .collect()
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
#[instrument(fields(repo = %repo_path.display(), pack = %pack_path.display(), pack_threads))]
pub async fn git_index_pack(repo_path: &Path, pack_path: &Path, pack_threads: usize) -> Result<()> {
    let pack_file = std::fs::File::open(pack_path)
        .with_context(|| format!("open pack file {}", pack_path.display()))?;
    let input_pack_size = pack_file.metadata().map(|m| m.len()).unwrap_or_default();

    let mut cmd = git_command(GitProcessPriority::Background);
    cmd.arg("-C")
        .arg(repo_path)
        .arg("index-pack")
        .arg("--stdin")
        .arg(format!("--threads={pack_threads}"))
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
        pack_threads,
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
                    pack_threads,
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
        pack_threads,
        elapsed_secs = started_at.elapsed().as_secs(),
        input_pack_size,
        "git index-pack finished"
    );
    Ok(())
}

#[instrument(fields(pack = %pack_path.display(), idx = %idx_path.display(), pack_threads))]
pub async fn git_index_pack_to_idx(
    pack_path: &Path,
    idx_path: &Path,
    pack_threads: usize,
) -> Result<()> {
    let mut cmd = git_command(GitProcessPriority::Background);
    cmd.arg("index-pack")
        .arg(format!("--threads={pack_threads}"))
        .arg("-o")
        .arg(idx_path)
        .arg(pack_path);

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let started_at = std::time::Instant::now();
    info!(
        pack = %pack_path.display(),
        idx = %idx_path.display(),
        pack_threads,
        "git index-pack to idx started"
    );

    let output = cmd.output().await.with_context(|| {
        format!(
            "failed to spawn git index-pack for {} -> {}",
            pack_path.display(),
            idx_path.display()
        )
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git index-pack {} -> {} failed (status {}): {}",
            pack_path.display(),
            idx_path.display(),
            output.status,
            stderr.trim(),
        );
    }

    info!(
        pack = %pack_path.display(),
        idx = %idx_path.display(),
        pack_threads,
        elapsed_secs = started_at.elapsed().as_secs(),
        "git index-pack to idx finished"
    );

    Ok(())
}

/// Run `git fsck --connectivity-only` in a bare repo.
#[instrument(fields(repo = %repo_path.display()))]
pub async fn git_fsck_connectivity_only(repo_path: &Path) -> Result<()> {
    git_fsck_connectivity_only_with_priority(repo_path, GitProcessPriority::Normal).await
}

#[instrument(fields(repo = %repo_path.display()))]
pub async fn git_fsck_connectivity_only_background(repo_path: &Path) -> Result<()> {
    git_fsck_connectivity_only_with_priority(repo_path, GitProcessPriority::Background).await
}

async fn git_fsck_connectivity_only_with_priority(
    repo_path: &Path,
    priority: GitProcessPriority,
) -> Result<()> {
    let mut cmd = git_command(priority);
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

/// Check a batch of object IDs and return the subset missing from the bare repo.
#[instrument(fields(repo = %repo_path.display(), object_count = oids.len()))]
pub async fn git_missing_objects(repo_path: &Path, oids: &[String]) -> Result<Vec<String>> {
    if oids.is_empty() {
        return Ok(Vec::new());
    }

    let mut input = Vec::with_capacity(oids.iter().map(|oid| oid.len() + 1).sum());
    for oid in oids {
        input.extend_from_slice(oid.as_bytes());
        input.push(b'\n');
    }

    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo_path)
        .arg("cat-file")
        .arg("--batch-check");

    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .context("failed to spawn git cat-file --batch-check")?;

    let mut stdin = child
        .stdin
        .take()
        .context("failed to capture git cat-file stdin")?;
    let stdin_writer = tokio::spawn(async move {
        stdin
            .write_all(&input)
            .await
            .context("failed to write object ids to git cat-file")?;
        stdin
            .shutdown()
            .await
            .context("failed to close git cat-file stdin")?;
        Ok::<(), anyhow::Error>(())
    });

    let output = child
        .wait_with_output()
        .await
        .context("failed to wait on git cat-file --batch-check")?;
    stdin_writer
        .await
        .context("git cat-file stdin writer task join failed")??;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git cat-file --batch-check failed (status {}): {}",
            output.status,
            stderr.trim(),
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut missing = Vec::new();
    for line in stdout.lines() {
        if let Some(oid) = line.strip_suffix(" missing") {
            missing.push(oid.to_string());
        }
    }

    Ok(missing)
}

#[cfg(test)]
#[instrument(fields(repo = %repo_path.display(), tips = tips.len()))]
pub async fn git_rev_list_objects(repo_path: &Path, tips: &[String]) -> Result<Vec<String>> {
    git_rev_list_objects_excluding(repo_path, tips, &[]).await
}

#[instrument(fields(repo = %repo_path.display(), tips = tips.len(), excluded_tips = excluded_tips.len()))]
pub async fn git_rev_list_objects_excluding(
    repo_path: &Path,
    tips: &[String],
    excluded_tips: &[String],
) -> Result<Vec<String>> {
    if tips.is_empty() {
        return Ok(Vec::new());
    }

    let input_len = tips.iter().map(|tip| tip.len() + 1).sum::<usize>()
        + excluded_tips.iter().map(|tip| tip.len() + 2).sum::<usize>();
    let mut input = Vec::with_capacity(input_len);
    for tip in tips {
        input.extend_from_slice(tip.as_bytes());
        input.push(b'\n');
    }
    for tip in excluded_tips {
        input.push(b'^');
        input.extend_from_slice(tip.as_bytes());
        input.push(b'\n');
    }

    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo_path)
        .arg("rev-list")
        .arg("--objects")
        .arg("--stdin");

    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .context("failed to spawn git rev-list --objects")?;
    let mut stdin = child
        .stdin
        .take()
        .context("failed to capture git rev-list stdin")?;
    let stdin_writer = tokio::spawn(async move {
        stdin
            .write_all(&input)
            .await
            .context("failed to write revisions to git rev-list --objects")?;
        stdin
            .shutdown()
            .await
            .context("failed to close git rev-list stdin")?;
        Ok::<(), anyhow::Error>(())
    });

    let output = child
        .wait_with_output()
        .await
        .context("failed to wait on git rev-list --objects")?;
    stdin_writer
        .await
        .context("git rev-list --objects stdin writer task join failed")??;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git rev-list --objects failed (status {}): {}",
            output.status,
            stderr.trim(),
        );
    }

    let stdout = String::from_utf8(output.stdout).context("git rev-list output was not UTF-8")?;
    let mut objects = Vec::new();
    let mut seen = HashSet::new();
    for line in stdout.lines() {
        let Some(oid) = line.split_whitespace().next() else {
            continue;
        };
        if oid.len() == 40 && seen.insert(oid.to_string()) {
            objects.push(oid.to_string());
        }
    }
    Ok(objects)
}

/// Return true when every revision in `candidate_ancestors` is reachable from
/// at least one revision in `descendants`.
#[cfg(test)]
#[instrument(fields(repo = %repo_path.display(), candidate_ancestors = candidate_ancestors.len(), descendants = descendants.len()))]
pub async fn git_revisions_reachable_from_any(
    repo_path: &Path,
    candidate_ancestors: &[String],
    descendants: &[String],
) -> Result<bool> {
    if candidate_ancestors.is_empty() {
        return Ok(true);
    }
    if descendants.is_empty() {
        return Ok(false);
    }

    let mut input = Vec::new();
    for oid in candidate_ancestors {
        input.extend_from_slice(oid.as_bytes());
        input.push(b'\n');
    }
    for oid in descendants {
        input.push(b'^');
        input.extend_from_slice(oid.as_bytes());
        input.push(b'\n');
    }

    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo_path)
        .arg("rev-list")
        .arg("--stdin")
        .arg("--max-count=1");

    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    debug!("spawning git rev-list reachability check");

    let mut child = cmd
        .spawn()
        .context("failed to spawn git rev-list reachability check")?;
    let mut stdin = child
        .stdin
        .take()
        .context("failed to capture git rev-list stdin")?;
    let stdin_writer = tokio::spawn(async move {
        stdin
            .write_all(&input)
            .await
            .context("failed to write revisions to git rev-list")?;
        stdin
            .shutdown()
            .await
            .context("failed to close git rev-list stdin")?;
        Ok::<(), anyhow::Error>(())
    });

    let output = child
        .wait_with_output()
        .await
        .context("failed to wait on git rev-list reachability check")?;
    stdin_writer
        .await
        .context("git rev-list stdin writer task join failed")??;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git rev-list reachability check failed (status {}): {}",
            output.status,
            stderr.trim(),
        );
    }

    Ok(output.stdout.iter().all(|byte| byte.is_ascii_whitespace()))
}

#[cfg(test)]
fn git_cat_file_missing_object(status: &std::process::ExitStatus, stderr: &str) -> bool {
    status.code() == Some(1)
        || (status.code() == Some(128) && stderr.contains("Not a valid object name"))
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

/// Run `git -C <repo_path> bundle verify <bundle_path>`.
#[instrument(fields(repo = %repo_path.display(), bundle = %bundle_path.display()))]
pub async fn git_bundle_verify(repo_path: &Path, bundle_path: &Path) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo_path)
        .arg("bundle")
        .arg("verify")
        .arg(bundle_path);

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
    pack_threads: usize,
) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo_path)
        .arg("-c")
        .arg(format!("pack.threads={pack_threads}"))
        .arg("bundle")
        .arg("create")
        .arg(output);
    set_tmpdir_to_output_parent(&mut cmd, output);

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
    pack_threads: usize,
) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo_path)
        .arg("-c")
        .arg(format!("pack.threads={pack_threads}"))
        .arg("bundle")
        .arg("create")
        .arg(format!("--filter={filter}"))
        .arg(output)
        .arg("--all");
    set_tmpdir_to_output_parent(&mut cmd, output);

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

/// Generate a raw pack containing objects reachable from `new_tips` but not
/// reachable from `prev_tips`.
#[instrument(fields(repo = %repo_path.display(), object_count = object_ids.len(), pack_threads))]
pub async fn git_pack_objects_exact(
    repo_path: &Path,
    object_ids: &[String],
    pack_threads: usize,
) -> Result<Vec<u8>> {
    git_pack_objects_exact_with_priority(
        repo_path,
        object_ids,
        pack_threads,
        GitProcessPriority::Normal,
    )
    .await
}

pub async fn git_pack_objects_exact_background(
    repo_path: &Path,
    object_ids: &[String],
    pack_threads: usize,
) -> Result<Vec<u8>> {
    git_pack_objects_exact_with_priority(
        repo_path,
        object_ids,
        pack_threads,
        GitProcessPriority::Background,
    )
    .await
}

async fn git_pack_objects_exact_with_priority(
    repo_path: &Path,
    object_ids: &[String],
    pack_threads: usize,
    priority: GitProcessPriority,
) -> Result<Vec<u8>> {
    if object_ids.is_empty() {
        bail!("cannot create exact pack without object ids");
    }

    let mut input = Vec::with_capacity(object_ids.iter().map(|oid| oid.len() + 1).sum());
    for oid in object_ids {
        input.extend_from_slice(oid.as_bytes());
        input.push(b'\n');
    }

    let mut cmd = git_command(priority);
    cmd.arg("-C")
        .arg(repo_path)
        .arg("-c")
        .arg(format!("pack.threads={pack_threads}"))
        .arg("pack-objects")
        .arg("--stdout")
        .arg("--non-empty")
        .arg("--no-reuse-delta")
        .arg("--no-delta-base-offset");

    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .context("failed to spawn git pack-objects exact")?;
    let mut stdin = child
        .stdin
        .take()
        .context("failed to capture git pack-objects exact stdin")?;
    let stdin_writer = tokio::spawn(async move {
        stdin
            .write_all(&input)
            .await
            .context("failed to write object ids to git pack-objects exact")?;
        stdin
            .shutdown()
            .await
            .context("failed to close git pack-objects exact stdin")?;
        Ok::<(), anyhow::Error>(())
    });

    let output = child
        .wait_with_output()
        .await
        .context("failed to wait on git pack-objects exact")?;
    stdin_writer
        .await
        .context("git pack-objects exact stdin writer task join failed")??;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git pack-objects exact failed (status {}): {}",
            output.status,
            stderr.trim(),
        );
    }
    if output.stdout.is_empty() {
        bail!("git pack-objects exact produced an empty pack");
    }

    Ok(output.stdout)
}

fn set_tmpdir_to_output_parent(cmd: &mut Command, output: &Path) {
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        cmd.env("TMPDIR", parent);
    }
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
    use std::process::Command as StdCommand;
    use tokio::time::{Duration, timeout};

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

    #[tokio::test]
    async fn hardlink_snapshot_bare_local_preserves_refs_and_objects() {
        let tempdir = tempfile::tempdir().unwrap();
        let work_path = tempdir.path().join("work");
        let source_path = tempdir.path().join("source.git");
        let snapshot_path = tempdir.path().join("snapshot.git");

        assert_git_success(StdCommand::new("git").arg("init").arg(&work_path));
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("config")
                .arg("user.email")
                .arg("test@example.com"),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("config")
                .arg("user.name")
                .arg("Test User"),
        );
        std::fs::write(work_path.join("file.txt"), "hello\n").unwrap();
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("add")
                .arg("."),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("commit")
                .arg("-m")
                .arg("initial"),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("clone")
                .arg("--bare")
                .arg(&work_path)
                .arg(&source_path),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&source_path)
                .arg("repack")
                .arg("-ad"),
        );

        git_snapshot_bare_local(&source_path, &snapshot_path)
            .await
            .unwrap();

        let source_head = git_stdout(
            StdCommand::new("git")
                .arg("-C")
                .arg(&source_path)
                .arg("rev-parse")
                .arg("HEAD"),
        );
        let snapshot_head = git_stdout(
            StdCommand::new("git")
                .arg("-C")
                .arg(&snapshot_path)
                .arg("rev-parse")
                .arg("HEAD"),
        );
        assert_eq!(source_head, snapshot_head);
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&snapshot_path)
                .arg("fsck")
                .arg("--no-progress"),
        );
    }

    #[tokio::test]
    async fn hardlink_snapshot_bare_local_supports_smart_clone() {
        let tempdir = tempfile::tempdir().unwrap();
        let work_path = tempdir.path().join("work");
        let source_path = tempdir.path().join("source.git");
        let snapshot_path = tempdir.path().join("snapshot.git");
        let clone_path = tempdir.path().join("clone");

        assert_git_success(StdCommand::new("git").arg("init").arg(&work_path));
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("config")
                .arg("user.email")
                .arg("test@example.com"),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("config")
                .arg("user.name")
                .arg("Test User"),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("checkout")
                .arg("-b")
                .arg("main"),
        );

        std::fs::write(work_path.join("README.md"), "hello\n").unwrap();
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("add")
                .arg("."),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("commit")
                .arg("-m")
                .arg("main"),
        );

        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("checkout")
                .arg("-b")
                .arg("side"),
        );
        std::fs::write(work_path.join("side.txt"), "side\n").unwrap();
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("add")
                .arg("side.txt"),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("commit")
                .arg("-m")
                .arg("side"),
        );

        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("checkout")
                .arg("--orphan")
                .arg("unrelated"),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("rm")
                .arg("-rf")
                .arg("."),
        );
        std::fs::write(work_path.join("unrelated.txt"), "unrelated\n").unwrap();
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("add")
                .arg("unrelated.txt"),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("commit")
                .arg("-m")
                .arg("unrelated"),
        );

        assert_git_success(
            StdCommand::new("git")
                .arg("clone")
                .arg("--bare")
                .arg(&work_path)
                .arg(&source_path),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&source_path)
                .arg("repack")
                .arg("-ad"),
        );

        git_snapshot_bare_local(&source_path, &snapshot_path)
            .await
            .unwrap();

        assert_git_success(
            StdCommand::new("git")
                .arg("clone")
                .arg("--no-local")
                .arg(format!("file://{}", snapshot_path.display()))
                .arg(&clone_path),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&clone_path)
                .arg("fsck")
                .arg("--no-progress"),
        );
    }

    #[test]
    fn large_fetch_refspec_lists_are_sent_on_stdin() {
        let small = vec!["+refs/heads/main:refs/heads/main".to_string(); 100];
        let large = vec!["+refs/heads/main:refs/heads/main".to_string(); 101];

        assert!(!should_feed_fetch_refspecs_on_stdin(&small));
        assert!(should_feed_fetch_refspecs_on_stdin(&large));
    }

    #[test]
    fn fetch_refspec_stdin_encoding_is_line_delimited() {
        let input = encode_fetch_refspecs_stdin(&[
            "+refs/heads/main:refs/heads/main".to_string(),
            "+refs/heads/dev:refs/heads/dev".to_string(),
        ]);

        assert_eq!(
            input,
            b"+refs/heads/main:refs/heads/main\n+refs/heads/dev:refs/heads/dev\n"
        );
    }

    #[test]
    fn missing_remote_ref_parser_extracts_refnames_from_git_fetch_stderr() {
        let stderr = "\
fatal: couldn't find remote ref refs/heads/foo/locks-master-web-infra
fatal: something else
fatal: couldn't find remote ref refs/tags/tmp-lock
";

        assert_eq!(
            missing_remote_refs_from_fetch_stderr(stderr),
            BTreeSet::from([
                "refs/heads/foo/locks-master-web-infra",
                "refs/tags/tmp-lock"
            ])
        );
    }

    #[test]
    fn bundle_create_tmpdir_env_uses_output_parent() {
        let tmpdir_key = std::ffi::OsStr::new("TMPDIR");
        let output = Path::new("/cache/.state/bundle-tmp/work/repo.bundle");
        let mut cmd = Command::new("git");

        set_tmpdir_to_output_parent(&mut cmd, output);

        let tmpdir = cmd
            .as_std()
            .get_envs()
            .find_map(|(key, value)| (key == tmpdir_key).then_some(value))
            .flatten();

        assert_eq!(
            tmpdir,
            Some(Path::new("/cache/.state/bundle-tmp/work").as_os_str())
        );
    }

    #[test]
    fn bundle_create_tmpdir_env_ignores_parentless_output() {
        let tmpdir_key = std::ffi::OsStr::new("TMPDIR");
        let mut cmd = Command::new("git");

        set_tmpdir_to_output_parent(&mut cmd, Path::new("repo.bundle"));

        assert!(!cmd.as_std().get_envs().any(|(key, _)| key == tmpdir_key));
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

    #[test]
    fn git_cat_file_invalid_object_name_counts_as_missing() {
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg("exit 128")
            .status()
            .unwrap();
        assert!(git_cat_file_missing_object(
            &status,
            "fatal: Not a valid object name 07ae7ae^{object}"
        ));
    }

    #[tokio::test]
    async fn git_missing_objects_handles_large_batch_output_without_deadlocking() {
        let tempdir = tempfile::tempdir().unwrap();
        let repo_path = tempdir.path();

        let status = StdCommand::new("git")
            .arg("init")
            .arg(repo_path)
            .status()
            .unwrap();
        assert!(status.success());

        let status = StdCommand::new("git")
            .arg("-C")
            .arg(repo_path)
            .arg("config")
            .arg("user.email")
            .arg("test@example.com")
            .status()
            .unwrap();
        assert!(status.success());

        let status = StdCommand::new("git")
            .arg("-C")
            .arg(repo_path)
            .arg("config")
            .arg("user.name")
            .arg("Test User")
            .status()
            .unwrap();
        assert!(status.success());

        std::fs::write(repo_path.join("file.txt"), "hello\n").unwrap();

        let status = StdCommand::new("git")
            .arg("-C")
            .arg(repo_path)
            .arg("add")
            .arg("file.txt")
            .status()
            .unwrap();
        assert!(status.success());

        let status = StdCommand::new("git")
            .arg("-C")
            .arg(repo_path)
            .arg("commit")
            .arg("-m")
            .arg("initial")
            .status()
            .unwrap();
        assert!(status.success());

        let head = String::from_utf8(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("rev-parse")
                .arg("HEAD")
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();

        let wants = vec![head; 4096];
        let missing = timeout(
            Duration::from_secs(10),
            git_missing_objects(repo_path, &wants),
        )
        .await
        .expect("git_missing_objects timed out")
        .unwrap();

        assert!(missing.is_empty());
    }

    #[tokio::test]
    async fn git_revisions_reachable_from_any_detects_non_linear_boundaries() {
        let tempdir = tempfile::tempdir().unwrap();
        let repo_path = tempdir.path();

        assert_git_success(StdCommand::new("git").arg("init").arg(repo_path));
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("config")
                .arg("user.email")
                .arg("test@example.com"),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("config")
                .arg("user.name")
                .arg("Test User"),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("switch")
                .arg("-c")
                .arg("main"),
        );

        std::fs::write(repo_path.join("base.txt"), "base\n").unwrap();
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("add")
                .arg("."),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("commit")
                .arg("-m")
                .arg("base"),
        );
        let main_v1 = git_stdout(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("rev-parse")
                .arg("HEAD"),
        )
        .trim()
        .to_string();

        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("switch")
                .arg("-c")
                .arg("feature"),
        );
        std::fs::write(repo_path.join("feature.txt"), "feature\n").unwrap();
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("add")
                .arg("."),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("commit")
                .arg("-m")
                .arg("feature"),
        );
        let feature_v1 = git_stdout(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("rev-parse")
                .arg("HEAD"),
        )
        .trim()
        .to_string();

        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("switch")
                .arg("main"),
        );
        std::fs::write(repo_path.join("main.txt"), "main\n").unwrap();
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("add")
                .arg("."),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("commit")
                .arg("-m")
                .arg("main"),
        );
        let main_v2 = git_stdout(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("rev-parse")
                .arg("HEAD"),
        )
        .trim()
        .to_string();

        assert!(
            git_revisions_reachable_from_any(
                repo_path,
                std::slice::from_ref(&main_v1),
                std::slice::from_ref(&main_v2),
            )
            .await
            .unwrap()
        );
        assert!(
            !git_revisions_reachable_from_any(
                repo_path,
                std::slice::from_ref(&feature_v1),
                std::slice::from_ref(&main_v2),
            )
            .await
            .unwrap()
        );
        assert!(
            !git_revisions_reachable_from_any(repo_path, &[main_v1, feature_v1], &[main_v2])
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn git_rev_list_objects_excluding_returns_only_delta_closure() {
        let tempdir = tempfile::tempdir().unwrap();
        let repo_path = tempdir.path();

        assert_git_success(StdCommand::new("git").arg("init").arg(repo_path));
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("config")
                .arg("user.email")
                .arg("test@example.com"),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("config")
                .arg("user.name")
                .arg("Test User"),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("switch")
                .arg("-c")
                .arg("main"),
        );

        std::fs::write(repo_path.join("base.txt"), "base\n").unwrap();
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("add")
                .arg("."),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("commit")
                .arg("-m")
                .arg("base"),
        );
        let base = git_stdout(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("rev-parse")
                .arg("HEAD"),
        )
        .trim()
        .to_string();

        std::fs::write(repo_path.join("delta.txt"), "delta\n").unwrap();
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("add")
                .arg("."),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("commit")
                .arg("-m")
                .arg("delta"),
        );
        let head = git_stdout(
            StdCommand::new("git")
                .arg("-C")
                .arg(repo_path)
                .arg("rev-parse")
                .arg("HEAD"),
        )
        .trim()
        .to_string();

        let full = git_rev_list_objects(repo_path, std::slice::from_ref(&head))
            .await
            .unwrap();
        let delta = git_rev_list_objects_excluding(
            repo_path,
            std::slice::from_ref(&head),
            std::slice::from_ref(&base),
        )
        .await
        .unwrap();

        assert!(!delta.is_empty());
        assert!(delta.len() < full.len());
        assert!(delta.contains(&head));
        assert!(!delta.contains(&base));
    }

    #[tokio::test]
    async fn exact_missing_object_sets_shrink_for_shared_history_candidates() {
        let tempdir = tempfile::tempdir().unwrap();
        let repo_path = tempdir.path().join("repo");
        let cache_view_path = tempdir.path().join("cache-view.git");

        assert_git_success(StdCommand::new("git").arg("init").arg(&repo_path));
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&repo_path)
                .arg("config")
                .arg("user.email")
                .arg("test@example.com"),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&repo_path)
                .arg("config")
                .arg("user.name")
                .arg("Test User"),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&repo_path)
                .arg("switch")
                .arg("-c")
                .arg("main"),
        );

        std::fs::write(repo_path.join("shared.txt"), "shared\n").unwrap();
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&repo_path)
                .arg("add")
                .arg("."),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&repo_path)
                .arg("commit")
                .arg("-m")
                .arg("base"),
        );
        let base = git_stdout(
            StdCommand::new("git")
                .arg("-C")
                .arg(&repo_path)
                .arg("rev-parse")
                .arg("HEAD"),
        )
        .trim()
        .to_string();

        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&repo_path)
                .arg("switch")
                .arg("-c")
                .arg("feature"),
        );
        std::fs::write(repo_path.join("feature.txt"), "feature\n").unwrap();
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&repo_path)
                .arg("add")
                .arg("."),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&repo_path)
                .arg("commit")
                .arg("-m")
                .arg("feature"),
        );
        let feature = git_stdout(
            StdCommand::new("git")
                .arg("-C")
                .arg(&repo_path)
                .arg("rev-parse")
                .arg("HEAD"),
        )
        .trim()
        .to_string();

        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&repo_path)
                .arg("switch")
                .arg("main"),
        );
        std::fs::write(repo_path.join("main.txt"), "main\n").unwrap();
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&repo_path)
                .arg("add")
                .arg("."),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&repo_path)
                .arg("commit")
                .arg("-m")
                .arg("main"),
        );
        let main = git_stdout(
            StdCommand::new("git")
                .arg("-C")
                .arg(&repo_path)
                .arg("rev-parse")
                .arg("HEAD"),
        )
        .trim()
        .to_string();

        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&repo_path)
                .arg("switch")
                .arg("--orphan")
                .arg("unrelated"),
        );
        std::fs::write(repo_path.join("unrelated.txt"), "unrelated\n").unwrap();
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&repo_path)
                .arg("add")
                .arg("."),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&repo_path)
                .arg("commit")
                .arg("-m")
                .arg("unrelated"),
        );
        let unrelated = git_stdout(
            StdCommand::new("git")
                .arg("-C")
                .arg(&repo_path)
                .arg("rev-parse")
                .arg("HEAD"),
        )
        .trim()
        .to_string();

        let base_objects = git_rev_list_objects(&repo_path, std::slice::from_ref(&base))
            .await
            .unwrap();
        let base_pack = git_pack_objects_exact(&repo_path, &base_objects, 1)
            .await
            .unwrap();

        git_init_bare(&cache_view_path).await.unwrap();
        let pack_dir = cache_view_path.join("objects").join("pack");
        let pack_path = pack_dir.join("pack-base.pack");
        let idx_path = pack_dir.join("pack-base.idx");
        std::fs::write(&pack_path, &base_pack).unwrap();
        git_index_pack_to_idx(&pack_path, &idx_path, 1)
            .await
            .unwrap();

        let main_objects = git_rev_list_objects(&repo_path, std::slice::from_ref(&main))
            .await
            .unwrap();
        let missing_main = git_missing_objects(&cache_view_path, &main_objects)
            .await
            .unwrap();
        assert!(!main_objects.is_empty());
        assert!(missing_main.len() < main_objects.len());
        let main_full_pack = git_pack_objects_exact(&repo_path, &main_objects, 1)
            .await
            .unwrap();
        let main_delta_pack = git_pack_objects_exact(&repo_path, &missing_main, 1)
            .await
            .unwrap();
        assert!(
            main_delta_pack.len() < main_full_pack.len(),
            "fast-forward delta pack should be smaller than a full pack"
        );

        let feature_objects = git_rev_list_objects(&repo_path, std::slice::from_ref(&feature))
            .await
            .unwrap();
        let missing_feature = git_missing_objects(&cache_view_path, &feature_objects)
            .await
            .unwrap();
        assert!(!feature_objects.is_empty());
        assert!(missing_feature.len() < feature_objects.len());
        let feature_full_pack = git_pack_objects_exact(&repo_path, &feature_objects, 1)
            .await
            .unwrap();
        let feature_delta_pack = git_pack_objects_exact(&repo_path, &missing_feature, 1)
            .await
            .unwrap();
        assert!(
            feature_delta_pack.len() < feature_full_pack.len(),
            "shared-history delta pack should be smaller than a full pack"
        );

        let unrelated_objects = git_rev_list_objects(&repo_path, std::slice::from_ref(&unrelated))
            .await
            .unwrap();
        let missing_unrelated = git_missing_objects(&cache_view_path, &unrelated_objects)
            .await
            .unwrap();
        assert_eq!(missing_unrelated.len(), unrelated_objects.len());
        let unrelated_full_pack = git_pack_objects_exact(&repo_path, &unrelated_objects, 1)
            .await
            .unwrap();
        let unrelated_delta_pack = git_pack_objects_exact(&repo_path, &missing_unrelated, 1)
            .await
            .unwrap();
        assert_eq!(
            unrelated_delta_pack.len(),
            unrelated_full_pack.len(),
            "unrelated histories should not see pack shrinkage from the cache base"
        );
    }

    #[tokio::test]
    async fn git_fetch_refspecs_handles_large_selected_fetch_via_stdin() {
        let tempdir = tempfile::tempdir().unwrap();
        let remote_path = tempdir.path().join("remote");
        let cache_path = tempdir.path().join("cache.git");

        assert_git_success(StdCommand::new("git").arg("init").arg(&remote_path));
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&remote_path)
                .arg("config")
                .arg("user.email")
                .arg("test@example.com"),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&remote_path)
                .arg("config")
                .arg("user.name")
                .arg("Test User"),
        );

        std::fs::write(remote_path.join("file.txt"), "hello\n").unwrap();
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&remote_path)
                .arg("add")
                .arg("file.txt"),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&remote_path)
                .arg("commit")
                .arg("-m")
                .arg("initial"),
        );

        let head = git_stdout(
            StdCommand::new("git")
                .arg("-C")
                .arg(&remote_path)
                .arg("rev-parse")
                .arg("HEAD"),
        )
        .trim()
        .to_string();

        for index in 0..=FETCH_REFSPECS_STDIN_THRESHOLD {
            assert_git_success(
                StdCommand::new("git")
                    .arg("-C")
                    .arg(&remote_path)
                    .arg("update-ref")
                    .arg(format!("refs/heads/branch-{index:03}"))
                    .arg(&head),
            );
        }

        git_init_bare(&cache_path).await.unwrap();

        let refspecs = (0..=FETCH_REFSPECS_STDIN_THRESHOLD)
            .map(|index| format!("+refs/heads/branch-{index:03}:refs/heads/branch-{index:03}"))
            .collect::<Vec<_>>();

        timeout(
            Duration::from_secs(10),
            git_fetch_refspecs_with_context(
                &cache_path,
                remote_path.to_str().unwrap(),
                &[],
                &refspecs,
                false,
                Some("test"),
            ),
        )
        .await
        .expect("git_fetch_refspecs timed out")
        .unwrap();

        let refs = git_stdout(
            StdCommand::new("git")
                .arg("-C")
                .arg(&cache_path)
                .arg("for-each-ref")
                .arg("--format=%(refname)")
                .arg("refs/heads"),
        );

        assert_eq!(refs.lines().count(), refspecs.len());
        assert!(refs.contains("refs/heads/branch-000"));
        assert!(refs.contains("refs/heads/branch-100"));
    }

    #[tokio::test]
    async fn selected_fetch_retries_after_dropping_missing_remote_refs() {
        let tempdir = tempfile::tempdir().unwrap();
        let work_path = tempdir.path().join("work");
        let remote_path = tempdir.path().join("remote.git");
        let cache_path = tempdir.path().join("cache.git");

        assert_git_success(StdCommand::new("git").arg("init").arg(&work_path));
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("config")
                .arg("user.email")
                .arg("test@example.com"),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("config")
                .arg("user.name")
                .arg("Test User"),
        );

        std::fs::write(work_path.join("file.txt"), "hello\n").unwrap();
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("add")
                .arg("file.txt"),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("commit")
                .arg("-m")
                .arg("initial"),
        );

        let default_branch = git_stdout(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("symbolic-ref")
                .arg("--short")
                .arg("HEAD"),
        )
        .trim()
        .to_string();
        let default_branch_ref = format!("refs/heads/{default_branch}");

        git_init_bare(&remote_path).await.unwrap();
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("push")
                .arg(remote_path.to_str().unwrap())
                .arg(format!("HEAD:{default_branch_ref}")),
        );
        git_init_bare(&cache_path).await.unwrap();

        let main_refspec = format!("+{default_branch_ref}:{default_branch_ref}");
        let vanished_refspec =
            "+refs/heads/foo/locks-vanished:refs/heads/foo/locks-vanished".to_string();
        let result = timeout(
            Duration::from_secs(10),
            git_fetch_refspecs_allow_missing_remote_refs_with_context(
                &cache_path,
                remote_path.to_str().unwrap(),
                &[],
                &[main_refspec.clone(), vanished_refspec.clone()],
                false,
                Some("test"),
            ),
        )
        .await
        .expect("selected fetch timed out")
        .unwrap();

        assert_eq!(result.fetched_refspecs, vec![main_refspec]);
        assert_eq!(result.missing_remote_refspecs, vec![vanished_refspec]);
        assert!(result.fetch_result.refs_updated <= 1);

        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&cache_path)
                .arg("rev-parse")
                .arg("--verify")
                .arg(default_branch_ref),
        );
        assert!(
            !StdCommand::new("git")
                .arg("-C")
                .arg(&cache_path)
                .arg("rev-parse")
                .arg("--verify")
                .arg("refs/heads/foo/locks-vanished")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap()
                .success()
        );
    }

    #[tokio::test]
    async fn git_prepare_published_generation_indexes_writes_midx_bitmap() {
        let tempdir = tempfile::tempdir().unwrap();
        let work_path = tempdir.path().join("work");
        let bare_path = tempdir.path().join("repo.git");

        assert!(
            StdCommand::new("git")
                .arg("init")
                .arg(&work_path)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("config")
                .arg("user.email")
                .arg("test@example.com")
                .status()
                .unwrap()
                .success()
        );
        assert!(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("config")
                .arg("user.name")
                .arg("Test User")
                .status()
                .unwrap()
                .success()
        );

        for index in 0..3 {
            std::fs::write(work_path.join(format!("file-{index}.txt")), "hello\n").unwrap();
            assert!(
                StdCommand::new("git")
                    .arg("-C")
                    .arg(&work_path)
                    .arg("add")
                    .arg(".")
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(
                StdCommand::new("git")
                    .arg("-C")
                    .arg(&work_path)
                    .arg("commit")
                    .arg("-m")
                    .arg(format!("commit {index}"))
                    .status()
                    .unwrap()
                    .success()
            );
        }

        assert!(
            StdCommand::new("git")
                .arg("clone")
                .arg("--bare")
                .arg(&work_path)
                .arg(&bare_path)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            StdCommand::new("git")
                .arg("-C")
                .arg(&bare_path)
                .arg("repack")
                .arg("-d")
                .status()
                .unwrap()
                .success()
        );

        git_prepare_published_generation_indexes(&bare_path, 1)
            .await
            .unwrap();

        let pack_dir = bare_path.join("objects").join("pack");
        assert!(pack_dir.join("multi-pack-index").is_file());
        assert!(
            std::fs::read_dir(&pack_dir).unwrap().any(|entry| {
                let file_name = entry.unwrap().file_name();
                let file_name = file_name.to_string_lossy();
                file_name.starts_with("multi-pack-index-") && file_name.ends_with(".bitmap")
            }),
            "expected a MIDX bitmap in {}",
            pack_dir.display()
        );

        assert!(
            StdCommand::new("git")
                .arg("-C")
                .arg(&bare_path)
                .arg("multi-pack-index")
                .arg("verify")
                .status()
                .unwrap()
                .success()
        );
    }

    #[test]
    fn repo_uses_object_alternates_detects_nonempty_alternates_file() {
        let tempdir = tempfile::tempdir().unwrap();
        let repo_path = tempdir.path().join("repo.git");
        let alternates_path = repo_path.join("objects").join("info").join("alternates");
        std::fs::create_dir_all(alternates_path.parent().unwrap()).unwrap();

        assert!(!repo_uses_object_alternates(&repo_path).unwrap());

        std::fs::write(&alternates_path, "\n  \n").unwrap();
        assert!(!repo_uses_object_alternates(&repo_path).unwrap());

        std::fs::write(&alternates_path, "/tmp/source.git/objects\n").unwrap();
        assert!(repo_uses_object_alternates(&repo_path).unwrap());
    }

    #[tokio::test]
    async fn git_multi_pack_index_write_supports_synthetic_packstores() {
        let tempdir = tempfile::tempdir().unwrap();
        let work_path = tempdir.path().join("work");
        let packstore_path = tempdir.path().join("packstore");
        let object_dir = packstore_path.join("objects");
        let pack_dir = object_dir.join("pack");

        assert_git_success(StdCommand::new("git").arg("init").arg(&work_path));
        assert_git_success(
            StdCommand::new("git")
                .arg("init")
                .arg("--bare")
                .arg(&packstore_path),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("config")
                .arg("user.email")
                .arg("test@example.com"),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("config")
                .arg("user.name")
                .arg("Test User"),
        );

        std::fs::write(work_path.join("file.txt"), "hello\n").unwrap();
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("add")
                .arg("file.txt"),
        );
        assert_git_success(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("commit")
                .arg("-m")
                .arg("initial"),
        );

        let head = git_stdout(
            StdCommand::new("git")
                .arg("-C")
                .arg(&work_path)
                .arg("rev-parse")
                .arg("HEAD"),
        )
        .trim()
        .to_string();
        let object_ids = git_rev_list_objects(&work_path, std::slice::from_ref(&head))
            .await
            .unwrap();
        let pack = git_pack_objects_exact(&work_path, &object_ids, 1)
            .await
            .unwrap();

        std::fs::create_dir_all(&pack_dir).unwrap();
        let pack_path = pack_dir.join("pack-base.pack");
        let idx_path = pack_dir.join("pack-base.idx");
        std::fs::write(&pack_path, &pack).unwrap();
        git_index_pack_to_idx(&pack_path, &idx_path, 1)
            .await
            .unwrap();

        git_multi_pack_index_write_for_object_dir(&object_dir, false, 1)
            .await
            .unwrap();
        assert!(pack_dir.join("multi-pack-index").is_file());

        assert!(
            StdCommand::new("git")
                .current_dir(&packstore_path)
                .env("GIT_DIR", &packstore_path)
                .arg("multi-pack-index")
                .arg(format!("--object-dir={}", object_dir.display()))
                .arg("verify")
                .status()
                .unwrap()
                .success()
        );
    }

    fn assert_git_success(command: &mut StdCommand) {
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "git command failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn git_stdout(command: &mut StdCommand) -> String {
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "git command failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }
}
