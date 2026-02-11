//! SSH upstream proxy to GHE.
//!
//! When a requested repository is not available in the local bare-repo cache,
//! this module proxies the `git-upload-pack` exchange to the upstream GHE
//! appliance.  It resolves the appropriate credential (PAT or SSH key) from
//! the application configuration and shells out to `git` for the actual
//! transport.

use anyhow::{bail, Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{debug, info, instrument, warn};

use crate::config::{Config, CredentialMode};
use crate::AppState;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Proxy a `git-upload-pack` request to the upstream GHE appliance.
///
/// The function resolves the upstream clone URL and credential for the given
/// `owner_repo` slug (`"owner/repo"`) and then runs a local
/// `git upload-pack` (or `git ls-remote` + stateless transport) against
/// the upstream, piping `input` to the process stdin and returning stdout.
///
/// Returns the raw bytes produced by the upstream `git-upload-pack`.
#[instrument(skip(state, input), fields(%owner_repo))]
pub async fn proxy_upload_pack_to_ghe(
    state: &AppState,
    owner_repo: &str,
    input: &[u8],
) -> Result<Vec<u8>> {
    let (owner, repo) = split_owner_repo(owner_repo)?;

    // Resolve clone URL and environment variables for credential injection.
    let (clone_url, env_vars) = resolve_upstream_url_and_creds(&state.config, owner, repo)?;

    debug!(
        clone_url = %clone_url,
        "proxying git-upload-pack to upstream GHE"
    );

    // Use `git-upload-pack` in stateless-rpc mode against the remote URL
    // by leveraging `git upload-pack --stateless-rpc <url>`.  In practice
    // this requires the remote to support the smart HTTP protocol.  For SSH
    // mode, we fall back to a direct `git ls-remote` + packfile fetch.
    let output = git_upload_pack_remote(&clone_url, input, &env_vars).await?;

    info!(
        owner_repo = %owner_repo,
        output_bytes = output.len(),
        "upstream proxy complete"
    );

    Ok(output)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Split an `owner/repo` slug into its two components.
fn split_owner_repo(slug: &str) -> Result<(&str, &str)> {
    let mut parts = slug.splitn(2, '/');
    let owner = parts.next().context("missing owner in repo slug")?;
    let repo = parts.next().context("missing repo in repo slug")?;
    if owner.is_empty() || repo.is_empty() {
        bail!("invalid owner/repo slug: {slug:?}");
    }
    Ok((owner, repo))
}

/// Resolve the clone URL and any environment variables needed for credential
/// injection based on the application configuration.
///
/// For PAT mode the clone URL is an HTTPS URL and the environment contains
/// the `GIT_ASKPASS` or header-based auth.  For SSH mode the URL uses the
/// `git@host:owner/repo.git` form and the environment is empty (the SSH key
/// is expected to be available via the agent or keyring).
fn resolve_upstream_url_and_creds(
    config: &Config,
    owner: &str,
    repo: &str,
) -> Result<(String, Vec<(String, String)>)> {
    // Determine credential mode: check per-org override, then fall back to default.
    let mode = config
        .upstream_credentials
        .orgs
        .get(owner)
        .map(|oc| oc.mode)
        .unwrap_or(config.upstream_credentials.default_mode);

    match mode {
        CredentialMode::Pat => {
            // Resolve the PAT from the environment variable.
            let token_env = config
                .upstream_credentials
                .orgs
                .get(owner)
                .map(|oc| oc.keyring_key_name.as_str())
                .unwrap_or(&config.ghe.admin_token_env);

            let token = std::env::var(token_env).unwrap_or_default();

            // HTTPS clone URL with embedded token for authentication.
            let url = if token.is_empty() {
                format!("https://{}/{}/{}.git", config.ghe.hostname, owner, repo)
            } else {
                format!(
                    "https://x-access-token:{token}@{}/{}/{}.git",
                    config.ghe.hostname, owner, repo,
                )
            };

            // Set GIT_TERMINAL_PROMPT=0 to prevent interactive prompts.
            let env_vars = vec![
                ("GIT_TERMINAL_PROMPT".to_string(), "0".to_string()),
            ];

            Ok((url, env_vars))
        }

        CredentialMode::Ssh => {
            let url = format!(
                "git@{}:{}/{}.git",
                config.ghe.hostname, owner, repo,
            );

            // For SSH mode the key should be available via ssh-agent or the
            // kernel keyring; no extra env vars needed beyond disabling prompts.
            let env_vars = vec![
                ("GIT_TERMINAL_PROMPT".to_string(), "0".to_string()),
                ("GIT_SSH_COMMAND".to_string(), "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null".to_string()),
            ];

            Ok((url, env_vars))
        }
    }
}

/// Run a `git-upload-pack` exchange against a remote URL.
///
/// For HTTPS remotes this uses the stateless-rpc smart HTTP protocol via
/// `git upload-pack --stateless-rpc`.  The `input` bytes are piped to stdin
/// and stdout is captured.
///
/// If the input is empty (initial advertisement request), we use
/// `git ls-remote` instead to fetch the initial ref advertisement.
async fn git_upload_pack_remote(
    url: &str,
    input: &[u8],
    env_vars: &[(String, String)],
) -> Result<Vec<u8>> {
    if input.is_empty() {
        // Initial ref advertisement -- use ls-remote to get the ref list.
        debug!(url = %url, "fetching ref advertisement via git ls-remote");

        let mut cmd = Command::new("git");
        cmd.arg("ls-remote").arg(url);
        cmd.env("GIT_TERMINAL_PROMPT", "0");
        for (k, v) in env_vars {
            cmd.env(k, v);
        }
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let output = cmd
            .output()
            .await
            .context("failed to spawn git ls-remote")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("git ls-remote failed (status {}): {}", output.status, stderr);
        }

        return Ok(output.stdout);
    }

    // Full pack negotiation -- use git upload-pack --stateless-rpc with the
    // URL treated as a local path (this only works for local repos).  For
    // remote URLs we need to use the HTTP transport directly.
    //
    // The most portable approach is to use `git fetch` into a temporary bare
    // repo from which we then serve upload-pack locally.  Since upstream
    // proxy is a fallback path, we optimise for correctness over performance.
    debug!(
        url = %url,
        input_bytes = input.len(),
        "proxying pack data via temporary clone"
    );

    let tmp_dir = tempfile::tempdir().context("failed to create temp dir for upstream proxy")?;
    let tmp_repo = tmp_dir.path().join("proxy.git");

    // Initialise a temporary bare repo.
    let init_status = Command::new("git")
        .arg("init")
        .arg("--bare")
        .arg(&tmp_repo)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .status()
        .await
        .context("failed to init temporary bare repo")?;

    if !init_status.success() {
        bail!("git init --bare failed for temporary proxy repo");
    }

    // Fetch from upstream into the temporary repo.
    let mut fetch_cmd = Command::new("git");
    fetch_cmd
        .arg("-C")
        .arg(&tmp_repo)
        .arg("fetch")
        .arg(url)
        .arg("+refs/*:refs/*");
    fetch_cmd.env("GIT_TERMINAL_PROMPT", "0");
    for (k, v) in env_vars {
        fetch_cmd.env(k, v);
    }
    fetch_cmd.stdout(std::process::Stdio::piped());
    fetch_cmd.stderr(std::process::Stdio::piped());

    let fetch_output = fetch_cmd
        .output()
        .await
        .context("failed to fetch from upstream")?;

    if !fetch_output.status.success() {
        let stderr = String::from_utf8_lossy(&fetch_output.stderr);
        bail!(
            "git fetch from upstream failed (status {}): {}",
            fetch_output.status,
            stderr,
        );
    }

    // Now serve upload-pack from the temporary repo.
    let mut upload_cmd = Command::new("git");
    upload_cmd
        .arg("upload-pack")
        .arg("--stateless-rpc")
        .arg(&tmp_repo);
    upload_cmd.stdin(std::process::Stdio::piped());
    upload_cmd.stdout(std::process::Stdio::piped());
    upload_cmd.stderr(std::process::Stdio::piped());

    let mut child = upload_cmd
        .spawn()
        .context("failed to spawn git upload-pack on temp repo")?;

    // Write input to stdin.
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input).await.ok();
        drop(stdin);
    }

    let output = child
        .wait_with_output()
        .await
        .context("git upload-pack on temp repo failed")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(
            status = %output.status,
            stderr = %stderr,
            "git upload-pack on temp repo exited with error"
        );
    }

    // The temporary directory is cleaned up when `tmp_dir` is dropped.
    Ok(output.stdout)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_owner_repo_valid() {
        let (owner, repo) = split_owner_repo("acme/widgets").unwrap();
        assert_eq!(owner, "acme");
        assert_eq!(repo, "widgets");
    }

    #[test]
    fn split_owner_repo_with_subpath() {
        let (owner, repo) = split_owner_repo("org/deep/nested").unwrap();
        assert_eq!(owner, "org");
        assert_eq!(repo, "deep/nested");
    }

    #[test]
    fn split_owner_repo_invalid() {
        assert!(split_owner_repo("noslash").is_err());
        assert!(split_owner_repo("/repo").is_err());
        assert!(split_owner_repo("owner/").is_err());
    }
}
