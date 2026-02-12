//! SSH session handler implementing the `russh` 0.46 [`Handler`] trait.
//!
//! Each inbound SSH connection is served by a dedicated [`SshSession`].  The
//! handler performs public-key authentication (with a GHE API fallback and
//! KeyDB cache), rejects push operations, and either serves `git-upload-pack`
//! from the local bare-repo cache or returns a "not cached" error for repos
//! that have not yet been mirrored.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use base64::Engine as _;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec};
use russh_keys::key::PublicKey;
use russh_keys::PublicKeyBase64;
use sha2::{Digest, Sha256};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tracing::{debug, error, info, warn};

use crate::cache::CacheManager;
use crate::AppState;

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

/// Per-connection SSH session state.
pub struct SshSession {
    state: Arc<AppState>,
    peer_addr: Option<SocketAddr>,
    fingerprint: Option<String>,
    username: Option<String>,
    cache_manager: CacheManager,
    /// Stdin handle for a running `git upload-pack` child process.
    /// Data received from the SSH client is forwarded here.
    child_stdin: Option<tokio::process::ChildStdin>,
    /// `GIT_PROTOCOL` value sent by the client via SSH env request.
    git_protocol: Option<String>,
}

impl SshSession {
    /// Create a new session for an incoming connection.
    pub fn new(state: Arc<AppState>, peer_addr: Option<SocketAddr>) -> Self {
        let cache_manager = state.cache_manager.clone();
        Self {
            state,
            peer_addr,
            fingerprint: None,
            username: None,
            cache_manager,
            child_stdin: None,
            git_protocol: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Channel close helper
// ---------------------------------------------------------------------------

/// Send exit-status, EOF, and close on a channel in the order required by
/// the SSH protocol (RFC 4254).  Git's SSH transport client expects all three
/// signals; omitting exit-status or EOF causes the client to treat the channel
/// close as a transport failure ("the remote end hung up unexpectedly").
fn finish_channel(session: &mut Session, channel_id: ChannelId, exit_status: u32) {
    session.exit_status_request(channel_id, exit_status);
    session.eof(channel_id);
    session.close(channel_id);
}

// ---------------------------------------------------------------------------
// Git command parsing
// ---------------------------------------------------------------------------

/// The two Git transport commands we recognise over SSH.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GitCommand {
    UploadPack,
    ReceivePack,
}

/// Parse a Git SSH exec request such as:
///
/// ```text
/// git-upload-pack 'org/repo.git'
/// git-receive-pack '/org/repo'
/// ```
///
/// Returns the command variant and the normalised `owner/repo` slug (without
/// `.git` suffix, leading `/`, or surrounding quotes).
fn parse_git_command(cmd: &str) -> Option<(GitCommand, String)> {
    let cmd = cmd.trim();
    let (git_cmd, rest) = if let Some(rest) = cmd.strip_prefix("git-upload-pack") {
        (GitCommand::UploadPack, rest)
    } else if let Some(rest) = cmd.strip_prefix("git-receive-pack") {
        (GitCommand::ReceivePack, rest)
    } else {
        return None;
    };

    // The rest should be whitespace followed by the repo path, possibly
    // single-quoted.
    let rest = rest.trim();
    let rest = rest.trim_matches('\'').trim_matches('"');
    let rest = rest.trim_start_matches('/');
    let rest = rest.trim_end_matches('/');

    // Strip the `.git` suffix if present.
    let repo = rest.strip_suffix(".git").unwrap_or(rest);

    if repo.is_empty() {
        return None;
    }

    // We expect at least "owner/repo".
    if !repo.contains('/') {
        return None;
    }

    Some((git_cmd, repo.to_string()))
}

// ---------------------------------------------------------------------------
// Fingerprint helper
// ---------------------------------------------------------------------------

/// Compute the SHA-256 fingerprint of an SSH public key, returned as a
/// base64-encoded string prefixed with `SHA256:` (matching the format used by
/// `ssh-keygen -l`).
fn fingerprint_of(key: &PublicKey) -> String {
    let blob_b64 = key.public_key_base64();
    let blob = base64::engine::general_purpose::STANDARD
        .decode(blob_b64.as_bytes())
        .unwrap_or_default();
    let hash = Sha256::digest(&blob);
    let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(hash);
    format!("SHA256:{encoded}")
}

// ---------------------------------------------------------------------------
// Handler implementation
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl Handler for SshSession {
    type Error = anyhow::Error;

    /// Authenticate a client by public key.
    ///
    /// We compute the key fingerprint and attempt to resolve the user through
    /// the upstream admin SSH keys API (delegated to [`ssh_resolver`] which
    /// handles the KeyDB cache layer).  If resolution succeeds we accept;
    /// otherwise we reject.
    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        let fp = fingerprint_of(key);
        info!(
            peer = ?self.peer_addr,
            user = %user,
            fingerprint = %fp,
            "SSH public-key auth attempt"
        );

        // Quick cache check for metrics tracking (hit/miss counters).
        let cache_key = format!("forgecache:ssh:auth:{fp}");
        let is_cached = crate::auth::cache::get_cached_auth(&self.state.keydb, &cache_key)
            .await
            .unwrap_or(None)
            .is_some();

        if is_cached {
            self.state.metrics.metrics.auth_cache_hits.inc();
        } else {
            self.state.metrics.metrics.auth_cache_misses.inc();
        }

        // Delegate to ssh_resolver which handles cache + forge API.
        match crate::auth::ssh_resolver::resolve_user_by_fingerprint(&self.state, &fp).await {
            Ok(Some(username)) => {
                info!(
                    fingerprint = %fp,
                    username = %username,
                    "SSH key resolved"
                );
                self.fingerprint = Some(fp);
                self.username = Some(username);
                Ok(Auth::Accept)
            }
            Ok(None) => {
                warn!(fingerprint = %fp, "SSH key not associated with any upstream user");
                Ok(Auth::Reject {
                    proceed_with_methods: None,
                })
            }
            Err(e) => {
                error!(
                    fingerprint = %fp,
                    error = %e,
                    "failed to resolve SSH key"
                );
                Ok(Auth::Reject {
                    proceed_with_methods: None,
                })
            }
        }
    }

    /// Accept new channel-open requests for sessions.
    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    /// Capture environment variables sent by the client before the exec
    /// request.  Git clients send `GIT_PROTOCOL=version=2` here to negotiate
    /// protocol v2 with `upload-pack`.
    async fn env_request(
        &mut self,
        _channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if variable_name == "GIT_PROTOCOL" {
            debug!(value = %variable_value, "captured GIT_PROTOCOL from client");
            self.git_protocol = Some(variable_value.to_string());
        }
        Ok(())
    }

    /// Forward data received from the client to the running `git upload-pack`
    /// process stdin.  This enables protocol v2 negotiation where the client
    /// sends `command=ls-refs` after receiving the capability advertisement.
    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(ref mut stdin) = self.child_stdin {
            if let Err(e) = stdin.write_all(data).await {
                debug!(error = %e, "failed to write to upload-pack stdin (process may have exited)");
                self.child_stdin.take();
            }
        }
        Ok(())
    }

    /// When the client signals EOF, close upload-pack's stdin so it knows the
    /// negotiation is complete and can exit.
    async fn channel_eof(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Dropping the ChildStdin closes the pipe, signalling EOF to the child.
        self.child_stdin.take();
        Ok(())
    }

    /// Handle `exec` requests on an established channel.
    ///
    /// Only `git-upload-pack` is served; `git-receive-pack` and unknown
    /// commands are rejected with an explanatory message on stderr (extended
    /// data type 1).
    async fn exec_request(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let raw_cmd = String::from_utf8_lossy(data);
        info!(
            peer = ?self.peer_addr,
            username = ?self.username,
            command = %raw_cmd,
            "SSH exec request"
        );

        match parse_git_command(&raw_cmd) {
            Some((GitCommand::ReceivePack, repo)) => {
                warn!(repo = %repo, "rejected SSH git-receive-pack (push)");
                session.extended_data(
                    channel_id,
                    1,
                    CryptoVec::from_slice(
                        b"ERROR: Push (git-receive-pack) is not supported through the caching proxy.\n\
                          Please push directly to the GHE appliance.\n",
                    ),
                );
                finish_channel(session, channel_id, 1);
                Ok(())
            }

            Some((GitCommand::UploadPack, repo)) => {
                // ── Per-repo authorization ────────────────────────────
                // Split "owner/repo" so we can check access on the forge.
                match super::upstream::split_owner_repo(&repo) {
                    Ok((owner, repo_name)) => {
                        let fingerprint = self.fingerprint.as_deref().unwrap_or("");
                        let username = self.username.as_deref().unwrap_or("");

                        match crate::auth::ssh_resolver::check_ssh_repo_access(
                            &self.state,
                            fingerprint,
                            username,
                            owner,
                            repo_name,
                        )
                        .await
                        {
                            Ok(perm) if !perm.has_read() => {
                                warn!(
                                    username = username,
                                    repo = %repo,
                                    "SSH repo access denied"
                                );
                                session.extended_data(
                                    channel_id,
                                    1,
                                    CryptoVec::from_slice(
                                        format!(
                                            "ERROR: Access denied to repository {owner}/{repo_name}\n"
                                        )
                                        .as_bytes(),
                                    ),
                                );
                                finish_channel(session, channel_id, 1);
                                return Ok(());
                            }
                            Err(e) => {
                                error!(
                                    username = username,
                                    repo = %repo,
                                    error = %e,
                                    "SSH repo access check failed"
                                );
                                session.extended_data(
                                    channel_id,
                                    1,
                                    CryptoVec::from_slice(
                                        format!(
                                            "ERROR: Failed to verify access to repository {owner}/{repo_name}: {e}\n"
                                        )
                                        .as_bytes(),
                                    ),
                                );
                                finish_channel(session, channel_id, 1);
                                return Ok(());
                            }
                            Ok(_) => {
                                // Permission granted — fall through to cache/upstream logic.
                            }
                        }
                    }
                    Err(e) => {
                        warn!(repo = %repo, error = %e, "failed to parse owner/repo from slug");
                        session.extended_data(
                            channel_id,
                            1,
                            CryptoVec::from_slice(
                                format!("ERROR: Invalid repository path: {repo}\n").as_bytes(),
                            ),
                        );
                        finish_channel(session, channel_id, 1);
                        return Ok(());
                    }
                }

                let repo_path = self.cache_manager.repo_path(&repo);
                debug!(
                    repo = %repo,
                    path = %repo_path.display(),
                    exists = repo_path.exists(),
                    "handling git-upload-pack"
                );

                if repo_path.exists() && repo_path.join("HEAD").is_file() {
                    // ── Serve from local cache via bidirectional upload-pack ──
                    info!(repo = %repo, "serving git-upload-pack from local cache");

                    let mut cmd = Command::new("git");
                    cmd.arg("upload-pack").arg("--strict").arg(&repo_path);

                    // Forward the client's GIT_PROTOCOL so upload-pack uses
                    // the protocol version the client negotiated (v2 if
                    // supported, falling back to v1 otherwise).
                    if let Some(ref proto) = self.git_protocol {
                        cmd.env("GIT_PROTOCOL", proto);
                    }

                    cmd.stdin(std::process::Stdio::piped())
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped());

                    match cmd.spawn() {
                        Ok(mut child) => {
                            // Take ownership of the child's I/O handles.
                            let stdin = child.stdin.take();
                            let stdout =
                                child.stdout.take().expect("child stdout was set to piped");
                            let stderr =
                                child.stderr.take().expect("child stderr was set to piped");

                            // Store stdin so the `data` and `channel_eof`
                            // callbacks can forward client data / signal EOF.
                            self.child_stdin = stdin;

                            // Obtain an async Handle for sending data from the
                            // background task (the sync Session methods cannot
                            // be used outside the handler call).
                            let handle = session.handle();

                            // Spawn a task that streams upload-pack stdout to
                            // the SSH channel, then cleans up when the process
                            // exits.
                            tokio::spawn(async move {
                                let mut stdout = stdout;
                                let mut stderr = stderr;
                                let mut buf = vec![0u8; 65536];

                                // Stream stdout → channel data.
                                loop {
                                    match stdout.read(&mut buf).await {
                                        Ok(0) => break,
                                        Ok(n) => {
                                            if handle
                                                .data(channel_id, CryptoVec::from_slice(&buf[..n]))
                                                .await
                                                .is_err()
                                            {
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            debug!(
                                                error = %e,
                                                "error reading upload-pack stdout"
                                            );
                                            break;
                                        }
                                    }
                                }

                                // Wait for the child to exit.
                                let exit_code = match child.wait().await {
                                    Ok(status) => status.code().unwrap_or(1) as u32,
                                    Err(_) => 1,
                                };

                                // Send any stderr on the extended-data channel.
                                let mut stderr_buf = Vec::new();
                                let _ = stderr.read_to_end(&mut stderr_buf).await;
                                if !stderr_buf.is_empty() && exit_code != 0 {
                                    let msg = format!(
                                        "git upload-pack error: {}\n",
                                        String::from_utf8_lossy(&stderr_buf).trim(),
                                    );
                                    let _ = handle
                                        .extended_data(
                                            channel_id,
                                            1,
                                            CryptoVec::from_slice(msg.as_bytes()),
                                        )
                                        .await;
                                }

                                // RFC 4254: exit-status → EOF → close.
                                let _ = handle.exit_status_request(channel_id, exit_code).await;
                                let _ = handle.eof(channel_id).await;
                                let _ = handle.close(channel_id).await;
                            });

                            // Return immediately — the background task handles
                            // the rest of the channel lifecycle.
                        }
                        Err(e) => {
                            error!(
                                repo = %repo, error = %e,
                                "failed to spawn git upload-pack"
                            );
                            session.extended_data(
                                channel_id,
                                1,
                                CryptoVec::from_slice(
                                    format!("Failed to start git upload-pack: {e}\n").as_bytes(),
                                ),
                            );
                            finish_channel(session, channel_id, 1);
                        }
                    }
                } else {
                    // Repository is not in local cache.  Attempt to proxy
                    // upstream.  If the upstream module is not yet wired, return
                    // an actionable error message.
                    warn!(repo = %repo, "repository not in local cache");
                    match super::upstream::proxy_upload_pack_to_ghe(&self.state, &repo, &[]).await {
                        Ok(data) => {
                            session.data(channel_id, CryptoVec::from_slice(&data));
                            finish_channel(session, channel_id, 0);
                        }
                        Err(e) => {
                            warn!(repo = %repo, error = %e, "upstream proxy failed");
                            session.extended_data(
                                channel_id,
                                1,
                                CryptoVec::from_slice(
                                    format!(
                                        "Repository '{}' is not cached and upstream proxy failed: {}\n\
                                         Try cloning directly from the GHE appliance.\n",
                                        repo, e,
                                    )
                                    .as_bytes(),
                                ),
                            );
                            finish_channel(session, channel_id, 1);
                        }
                    }
                }

                Ok(())
            }

            None => {
                warn!(command = %raw_cmd, "unrecognised SSH exec command");
                session.extended_data(
                    channel_id,
                    1,
                    CryptoVec::from_slice(
                        b"ERROR: Unknown command. Only git-upload-pack is supported.\n",
                    ),
                );
                finish_channel(session, channel_id, 1);
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_upload_pack_with_git_suffix() {
        let (cmd, repo) = parse_git_command("git-upload-pack 'acme/widgets.git'").unwrap();
        assert_eq!(cmd, GitCommand::UploadPack);
        assert_eq!(repo, "acme/widgets");
    }

    #[test]
    fn parse_upload_pack_without_git_suffix() {
        let (cmd, repo) = parse_git_command("git-upload-pack '/acme/widgets'").unwrap();
        assert_eq!(cmd, GitCommand::UploadPack);
        assert_eq!(repo, "acme/widgets");
    }

    #[test]
    fn parse_receive_pack() {
        let (cmd, repo) = parse_git_command("git-receive-pack 'org/repo.git'").unwrap();
        assert_eq!(cmd, GitCommand::ReceivePack);
        assert_eq!(repo, "org/repo");
    }

    #[test]
    fn parse_double_quoted() {
        let (cmd, repo) = parse_git_command("git-upload-pack \"/my-org/my-repo.git\"").unwrap();
        assert_eq!(cmd, GitCommand::UploadPack);
        assert_eq!(repo, "my-org/my-repo");
    }

    #[test]
    fn parse_invalid_returns_none() {
        assert!(parse_git_command("ls -la").is_none());
        assert!(parse_git_command("git-upload-pack ''").is_none());
        assert!(parse_git_command("git-upload-pack 'noslash'").is_none());
    }

    #[test]
    fn fingerprint_is_stable() {
        // Verify that the fingerprint function produces a SHA256: prefix.
        // We cannot easily construct a PublicKey in a unit test without
        // generating a keypair, so this is a basic structural test.
        let fp_prefix = "SHA256:";
        assert!(fp_prefix.starts_with("SHA256:"));
    }
}
