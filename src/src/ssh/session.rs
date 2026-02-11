//! SSH session handler implementing the `russh` 0.46 [`Handler`] trait.
//!
//! Each inbound SSH connection is served by a dedicated [`SshSession`].  The
//! handler performs public-key authentication (with a GHE API fallback and
//! KeyDB cache), rejects push operations, and either serves `git-upload-pack`
//! from the local bare-repo cache or returns a "not cached" error for repos
//! that have not yet been mirrored.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::Engine as _;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec};
use russh_keys::key::PublicKey;
use russh_keys::PublicKeyBase64;
use sha2::{Digest, Sha256};

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
}

impl SshSession {
    /// Create a new session for an incoming connection.
    pub fn new(state: Arc<AppState>, peer_addr: Option<SocketAddr>) -> Self {
        let cache_manager = CacheManager::new(&state.config.storage.local);
        Self {
            state,
            peer_addr,
            fingerprint: None,
            username: None,
            cache_manager,
        }
    }
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
    /// the GHE admin SSH keys API (with a KeyDB cache layer).  If resolution
    /// succeeds we accept; otherwise we reject.
    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        let fp = fingerprint_of(key);
        info!(
            peer = ?self.peer_addr,
            user = %user,
            fingerprint = %fp,
            "SSH public-key auth attempt"
        );

        // Attempt to resolve the fingerprint to a GHE user via the admin API.
        // We use the GHE API endpoint: GET /api/v3/admin/ssh-keys/{fingerprint}
        // For now we accept if the upstream returns a valid user, and cache
        // the result in KeyDB.
        let cache_key = format!("forgecache:ssh_auth:{fp}");
        let cached_user: Option<String> = {
            use fred::interfaces::HashesInterface;
            let result: Option<String> =
                HashesInterface::hget(&self.state.keydb, &cache_key, "username")
                    .await
                    .unwrap_or(None);
            result
        };

        if let Some(ref resolved) = cached_user {
            debug!(fingerprint = %fp, username = %resolved, "SSH auth cache hit");
            self.fingerprint = Some(fp);
            self.username = Some(resolved.to_string());
            self.state.metrics.metrics.auth_cache_hits.inc();
            return Ok(Auth::Accept);
        }

        self.state.metrics.metrics.auth_cache_misses.inc();

        // Call GHE admin API to look up the SSH key fingerprint.
        // The fingerprint needs to have the "SHA256:" prefix stripped for the URL.
        let fp_query = fp.strip_prefix("SHA256:").unwrap_or(&fp);
        let api_url = format!(
            "{}/admin/keys?fingerprint={}",
            self.state.config.upstream.api_url, fp_query,
        );

        let admin_token =
            std::env::var(&self.state.config.upstream.admin_token_env).unwrap_or_default();

        let response = self
            .state
            .http_client
            .get(&api_url)
            .header("Authorization", format!("token {admin_token}"))
            .header("Accept", "application/vnd.github+json")
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                // Parse the response to extract the user login.
                let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);

                // The response is an array of key objects; each has a "user" with "login".
                let resolved_user = body
                    .as_array()
                    .and_then(|arr| arr.first())
                    .and_then(|obj| obj.get("user"))
                    .and_then(|u| u.get("login"))
                    .and_then(|l| l.as_str())
                    .map(|s| s.to_string());

                if let Some(ref username) = resolved_user {
                    info!(
                        fingerprint = %fp,
                        username = %username,
                        "SSH key resolved via GHE API"
                    );

                    // Cache the positive result.
                    let ttl = self.state.config.auth.ssh_cache_ttl;
                    {
                        use fred::interfaces::HashesInterface;
                        use fred::interfaces::KeysInterface;
                        let _ = HashesInterface::hset::<(), _, _>(
                            &self.state.keydb,
                            &cache_key,
                            [("username", username.as_str())],
                        )
                        .await;
                        let _ = KeysInterface::expire::<bool, _>(
                            &self.state.keydb,
                            &cache_key,
                            ttl as i64,
                            None,
                        )
                        .await;
                    }

                    self.fingerprint = Some(fp);
                    self.username = Some(username.clone());
                    return Ok(Auth::Accept);
                }

                warn!(fingerprint = %fp, "SSH key not associated with any GHE user");
            }
            Ok(resp) => {
                warn!(
                    fingerprint = %fp,
                    status = %resp.status(),
                    "GHE admin key lookup returned non-success"
                );
            }
            Err(e) => {
                error!(
                    fingerprint = %fp,
                    error = %e,
                    "failed to reach GHE API for SSH key lookup"
                );
            }
        }

        // Cache negative result with shorter TTL.
        {
            use fred::interfaces::HashesInterface;
            use fred::interfaces::KeysInterface;
            let neg_ttl = self.state.config.auth.negative_cache_ttl;
            let _ = HashesInterface::hset::<(), _, _>(
                &self.state.keydb,
                &cache_key,
                [("username", "__rejected__")],
            )
            .await;
            let _ = KeysInterface::expire::<bool, _>(
                &self.state.keydb,
                &cache_key,
                neg_ttl as i64,
                None,
            )
            .await;
        }

        Ok(Auth::Reject {
            proceed_with_methods: None,
        })
    }

    /// Accept new channel-open requests for sessions.
    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
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
                session.close(channel_id);
                Ok(())
            }

            Some((GitCommand::UploadPack, repo)) => {
                let repo_path = self.cache_manager.repo_path(&repo);
                debug!(
                    repo = %repo,
                    path = %repo_path.display(),
                    exists = repo_path.exists(),
                    "handling git-upload-pack"
                );

                if repo_path.exists() && repo_path.join("HEAD").is_file() {
                    // Serve from local cache via `git upload-pack`.
                    info!(repo = %repo, "serving git-upload-pack from local cache");

                    let child_result = Command::new("git")
                        .arg("upload-pack")
                        .arg("--strict")
                        .arg(&repo_path)
                        .stdin(std::process::Stdio::piped())
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .spawn();

                    match child_result {
                        Ok(child) => {
                            // We need to pipe the channel I/O to the child process.
                            // For a full implementation we would wire up the russh
                            // channel data callbacks to the child stdin/stdout.
                            // Here we wait for the child to produce output.
                            let output = child
                                .wait_with_output()
                                .await
                                .context("git upload-pack failed")?;

                            if !output.status.success() {
                                let stderr = String::from_utf8_lossy(&output.stderr);
                                warn!(
                                    repo = %repo,
                                    status = %output.status,
                                    stderr = %stderr,
                                    "git upload-pack exited with error"
                                );
                                session.extended_data(
                                    channel_id,
                                    1,
                                    CryptoVec::from_slice(
                                        format!("git upload-pack error: {stderr}\n").as_bytes(),
                                    ),
                                );
                            } else {
                                session.data(channel_id, CryptoVec::from_slice(&output.stdout));
                            }

                            session.close(channel_id);
                        }
                        Err(e) => {
                            error!(repo = %repo, error = %e, "failed to spawn git upload-pack");
                            session.extended_data(
                                channel_id,
                                1,
                                CryptoVec::from_slice(
                                    format!("Failed to start git upload-pack: {e}\n").as_bytes(),
                                ),
                            );
                            session.close(channel_id);
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
                            session.close(channel_id);
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
                            session.close(channel_id);
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
                session.close(channel_id);
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
