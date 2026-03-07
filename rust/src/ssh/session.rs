//! SSH session handler implementing the `russh` 0.46 [`Handler`] trait.
//!
//! Each inbound SSH connection is served by a dedicated [`SshSession`].  The
//! handler performs public-key authentication (with an upstream forge API fallback and
//! Valkey cache), rejects push operations, and either serves `git-upload-pack`
//! from the local bare-repo cache or returns a "not cached" error for repos
//! that have not yet been mirrored.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use base64::Engine as _;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec};
use russh_keys::PublicKeyBase64;
use russh_keys::key::PublicKey;
use sha2::{Digest, Sha256};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::AppState;
use crate::cache::CacheManager;

/// Upper bound for a single SSH channel data message payload.
///
/// Keeping frames at or below 32 KiB avoids relying on library-side
/// fragmentation behavior for large buffers while streaming big packfiles.
const SSH_DATA_CHUNK_SIZE: usize = 32 * 1024;

#[derive(Debug, Default, Clone)]
struct UpstreamProxyChannelState {
    stream_finished: bool,
    exit_status_sent: bool,
    eof_sent: bool,
    close_sent: bool,
    client_eof_seen: bool,
    client_close_seen: bool,
}

struct UpstreamUploadPackRequest {
    owner_repo: String,
    want_have: Vec<u8>,
    authenticated: bool,
    git_protocol: Option<String>,
}

#[derive(Clone, Copy)]
struct UpstreamUploadPackBehavior {
    warn_on_disconnect: bool,
    should_close_channel: bool,
    capture_for_hydration: bool,
}

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
    /// Session channels opened for this connection, keyed by channel id.
    /// Cached-path upload-pack streaming uses the channel writer API so large
    /// responses honor SSH window backpressure.
    channels: HashMap<ChannelId, Channel<Msg>>,
    /// `GIT_PROTOCOL` value sent by the client via SSH env request.
    git_protocol: Option<String>,
    /// For PAT-mode upstream proxy (uncached repos):
    /// `(owner_repo, want_have_buf, authenticated, git_protocol)`.
    ///
    /// SSH auth is fail-closed: unresolved fingerprints are rejected at auth
    /// time, so `authenticated` should be `true` for normal requests.
    upstream_proxy_buf: Option<(String, Vec<u8>, bool, Option<String>)>,
    /// Per-channel lifecycle state for the uncached upstream proxy path.
    upstream_proxy_channels: Arc<Mutex<HashMap<ChannelId, UpstreamProxyChannelState>>>,
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
            channels: HashMap::new(),
            git_protocol: None,
            upstream_proxy_buf: None,
            upstream_proxy_channels: Arc::new(Mutex::new(HashMap::new())),
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

fn parse_pkt_line_len(header: &[u8]) -> Option<usize> {
    if header.len() != 4 {
        return None;
    }
    let text = std::str::from_utf8(header).ok()?;
    usize::from_str_radix(text, 16).ok()
}

fn is_single_round_fetch_request(buf: &[u8]) -> bool {
    if !buf.ends_with(b"0000") {
        return false;
    }

    let mut saw_want = false;
    let mut offset = 0usize;

    while offset + 4 <= buf.len() {
        let len = match parse_pkt_line_len(&buf[offset..offset + 4]) {
            Some(len) => len,
            None => return false,
        };

        if len == 0 {
            return offset + 4 == buf.len() && saw_want;
        }

        if len < 4 || offset + len > buf.len() {
            return false;
        }

        let payload = &buf[offset + 4..offset + len];
        if payload.starts_with(b"want ") {
            saw_want = true;
        } else if payload.starts_with(b"have ") || payload == b"done\n" {
            return false;
        }

        offset += len;
    }

    false
}

#[cfg(test)]
fn is_complete_v2_fetch_request(buf: &[u8]) -> bool {
    matches!(
        split_next_complete_v2_request(buf),
        Some((V2RequestKind::Fetch, len)) if len == buf.len()
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V2RequestKind {
    LsRefs,
    Fetch,
}

fn split_next_complete_v2_request(buf: &[u8]) -> Option<(V2RequestKind, usize)> {
    let mut request_kind = None;
    let mut offset = 0usize;

    while offset + 4 <= buf.len() {
        let len = parse_pkt_line_len(&buf[offset..offset + 4])?;

        if len == 0 {
            offset += 4;
            return request_kind.map(|kind| (kind, offset));
        }

        if len == 1 || len == 2 {
            offset += 4;
            continue;
        }

        if len < 4 || offset + len > buf.len() {
            return None;
        }

        let payload = &buf[offset + 4..offset + len];
        let payload = payload.strip_suffix(b"\n").unwrap_or(payload);
        if payload == b"command=fetch" {
            request_kind = Some(V2RequestKind::Fetch);
        } else if payload == b"command=ls-refs" {
            request_kind = Some(V2RequestKind::LsRefs);
        }

        offset += len;
    }

    None
}

#[cfg(test)]
fn complete_v2_request_kind(buf: &[u8]) -> Option<V2RequestKind> {
    match split_next_complete_v2_request(buf) {
        Some((kind, len)) if len == buf.len() => Some(kind),
        _ => None,
    }
}

fn summarize_pkt_lines(buf: &[u8]) -> String {
    const MAX_SUMMARY_LINES: usize = 12;
    const MAX_TOTAL_CHARS: usize = 512;

    let mut out = Vec::new();
    let mut offset = 0usize;
    let mut total_lines = 0usize;
    let mut want_lines = 0usize;
    let mut hidden_lines = 0usize;

    while offset + 4 <= buf.len() {
        total_lines += 1;
        let len = match parse_pkt_line_len(&buf[offset..offset + 4]) {
            Some(len) => len,
            None => {
                let summary = format!("invalid-len@{offset}");
                if out.len() < MAX_SUMMARY_LINES {
                    out.push(summary);
                } else {
                    hidden_lines += 1;
                }
                break;
            }
        };

        let summary = match len {
            0 => {
                offset += 4;
                "flush".to_string()
            }
            1 => {
                offset += 4;
                "delimiter".to_string()
            }
            2 => {
                offset += 4;
                "response-end".to_string()
            }
            n => {
                if n < 4 || offset + n > buf.len() {
                    let summary = format!("truncated@{offset}:{n}");
                    if out.len() < MAX_SUMMARY_LINES {
                        out.push(summary);
                    } else {
                        hidden_lines += 1;
                    }
                    break;
                }
                let payload =
                    String::from_utf8_lossy(&buf[offset + 4..offset + n]).replace('\n', "\\n");
                offset += n;
                if payload.starts_with("want ") {
                    want_lines += 1;
                    continue;
                }
                payload
            }
        };

        if out.len() < MAX_SUMMARY_LINES {
            out.push(summary);
        } else {
            hidden_lines += 1;
        }
    }

    if want_lines > 0 {
        out.push(format!("want_count={want_lines}"));
    }
    if total_lines > out.len() {
        out.push(format!("pkt_line_count={total_lines}"));
    }
    if hidden_lines > 0 {
        out.push(format!("truncated_lines={hidden_lines}"));
    }

    let mut summary = out.join(" | ");
    if summary.len() > MAX_TOTAL_CHARS {
        summary.truncate(MAX_TOTAL_CHARS.saturating_sub("...".len()));
        summary.push_str("...");
    }
    summary
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
    /// We compute the key fingerprint and resolve the upstream username via
    /// sidecar + cache.  Resolution must succeed; unresolved fingerprints are
    /// rejected so cached repos cannot bypass forge authorization checks.
    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        let fp = fingerprint_of(key);
        info!(
            peer = ?self.peer_addr,
            user = %user,
            fingerprint = %fp,
            "SSH public-key auth attempt"
        );

        // Quick cache check for metrics tracking (hit/miss counters).
        let cache_key = format!("forgeproxy:ssh:auth:{fp}");
        let is_cached = crate::auth::cache::get_cached_auth(&self.state.valkey, &cache_key)
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
                warn!(fingerprint = %fp, "SSH key unresolved; rejecting");
                Ok(Auth::Reject {
                    proceed_with_methods: None,
                })
            }
            Err(e) => {
                warn!(
                    fingerprint = %fp,
                    error = %e,
                    "sidecar key resolution failed; rejecting"
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
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.channels.insert(channel.id(), channel);
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
    /// process stdin (cached path), or accumulate it for the upstream HTTP
    /// proxy (uncached path).
    ///
    /// For the proxy path, git never sends `SSH_MSG_CHANNEL_EOF` after "done"
    /// — it keeps the channel open to read the packfile.  We therefore detect
    /// the `0009done\n` pkt-line here and trigger the upstream POST immediately.
    async fn data(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Cached path: forward to upload-pack stdin.
        if let Some(ref mut stdin) = self.child_stdin
            && let Err(e) = stdin.write_all(data).await
        {
            debug!(error = %e, "failed to write to upload-pack stdin (process may have exited)");
            self.child_stdin.take();
        }

        // PAT-mode upstream proxy: accumulate want/have, then POST when the
        // client signals end-of-negotiation.
        //
        // Two termination patterns in git protocol v1:
        //   1. "0009done\n" — normal multi-round have/ack negotiation.
        //   2. Flush "0000" after wants (no haves) — shallow/single-round fetch
        //      (e.g. `git clone --depth 1`).  The client never sends "done" in
        //      this case; the flush IS the signal.
        let mut request_batch = Vec::new();
        let post_action = if let Some((ref repo, ref mut buf, authenticated, ref git_protocol)) =
            self.upstream_proxy_buf
        {
            debug!(
                repo = %repo,
                incoming_bytes = data.len(),
                total_buffered = buf.len() + data.len(),
                "DIAG: upstream proxy received client data"
            );
            buf.extend_from_slice(data);
            let has_done = buf.windows(9).any(|w| w == b"0009done\n");
            let ends_with_flush = buf.ends_with(b"0000");
            // Shallow/no-negotiation (protocol v1): wants followed by flush, no haves.
            // This exact request shape should POST immediately instead of
            // waiting for channel EOF, which Git does not send before reading
            // the packfile.
            let pkt_summary = if self.git_protocol.as_deref() == Some("version=2") {
                Some(summarize_pkt_lines(buf))
            } else {
                None
            };
            let has_flush_after_wants = if self.git_protocol.as_deref() == Some("version=2") {
                false
            } else {
                is_single_round_fetch_request(buf)
            };
            let mut v2_request_kind = None;
            if self.git_protocol.as_deref() == Some("version=2") {
                while let Some((kind, req_len)) = split_next_complete_v2_request(buf) {
                    let remaining = buf.split_off(req_len);
                    let request_bytes = std::mem::replace(buf, remaining);
                    request_batch.push((
                        repo.clone(),
                        kind,
                        request_bytes,
                        authenticated,
                        git_protocol.clone(),
                    ));
                    v2_request_kind = Some(kind);
                    if kind == V2RequestKind::Fetch {
                        break;
                    }
                }
            }
            debug!(
                repo = %repo,
                git_protocol = ?self.git_protocol,
                has_done,
                ends_with_flush,
                has_flush_after_wants,
                v2_request_kind = ?v2_request_kind,
                pkt_summary = ?pkt_summary,
                "DIAG: upstream proxy request completion check"
            );
            if self.git_protocol.as_deref() == Some("version=2") {
                None
            } else if has_done || has_flush_after_wants {
                Some((
                    repo.clone(),
                    V2RequestKind::Fetch,
                    std::mem::take(buf),
                    authenticated,
                    git_protocol.clone(),
                ))
            } else {
                None
            }
        } else {
            None
        };

        if !request_batch.is_empty() {
            let fetch_in_batch = request_batch
                .iter()
                .any(|(_, kind, _, _, _)| *kind == V2RequestKind::Fetch);
            let fetch_stream_channel = if fetch_in_batch {
                self.channels.remove(&channel_id)
            } else {
                None
            };
            if fetch_in_batch {
                self.upstream_proxy_buf = None;
            }

            let state = Arc::clone(&self.state);
            let channel_states = Arc::clone(&self.upstream_proxy_channels);
            let handle = session.handle();
            tokio::spawn(async move {
                let mut fetch_stream_channel = fetch_stream_channel;
                for (owner_repo, request_kind, want_have, authenticated, git_protocol) in
                    request_batch
                {
                    info!(
                        repo = %owner_repo,
                        request_kind = ?request_kind,
                        want_have_bytes = want_have.len(),
                        authenticated,
                        "upstream proxy: request complete, POSTing to upstream"
                    );
                    proxy_upstream_upload_pack(
                        Arc::clone(&state),
                        Arc::clone(&channel_states),
                        handle.clone(),
                        channel_id,
                        if request_kind == V2RequestKind::Fetch {
                            fetch_stream_channel.take()
                        } else {
                            None
                        },
                        UpstreamUploadPackRequest {
                            owner_repo,
                            want_have,
                            authenticated,
                            git_protocol,
                        },
                        UpstreamUploadPackBehavior {
                            warn_on_disconnect: true,
                            should_close_channel: request_kind == V2RequestKind::Fetch,
                            capture_for_hydration: request_kind == V2RequestKind::Fetch,
                        },
                    )
                    .await;
                }
            });
        }

        if let Some((owner_repo, request_kind, want_have, authenticated, git_protocol)) =
            post_action
        {
            let stream_channel = if request_kind == V2RequestKind::Fetch {
                self.channels.remove(&channel_id)
            } else {
                None
            };
            if request_kind == V2RequestKind::Fetch {
                self.upstream_proxy_buf = None;
            }
            info!(
                repo = %owner_repo,
                request_kind = ?request_kind,
                want_have_bytes = want_have.len(),
                authenticated,
                "upstream proxy: request complete, POSTing to upstream"
            );
            let state = Arc::clone(&self.state);
            let channel_states = Arc::clone(&self.upstream_proxy_channels);
            let handle = session.handle();
            tokio::spawn(async move {
                proxy_upstream_upload_pack(
                    state,
                    channel_states,
                    handle,
                    channel_id,
                    stream_channel,
                    UpstreamUploadPackRequest {
                        owner_repo,
                        want_have,
                        authenticated,
                        git_protocol,
                    },
                    UpstreamUploadPackBehavior {
                        warn_on_disconnect: true,
                        should_close_channel: request_kind == V2RequestKind::Fetch,
                        capture_for_hydration: request_kind == V2RequestKind::Fetch,
                    },
                )
                .await;
            });
        }

        Ok(())
    }

    /// When the client signals EOF, close upload-pack's stdin (cached path).
    /// For the proxy path, the POST is triggered from `data` on the "done"
    /// pkt-line; this is a fallback in case that detection missed it.
    async fn channel_eof(
        &mut self,
        channel_id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Cached path: dropping ChildStdin closes the pipe → child exits.
        self.child_stdin.take();

        debug!(
            channel = ?channel_id,
            has_upstream_buf = self.upstream_proxy_buf.is_some(),
            "DIAG: channel_eof fired"
        );

        if let Some(state) = self
            .upstream_proxy_channels
            .lock()
            .await
            .get_mut(&channel_id)
        {
            state.client_eof_seen = true;
        }

        // PAT-mode upstream proxy: POST buffered want/have, stream packfile back.
        if let Some((owner_repo, want_have, authenticated, git_protocol)) =
            self.upstream_proxy_buf.take()
        {
            let stream_channel = self.channels.remove(&channel_id);
            debug!(repo = %owner_repo, want_have_bytes = want_have.len(), authenticated, "upstream proxy: channel_eof received, POSTing to upstream");
            let state = Arc::clone(&self.state);
            let channel_states = Arc::clone(&self.upstream_proxy_channels);
            let handle = session.handle();
            tokio::spawn(async move {
                proxy_upstream_upload_pack(
                    state,
                    channel_states,
                    handle,
                    channel_id,
                    stream_channel,
                    UpstreamUploadPackRequest {
                        owner_repo,
                        want_have,
                        authenticated,
                        git_protocol,
                    },
                    UpstreamUploadPackBehavior {
                        warn_on_disconnect: false,
                        should_close_channel: true,
                        capture_for_hydration: true,
                    },
                )
                .await;
            });
        }

        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel_id: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut close_state = None;
        {
            let mut channels = self.upstream_proxy_channels.lock().await;
            if let Some(state) = channels.get_mut(&channel_id) {
                state.client_close_seen = true;
                close_state = Some(state.clone());
            }
        }

        if let Some(state) = close_state {
            debug!(
                channel = ?channel_id,
                stream_finished = state.stream_finished,
                exit_status_sent = state.exit_status_sent,
                eof_sent = state.eof_sent,
                close_sent = state.close_sent,
                client_eof_seen = state.client_eof_seen,
                client_close_seen = state.client_close_seen,
                "DIAG: channel_close fired"
            );
        }

        self.upstream_proxy_channels
            .lock()
            .await
            .remove(&channel_id);
        self.channels.remove(&channel_id);
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
                          Please push directly to the upstream forge.\n",
                    ),
                );
                finish_channel(session, channel_id, 1);
                Ok(())
            }

            Some((GitCommand::UploadPack, repo)) => {
                // ── Path validation ──────────────────────────────────
                if repo.contains("..") || repo.contains('\0') {
                    warn!(repo = %repo, "rejected SSH exec with path traversal attempt");
                    session.extended_data(
                        channel_id,
                        1,
                        CryptoVec::from_slice(b"ERROR: Invalid repository path.\n"),
                    );
                    finish_channel(session, channel_id, 1);
                    return Ok(());
                }

                // ── Per-repo authorization ────────────────────────────
                // Split "owner/repo" so we can check read access on the forge.
                match super::upstream::split_owner_repo(&repo) {
                    Ok((owner, repo_name)) => {
                        let username = match self.username.as_deref() {
                            Some(u) => u,
                            None => {
                                session.extended_data(
                                    channel_id,
                                    1,
                                    CryptoVec::from_slice(
                                        b"ERROR: SSH identity could not be resolved.\n",
                                    ),
                                );
                                finish_channel(session, channel_id, 1);
                                return Ok(());
                            }
                        };
                        let fingerprint = self.fingerprint.as_deref().unwrap_or("");
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
                                    username,
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
                                    username,
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

                if self.cache_manager.has_repo(&repo) {
                    // ── Serve from local cache via bidirectional upload-pack ──
                    info!(repo = %repo, "serving git-upload-pack from local cache");
                    let Some(channel) = self.channels.remove(&channel_id) else {
                        error!(repo = %repo, channel = ?channel_id, "missing SSH channel handle for cached upload-pack");
                        session.extended_data(
                            channel_id,
                            1,
                            CryptoVec::from_slice(b"ERROR: Internal SSH channel state missing.\n"),
                        );
                        finish_channel(session, channel_id, 1);
                        return Ok(());
                    };

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

                            // RFC 4254 §6.5: the client won't read channel data
                            // until it receives SSH_MSG_CHANNEL_SUCCESS for the
                            // exec request.  Send it now, before the background
                            // task starts streaming upload-pack stdout.
                            session.channel_success(channel_id);

                            // Obtain an async Handle for sending data from the
                            // background task (the sync Session methods cannot
                            // be used outside the handler call).
                            let handle = session.handle();

                            // Spawn a task that streams upload-pack stdout to
                            // the SSH channel using russh's channel writer so
                            // large responses obey SSH window backpressure.
                            tokio::spawn(async move {
                                let mut stdout = stdout;
                                let mut stderr = stderr;
                                let mut channel_writer = channel.make_writer();
                                let mut disconnected = false;

                                if let Err(e) =
                                    tokio::io::copy(&mut stdout, &mut channel_writer).await
                                {
                                    debug!(
                                        error = %e,
                                        "error streaming upload-pack stdout to SSH channel"
                                    );
                                    disconnected = true;
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
                                if !disconnected {
                                    let _ = handle.exit_status_request(channel_id, exit_code).await;
                                    let _ = tokio::io::AsyncWriteExt::shutdown(&mut channel_writer)
                                        .await;
                                    let _ = handle.close(channel_id).await;
                                }
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
                    // Repository is not in local cache — proxy upstream via HTTP
                    // smart protocol.  Phase 1: fetch ref advertisement (async,
                    // via background task so we don't block the russh event
                    // loop and match the same handle.data() pattern used by the
                    // cached path).  Phase 2 happens in `channel_eof`.
                    warn!(repo = %repo, "repository not in local cache; proxying upstream");

                    // Capture whether this session has a resolved username.
                    // Auth is fail-closed, so this should be true in normal
                    // operation.
                    let authenticated = self.username.is_some();

                    // Initialise the accumulation buffer NOW, before spawning,
                    // so the `data` callback can capture any client bytes that
                    // arrive while the advertisement is being fetched (in
                    // practice git won't send anything until it receives the
                    // advertisement, but initialising here is race-safe).
                    self.upstream_proxy_buf = Some((
                        repo.clone(),
                        Vec::new(),
                        authenticated,
                        self.git_protocol.clone(),
                    ));
                    self.upstream_proxy_channels
                        .lock()
                        .await
                        .insert(channel_id, UpstreamProxyChannelState::default());

                    // RFC 4254 §6.5: OpenSSH won't read channel data until it
                    // receives SSH_MSG_CHANNEL_SUCCESS.  Send it now so the
                    // client starts reading before the background task writes
                    // the ref advertisement (avoids TCP deadlock).
                    session.channel_success(channel_id);

                    let state = Arc::clone(&self.state);
                    let channel_states = Arc::clone(&self.upstream_proxy_channels);
                    let handle = session.handle();
                    let repo_bg = repo.clone();
                    let git_protocol = self.git_protocol.clone();
                    tokio::spawn(async move {
                        match super::upstream::fetch_ref_advertisement(
                            &state,
                            &repo_bg,
                            authenticated,
                            git_protocol.as_deref(),
                        )
                        .await
                        {
                            Ok(advert) => {
                                // Forward ref advertisement; channel stays open
                                // for want/have — `channel_eof` will POST.
                                debug!(repo = %repo_bg, bytes = advert.len(), "DIAG: sending ref advertisement via handle.data");
                                match handle
                                    .data(channel_id, CryptoVec::from_slice(&advert))
                                    .await
                                {
                                    Ok(()) => {
                                        debug!(repo = %repo_bg, "DIAG: handle.data returned Ok")
                                    }
                                    Err(_) => {
                                        warn!(repo = %repo_bg, "DIAG: handle.data returned Err — session receiver dropped")
                                    }
                                }
                            }
                            Err(e) => {
                                error!(
                                    repo = %repo_bg,
                                    error = %format!("{e:#}"),
                                    "upstream proxy ref advertisement failed"
                                );
                                let msg = format!(
                                    "Repository '{}' is not cached and upstream proxy failed: {}\n\
                                     Try cloning directly from the upstream forge.\n",
                                    repo_bg, e,
                                );
                                let _ = handle
                                    .extended_data(
                                        channel_id,
                                        1,
                                        CryptoVec::from_slice(msg.as_bytes()),
                                    )
                                    .await;
                                let _ = handle.exit_status_request(channel_id, 1).await;
                                let _ = handle.eof(channel_id).await;
                                if let Some(state) =
                                    channel_states.lock().await.get_mut(&channel_id)
                                {
                                    state.stream_finished = true;
                                    state.exit_status_sent = true;
                                    state.eof_sent = true;
                                    state.close_sent = true;
                                }
                                let _ = handle.close(channel_id).await;
                            }
                        }
                    });
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

/// Proxy `git-upload-pack` to the upstream forge and stream the response back
/// to the SSH client. Channel close is coordinated by the main SSH handler
/// after the client acknowledges teardown.
async fn proxy_upstream_upload_pack(
    state: Arc<AppState>,
    channel_states: Arc<Mutex<HashMap<ChannelId, UpstreamProxyChannelState>>>,
    handle: russh::server::Handle,
    channel_id: ChannelId,
    stream_channel: Option<Channel<Msg>>,
    request: UpstreamUploadPackRequest,
    behavior: UpstreamUploadPackBehavior,
) {
    let UpstreamUploadPackRequest {
        owner_repo,
        want_have,
        authenticated,
        git_protocol,
    } = request;
    match super::upstream::post_upload_pack_stream(
        &state,
        &owner_repo,
        &want_have,
        authenticated,
        git_protocol.as_deref(),
    )
    .await
    {
        Ok(stream) => {
            use futures::Stream;
            use std::pin::Pin;
            let mut stream = Pin::new(Box::new(stream));
            let mut channel_writer = stream_channel.map(|channel| channel.make_writer());
            let mut total_bytes: u64 = 0;
            let mut had_error = false;
            let auth_header = if authenticated {
                build_clone_auth_header_for_repo(&state, &owner_repo).await
            } else {
                None
            };
            let mut capture = if behavior.capture_for_hydration {
                match crate::tee_hydration::TeeCapture::start(
                    &state.cache_manager.base_path,
                    &owner_repo,
                    "ssh",
                )
                .await
                {
                    Ok(mut capture) => {
                        if let Err(e) = capture.write_request(&want_have).await {
                            warn!(
                                repo = %owner_repo,
                                error = %e,
                                "failed to record SSH tee request"
                            );
                            None
                        } else {
                            Some(capture)
                        }
                    }
                    Err(e) => {
                        warn!(
                            repo = %owner_repo,
                            error = %e,
                            "failed to start tee capture for SSH miss"
                        );
                        None
                    }
                }
            } else {
                None
            };
            while let Some(chunk_result) =
                std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await
            {
                match chunk_result {
                    Ok(chunk) => {
                        total_bytes += chunk.len() as u64;
                        if let Some(active_capture) = capture.as_mut()
                            && let Err(e) = active_capture.write_response_chunk(&chunk).await
                        {
                            warn!(
                                repo = %owner_repo,
                                error = %e,
                                "failed to record SSH tee response chunk"
                            );
                            capture = None;
                        }
                        if let Some(writer) = channel_writer.as_mut() {
                            if let Err(e) = writer.write_all(&chunk).await {
                                if behavior.warn_on_disconnect {
                                    warn!(
                                        repo = %owner_repo,
                                        error = %e,
                                        "client disconnected during pack stream"
                                    );
                                }
                                had_error = true;
                            }
                        } else {
                            for part in chunk.chunks(SSH_DATA_CHUNK_SIZE) {
                                if handle
                                    .data(channel_id, CryptoVec::from_slice(part))
                                    .await
                                    .is_err()
                                {
                                    if behavior.warn_on_disconnect {
                                        warn!(
                                            repo = %owner_repo,
                                            "client disconnected during pack stream"
                                        );
                                    }
                                    had_error = true;
                                    break;
                                }
                            }
                            if had_error {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            repo = %owner_repo,
                            error = %e,
                            "error reading upstream pack stream"
                        );
                        had_error = true;
                        break;
                    }
                }
            }
            if had_error {
                if let Some(active_capture) = capture.take() {
                    let _ = active_capture.finish(false).await;
                }
                if behavior.should_close_channel {
                    let _ = handle.exit_status_request(channel_id, 1).await;
                    if let Some(state) = channel_states.lock().await.get_mut(&channel_id) {
                        state.stream_finished = true;
                        state.exit_status_sent = true;
                    }
                }
            } else {
                info!(
                    repo = %owner_repo,
                    total_bytes,
                    "upstream proxy pack stream complete"
                );
                if let Some(active_capture) = capture.take() {
                    let capture_dir = active_capture.dir().to_path_buf();
                    let _ = active_capture.finish(true).await;
                    if let Ok((owner, repo)) = super::upstream::split_owner_repo(&owner_repo) {
                        let state_bg = Arc::clone(&state);
                        let owner_bg = owner.to_string();
                        let repo_bg = repo.to_string();
                        let owner_repo_bg = owner_repo.clone();
                        let auth_bg = auth_header.clone();
                        tokio::spawn(async move {
                            if let Err(e) =
                                crate::coordination::registry::try_ensure_repo_cloned_from_tee(
                                    &state_bg,
                                    &owner_bg,
                                    &repo_bg,
                                    auth_bg.as_deref(),
                                    capture_dir,
                                )
                                .await
                            {
                                warn!(
                                    repo = %owner_repo_bg,
                                    error = %e,
                                    "tee hydration after SSH miss failed"
                                );
                            }
                        });
                    }
                }
                if behavior.should_close_channel {
                    let _ = handle.exit_status_request(channel_id, 0).await;
                    if let Some(state) = channel_states.lock().await.get_mut(&channel_id) {
                        state.stream_finished = true;
                        state.exit_status_sent = true;
                    }
                }
            }
            if behavior.should_close_channel {
                if let Some(writer) = channel_writer.as_mut() {
                    let _ = writer.shutdown().await;
                } else {
                    let _ = handle.eof(channel_id).await;
                }
                if let Some(state) = channel_states.lock().await.get_mut(&channel_id) {
                    state.eof_sent = true;
                    state.close_sent = true;
                }
                let _ = handle.close(channel_id).await;
            }
        }
        Err(e) => {
            error!(
                repo = %owner_repo,
                error = %format!("{e:#}"),
                "upstream proxy POST failed"
            );
            let msg = format!(
                "Repository '{}' upstream proxy failed: {}\n\
                 Try cloning directly from the upstream forge.\n",
                owner_repo, e,
            );
            let _ = handle
                .extended_data(channel_id, 1, CryptoVec::from_slice(msg.as_bytes()))
                .await;
            if behavior.should_close_channel {
                let _ = handle.exit_status_request(channel_id, 1).await;
                let _ = handle.eof(channel_id).await;
                if let Some(state) = channel_states.lock().await.get_mut(&channel_id) {
                    state.stream_finished = true;
                    state.exit_status_sent = true;
                    state.eof_sent = true;
                    state.close_sent = true;
                }
                let _ = handle.close(channel_id).await;
            }
        }
    }
}

/// Build a `Bearer` auth header for clone/fetch operations for this repo's org.
/// Returns `None` if the token cannot be resolved.
async fn build_clone_auth_header_for_repo(state: &AppState, owner_repo: &str) -> Option<String> {
    let (owner, _) = super::upstream::split_owner_repo(owner_repo).ok()?;
    let token_key = state
        .config
        .upstream_credentials
        .orgs
        .get(owner)
        .map(|oc| oc.keyring_key_name.as_str())
        .unwrap_or(&state.config.upstream.admin_token_env);

    let token = crate::credentials::keyring::resolve_secret(token_key).await?;
    if token.is_empty() {
        return None;
    }
    Some(format!("Bearer {token}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt_line(payload: &str) -> String {
        format!("{:04x}{payload}", payload.len() + 4)
    }

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
    fn parse_rejects_traversal_in_repo_path() {
        // parse_git_command itself doesn't validate traversal, but the
        // exec_request handler checks for ".." before proceeding.
        let (_, repo) = parse_git_command("git-upload-pack '../../etc/passwd'").unwrap();
        assert!(repo.contains(".."));
    }

    #[test]
    fn parse_traversal_in_owner() {
        let (_, repo) = parse_git_command("git-upload-pack '../evil/repo'").unwrap();
        assert!(repo.contains(".."));
    }

    #[test]
    fn fingerprint_has_sha256_prefix() {
        let keypair = russh_keys::key::KeyPair::generate_ed25519();
        let pubkey = keypair.clone_public_key().unwrap();
        let fp = fingerprint_of(&pubkey);
        assert!(
            fp.starts_with("SHA256:"),
            "fingerprint should start with SHA256: prefix, got: {fp}"
        );
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let keypair = russh_keys::key::KeyPair::generate_ed25519();
        let pubkey = keypair.clone_public_key().unwrap();
        let fp1 = fingerprint_of(&pubkey);
        let fp2 = fingerprint_of(&pubkey);
        assert_eq!(
            fp1, fp2,
            "fingerprint should be deterministic for the same key"
        );
    }

    #[test]
    fn fingerprint_has_correct_length() {
        let keypair = russh_keys::key::KeyPair::generate_ed25519();
        let pubkey = keypair.clone_public_key().unwrap();
        let fp = fingerprint_of(&pubkey);
        // SHA256: prefix (7 chars) + 43 base64-no-pad chars = 50 total
        assert_eq!(
            fp.len(),
            50,
            "fingerprint length should be 50, got: {} ({})",
            fp.len(),
            fp
        );
    }

    #[test]
    fn single_round_fetch_request_detects_want_want_deepen_flush() {
        let req = format!(
            "{}{}{}0000",
            pkt_line(
                "want 8ec1e5b69fa78abab5efd3fd9e63cbf0aa025b4f multi_ack_detailed side-band-64k thin-pack include-tag ofs-delta deepen-since deepen-not agent=git/2.51.2-Linux\n"
            ),
            pkt_line("want 8ec1e5b69fa78abab5efd3fd9e63cbf0aa025b4f\n"),
            pkt_line("deepen 1\n"),
        );
        assert!(is_single_round_fetch_request(req.as_bytes()), "{req:?}");
    }

    #[test]
    fn single_round_fetch_request_rejects_have_negotiation() {
        let req = format!(
            "{}{}0000",
            pkt_line("want 8ec1e5b69fa78abab5efd3fd9e63cbf0aa025b4f\n"),
            pkt_line("have 8ec1e5b69fa78abab5efd3fd9e63cbf0aa025b4f\n"),
        );
        assert!(!is_single_round_fetch_request(req.as_bytes()));
    }

    #[test]
    fn complete_v2_fetch_request_detects_fetch_sections() {
        let req = format!(
            "{}{}0001{}{}0000",
            pkt_line("command=fetch\n"),
            pkt_line("agent=git/2.51.2\n"),
            pkt_line("thin-pack\n"),
            pkt_line("ofs-delta\n"),
        );
        assert!(is_complete_v2_fetch_request(req.as_bytes()), "{req:?}");
    }

    #[test]
    fn complete_v2_request_kind_detects_fetch_without_trailing_newlines() {
        let req = format!(
            "{}{}0001{}{}{}0000",
            pkt_line("command=fetch"),
            pkt_line("agent=git/2.52.0-Linux"),
            pkt_line("thin-pack"),
            pkt_line("ofs-delta"),
            pkt_line("done"),
        );
        assert_eq!(
            complete_v2_request_kind(req.as_bytes()),
            Some(V2RequestKind::Fetch),
            "{req:?}"
        );
    }

    #[test]
    fn complete_v2_request_kind_detects_ls_refs() {
        let req = format!(
            "{}{}{}0001{}{}{}0000",
            pkt_line("command=ls-refs\n"),
            pkt_line("agent=git/2.52.0-Linux\n"),
            pkt_line("object-format=sha1\n"),
            pkt_line("peel\n"),
            pkt_line("symrefs\n"),
            pkt_line("unborn\n"),
        );
        assert_eq!(
            complete_v2_request_kind(req.as_bytes()),
            Some(V2RequestKind::LsRefs),
            "{req:?}"
        );
    }

    #[test]
    fn split_next_complete_v2_request_extracts_front_request_only() {
        let req = format!(
            "{}{}0001{}0000{}{}0001{}{}0000",
            pkt_line("command=ls-refs\n"),
            pkt_line("agent=git/2.52.0-Linux\n"),
            pkt_line("peel\n"),
            pkt_line("command=fetch\n"),
            pkt_line("agent=git/2.52.0-Linux\n"),
            pkt_line("thin-pack\n"),
            pkt_line("done\n"),
        );

        let (kind, len) = split_next_complete_v2_request(req.as_bytes()).unwrap();
        assert_eq!(kind, V2RequestKind::LsRefs);
        assert_eq!(
            complete_v2_request_kind(&req.as_bytes()[..len]),
            Some(V2RequestKind::LsRefs)
        );
        assert_eq!(
            complete_v2_request_kind(&req.as_bytes()[len..]),
            Some(V2RequestKind::Fetch)
        );
    }

    #[test]
    fn split_next_complete_v2_request_waits_for_full_fetch_when_chunked() {
        let fetch = format!(
            "{}{}0001{}{}0000",
            pkt_line("command=fetch\n"),
            pkt_line("agent=git/2.52.0-Linux\n"),
            pkt_line("thin-pack\n"),
            pkt_line("done\n"),
        );

        for split_at in 1..fetch.len() {
            let prefix = &fetch.as_bytes()[..split_at];
            let suffix = &fetch.as_bytes()[split_at..];
            assert!(
                split_next_complete_v2_request(prefix).is_none(),
                "prefix unexpectedly parsed as complete at split {split_at}"
            );

            let mut combined = prefix.to_vec();
            combined.extend_from_slice(suffix);
            assert_eq!(
                split_next_complete_v2_request(&combined),
                Some((V2RequestKind::Fetch, fetch.len())),
                "combined buffer should parse after split {split_at}"
            );
        }
    }

    #[test]
    fn split_next_complete_v2_request_handles_back_to_back_requests_across_chunks() {
        let ls_refs = format!(
            "{}{}0001{}{}0000",
            pkt_line("command=ls-refs\n"),
            pkt_line("agent=git/2.52.0-Linux\n"),
            pkt_line("peel\n"),
            pkt_line("symrefs\n"),
        );
        let fetch = format!(
            "{}{}0001{}{}0000",
            pkt_line("command=fetch\n"),
            pkt_line("agent=git/2.52.0-Linux\n"),
            pkt_line("thin-pack\n"),
            pkt_line("done\n"),
        );
        let req = format!("{ls_refs}{fetch}");

        let boundary = ls_refs.len() + 7;
        let prefix = &req.as_bytes()[..boundary];
        let suffix = &req.as_bytes()[boundary..];

        let (kind, len) = split_next_complete_v2_request(prefix).unwrap();
        assert_eq!(kind, V2RequestKind::LsRefs);
        assert_eq!(len, ls_refs.len());

        let mut remaining = prefix[len..].to_vec();
        remaining.extend_from_slice(suffix);
        assert_eq!(
            split_next_complete_v2_request(&remaining),
            Some((V2RequestKind::Fetch, fetch.len()))
        );
    }

    #[test]
    fn split_next_complete_v2_request_leaves_trailing_fetch_bytes_buffered() {
        let ls_refs = format!(
            "{}{}0001{}0000",
            pkt_line("command=ls-refs\n"),
            pkt_line("agent=git/2.52.0-Linux\n"),
            pkt_line("peel\n"),
        );
        let fetch_prefix = format!(
            "{}{}0001",
            pkt_line("command=fetch\n"),
            pkt_line("agent=git/2.52.0-Linux\n"),
        );
        let buf = format!("{ls_refs}{fetch_prefix}");

        let (kind, len) = split_next_complete_v2_request(buf.as_bytes()).unwrap();
        assert_eq!(kind, V2RequestKind::LsRefs);
        assert_eq!(len, ls_refs.len());
        assert!(
            split_next_complete_v2_request(&buf.as_bytes()[len..]).is_none(),
            "partial trailing fetch should remain buffered"
        );
    }

    #[test]
    fn summarize_pkt_lines_bounds_large_want_lists() {
        let mut req = String::new();
        req.push_str(&pkt_line("command=fetch\n"));
        req.push_str("0001");
        for idx in 0..20 {
            req.push_str(&pkt_line(&format!("want {:040x}\n", idx)));
        }
        req.push_str("0000");

        let summary = summarize_pkt_lines(req.as_bytes());
        assert!(
            !summary.contains("want 0000000000000000000000000000000000000000"),
            "summary should not dump raw want lines: {summary:?}"
        );
        assert!(
            summary.contains("want_count=20"),
            "summary should report total want count: {summary:?}"
        );
        assert!(
            summary.contains("pkt_line_count="),
            "summary should report total pkt-line count: {summary:?}"
        );
        assert!(
            summary.len() <= 512,
            "summary should remain bounded: {} chars",
            summary.len()
        );
    }

    #[test]
    fn complete_v2_fetch_request_rejects_missing_command() {
        let req = format!("{}0000", pkt_line("agent=git/2.51.2\n"));
        assert!(!is_complete_v2_fetch_request(req.as_bytes()));
    }
}
