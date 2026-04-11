//! SSH session handler implementing the `russh` [`Handler`] trait.
//!
//! Each inbound SSH connection is served by a dedicated [`SshSession`].  The
//! handler performs public-key authentication (with an upstream forge API fallback and
//! Valkey cache), rejects push operations, and either serves `git-upload-pack`
//! from the local bare-repo cache or returns a "not cached" error for repos
//! that have not yet been mirrored.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use anyhow::Result;
use base64::Engine as _;
use russh::keys::{PublicKey, PublicKeyBase64};
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf};
use sha2::{Digest, Sha256};

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::{Instrument, debug, error, info, warn};

use crate::AppState;
use crate::cache::CacheManager;
use crate::clone_support::{
    CloneCompletion, LocalUploadPackMode, UpstreamHydrationRequest, UpstreamHydrationTracker,
    spawn_local_upload_pack, wait_for_local_upload_pack_exit,
};
use crate::coordination::registry::{LocalServeDecision, LocalServeRepoSource};
use crate::metrics::{
    ActiveConnectionGuard, CacheStatus, CloneDownstreamBytesLabels, ClonePhase, CloneSource,
    CloneUpstreamBytesLabels, Protocol,
};
use crate::observability::GitRequestObservation;

/// Upper bound for a single SSH channel data message payload.
///
/// Keeping frames at or below 32 KiB avoids relying on library-side
/// fragmentation behavior for large buffers while streaming big packfiles.
const SSH_DATA_CHUNK_SIZE: usize = 32 * 1024;

fn ssh_git_request_observation(
    state: &AppState,
    owner_repo: &str,
    username: Option<&str>,
    fingerprint: Option<&str>,
    git_protocol: Option<&str>,
    git_session_id: Option<String>,
) -> GitRequestObservation {
    let (owner, repo) =
        super::upstream::split_owner_repo(owner_repo).unwrap_or((owner_repo, "<unknown>"));
    GitRequestObservation::new(
        &state.config,
        owner,
        repo,
        username.unwrap_or("anonymous"),
        git_protocol,
        fingerprint.unwrap_or(""),
        "ssh",
        git_session_id,
    )
}

#[derive(Debug, Clone)]
struct UpstreamProxyChannelState {
    owner_repo: Option<String>,
    output_lock: Arc<Mutex<()>>,
    first_write_completed_at: Option<Instant>,
    last_write_completed_at: Option<Instant>,
    bytes_written_to_client: u64,
    stream_finished: bool,
    exit_status_sent: bool,
    eof_sent: bool,
    close_sent: bool,
    client_eof_seen: bool,
    client_close_seen: bool,
}

impl Default for UpstreamProxyChannelState {
    fn default() -> Self {
        Self {
            owner_repo: None,
            output_lock: Arc::new(Mutex::new(())),
            first_write_completed_at: None,
            last_write_completed_at: None,
            bytes_written_to_client: 0,
            stream_finished: false,
            exit_status_sent: false,
            eof_sent: false,
            close_sent: false,
            client_eof_seen: false,
            client_close_seen: false,
        }
    }
}

struct UpstreamUploadPackRequest {
    owner_repo: String,
    want_have: Vec<u8>,
    authenticated: bool,
    git_protocol: Option<String>,
    request_kind: V2RequestKind,
    metric_username: String,
}

#[derive(Clone, Copy)]
struct UpstreamUploadPackBehavior {
    warn_on_disconnect: bool,
    should_close_channel: bool,
    capture_for_hydration: bool,
}

struct UpstreamUploadPackContext {
    state: Arc<AppState>,
    channel_states: Arc<Mutex<HashMap<ChannelId, UpstreamProxyChannelState>>>,
    capture_metadata:
        Arc<Mutex<HashMap<ChannelId, crate::coordination::registry::RequestAdvertisedRefs>>>,
    handle: russh::server::Handle,
    channel_id: ChannelId,
    stream_channel: Option<Arc<ChannelWriteHalf<Msg>>>,
    output_lock: Arc<Mutex<()>>,
}

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

/// Per-connection SSH session state.
pub struct SshSession {
    state: Arc<AppState>,
    _active_connection: ActiveConnectionGuard,
    peer_addr: Option<SocketAddr>,
    fingerprint: Option<String>,
    username: Option<String>,
    cache_manager: CacheManager,
    /// Stdin handle for a running `git upload-pack` child process.
    /// Data received from the SSH client is forwarded here.
    child_stdin: Option<tokio::process::ChildStdin>,
    /// Session channels opened for this connection, keyed by channel id.
    /// We retain the handles for the lifetime of the SSH channel so protocol
    /// v2 ls-refs and fetch both use the same window-aware writer.
    channels: HashMap<ChannelId, Arc<ChannelWriteHalf<Msg>>>,
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
    /// Metadata from the uncached SSH negotiation that can later be used to
    /// publish a capture-derived generation before full convergence.
    upstream_capture_metadata:
        Arc<Mutex<HashMap<ChannelId, crate::coordination::registry::RequestAdvertisedRefs>>>,
}

impl SshSession {
    /// Create a new session for an incoming connection.
    pub fn new(state: Arc<AppState>, peer_addr: Option<SocketAddr>) -> Self {
        let active_connection = state.begin_active_connection(Protocol::Ssh);
        let cache_manager = state.cache_manager.clone();
        Self {
            state,
            _active_connection: active_connection,
            peer_addr,
            fingerprint: None,
            username: None,
            cache_manager,
            child_stdin: None,
            channels: HashMap::new(),
            git_protocol: None,
            upstream_proxy_buf: None,
            upstream_proxy_channels: Arc::new(Mutex::new(HashMap::new())),
            upstream_capture_metadata: Arc::new(Mutex::new(HashMap::new())),
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
    let _ = session.exit_status_request(channel_id, exit_status);
    let _ = session.eof(channel_id);
    let _ = session.close(channel_id);
}

/// Finalize upload-pack in RFC 4254 order after the response stream has been
/// copied through the SSH channel's window-aware writer.
///
/// The important constraint is that we must not let `ChannelTx::poll_shutdown`
/// send SSH EOF on our behalf before the exit-status request is queued, so the
/// response stream itself is copied with `write_all()` only and EOF is sent
/// explicitly here.
#[allow(clippy::too_many_arguments)]
async fn wait_for_channel_drain(
    owner_repo: &str,
    handle: &russh::server::Handle,
    channel_id: ChannelId,
    total_bytes: u64,
    wait_timeout: Duration,
    reason: &str,
) -> bool {
    let drain_deadline = Instant::now() + wait_timeout;
    let mut pending_data_polls = 0u32;
    let mut pending_data_cleared = false;

    info!(
        repo = %owner_repo,
        ?channel_id,
        total_bytes,
        drain_wait_secs = wait_timeout.as_secs(),
        reason,
        "awaiting russh channel drain"
    );

    loop {
        match handle.has_pending_data(channel_id).await {
            Ok(false) => {
                pending_data_cleared = true;
                break;
            }
            Ok(true) => {
                pending_data_polls += 1;
                if Instant::now() >= drain_deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                warn!(
                    repo = %owner_repo,
                    ?channel_id,
                    total_bytes,
                    error = ?error,
                    reason,
                    "failed to query russh pending channel data"
                );
                break;
            }
        }
    }

    if pending_data_cleared {
        info!(
            repo = %owner_repo,
            ?channel_id,
            total_bytes,
            pending_data_polls,
            reason,
            "russh channel drain completed"
        );
    } else {
        warn!(
            repo = %owner_repo,
            ?channel_id,
            total_bytes,
            pending_data_polls,
            drain_wait_secs = wait_timeout.as_secs(),
            reason,
            "russh channel drain did not complete"
        );
    }

    pending_data_cleared
}

#[allow(clippy::too_many_arguments)]
async fn finalize_upload_pack_channel(
    owner_repo: &str,
    handle: &russh::server::Handle,
    channel_states: &Arc<Mutex<HashMap<ChannelId, UpstreamProxyChannelState>>>,
    channel_id: ChannelId,
    exit_status: u32,
    total_bytes: u64,
    close_grace_period: Duration,
) {
    let pre_finalize_state = channel_states.lock().await.get(&channel_id).cloned();
    let finalize_started_at = Instant::now();
    if let Some(state) = pre_finalize_state.as_ref() {
        let first_write_completed_ms_ago = state.first_write_completed_at.map(|at| {
            finalize_started_at
                .saturating_duration_since(at)
                .as_millis() as u64
        });
        let last_write_completed_ms_ago = state.last_write_completed_at.map(|at| {
            finalize_started_at
                .saturating_duration_since(at)
                .as_millis() as u64
        });
        info!(
            repo = %owner_repo,
            ?channel_id,
            total_bytes,
            exit_status,
            bytes_written_to_client = state.bytes_written_to_client,
            first_write_completed_ms_ago,
            last_write_completed_ms_ago,
            client_eof_seen = state.client_eof_seen,
            client_close_seen = state.client_close_seen,
            stream_finished = state.stream_finished,
            exit_status_sent = state.exit_status_sent,
            eof_sent = state.eof_sent,
            close_sent = state.close_sent,
            "finalizing SSH upload-pack channel"
        );
    } else {
        info!(
            repo = %owner_repo,
            ?channel_id,
            total_bytes,
            exit_status,
            "finalizing SSH upload-pack channel without tracked channel state"
        );
    }

    let _pending_data_cleared = wait_for_channel_drain(
        owner_repo,
        handle,
        channel_id,
        total_bytes,
        close_grace_period,
        "before sending SSH upload-pack exit-status and EOF",
    )
    .await;

    let exit_status_sent = match handle.exit_status_request(channel_id, exit_status).await {
        Ok(()) => {
            info!(
                repo = %owner_repo,
                ?channel_id,
                total_bytes,
                exit_status,
                "SSH upload-pack exit-status sent"
            );
            true
        }
        Err(error) => {
            warn!(
                repo = %owner_repo,
                ?channel_id,
                total_bytes,
                exit_status,
                error = ?error,
                "SSH upload-pack exit-status failed"
            );
            false
        }
    };

    let eof_sent = match handle.eof(channel_id).await {
        Ok(()) => {
            info!(
                repo = %owner_repo,
                ?channel_id,
                total_bytes,
                "SSH upload-pack EOF sent"
            );
            true
        }
        Err(error) => {
            warn!(
                repo = %owner_repo,
                ?channel_id,
                total_bytes,
                error = ?error,
                "SSH upload-pack EOF failed"
            );
            false
        }
    };

    let client_close_seen = if let Some(state) = channel_states.lock().await.get_mut(&channel_id) {
        state.stream_finished = true;
        state.exit_status_sent = exit_status_sent;
        state.eof_sent = eof_sent;
        state.client_close_seen
    } else {
        false
    };

    let close_reason = if client_close_seen {
        "client-close-already-seen"
    } else {
        "server-close"
    };
    let close_sent = match handle.close(channel_id).await {
        Ok(()) => {
            if let Some(state) = channel_states.lock().await.get_mut(&channel_id) {
                state.close_sent = true;
            }
            info!(
                repo = %owner_repo,
                ?channel_id,
                total_bytes,
                close_reason,
                "SSH upload-pack close sent"
            );
            true
        }
        Err(error) => {
            warn!(
                repo = %owner_repo,
                ?channel_id,
                total_bytes,
                close_reason,
                error = ?error,
                "SSH upload-pack close failed"
            );
            false
        }
    };

    info!(
        repo = %owner_repo,
        ?channel_id,
        total_bytes,
        exit_status,
        eof_sent,
        exit_status_sent,
        close_sent,
        "SSH upload-pack stream finalized"
    );
}

async fn send_channel_data_chunks(
    handle: &russh::server::Handle,
    channel_id: ChannelId,
    data: &[u8],
) -> Result<(), ()> {
    for part in data.chunks(SSH_DATA_CHUNK_SIZE) {
        handle
            .data(channel_id, part.to_vec())
            .await
            .map_err(|_| ())?;
    }

    Ok(())
}

async fn send_channel_response_data<W>(
    handle: &russh::server::Handle,
    channel_id: ChannelId,
    mut stream_writer: Option<&mut W>,
    channel_states: &Arc<Mutex<HashMap<ChannelId, UpstreamProxyChannelState>>>,
    data: &[u8],
) -> Result<(), ()>
where
    W: AsyncWrite + Unpin,
{
    let result = if let Some(stream_writer) = stream_writer.as_mut() {
        stream_writer.write_all(data).await.map_err(|_| ())
    } else {
        send_channel_data_chunks(handle, channel_id, data).await
    };

    if result.is_ok() {
        let now = Instant::now();
        if let Some(state) = channel_states.lock().await.get_mut(&channel_id) {
            state.bytes_written_to_client += data.len() as u64;
            state.last_write_completed_at = Some(now);
            if state.first_write_completed_at.is_none() {
                state.first_write_completed_at = Some(now);
            }
        }
    }

    result
}

fn spawn_channel_read_drain(mut read_half: ChannelReadHalf) {
    tokio::spawn(async move {
        while let Some(msg) = read_half.wait().await {
            if matches!(msg, ChannelMsg::Close) {
                break;
            }
        }
    });
}

async fn output_lock_for_channel(
    channel_states: &Arc<Mutex<HashMap<ChannelId, UpstreamProxyChannelState>>>,
    channel_id: ChannelId,
) -> Arc<Mutex<()>> {
    channel_states
        .lock()
        .await
        .get(&channel_id)
        .map(|state| Arc::clone(&state.output_lock))
        .unwrap_or_else(|| Arc::new(Mutex::new(())))
}

struct LocalUploadPackResponseContext {
    handle: russh::server::Handle,
    channel_states: Arc<Mutex<HashMap<ChannelId, UpstreamProxyChannelState>>>,
    channel_id: ChannelId,
    stream_channel: Option<Arc<ChannelWriteHalf<Msg>>>,
    should_close_channel: bool,
}

async fn serve_local_upload_pack_once(
    state: &AppState,
    owner_repo: &str,
    serve_from: LocalServeRepoSource,
    request_body: &[u8],
    git_protocol: Option<&str>,
    completion: CloneCompletion,
    response: LocalUploadPackResponseContext,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let LocalUploadPackResponseContext {
        handle,
        channel_states,
        channel_id,
        stream_channel,
        should_close_channel,
    } = response;

    let mut process = match spawn_local_upload_pack(
        state,
        owner_repo,
        Protocol::Ssh,
        serve_from,
        LocalUploadPackMode::StatelessRpc,
        git_protocol,
    )
    .await
    {
        Ok(process) => process,
        Err(error) => {
            error!(repo = %owner_repo, error = %error, "failed to spawn local git upload-pack");
            if should_close_channel {
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
            return;
        }
    };
    if let Some(mut stdin) = process.stdin.take()
        && let Err(error) = stdin.write_all(request_body).await
    {
        error!(repo = %owner_repo, error = %error, "failed to write buffered request to local git upload-pack");
    }

    let Some(mut stdout) = process.stdout.take() else {
        error!(repo = %owner_repo, "missing stdout from local git upload-pack");
        return;
    };
    let Some(mut stderr) = process.stderr.take() else {
        error!(repo = %owner_repo, "missing stderr from local git upload-pack");
        return;
    };
    let crate::clone_support::LocalUploadPackProcess {
        child,
        upload_pack_guard: _upload_pack_guard,
        _lease: _repo_lease,
        ..
    } = process;
    let mut child = child;

    let mut total_bytes: u64 = 0;
    let mut stream_writer = stream_channel.as_ref().map(|channel| channel.make_writer());
    let downstream_counter = state
        .metrics
        .metrics
        .clone_downstream_bytes
        .get_or_create(&CloneDownstreamBytesLabels {
            protocol: Protocol::Ssh,
            phase: ClonePhase::UploadPack,
            source: CloneSource::Local,
            username: completion.metric_username.clone(),
            repo: completion.metric_repo.clone(),
        })
        .clone();
    let _active_clone_guard =
        state.begin_active_clone(Protocol::Ssh, completion.cache_status.clone());
    let mut stdout_buf = vec![0u8; SSH_DATA_CHUNK_SIZE];
    loop {
        match stdout.read(&mut stdout_buf).await {
            Ok(0) => break,
            Ok(read) => {
                let chunk = &stdout_buf[..read];
                if send_channel_response_data(
                    &handle,
                    channel_id,
                    stream_writer.as_mut(),
                    &channel_states,
                    chunk,
                )
                .await
                .is_err()
                {
                    warn!(
                        repo = %owner_repo,
                        serve_from = %serve_from,
                        total_bytes,
                        "client disconnected during local git upload-pack response"
                    );
                    break;
                }
                total_bytes += read as u64;
                downstream_counter.inc_by(read as u64);
            }
            Err(error) => {
                error!(repo = %owner_repo, error = %error, "failed to read local git upload-pack stdout");
                break;
            }
        }
    }

    let completed_successfully =
        match wait_for_local_upload_pack_exit(&mut child, &mut stderr).await {
            Ok(exit) if !exit.status.success() => {
                warn!(
                    repo = %owner_repo,
                    serve_from = %serve_from,
                    status = %exit.status,
                    stderr = %String::from_utf8_lossy(&exit.stderr),
                    "local git upload-pack exited with non-zero status"
                );
                false
            }
            Ok(exit) => {
                info!(
                    repo = %owner_repo,
                    serve_from = %serve_from,
                    total_bytes,
                    status = %exit.status,
                    "local SSH git upload-pack completed"
                );
                true
            }
            Err(error) => {
                error!(
                    repo = %owner_repo,
                    serve_from = %serve_from,
                    error = %error,
                    "failed to wait on local git upload-pack"
                );
                false
            }
        };

    if completed_successfully {
        crate::metrics::observe_upload_pack_duration(
            &state.metrics,
            Protocol::Ssh,
            CloneSource::Local,
            &completion.metric_repo,
            completion.started_at.elapsed(),
        );
        completion.record_success(&state.metrics, Protocol::Ssh);
    }

    if should_close_channel {
        let exit_status = if completed_successfully { 0 } else { 1 };
        info!(
            repo = %owner_repo,
            serve_from = %serve_from,
            total_bytes,
            exit_status,
            "finalizing local SSH git upload-pack channel"
        );
        finalize_upload_pack_channel(
            owner_repo,
            &handle,
            &channel_states,
            channel_id,
            exit_status,
            total_bytes,
            Duration::from_secs(state.config.clone.ssh_upload_pack_close_grace_secs),
        )
        .await;
    }
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

impl std::fmt::Display for V2RequestKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LsRefs => f.write_str("ls_refs"),
            Self::Fetch => f.write_str("fetch"),
        }
    }
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

#[cfg(test)]
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
                    partial_success: false,
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
                    partial_success: false,
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
        let channel_id = channel.id();
        let (read_half, write_half) = channel.split();
        spawn_channel_read_drain(read_half);
        self.channels.insert(channel_id, Arc::new(write_half));
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
            buf.extend_from_slice(data);
            let has_done = buf.windows(9).any(|w| w == b"0009done\n");
            // Shallow/no-negotiation (protocol v1): wants followed by flush, no haves.
            // This exact request shape should POST immediately instead of
            // waiting for channel EOF, which Git does not send before reading
            // the packfile.
            let has_flush_after_wants = if self.git_protocol.as_deref() == Some("version=2") {
                false
            } else {
                is_single_round_fetch_request(buf)
            };
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
                    if kind == V2RequestKind::Fetch {
                        break;
                    }
                }
            }
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
            let stream_channel = self.channels.get(&channel_id).cloned();
            let has_fetch_request = request_batch
                .iter()
                .any(|(_, kind, _, _, _)| *kind == V2RequestKind::Fetch);
            if has_fetch_request {
                self.upstream_proxy_buf = None;
            }

            let state = Arc::clone(&self.state);
            let channel_states = Arc::clone(&self.upstream_proxy_channels);
            let capture_metadata = Arc::clone(&self.upstream_capture_metadata);
            let handle = session.handle();
            let output_lock = output_lock_for_channel(&channel_states, channel_id).await;
            let metric_username =
                crate::metrics::clone_metric_username(self.username.as_deref(), true);
            let request_span = ssh_git_request_observation(
                &state,
                request_batch
                    .first()
                    .map(|(owner_repo, _, _, _, _)| owner_repo.as_str())
                    .unwrap_or("unknown/<unknown>"),
                Some(&metric_username),
                self.fingerprint.as_deref(),
                self.git_protocol.as_deref(),
                Some(format!("ssh-channel-{channel_id:?}")),
            )
            .make_span("ssh_upload_pack", "post-upload-pack");
            tokio::spawn(
                async move {
                    for (owner_repo, request_kind, want_have, authenticated, git_protocol) in
                        request_batch
                    {
                        info!(
                            repo = %owner_repo,
                            request_kind = %request_kind,
                            want_have_bytes = want_have.len(),
                            authenticated,
                            "upstream proxy: request complete, POSTing to upstream"
                        );
                        proxy_upstream_upload_pack(
                            UpstreamUploadPackContext {
                                state: Arc::clone(&state),
                                channel_states: Arc::clone(&channel_states),
                                capture_metadata: Arc::clone(&capture_metadata),
                                handle: handle.clone(),
                                channel_id,
                                stream_channel: stream_channel.clone(),
                                output_lock: Arc::clone(&output_lock),
                            },
                            UpstreamUploadPackRequest {
                                owner_repo,
                                want_have,
                                authenticated,
                                git_protocol,
                                request_kind,
                                metric_username: metric_username.clone(),
                            },
                            UpstreamUploadPackBehavior {
                                warn_on_disconnect: true,
                                should_close_channel: request_kind == V2RequestKind::Fetch,
                                capture_for_hydration: request_kind == V2RequestKind::Fetch,
                            },
                        )
                        .await;
                    }
                }
                .instrument(request_span),
            );
        }

        if let Some((owner_repo, request_kind, want_have, authenticated, git_protocol)) =
            post_action
        {
            let stream_channel = self.channels.get(&channel_id).cloned();
            if request_kind == V2RequestKind::Fetch {
                self.upstream_proxy_buf = None;
            }
            info!(
                repo = %owner_repo,
                request_kind = %request_kind,
                want_have_bytes = want_have.len(),
                authenticated,
                "upstream proxy: request complete, POSTing to upstream"
            );
            let state = Arc::clone(&self.state);
            let channel_states = Arc::clone(&self.upstream_proxy_channels);
            let capture_metadata = Arc::clone(&self.upstream_capture_metadata);
            let handle = session.handle();
            let output_lock = output_lock_for_channel(&channel_states, channel_id).await;
            let metric_username =
                crate::metrics::clone_metric_username(self.username.as_deref(), true);
            let request_span = ssh_git_request_observation(
                &state,
                &owner_repo,
                Some(&metric_username),
                self.fingerprint.as_deref(),
                git_protocol.as_deref(),
                Some(format!("ssh-channel-{channel_id:?}")),
            )
            .make_span("ssh_upload_pack", "post-upload-pack");
            tokio::spawn(
                async move {
                    proxy_upstream_upload_pack(
                        UpstreamUploadPackContext {
                            state,
                            channel_states,
                            capture_metadata,
                            handle,
                            channel_id,
                            stream_channel,
                            output_lock,
                        },
                        UpstreamUploadPackRequest {
                            owner_repo,
                            want_have,
                            authenticated,
                            git_protocol,
                            request_kind,
                            metric_username,
                        },
                        UpstreamUploadPackBehavior {
                            warn_on_disconnect: true,
                            should_close_channel: request_kind == V2RequestKind::Fetch,
                            capture_for_hydration: request_kind == V2RequestKind::Fetch,
                        },
                    )
                    .await;
                }
                .instrument(request_span),
            );
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
            let stream_channel = self.channels.get(&channel_id).cloned();
            let state = Arc::clone(&self.state);
            let channel_states = Arc::clone(&self.upstream_proxy_channels);
            let capture_metadata = Arc::clone(&self.upstream_capture_metadata);
            let handle = session.handle();
            let output_lock = output_lock_for_channel(&channel_states, channel_id).await;
            let metric_username =
                crate::metrics::clone_metric_username(self.username.as_deref(), true);
            let request_span = ssh_git_request_observation(
                &state,
                &owner_repo,
                Some(&metric_username),
                self.fingerprint.as_deref(),
                git_protocol.as_deref(),
                Some(format!("ssh-channel-{channel_id:?}")),
            )
            .make_span("ssh_upload_pack", "channel-eof");
            tokio::spawn(
                async move {
                    proxy_upstream_upload_pack(
                        UpstreamUploadPackContext {
                            state,
                            channel_states,
                            capture_metadata,
                            handle,
                            channel_id,
                            stream_channel,
                            output_lock,
                        },
                        UpstreamUploadPackRequest {
                            owner_repo,
                            want_have,
                            authenticated,
                            git_protocol,
                            request_kind: V2RequestKind::Fetch,
                            metric_username,
                        },
                        UpstreamUploadPackBehavior {
                            warn_on_disconnect: false,
                            should_close_channel: true,
                            capture_for_hydration: true,
                        },
                    )
                    .await;
                }
                .instrument(request_span),
            );
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
            info!(
                repo = state.owner_repo.as_deref().unwrap_or("<unknown>"),
                channel = ?channel_id,
                stream_finished = state.stream_finished,
                exit_status_sent = state.exit_status_sent,
                eof_sent = state.eof_sent,
                close_sent = state.close_sent,
                client_eof_seen = state.client_eof_seen,
                "SSH client channel close observed"
            );
            if !state.stream_finished {
                warn!(
                    repo = state.owner_repo.as_deref().unwrap_or("<unknown>"),
                    channel = ?channel_id,
                    stream_finished = state.stream_finished,
                    exit_status_sent = state.exit_status_sent,
                    eof_sent = state.eof_sent,
                    close_sent = state.close_sent,
                    client_eof_seen = state.client_eof_seen,
                    client_close_seen = state.client_close_seen,
                    "SSH channel closed before forgeproxy marked upload-pack stream finished"
                );
            }
        }

        self.upstream_proxy_channels
            .lock()
            .await
            .remove(&channel_id);
        self.upstream_capture_metadata
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
                let _ = session.extended_data(
                    channel_id,
                    1,
                    &b"ERROR: Push (git-receive-pack) is not supported through the caching proxy.\n\
                      Please push directly to the upstream forge.\n"[..],
                );
                finish_channel(session, channel_id, 1);
                Ok(())
            }

            Some((GitCommand::UploadPack, repo)) => {
                // ── Path validation ──────────────────────────────────
                if repo.contains("..") || repo.contains('\0') {
                    warn!(repo = %repo, "rejected SSH exec with path traversal attempt");
                    let _ = session.extended_data(
                        channel_id,
                        1,
                        &b"ERROR: Invalid repository path.\n"[..],
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
                                let _ = session.extended_data(
                                    channel_id,
                                    1,
                                    &b"ERROR: SSH identity could not be resolved.\n"[..],
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
                                let _ = session.extended_data(
                                    channel_id,
                                    1,
                                    format!(
                                        "ERROR: Access denied to repository {owner}/{repo_name}\n"
                                    )
                                    .into_bytes(),
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
                                let _ = session.extended_data(
                                    channel_id,
                                    1,
                                    format!(
                                        "ERROR: Failed to verify access to repository {owner}/{repo_name}: {e}\n"
                                    )
                                    .into_bytes(),
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
                        let _ = session.extended_data(
                            channel_id,
                            1,
                            format!("ERROR: Invalid repository path: {repo}\n").into_bytes(),
                        );
                        finish_channel(session, channel_id, 1);
                        return Ok(());
                    }
                }

                let request_observation = ssh_git_request_observation(
                    &self.state,
                    &repo,
                    self.username.as_deref(),
                    self.fingerprint.as_deref(),
                    self.git_protocol.as_deref(),
                    Some(format!("ssh-channel-{channel_id:?}")),
                );
                let request_span = request_observation.make_span("ssh_upload_pack", "exec");
                let _request_guard = request_span.enter();

                let repo_path = self.cache_manager.repo_path(&repo);
                debug!(
                    repo = %repo,
                    path = %repo_path.display(),
                    exists = repo_path.exists(),
                    "handling git-upload-pack"
                );

                let repo_cached_locally = self.cache_manager.has_repo(&repo);
                let route_v2_through_upstream = self.git_protocol.as_deref() == Some("version=2");

                if repo_cached_locally && !route_v2_through_upstream {
                    let clone_started = Instant::now();
                    // ── Serve from local cache via bidirectional upload-pack ──
                    let Some(channel) = self.channels.get(&channel_id).cloned() else {
                        error!(repo = %repo, channel = ?channel_id, "missing SSH channel handle for cached upload-pack");
                        let _ = session.extended_data(
                            channel_id,
                            1,
                            &b"ERROR: Internal SSH channel state missing.\n"[..],
                        );
                        finish_channel(session, channel_id, 1);
                        return Ok(());
                    };

                    match spawn_local_upload_pack(
                        &self.state,
                        &repo,
                        Protocol::Ssh,
                        LocalServeRepoSource::PublishedGeneration,
                        LocalUploadPackMode::Interactive,
                        self.git_protocol.as_deref(),
                    )
                    .await
                    {
                        Ok(mut process) => {
                            // Take ownership of the child's I/O handles.
                            let stdin = process.stdin.take();
                            let stdout = process
                                .stdout
                                .take()
                                .expect("child stdout was set to piped");
                            let stderr = process
                                .stderr
                                .take()
                                .expect("child stderr was set to piped");
                            let crate::clone_support::LocalUploadPackProcess {
                                child,
                                upload_pack_guard,
                                _lease: repo_lease,
                                ..
                            } = process;
                            let mut child = child;

                            // Store stdin so the `data` and `channel_eof`
                            // callbacks can forward client data / signal EOF.
                            self.child_stdin = stdin;

                            // RFC 4254 §6.5: the client won't read channel data
                            // until it receives SSH_MSG_CHANNEL_SUCCESS for the
                            // exec request.  Send it now, before the background
                            // task starts streaming upload-pack stdout.
                            let _ = session.channel_success(channel_id);

                            // Obtain an async Handle for sending data from the
                            // background task (the sync Session methods cannot
                            // be used outside the handler call).
                            let handle = session.handle();
                            let channel_states = Arc::clone(&self.upstream_proxy_channels);
                            let repo_for_stream = repo.clone();
                            let state_for_stream = Arc::clone(&self.state);
                            let stream_channel = channel;
                            let close_grace_secs =
                                self.state.config.clone.ssh_upload_pack_close_grace_secs;
                            let metric_username = crate::metrics::clone_metric_username(
                                self.username.as_deref(),
                                true,
                            );

                            // Spawn a task that streams upload-pack stdout
                            // with explicit `Handle::data()` chunking and then
                            // finalizes the channel in RFC 4254 order.
                            tokio::spawn(async move {
                                let _upload_pack_guard = upload_pack_guard;
                                let _repo_lease = repo_lease;
                                let _active_clone_guard = state_for_stream
                                    .begin_active_clone(Protocol::Ssh, CacheStatus::Hot);
                                let mut stdout = stdout;
                                let mut stderr = stderr;
                                let mut disconnected = false;
                                let mut total_bytes: u64 = 0;
                                let mut stream_writer = stream_channel.make_writer();
                                let clone_started = clone_started;
                                let downstream_counter = state_for_stream
                                    .metrics
                                    .metrics
                                    .clone_downstream_bytes
                                    .get_or_create(&CloneDownstreamBytesLabels {
                                        protocol: Protocol::Ssh,
                                        phase: ClonePhase::UploadPack,
                                        source: CloneSource::Local,
                                        username: metric_username.clone(),
                                        repo: repo_for_stream.clone(),
                                    })
                                    .clone();

                                let mut stdout_buf = vec![0u8; SSH_DATA_CHUNK_SIZE];
                                loop {
                                    match stdout.read(&mut stdout_buf).await {
                                        Ok(0) => break,
                                        Ok(read) => {
                                            if send_channel_response_data(
                                                &handle,
                                                channel_id,
                                                Some(&mut stream_writer),
                                                &channel_states,
                                                &stdout_buf[..read],
                                            )
                                            .await
                                            .is_err()
                                            {
                                                debug!(
                                                    repo = %repo_for_stream,
                                                    ?channel_id,
                                                    total_bytes,
                                                    "error streaming upload-pack stdout to SSH channel"
                                                );
                                                disconnected = true;
                                                break;
                                            }
                                            total_bytes += read as u64;
                                            downstream_counter.inc_by(read as u64);
                                        }
                                        Err(error) => {
                                            error!(
                                                repo = %repo_for_stream,
                                                ?channel_id,
                                                total_bytes,
                                                error = %error,
                                                "failed to read local git upload-pack stdout"
                                            );
                                            disconnected = true;
                                            break;
                                        }
                                    }
                                }

                                let exit_code =
                                    match wait_for_local_upload_pack_exit(&mut child, &mut stderr)
                                        .await
                                    {
                                        Ok(exit) => {
                                            if exit.status.success() {
                                                crate::metrics::observe_upload_pack_duration(
                                                    &state_for_stream.metrics,
                                                    Protocol::Ssh,
                                                    CloneSource::Local,
                                                    &repo_for_stream,
                                                    clone_started.elapsed(),
                                                );
                                                CloneCompletion {
                                                    cache_status: CacheStatus::Hot,
                                                    started_at: clone_started,
                                                    metric_username: metric_username.clone(),
                                                    metric_repo: repo_for_stream.clone(),
                                                }
                                                .record_success(
                                                    &state_for_stream.metrics,
                                                    Protocol::Ssh,
                                                );
                                            } else if !exit.stderr.is_empty() {
                                                let msg = format!(
                                                    "git upload-pack error: {}\n",
                                                    String::from_utf8_lossy(&exit.stderr).trim(),
                                                );
                                                let _ = handle
                                                    .extended_data(channel_id, 1, msg.into_bytes())
                                                    .await;
                                            }
                                            exit.status.code().unwrap_or(1) as u32
                                        }
                                        Err(error) => {
                                            error!(
                                                repo = %repo_for_stream,
                                                ?channel_id,
                                                total_bytes,
                                                error = %error,
                                                "failed to wait on local git upload-pack"
                                            );
                                            1
                                        }
                                    };

                                // RFC 4254: exit-status → EOF → close.
                                if !disconnected {
                                    finalize_upload_pack_channel(
                                        &repo_for_stream,
                                        &handle,
                                        &channel_states,
                                        channel_id,
                                        exit_code,
                                        total_bytes,
                                        Duration::from_secs(close_grace_secs),
                                    )
                                    .await;
                                }
                            }
                            .instrument(request_span.clone()));

                            // Return immediately — the background task handles
                            // the rest of the channel lifecycle.
                        }
                        Err(e) => {
                            error!(
                                repo = %repo, error = %e,
                                "failed to spawn git upload-pack"
                            );
                            let _ = session.extended_data(
                                channel_id,
                                1,
                                format!("Failed to start git upload-pack: {e}\n").into_bytes(),
                            );
                            finish_channel(session, channel_id, 1);
                        }
                    }
                } else {
                    if route_v2_through_upstream {
                        info!(
                            repo = %repo,
                            has_local_repo = repo_cached_locally,
                            "SSH protocol v2 requires upstream ref resolution before deciding whether local disk can satisfy the fetch"
                        );
                    } else {
                        info!(
                            repo = %repo,
                            "cannot serve SSH upload-pack directly from local disk; proxying upstream"
                        );
                    }

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
                    let channel_state = UpstreamProxyChannelState {
                        owner_repo: Some(repo.clone()),
                        ..UpstreamProxyChannelState::default()
                    };
                    let output_lock = Arc::clone(&channel_state.output_lock);
                    self.upstream_proxy_channels
                        .lock()
                        .await
                        .insert(channel_id, channel_state);

                    // RFC 4254 §6.5: OpenSSH won't read channel data until it
                    // receives SSH_MSG_CHANNEL_SUCCESS.  Send it now so the
                    // client starts reading before the background task writes
                    // the ref advertisement (avoids TCP deadlock).
                    let _ = session.channel_success(channel_id);

                    let state = Arc::clone(&self.state);
                    let channel_states = Arc::clone(&self.upstream_proxy_channels);
                    let capture_metadata = Arc::clone(&self.upstream_capture_metadata);
                    let handle = session.handle();
                    let repo_bg = repo.clone();
                    let git_protocol = self.git_protocol.clone();
                    let close_grace_secs = self.state.config.clone.ssh_upload_pack_close_grace_secs;
                    let stream_channel = self.channels.get(&channel_id).cloned();
                    let metric_username =
                        crate::metrics::clone_metric_username(self.username.as_deref(), true);
                    tokio::spawn(async move {
                        match super::upstream::fetch_ref_advertisement(
                            &state,
                            &repo_bg,
                            authenticated,
                            git_protocol.as_deref(),
                            &metric_username,
                        )
                        .await
                        {
                            Ok(advert) => {
                                let _output_guard = output_lock.lock().await;
                                let mut stream_writer =
                                    stream_channel.as_ref().map(|channel| channel.make_writer());
                                capture_metadata
                                    .lock()
                                    .await
                                    .entry(channel_id)
                                    .or_default()
                                    .info_refs_advertisement = Some(advert.clone());
                                state
                                    .metrics
                                    .metrics
                                    .clone_downstream_bytes
                                    .get_or_create(&CloneDownstreamBytesLabels {
                                        protocol: Protocol::Ssh,
                                        phase: ClonePhase::InfoRefs,
                                        source: CloneSource::Upstream,
                                        username: metric_username,
                                        repo: repo_bg.clone(),
                                    })
                                    .inc_by(advert.len() as u64);
                                // Forward the initial protocol-v2 advertisement
                                // through the retained SSH channel writer so the
                                // entire session uses a single window-aware path.
                                match send_channel_response_data(
                                    &handle,
                                    channel_id,
                                    stream_writer.as_mut(),
                                    &channel_states,
                                    &advert,
                                )
                                .await
                                {
                                    Ok(()) => {}
                                    Err(_) => {
                                        warn!(repo = %repo_bg, "failed to send SSH ref advertisement")
                                    }
                                }
                            }
                            Err(e) => {
                                let _output_guard = output_lock.lock().await;
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
                                let _ = handle.extended_data(channel_id, 1, msg.into_bytes()).await;
                                finalize_upload_pack_channel(
                                    &repo_bg,
                                    &handle,
                                    &channel_states,
                                    channel_id,
                                    1,
                                    0,
                                    Duration::from_secs(close_grace_secs),
                                )
                                .await;
                            }
                        }
                    }
                    .instrument(request_span.clone()));
                }

                Ok(())
            }

            None => {
                warn!(command = %raw_cmd, "unrecognised SSH exec command");
                let _ = session.extended_data(
                    channel_id,
                    1,
                    &b"ERROR: Unknown command. Only git-upload-pack is supported.\n"[..],
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
    context: UpstreamUploadPackContext,
    request: UpstreamUploadPackRequest,
    behavior: UpstreamUploadPackBehavior,
) {
    let UpstreamUploadPackContext {
        state,
        channel_states,
        capture_metadata,
        handle,
        channel_id,
        stream_channel,
        output_lock,
    } = context;
    let UpstreamUploadPackRequest {
        owner_repo,
        want_have,
        authenticated,
        git_protocol,
        request_kind,
        metric_username,
    } = request;
    let _output_guard = output_lock.lock().await;
    let mut fetch_started_at = None;
    let mut fetch_cache_status = None;
    if request_kind == V2RequestKind::Fetch {
        fetch_started_at = Some(Instant::now());
        let wants = crate::tee_hydration::parse_fetch_request_metadata(&want_have)
            .map(|meta| meta.want_oids)
            .unwrap_or_default();
        let want_sample = wants
            .iter()
            .take(5)
            .map(|want| want.chars().take(12).collect::<String>())
            .collect::<Vec<String>>()
            .join(",");
        let advertised_refs = capture_metadata.lock().await.get(&channel_id).cloned();
        let auth_header = if authenticated {
            build_clone_auth_header_for_repo(&state, &owner_repo).await
        } else {
            None
        };
        let local_decision = crate::coordination::registry::resolve_local_fetch_serveability(
            &state,
            &owner_repo,
            &wants,
            auth_header.as_deref(),
            advertised_refs.as_ref(),
            "ssh",
            true,
        )
        .await;
        fetch_cache_status = Some(crate::coordination::registry::clone_cache_status(
            &local_decision,
        ));
        match &local_decision {
            LocalServeDecision::SatisfiesWants {
                serve_from,
                restored_from_s3_for_request,
                want_count,
                ..
            } => {
                info!(
                    repo = %owner_repo,
                    serve_from = %serve_from,
                    wants = *want_count,
                    want_sample,
                    restored_from_s3_for_request = *restored_from_s3_for_request,
                    "serving SSH fetch directly from local disk after want resolution"
                );
                serve_local_upload_pack_once(
                    &state,
                    &owner_repo,
                    *serve_from,
                    &want_have,
                    git_protocol.as_deref(),
                    CloneCompletion {
                        cache_status: crate::coordination::registry::clone_cache_status(
                            &local_decision,
                        ),
                        started_at: fetch_started_at
                            .expect("fetch start time must be set for fetch requests"),
                        metric_username: metric_username.clone(),
                        metric_repo: owner_repo.clone(),
                    },
                    LocalUploadPackResponseContext {
                        handle: handle.clone(),
                        channel_states: Arc::clone(&channel_states),
                        channel_id,
                        stream_channel,
                        should_close_channel: behavior.should_close_channel,
                    },
                )
                .await;
                return;
            }
            LocalServeDecision::Unavailable {
                had_local_repo_before_check,
                restored_from_s3_for_request,
            } => {
                info!(
                    repo = %owner_repo,
                    wants = wants.len(),
                    want_sample,
                    had_local_repo_before_check = *had_local_repo_before_check,
                    restored_from_s3_for_request = *restored_from_s3_for_request,
                    "cannot serve SSH fetch from local disk; no local published repo or request-time S3 restore is available"
                );
            }
            LocalServeDecision::MissingWantedObjects {
                had_local_repo_before_check,
                restored_from_s3_for_request,
                want_count,
                missing_wants,
            } => {
                let missing_sample = missing_wants
                    .iter()
                    .take(5)
                    .map(|want| want.chars().take(12).collect::<String>())
                    .collect::<Vec<String>>()
                    .join(",");
                info!(
                    repo = %owner_repo,
                    wants = *want_count,
                    missing_wants = missing_wants.len(),
                    want_sample,
                    missing_sample,
                    had_local_repo_before_check = *had_local_repo_before_check,
                    restored_from_s3_for_request = *restored_from_s3_for_request,
                    "local disk can only partially satisfy SSH fetch; proxying upstream for missing objects or completeness"
                );
            }
        }
    }

    let stream_channel = stream_channel;
    let mut stream_writer = stream_channel.as_ref().map(|channel| channel.make_writer());
    match super::upstream::post_upload_pack_stream(
        &state,
        &owner_repo,
        &want_have,
        authenticated,
        git_protocol.as_deref(),
        &metric_username,
    )
    .await
    {
        Ok(stream) => {
            use futures::Stream;
            use std::pin::Pin;
            let mut stream = Pin::new(Box::new(stream));
            let mut total_bytes: u64 = 0;
            let upstream_counter = state
                .metrics
                .metrics
                .clone_upstream_bytes
                .get_or_create(&CloneUpstreamBytesLabels {
                    protocol: Protocol::Ssh,
                    phase: ClonePhase::UploadPack,
                    username: metric_username.clone(),
                    repo: owner_repo.clone(),
                })
                .clone();
            let downstream_counter = state
                .metrics
                .metrics
                .clone_downstream_bytes
                .get_or_create(&CloneDownstreamBytesLabels {
                    protocol: Protocol::Ssh,
                    phase: ClonePhase::UploadPack,
                    source: CloneSource::Upstream,
                    username: metric_username.clone(),
                    repo: owner_repo.clone(),
                })
                .clone();
            let mut had_error = false;
            let mut response_buf = Vec::new();
            let auth_header = if authenticated {
                build_clone_auth_header_for_repo(&state, &owner_repo).await
            } else {
                None
            };
            let advertised_refs = capture_metadata.lock().await.get(&channel_id).cloned();
            let (owner, repo) =
                super::upstream::split_owner_repo(&owner_repo).unwrap_or((&owner_repo, ""));
            let mut hydration = UpstreamHydrationTracker::start(
                &state,
                owner,
                repo,
                auth_header.as_deref(),
                "ssh",
                UpstreamHydrationRequest {
                    advertised_refs: advertised_refs.as_ref(),
                    request_body: &want_have,
                    enable_hydration: behavior.capture_for_hydration,
                },
            )
            .await;
            let _active_clone_guard = if request_kind == V2RequestKind::Fetch {
                fetch_cache_status
                    .clone()
                    .map(|cache_status| state.begin_active_clone(Protocol::Ssh, cache_status))
            } else {
                None
            };
            while let Some(chunk_result) =
                std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await
            {
                match chunk_result {
                    Ok(chunk) => {
                        let chunk_len = chunk.len() as u64;
                        upstream_counter.inc_by(chunk_len);
                        if request_kind == V2RequestKind::LsRefs {
                            response_buf.extend_from_slice(&chunk);
                        }
                        hydration.record_response_chunk(chunk.clone()).await;
                        if send_channel_response_data(
                            &handle,
                            channel_id,
                            stream_writer.as_mut(),
                            &channel_states,
                            &chunk,
                        )
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
                        total_bytes += chunk_len;
                        downstream_counter.inc_by(chunk_len);
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
            if !had_error && request_kind == V2RequestKind::LsRefs {
                let mut metadata = capture_metadata.lock().await;
                let entry = metadata.entry(channel_id).or_default();
                entry.ls_refs_request = Some(want_have.clone());
                entry.ls_refs_response = Some(response_buf);
            }
            if had_error {
                hydration.handle_stream_error().await;
                if behavior.should_close_channel {
                    finalize_upload_pack_channel(
                        &owner_repo,
                        &handle,
                        &channel_states,
                        channel_id,
                        1,
                        total_bytes,
                        Duration::from_secs(state.config.clone.ssh_upload_pack_close_grace_secs),
                    )
                    .await;
                }
            } else {
                info!(
                    repo = %owner_repo,
                    total_bytes,
                    "upstream proxy pack stream complete"
                );
                if request_kind == V2RequestKind::Fetch
                    && let (Some(cache_status), Some(started_at)) =
                        (fetch_cache_status.clone(), fetch_started_at)
                {
                    crate::metrics::observe_upload_pack_duration(
                        &state.metrics,
                        Protocol::Ssh,
                        CloneSource::Upstream,
                        &owner_repo,
                        started_at.elapsed(),
                    );
                    CloneCompletion {
                        cache_status,
                        started_at,
                        metric_username: metric_username.clone(),
                        metric_repo: owner_repo.clone(),
                    }
                    .record_success(&state.metrics, Protocol::Ssh);
                }
                hydration.finish().await;
                if behavior.should_close_channel {
                    finalize_upload_pack_channel(
                        &owner_repo,
                        &handle,
                        &channel_states,
                        channel_id,
                        0,
                        total_bytes,
                        Duration::from_secs(state.config.clone.ssh_upload_pack_close_grace_secs),
                    )
                    .await;
                }
            }
        }
        Err(e) => {
            let wants = if request_kind == V2RequestKind::Fetch {
                crate::tee_hydration::parse_fetch_request_metadata(&want_have)
                    .map(|meta| meta.want_oids)
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            let want_sample = wants
                .iter()
                .take(5)
                .map(|want| want.chars().take(12).collect::<String>())
                .collect::<Vec<String>>()
                .join(",");
            error!(
                repo = %owner_repo,
                request_kind = %request_kind,
                wants = wants.len(),
                want_sample,
                error = %format!("{e:#}"),
                "cannot satisfy SSH upload-pack request from local disk and upstream upload-pack failed"
            );
            let msg = format!(
                "Repository '{}' upstream proxy failed: {}\n\
                 Try cloning directly from the upstream forge.\n",
                owner_repo, e,
            );
            let _ = handle.extended_data(channel_id, 1, msg.into_bytes()).await;
            if behavior.should_close_channel {
                finalize_upload_pack_channel(
                    &owner_repo,
                    &handle,
                    &channel_states,
                    channel_id,
                    1,
                    0,
                    Duration::from_secs(state.config.clone.ssh_upload_pack_close_grace_secs),
                )
                .await;
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
    fn v2_request_kind_display_uses_lowercase_labels() {
        assert_eq!(V2RequestKind::LsRefs.to_string(), "ls_refs");
        assert_eq!(V2RequestKind::Fetch.to_string(), "fetch");
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
        let keypair = russh::keys::PrivateKey::random(
            &mut russh::keys::ssh_key::rand_core::OsRng,
            russh::keys::Algorithm::Ed25519,
        )
        .unwrap();
        let pubkey = keypair.public_key().clone();
        let fp = fingerprint_of(&pubkey);
        assert!(
            fp.starts_with("SHA256:"),
            "fingerprint should start with SHA256: prefix, got: {fp}"
        );
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let keypair = russh::keys::PrivateKey::random(
            &mut russh::keys::ssh_key::rand_core::OsRng,
            russh::keys::Algorithm::Ed25519,
        )
        .unwrap();
        let pubkey = keypair.public_key().clone();
        let fp1 = fingerprint_of(&pubkey);
        let fp2 = fingerprint_of(&pubkey);
        assert_eq!(
            fp1, fp2,
            "fingerprint should be deterministic for the same key"
        );
    }

    #[test]
    fn fingerprint_has_correct_length() {
        let keypair = russh::keys::PrivateKey::random(
            &mut russh::keys::ssh_key::rand_core::OsRng,
            russh::keys::Algorithm::Ed25519,
        )
        .unwrap();
        let pubkey = keypair.public_key().clone();
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
