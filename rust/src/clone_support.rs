use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};
use tracing::{info, warn};

use crate::AppState;
use crate::coordination::registry::{
    LocalServeRepoLease, LocalServeRepoSource, RequestAdvertisedRefs, TeeCapturePermits,
};
use crate::metrics::{CacheStatus, MetricsRegistry, Protocol};

#[derive(Clone)]
pub struct CloneCompletion {
    pub cache_status: CacheStatus,
    pub started_at: Instant,
    pub metric_username: String,
    pub metric_repo: String,
}

impl CloneCompletion {
    pub fn record_success(&self, metrics: &MetricsRegistry, protocol: Protocol) {
        crate::metrics::record_clone_completion(
            metrics,
            protocol,
            self.cache_status.clone(),
            &self.metric_username,
            &self.metric_repo,
            self.started_at.elapsed(),
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalUploadPackMode {
    StatelessRpc,
    Interactive,
}

impl std::fmt::Display for LocalUploadPackMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StatelessRpc => f.write_str("stateless_rpc"),
            Self::Interactive => f.write_str("interactive"),
        }
    }
}

pub struct LocalUploadPackProcess {
    pub child: Child,
    pub stdin: Option<ChildStdin>,
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,
    pub upload_pack_guard: crate::metrics::UploadPackGuard,
    pub _global_upload_pack_permit: OwnedSemaphorePermit,
    pub _repo_upload_pack_permit: OwnedSemaphorePermit,
    pub _lease: LocalServeRepoLease,
}

pub async fn spawn_local_upload_pack_timeout(
    state: &AppState,
    owner_repo: &str,
    protocol: Protocol,
    serve_from: LocalServeRepoSource,
    mode: LocalUploadPackMode,
    git_protocol: Option<&str>,
    permit_timeout: Option<Duration>,
) -> Result<Option<LocalUploadPackProcess>> {
    let permit_wait_started = Instant::now();
    let repo_lease = crate::coordination::registry::acquire_local_serve_repo_lease_with_timeout(
        state,
        owner_repo,
        serve_from,
        permit_timeout,
    )
    .await?;
    let Some(repo_lease) = repo_lease else {
        return Ok(None);
    };
    let remaining_timeout =
        permit_timeout.map(|timeout| timeout.saturating_sub(permit_wait_started.elapsed()));

    spawn_local_upload_pack_with_lease_timeout(
        state,
        owner_repo,
        protocol,
        serve_from,
        repo_lease,
        mode,
        git_protocol,
        remaining_timeout,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn spawn_local_upload_pack_with_lease_timeout(
    state: &AppState,
    owner_repo: &str,
    protocol: Protocol,
    serve_from: LocalServeRepoSource,
    repo_lease: LocalServeRepoLease,
    mode: LocalUploadPackMode,
    git_protocol: Option<&str>,
    permit_timeout: Option<Duration>,
) -> Result<Option<LocalUploadPackProcess>> {
    let permit_wait_started = Instant::now();
    let repo_upload_pack_permit =
        acquire_local_repo_upload_pack_permit(state, owner_repo, permit_timeout).await?;
    let Some(repo_upload_pack_permit) = repo_upload_pack_permit else {
        return Ok(None);
    };
    let remaining_timeout =
        permit_timeout.map(|timeout| timeout.saturating_sub(permit_wait_started.elapsed()));
    let global_upload_pack_permit = acquire_owned_permit_with_timeout(
        state.local_upload_pack_semaphore.clone(),
        remaining_timeout,
        "local upload-pack semaphore closed",
    )
    .await?;
    let Some(global_upload_pack_permit) = global_upload_pack_permit else {
        return Ok(None);
    };
    let repo_path = repo_lease.repo_path().to_path_buf();

    let pack_threads = state.config().clone.local_upload_pack_threads;
    let mut cmd = Command::new("git");
    cmd.arg("-c")
        .arg(format!("pack.threads={pack_threads}"))
        .arg("upload-pack");
    if mode == LocalUploadPackMode::StatelessRpc {
        cmd.arg("--stateless-rpc");
    }
    cmd.arg("--strict")
        .arg(&repo_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(proto) = git_protocol {
        cmd.env("GIT_PROTOCOL", proto);
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn local git upload-pack for {owner_repo}"))?;
    let upload_pack_guard = state.begin_upload_pack(protocol.clone());
    let protocol_name = match protocol {
        Protocol::Https => "http",
        Protocol::Ssh => "ssh",
    };

    info!(
        repo = %owner_repo,
        protocol = protocol_name,
        serve_from = %serve_from,
        mode = %mode,
        pack_threads,
        path = %repo_path.display(),
        "serving upload-pack directly from local disk"
    );

    Ok(Some(LocalUploadPackProcess {
        stdin: child.stdin.take(),
        stdout: child.stdout.take(),
        stderr: child.stderr.take(),
        child,
        upload_pack_guard,
        _global_upload_pack_permit: global_upload_pack_permit,
        _repo_upload_pack_permit: repo_upload_pack_permit,
        _lease: repo_lease,
    }))
}

async fn acquire_local_repo_upload_pack_permit(
    state: &AppState,
    owner_repo: &str,
    timeout: Option<Duration>,
) -> Result<Option<OwnedSemaphorePermit>> {
    let semaphore = {
        let mut semaphores = state.repo_upload_pack_semaphores.lock().await;
        semaphores
            .entry(owner_repo.to_string())
            .or_insert_with(|| {
                std::sync::Arc::new(tokio::sync::Semaphore::new(
                    state
                        .config()
                        .clone
                        .max_concurrent_local_upload_packs_per_repo,
                ))
            })
            .clone()
    };

    acquire_owned_permit_with_timeout(semaphore, timeout, "repo upload-pack semaphore closed").await
}

async fn acquire_owned_permit_with_timeout(
    semaphore: Arc<Semaphore>,
    timeout: Option<Duration>,
    closed_message: &'static str,
) -> Result<Option<OwnedSemaphorePermit>> {
    if timeout == Some(Duration::ZERO) {
        return match semaphore.try_acquire_owned() {
            Ok(permit) => Ok(Some(permit)),
            Err(TryAcquireError::NoPermits) => Ok(None),
            Err(TryAcquireError::Closed) => Err(anyhow::anyhow!(closed_message)),
        };
    }

    let acquire = semaphore.acquire_owned();
    match timeout {
        Some(timeout) => match tokio::time::timeout(timeout, acquire).await {
            Ok(Ok(permit)) => Ok(Some(permit)),
            Ok(Err(_)) => Err(anyhow::anyhow!(closed_message)),
            Err(_) => Ok(None),
        },
        None => acquire
            .await
            .map(Some)
            .map_err(|_| anyhow::anyhow!(closed_message)),
    }
}

pub struct LocalUploadPackExit {
    pub status: std::process::ExitStatus,
    pub stderr: Vec<u8>,
    pub cpu_seconds: f64,
}

pub async fn wait_for_local_upload_pack_exit(
    child: &mut Child,
    stderr: &mut ChildStderr,
) -> std::io::Result<LocalUploadPackExit> {
    use tokio::io::AsyncReadExt;

    let mut stderr_buf = Vec::new();
    let _ = stderr.read_to_end(&mut stderr_buf).await;
    let cpu_seconds = child
        .id()
        .and_then(read_linux_process_cpu_seconds)
        .unwrap_or_default();
    let status = child.wait().await?;
    Ok(LocalUploadPackExit {
        status,
        stderr: stderr_buf,
        cpu_seconds,
    })
}

fn read_linux_process_cpu_seconds(pid: u32) -> Option<f64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(") ")?.1;
    let fields = after_comm.split_whitespace().collect::<Vec<_>>();
    let utime = fields.get(11)?.parse::<u64>().ok()?;
    let stime = fields.get(12)?.parse::<u64>().ok()?;
    Some((utime + stime) as f64 / linux_clock_ticks_per_second())
}

fn linux_clock_ticks_per_second() -> f64 {
    std::process::Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|stdout| stdout.trim().parse::<f64>().ok())
        .filter(|ticks| *ticks > 0.0)
        .unwrap_or(100.0)
}

async fn seed_tee_capture(
    capture: &crate::tee_hydration::TeeCapture,
    advertised_refs: Option<&RequestAdvertisedRefs>,
) -> Result<()> {
    let Some(advertised_refs) = advertised_refs else {
        return Ok(());
    };

    if let Some(info_refs_advertisement) = advertised_refs.info_refs_advertisement.as_deref() {
        capture
            .write_info_refs_advertisement(info_refs_advertisement)
            .await?;
    }
    if let Some(ls_refs_request) = advertised_refs.ls_refs_request.as_deref() {
        capture.write_ls_refs_request(ls_refs_request).await?;
    }
    if let Some(ls_refs_response) = advertised_refs.ls_refs_response.as_deref() {
        capture.write_ls_refs_response(ls_refs_response).await?;
    }

    Ok(())
}

pub struct UpstreamHydrationTracker {
    state: AppState,
    owner: String,
    repo: String,
    owner_repo: String,
    auth_header: Option<String>,
    protocol_name: &'static str,
    capture: Option<crate::tee_hydration::BufferedTeeCapture>,
    tee_capture_permits: Option<TeeCapturePermits>,
    enable_hydration: bool,
}

pub struct UpstreamHydrationRequest<'a> {
    pub advertised_refs: Option<&'a RequestAdvertisedRefs>,
    pub request_body: &'a [u8],
    pub enable_hydration: bool,
}

impl UpstreamHydrationTracker {
    pub async fn start(
        state: &AppState,
        owner: &str,
        repo: &str,
        auth_header: Option<&str>,
        protocol_name: &'static str,
        request: UpstreamHydrationRequest<'_>,
    ) -> Self {
        let owner_repo = crate::repo_identity::canonical_owner_repo(owner, repo);
        let tee_capture_permits = if request.enable_hydration {
            match crate::coordination::registry::try_acquire_tee_capture_permits(state, &owner_repo)
                .await
            {
                Ok(Some(permits)) => Some(permits),
                Ok(None) => {
                    crate::metrics::inc_hydration_skipped(
                        &state.metrics,
                        crate::metrics::HydrationSkipReason::SemaphoreSaturated,
                    );
                    info!(
                        repo = %owner_repo,
                        protocol = protocol_name,
                        host_limit = state.config().clone.max_concurrent_tee_captures,
                        per_repo_host_limit = state.config().clone.max_concurrent_tee_captures_per_repo_per_instance,
                        "skipping tee hydration because the tee capture semaphore is saturated"
                    );
                    None
                }
                Err(error) => {
                    warn!(
                        repo = %owner_repo,
                        protocol = protocol_name,
                        error = %error,
                        "failed to acquire tee capture permits for upstream miss"
                    );
                    None
                }
            }
        } else {
            None
        };

        let capture = if request.enable_hydration && tee_capture_permits.is_some() {
            match crate::tee_hydration::TeeCapture::start(
                &state.cache_manager.base_path,
                &owner_repo,
                protocol_name,
            )
            .await
            {
                Ok(mut capture) => {
                    let seeded = seed_tee_capture(&capture, request.advertised_refs).await;
                    let wrote_request = capture.write_request(request.request_body).await;
                    match (seeded, wrote_request) {
                        (Ok(()), Ok(())) => Some(capture),
                        (seed_result, request_result) => {
                            if let Err(error) = seed_result {
                                warn!(
                                    repo = %owner_repo,
                                    protocol = protocol_name,
                                    error = %error,
                                    "failed to seed upstream tee capture with advertised refs"
                                );
                            }
                            if let Err(error) = request_result {
                                warn!(
                                    repo = %owner_repo,
                                    protocol = protocol_name,
                                    error = %error,
                                    "failed to record tee request"
                                );
                            }
                            if capture.dir().exists()
                                && let Err(cleanup_error) =
                                    tokio::fs::remove_dir_all(capture.dir()).await
                            {
                                warn!(
                                    repo = %owner_repo,
                                    protocol = protocol_name,
                                    error = %cleanup_error,
                                    "failed to clean up incomplete tee capture"
                                );
                            }
                            None
                        }
                    }
                }
                Err(error) => {
                    warn!(
                        repo = %owner_repo,
                        protocol = protocol_name,
                        error = %error,
                        "failed to start tee capture for upstream miss"
                    );
                    None
                }
            }
        } else {
            None
        };

        Self {
            state: state.clone(),
            owner: owner.to_string(),
            repo: repo.to_string(),
            owner_repo,
            auth_header: auth_header.map(ToOwned::to_owned),
            protocol_name,
            capture: capture.map(crate::tee_hydration::BufferedTeeCapture::new),
            tee_capture_permits,
            enable_hydration: request.enable_hydration,
        }
    }

    pub async fn record_response_chunk(&mut self, chunk: Bytes) {
        if let Some(mut active_capture) = self.capture.take() {
            if let Err(error) = active_capture.try_write_response_chunk(chunk) {
                warn!(
                    repo = %self.owner_repo,
                    protocol = self.protocol_name,
                    error = %error,
                    buffer_bytes = crate::tee_hydration::CAPTURE_BUFFER_BYTES,
                    "dropping tee capture because disk capture fell behind the client stream"
                );
                if let Err(cleanup_error) = active_capture.abort().await {
                    warn!(
                        repo = %self.owner_repo,
                        protocol = self.protocol_name,
                        error = %cleanup_error,
                        "failed to clean up aborted tee capture"
                    );
                }
            } else {
                self.capture = Some(active_capture);
            }
        }
    }

    pub async fn handle_stream_error(&mut self) {
        if let Some(active_capture) = self.capture.take()
            && let Err(cleanup_error) = active_capture.abort().await
        {
            warn!(
                repo = %self.owner_repo,
                protocol = self.protocol_name,
                error = %cleanup_error,
                "failed to clean up aborted tee capture after proxy error"
            );
        }
        self.tee_capture_permits.take();
    }

    pub async fn finish(mut self) {
        if !self.enable_hydration {
            return;
        }

        let state = self.state.clone();
        let owner_bg = self.owner.clone();
        let repo_bg = self.repo.clone();
        let owner_repo_bg = self.owner_repo.clone();
        let auth_bg = self.auth_header.clone();
        let protocol_name = self.protocol_name;

        if let Some(active_capture) = self.capture.take() {
            match active_capture.finish_success().await {
                Ok(Some(capture_dir)) => {
                    let tee_capture_permits = self.tee_capture_permits.take();
                    tokio::spawn(async move {
                        let _tee_capture_permits = tee_capture_permits;
                        if let Err(error) =
                            crate::coordination::registry::try_ensure_repo_cloned_from_tee(
                                &state,
                                &owner_bg,
                                &repo_bg,
                                auth_bg.as_deref(),
                                capture_dir,
                            )
                            .await
                        {
                            warn!(
                                repo = %owner_repo_bg,
                                protocol = protocol_name,
                                error = %error,
                                "tee hydration after upstream miss failed"
                            );
                        }
                    });
                }
                Ok(None) => {
                    self.tee_capture_permits.take();
                    spawn_background_upstream_hydration(
                        state,
                        owner_bg,
                        repo_bg,
                        owner_repo_bg,
                        auth_bg,
                        protocol_name,
                        "background upstream hydration after miss completed without tee capture failed",
                    );
                }
                Err(error) => {
                    warn!(
                        repo = %self.owner_repo,
                        protocol = self.protocol_name,
                        error = %error,
                        "failed to finalize buffered tee capture"
                    );
                    self.tee_capture_permits.take();
                    spawn_background_upstream_hydration(
                        state,
                        owner_bg,
                        repo_bg,
                        owner_repo_bg,
                        auth_bg,
                        protocol_name,
                        "background upstream hydration after tee finalization failure failed",
                    );
                }
            }
        } else {
            spawn_background_upstream_hydration(
                state,
                owner_bg,
                repo_bg,
                owner_repo_bg.clone(),
                auth_bg,
                protocol_name,
                "background upstream hydration after miss completed without capture failed",
            );
            self.tee_capture_permits.take();
        }
    }
}

fn spawn_background_upstream_hydration(
    state: AppState,
    owner: String,
    repo: String,
    owner_repo: String,
    auth_header: Option<String>,
    protocol_name: &'static str,
    error_message: &'static str,
) {
    tokio::spawn(async move {
        if let Err(error) = crate::coordination::registry::ensure_repo_cloned_from_upstream(
            &state,
            &owner,
            &repo,
            auth_header.as_deref(),
        )
        .await
        {
            warn!(
                repo = %owner_repo,
                protocol = protocol_name,
                error = %error,
                error_chain = %format!("{error:#}"),
                "{error_message}"
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::Semaphore;

    use super::{LocalUploadPackMode, acquire_owned_permit_with_timeout};

    #[test]
    fn local_upload_pack_mode_display_uses_lowercase_labels() {
        assert_eq!(
            LocalUploadPackMode::StatelessRpc.to_string(),
            "stateless_rpc"
        );
        assert_eq!(LocalUploadPackMode::Interactive.to_string(), "interactive");
    }

    #[tokio::test]
    async fn upload_pack_permit_zero_timeout_returns_none_when_saturated() {
        let semaphore = Arc::new(Semaphore::new(1));
        let _held = semaphore.clone().acquire_owned().await.unwrap();

        let permit = acquire_owned_permit_with_timeout(
            semaphore,
            Some(Duration::ZERO),
            "test semaphore closed",
        )
        .await
        .unwrap();

        assert!(permit.is_none());
    }

    #[tokio::test]
    async fn upload_pack_permit_zero_timeout_uses_available_permit() {
        let semaphore = Arc::new(Semaphore::new(1));

        let permit = acquire_owned_permit_with_timeout(
            semaphore.clone(),
            Some(Duration::ZERO),
            "test semaphore closed",
        )
        .await
        .unwrap();

        assert!(permit.is_some());
        assert_eq!(semaphore.available_permits(), 0);
    }
}
