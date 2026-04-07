use std::time::Instant;

use anyhow::{Context, Result};
use bytes::Bytes;
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tracing::{info, warn};

use crate::AppState;
use crate::coordination::registry::{
    CloneHydrationPermits, LocalServeRepoLease, LocalServeRepoSource, RequestAdvertisedRefs,
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

pub struct LocalUploadPackProcess {
    pub child: Child,
    pub stdin: Option<ChildStdin>,
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,
    pub _lease: LocalServeRepoLease,
}

pub async fn spawn_local_upload_pack(
    state: &AppState,
    owner_repo: &str,
    protocol_name: &'static str,
    serve_from: LocalServeRepoSource,
    mode: LocalUploadPackMode,
    git_protocol: Option<&str>,
) -> Result<LocalUploadPackProcess> {
    let repo_lease = crate::coordination::registry::acquire_local_serve_repo_lease(
        state, owner_repo, serve_from,
    )
    .await?;
    let repo_path = repo_lease.repo_path().to_path_buf();

    let mut cmd = Command::new("git");
    cmd.arg("upload-pack");
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

    info!(
        repo = %owner_repo,
        protocol = protocol_name,
        serve_from = ?serve_from,
        mode = ?mode,
        path = %repo_path.display(),
        "serving upload-pack directly from local disk"
    );

    Ok(LocalUploadPackProcess {
        stdin: child.stdin.take(),
        stdout: child.stdout.take(),
        stderr: child.stderr.take(),
        child,
        _lease: repo_lease,
    })
}

pub struct LocalUploadPackExit {
    pub status: std::process::ExitStatus,
    pub stderr: Vec<u8>,
}

pub async fn wait_for_local_upload_pack_exit(
    child: &mut Child,
    stderr: &mut ChildStderr,
) -> std::io::Result<LocalUploadPackExit> {
    use tokio::io::AsyncReadExt;

    let mut stderr_buf = Vec::new();
    let _ = stderr.read_to_end(&mut stderr_buf).await;
    let status = child.wait().await?;
    Ok(LocalUploadPackExit {
        status,
        stderr: stderr_buf,
    })
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
    hydration_permits: Option<CloneHydrationPermits>,
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
        let owner_repo = format!("{owner}/{repo}");
        let mut hydration_permits = if request.enable_hydration {
            match crate::coordination::registry::try_acquire_clone_hydration_permits(
                state,
                &owner_repo,
            )
            .await
            {
                Ok(Some(permits)) => Some(permits),
                Ok(None) => {
                    info!(
                        repo = %owner_repo,
                        protocol = protocol_name,
                        per_instance_limit = state.config.clone.max_concurrent_upstream_clones_per_repo_per_instance,
                        cross_instance_limit = state.config.clone.max_concurrent_upstream_clones_per_repo_across_instances,
                        lease_ttl_secs = state.config.clone.lock_ttl,
                        "skipping tee hydration because the repo clone semaphore is saturated"
                    );
                    None
                }
                Err(error) => {
                    warn!(
                        repo = %owner_repo,
                        protocol = protocol_name,
                        error = %error,
                        "failed to acquire clone hydration permits for upstream miss"
                    );
                    None
                }
            }
        } else {
            None
        };

        let capture = if request.enable_hydration && hydration_permits.is_some() {
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

        if capture.is_none()
            && let Some(permits) = hydration_permits.take()
            && let Err(error) =
                crate::coordination::registry::release_clone_hydration_permits(state, permits).await
        {
            warn!(
                repo = %owner_repo,
                protocol = protocol_name,
                error = %error,
                "failed to release clone hydration permits after tee capture setup failure"
            );
        }

        Self {
            state: state.clone(),
            owner: owner.to_string(),
            repo: repo.to_string(),
            owner_repo,
            auth_header: auth_header.map(ToOwned::to_owned),
            protocol_name,
            capture: capture.map(crate::tee_hydration::BufferedTeeCapture::new),
            hydration_permits,
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
        if let Some(permits) = self.hydration_permits.take()
            && let Err(error) =
                crate::coordination::registry::release_clone_hydration_permits(&self.state, permits)
                    .await
        {
            warn!(
                repo = %self.owner_repo,
                protocol = self.protocol_name,
                error = %error,
                "failed to release clone hydration permits after proxy error"
            );
        }
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
                    if let Some(permits) = self.hydration_permits.take() {
                        tokio::spawn(async move {
                            if let Err(error) =
                                crate::coordination::registry::try_ensure_repo_cloned_from_tee_with_permits(
                                    &state,
                                    &owner_bg,
                                    &repo_bg,
                                    auth_bg.as_deref(),
                                    capture_dir,
                                    permits,
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
                    } else {
                        tokio::spawn(async move {
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
                }
                Ok(None) => {
                    if let Some(permits) = self.hydration_permits.take()
                        && let Err(error) =
                            crate::coordination::registry::release_clone_hydration_permits(
                                &self.state,
                                permits,
                            )
                            .await
                    {
                        warn!(
                            repo = %self.owner_repo,
                            protocol = self.protocol_name,
                            error = %error,
                            "failed to release clone hydration permits after dropping tee capture"
                        );
                    }
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
                    if let Some(permits) = self.hydration_permits.take()
                        && let Err(release_error) =
                            crate::coordination::registry::release_clone_hydration_permits(
                                &self.state,
                                permits,
                            )
                            .await
                    {
                        warn!(
                            repo = %self.owner_repo,
                            protocol = self.protocol_name,
                            error = %release_error,
                            "failed to release clone hydration permits after tee finalization failure"
                        );
                    }
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
            if let Some(permits) = self.hydration_permits.take()
                && let Err(error) = crate::coordination::registry::release_clone_hydration_permits(
                    &self.state,
                    permits,
                )
                .await
            {
                warn!(
                    repo = %owner_repo_bg,
                    protocol = self.protocol_name,
                    error = %error,
                    "failed to release clone hydration permits after miss completed without capture"
                );
            }
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
