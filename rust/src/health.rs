use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use chrono::{DateTime, NaiveDateTime, Utc};
use reqwest::header::HeaderMap;
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};

use crate::config::{BackendType, Config};

const GITHUB_TOKEN_EXPIRATION_HEADER: &str = "github-authentication-token-expiration";
const GITHUB_TOKEN_EXPIRATION_FORMAT: &str = "%Y-%m-%d %H:%M:%S UTC";
const HEALTH_WORKER_RESPONSE_TIMEOUT_MIN_SLACK_SECS: u64 = 5;
const HEALTH_WORKER_RESPONSE_TIMEOUT_DIVISOR: u64 = 2;

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: HealthStatus,
    pub version: String,
    pub git_revision: String,
    pub instance_id: String,
    pub checks: HealthChecks,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Ok,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Serialize)]
pub struct HealthChecks {
    pub valkey: CheckResult,
    pub ghe: CheckResult,
    pub disk: CheckResult,
    pub prewarm: CheckResult,
}

#[derive(Debug, Serialize)]
pub struct CheckResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl CheckResult {
    fn healthy() -> Self {
        Self {
            ok: true,
            detail: None,
        }
    }

    fn healthy_with_detail(detail: impl Into<String>) -> Self {
        Self {
            ok: true,
            detail: Some(detail.into()),
        }
    }

    fn unhealthy(detail: impl Into<String>) -> Self {
        Self {
            ok: false,
            detail: Some(detail.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Shared state expected by the handler
// ---------------------------------------------------------------------------

/// Minimal subset of `AppState` required by the health-check handler.
/// The concrete `AppState` in `main.rs` implements `Into` / stores the same
/// fields, so we accept it through a trait-object-friendly struct.
#[derive(Clone)]
pub struct HealthState {
    pub config: Arc<Config>,
    pub valkey: fred::clients::Pool,
    pub http_client: reqwest::Client,
    pub prewarm: PrewarmStatus,
}

struct HealthWorkerRequest {
    config: Arc<Config>,
    prewarm: PrewarmStatus,
    instance_id: String,
    response_tx: oneshot::Sender<(StatusCode, HealthResponse)>,
}

#[derive(Clone)]
pub struct HealthWorker {
    request_tx: mpsc::Sender<HealthWorkerRequest>,
}

#[derive(Debug, Clone, Default)]
pub struct PrewarmStatus {
    pub complete: bool,
    pub issues: Vec<String>,
    pub notes: Vec<String>,
}

impl PrewarmStatus {
    fn as_check_result(&self) -> CheckResult {
        if !self.complete {
            return CheckResult::unhealthy("startup repository pre-warm is still running");
        }

        if !self.issues.is_empty() {
            CheckResult::unhealthy(self.issues.join("; "))
        } else if !self.notes.is_empty() {
            CheckResult::healthy_with_detail(self.notes.join("; "))
        } else {
            CheckResult::healthy()
        }
    }
}

impl HealthWorker {
    pub fn start(valkey: fred::clients::Pool, http_client: reqwest::Client) -> Self {
        let (request_tx, mut request_rx) = mpsc::channel::<HealthWorkerRequest>(128);
        std::thread::Builder::new()
            .name("forgeproxy-health-worker".to_string())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .worker_threads(2)
                    .thread_name("forgeproxy-health-pool")
                    .build()
                    .expect("failed to build health worker runtime");
                runtime.block_on(async move {
                    while let Some(request) = request_rx.recv().await {
                        let valkey = valkey.clone();
                        let http_client = http_client.clone();
                        tokio::spawn(async move {
                            let state = HealthState {
                                config: request.config,
                                valkey,
                                http_client,
                                prewarm: request.prewarm,
                            };
                            let _ = request
                                .response_tx
                                .send(compute_health_response(&state, request.instance_id).await);
                        });
                    }
                });
            })
            .expect("failed to spawn health worker thread");
        Self { request_tx }
    }

    pub async fn run(
        &self,
        config: Arc<Config>,
        prewarm: PrewarmStatus,
        instance_id: String,
    ) -> (StatusCode, HealthResponse) {
        let timeout = health_worker_response_timeout(config.health.check_timeout_secs);
        let (response_tx, response_rx) = oneshot::channel();
        if self
            .request_tx
            .send(HealthWorkerRequest {
                config,
                prewarm,
                instance_id: instance_id.clone(),
                response_tx,
            })
            .await
            .is_err()
        {
            return worker_unavailable_response("health worker queue is unavailable", instance_id);
        }
        match tokio::time::timeout(timeout, response_rx).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                worker_unavailable_response("health worker dropped response", instance_id.clone())
            }
            Err(_) => worker_unavailable_response(
                "health worker timed out before responding",
                instance_id,
            ),
        }
    }
}

fn health_worker_response_timeout(check_timeout_secs: u64) -> Duration {
    Duration::from_secs(
        check_timeout_secs
            + HEALTH_WORKER_RESPONSE_TIMEOUT_MIN_SLACK_SECS
                .max(check_timeout_secs / HEALTH_WORKER_RESPONSE_TIMEOUT_DIVISOR),
    )
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

async fn check_valkey(pool: &fred::clients::Pool) -> CheckResult {
    match fred::interfaces::ClientLike::ping::<String>(pool, None).await {
        Ok(_) => CheckResult::healthy(),
        Err(e) => CheckResult::unhealthy(format!("PING failed: {e}")),
    }
}

async fn check_ghe(client: &reqwest::Client, config: &Config) -> CheckResult {
    let admin_token = crate::credentials::keyring::resolve_secret(&config.upstream.admin_token_env)
        .await
        .unwrap_or_default();
    if admin_token.is_empty() {
        return CheckResult::unhealthy(format!(
            "upstream admin token env '{}' is empty or unavailable",
            config.upstream.admin_token_env
        ));
    }

    let url = format!("{}/user", config.upstream.api_url.trim_end_matches('/'));
    let request = authenticated_probe_request(
        client
            .get(&url)
            .header("Accept", config.backend_type.accept_header()),
        config.backend_type,
        &admin_token,
    );

    match request.send().await {
        Ok(resp) if resp.status().is_success() => {
            successful_ghe_check(&url, resp.status(), resp.headers(), Utc::now())
        }
        Ok(resp) => CheckResult::unhealthy(format!("GET {} returned {}", url, resp.status())),
        Err(e) => CheckResult::unhealthy(format!("GET {} failed: {e}", url)),
    }
}

fn authenticated_probe_request(
    request: reqwest::RequestBuilder,
    backend_type: BackendType,
    admin_token: &str,
) -> reqwest::RequestBuilder {
    match backend_type {
        BackendType::Gitlab => request.header("PRIVATE-TOKEN", admin_token),
        BackendType::GithubEnterprise
        | BackendType::Github
        | BackendType::Gitea
        | BackendType::Forgejo => request.header("Authorization", format!("Bearer {admin_token}")),
    }
}

fn successful_ghe_check(
    url: &str,
    status: StatusCode,
    headers: &HeaderMap,
    now: DateTime<Utc>,
) -> CheckResult {
    match token_expiration_from_headers(headers) {
        Ok(Some(expires_at)) if expires_at <= now => {
            let elapsed_days = now.signed_duration_since(expires_at).num_days();
            CheckResult::unhealthy(format!(
                "GET {} {} (token EXPIRED {} days ago, {})",
                url,
                status,
                elapsed_days,
                expires_at.format(GITHUB_TOKEN_EXPIRATION_FORMAT)
            ))
        }
        Ok(Some(expires_at)) => {
            let remaining_days = expires_at.signed_duration_since(now).num_days();
            CheckResult {
                ok: true,
                detail: Some(format!(
                    "GET {} {} (token expires in {} days, {})",
                    url,
                    status,
                    remaining_days,
                    expires_at.format(GITHUB_TOKEN_EXPIRATION_FORMAT)
                )),
            }
        }
        Ok(None) => CheckResult {
            ok: true,
            detail: Some(format!("GET {} {} (token has no expiration)", url, status)),
        },
        Err(raw_value) => CheckResult::unhealthy(format!(
            "GET {} {} (invalid {} header: {})",
            url, status, GITHUB_TOKEN_EXPIRATION_HEADER, raw_value
        )),
    }
}

fn token_expiration_from_headers(headers: &HeaderMap) -> Result<Option<DateTime<Utc>>, String> {
    let Some(raw_value) = headers
        .get(GITHUB_TOKEN_EXPIRATION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };

    NaiveDateTime::parse_from_str(raw_value, GITHUB_TOKEN_EXPIRATION_FORMAT)
        .map(|parsed| Some(parsed.and_utc()))
        .map_err(|_| raw_value.to_string())
}

async fn check_disk(config: &Config) -> CheckResult {
    match disk_health_summary(
        "/",
        &config.storage.local.path,
        config.health.disk_min_available_percent,
    ) {
        Ok(summary) => {
            let any_low = summary
                .iter()
                .any(|fs| fs.available_percent < config.health.disk_min_available_percent);
            let detail = summary
                .iter()
                .map(|fs| {
                    format!(
                        "{}(path={}, cap={}, used={}, avail={}, avail_pct={:.1}%)",
                        fs.name,
                        fs.path,
                        fs.capacity_bytes,
                        fs.used_bytes,
                        fs.available_bytes,
                        fs.available_percent
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            if any_low {
                CheckResult::unhealthy(format!(
                    "filesystem available space below {:.1}% threshold: {detail}",
                    config.health.disk_min_available_percent
                ))
            } else {
                CheckResult::healthy_with_detail(format!(
                    "filesystem free-space check passed (threshold {:.1}%): {detail}",
                    config.health.disk_min_available_percent
                ))
            }
        }
        Err(error) => CheckResult::unhealthy(format!("disk check failed: {error}")),
    }
}

async fn run_check_with_timeout<F>(name: &str, timeout: Duration, check: F) -> CheckResult
where
    F: std::future::Future<Output = CheckResult>,
{
    match tokio::time::timeout(timeout, check).await {
        Ok(result) => result,
        Err(_) => CheckResult::unhealthy(format!(
            "{name} check timed out after {}s",
            timeout.as_secs()
        )),
    }
}

fn worker_unavailable_response(detail: &str, instance_id: String) -> (StatusCode, HealthResponse) {
    let checks = HealthChecks {
        valkey: CheckResult::unhealthy(detail),
        ghe: CheckResult::unhealthy(detail),
        disk: CheckResult::unhealthy(detail),
        prewarm: CheckResult::unhealthy(detail),
    };
    (
        StatusCode::SERVICE_UNAVAILABLE,
        HealthResponse {
            status: HealthStatus::Unhealthy,
            version: crate::build_info::VERSION.to_string(),
            git_revision: crate::build_info::git_revision().to_string(),
            instance_id,
            checks,
        },
    )
}

#[derive(Debug, Clone)]
struct FilesystemHealthSample {
    name: String,
    path: String,
    capacity_bytes: u64,
    used_bytes: u64,
    available_bytes: u64,
    available_percent: f64,
}

fn disk_health_summary(
    root_path: &str,
    cache_path: &str,
    _min_available_percent: f64,
) -> anyhow::Result<Vec<FilesystemHealthSample>> {
    use std::path::Path;

    let mut samples = Vec::new();
    let root = Path::new(root_path);
    samples.push(sample_filesystem("root", root)?);

    let cache = Path::new(cache_path);
    if cache != root && !same_filesystem(root, cache)? {
        samples.push(sample_filesystem("cache", cache)?);
    }

    Ok(samples)
}

fn sample_filesystem(name: &str, path: &std::path::Path) -> anyhow::Result<FilesystemHealthSample> {
    let usage = crate::cache::capacity::filesystem_usage_bytes(path)?;
    let available_percent = if usage.capacity_bytes == 0 {
        0.0
    } else {
        (usage.available_bytes as f64 / usage.capacity_bytes as f64) * 100.0
    };
    Ok(FilesystemHealthSample {
        name: name.to_string(),
        path: path.display().to_string(),
        capacity_bytes: usage.capacity_bytes,
        used_bytes: usage.used_bytes,
        available_bytes: usage.available_bytes,
        available_percent,
    })
}

#[cfg(unix)]
fn same_filesystem(a: &std::path::Path, b: &std::path::Path) -> anyhow::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let a_dev = std::fs::metadata(a)?.dev();
    let b_dev = std::fs::metadata(b)?.dev();
    Ok(a_dev == b_dev)
}

#[cfg(not(unix))]
fn same_filesystem(a: &std::path::Path, b: &std::path::Path) -> anyhow::Result<bool> {
    let a = std::fs::canonicalize(a)?;
    let b = std::fs::canonicalize(b)?;
    Ok(a == b)
}

// ---------------------------------------------------------------------------
// Aggregate status
// ---------------------------------------------------------------------------

fn aggregate_status(checks: &HealthChecks) -> HealthStatus {
    let all_ok = checks.valkey.ok && checks.ghe.ok && checks.disk.ok && checks.prewarm.ok;
    let any_critical = !checks.valkey.ok || !checks.ghe.ok; // Valkey and upstream auth are required for operation

    if all_ok {
        HealthStatus::Ok
    } else if any_critical {
        HealthStatus::Unhealthy
    } else {
        HealthStatus::Degraded
    }
}

async fn compute_health_response(
    state: &HealthState,
    instance_id: String,
) -> (StatusCode, HealthResponse) {
    let timeout = Duration::from_secs(state.config.health.check_timeout_secs);
    let (valkey, ghe, disk) = tokio::join!(
        run_check_with_timeout("valkey", timeout, check_valkey(&state.valkey)),
        run_check_with_timeout(
            "ghe",
            timeout,
            check_ghe(&state.http_client, state.config.as_ref())
        ),
        run_check_with_timeout("disk", timeout, check_disk(state.config.as_ref())),
    );

    let checks = HealthChecks {
        valkey,
        ghe,
        disk,
        prewarm: state.prewarm.as_check_result(),
    };
    let status = aggregate_status(&checks);
    let body = HealthResponse {
        status,
        version: crate::build_info::VERSION.to_string(),
        git_revision: crate::build_info::git_revision().to_string(),
        instance_id,
        checks,
    };

    let http_status = match status {
        HealthStatus::Ok | HealthStatus::Degraded => StatusCode::OK,
        HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };
    (http_status, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_probe_uses_bearer_auth_header() {
        let client = reqwest::Client::new();
        let request = authenticated_probe_request(
            client.get("https://example.test/api/v3/user"),
            BackendType::GithubEnterprise,
            "secret-token",
        )
        .build()
        .unwrap();

        assert_eq!(
            request.headers().get("Authorization").unwrap(),
            "Bearer secret-token"
        );
        assert!(request.headers().get("PRIVATE-TOKEN").is_none());
    }

    #[test]
    fn gitlab_probe_uses_private_token_header() {
        let client = reqwest::Client::new();
        let request = authenticated_probe_request(
            client.get("https://example.test/api/v4/user"),
            BackendType::Gitlab,
            "secret-token",
        )
        .build()
        .unwrap();

        assert_eq!(
            request.headers().get("PRIVATE-TOKEN").unwrap(),
            "secret-token"
        );
        assert!(request.headers().get("Authorization").is_none());
    }

    #[test]
    fn successful_probe_reports_token_expiry() {
        let mut headers = HeaderMap::new();
        headers.insert(
            GITHUB_TOKEN_EXPIRATION_HEADER,
            "2026-08-15 00:00:00 UTC".parse().unwrap(),
        );

        let result = successful_ghe_check(
            "https://ghe.example.test/api/v3/user",
            StatusCode::OK,
            &headers,
            DateTime::parse_from_rfc3339("2026-06-29T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        );

        assert!(result.ok);
        assert_eq!(
            result.detail.as_deref(),
            Some(
                "GET https://ghe.example.test/api/v3/user 200 OK (token expires in 47 days, 2026-08-15 00:00:00 UTC)"
            )
        );
    }

    #[test]
    fn successful_probe_without_expiration_header_reports_no_expiration() {
        let headers = HeaderMap::new();

        let result = successful_ghe_check(
            "https://ghe.example.test/api/v3/user",
            StatusCode::OK,
            &headers,
            DateTime::parse_from_rfc3339("2026-06-29T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        );

        assert!(result.ok);
        assert_eq!(
            result.detail.as_deref(),
            Some("GET https://ghe.example.test/api/v3/user 200 OK (token has no expiration)")
        );
    }

    #[test]
    fn expired_token_marks_probe_unhealthy() {
        let mut headers = HeaderMap::new();
        headers.insert(
            GITHUB_TOKEN_EXPIRATION_HEADER,
            "2026-04-08 00:00:00 UTC".parse().unwrap(),
        );

        let result = successful_ghe_check(
            "https://ghe.example.test/api/v3/user",
            StatusCode::OK,
            &headers,
            DateTime::parse_from_rfc3339("2026-04-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        );

        assert!(!result.ok);
        assert_eq!(
            result.detail.as_deref(),
            Some(
                "GET https://ghe.example.test/api/v3/user 200 OK (token EXPIRED 3 days ago, 2026-04-08 00:00:00 UTC)"
            )
        );
    }

    #[test]
    fn upstream_failure_is_critical_for_aggregate_status() {
        let checks = HealthChecks {
            valkey: CheckResult::healthy(),
            ghe: CheckResult::unhealthy("upstream auth failed"),
            disk: CheckResult::healthy(),
            prewarm: CheckResult::healthy(),
        };

        assert_eq!(aggregate_status(&checks), HealthStatus::Unhealthy);
    }

    #[test]
    fn incomplete_prewarm_is_degraded() {
        let checks = HealthChecks {
            valkey: CheckResult::healthy(),
            ghe: CheckResult::healthy(),
            disk: CheckResult::healthy(),
            prewarm: PrewarmStatus::default().as_check_result(),
        };

        assert_eq!(aggregate_status(&checks), HealthStatus::Degraded);
    }

    #[test]
    fn completed_prewarm_with_issues_is_degraded() {
        let checks = HealthChecks {
            valkey: CheckResult::healthy(),
            ghe: CheckResult::healthy(),
            disk: CheckResult::healthy(),
            prewarm: PrewarmStatus {
                complete: true,
                issues: vec!["foo/bar: upstream fetch failed".to_string()],
                notes: Vec::new(),
            }
            .as_check_result(),
        };

        assert_eq!(aggregate_status(&checks), HealthStatus::Degraded);
    }

    #[test]
    fn completed_prewarm_with_notes_remains_ok() {
        let checks = HealthChecks {
            valkey: CheckResult::healthy(),
            ghe: CheckResult::healthy(),
            disk: CheckResult::healthy(),
            prewarm: PrewarmStatus {
                complete: true,
                issues: Vec::new(),
                notes: vec![
                    "startup pre-warm exceeded timeout; force-opened readiness".to_string(),
                ],
            }
            .as_check_result(),
        };

        assert_eq!(aggregate_status(&checks), HealthStatus::Ok);
        assert!(checks.prewarm.ok);
    }

    #[tokio::test]
    async fn timed_out_check_is_unhealthy() {
        let result = run_check_with_timeout("ghe", Duration::from_millis(10), async {
            tokio::time::sleep(Duration::from_millis(25)).await;
            CheckResult::healthy()
        })
        .await;

        assert!(!result.ok);
        assert_eq!(
            result.detail.as_deref(),
            Some("ghe check timed out after 0s")
        );
    }

    #[test]
    fn health_worker_response_timeout_includes_queue_slack() {
        assert_eq!(health_worker_response_timeout(5), Duration::from_secs(10));
        assert_eq!(health_worker_response_timeout(10), Duration::from_secs(15));
        assert_eq!(health_worker_response_timeout(20), Duration::from_secs(30));
    }
}
