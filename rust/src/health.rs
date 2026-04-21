use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::{DateTime, NaiveDateTime, Utc};
use reqwest::header::HeaderMap;
use serde::Serialize;

use crate::config::{BackendType, Config};

const GITHUB_TOKEN_EXPIRATION_HEADER: &str = "github-authentication-token-expiration";
const GITHUB_TOKEN_EXPIRATION_FORMAT: &str = "%Y-%m-%d %H:%M:%S UTC";

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: HealthStatus,
    pub version: &'static str,
    pub git_revision: &'static str,
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
    let cache_path = &config.storage.local.path;

    let path = cache_path.clone();
    let max_percent = config.storage.local.max_percent;

    let result = tokio::task::spawn_blocking(move || disk_usage(&path, max_percent)).await;

    match result {
        Ok(Ok((usage, capacity, budget))) => {
            if usage.physical_bytes > budget {
                CheckResult::unhealthy(format!(
                    "cache physical_usage {} bytes exceeds configured budget {budget}; apparent_usage {} bytes",
                    usage.physical_bytes, usage.apparent_bytes,
                ))
            } else {
                let pct = if capacity > 0 {
                    (usage.physical_bytes as f64 / capacity as f64) * 100.0
                } else {
                    0.0
                };
                CheckResult {
                    ok: true,
                    detail: Some(format!(
                        "physical_usage {} / {budget} budget ({pct:.1}% of filesystem); apparent_usage {}",
                        usage.physical_bytes, usage.apparent_bytes,
                    )),
                }
            }
        }
        Ok(Err(e)) => CheckResult::unhealthy(format!("disk check failed: {e}")),
        Err(e) => CheckResult::unhealthy(format!("disk check task failed: {e}")),
    }
}

/// Compute (cache_usage, filesystem_capacity, configured_budget_bytes)
/// for the path's mount.
fn disk_usage(
    path: &str,
    max_percent: f64,
) -> anyhow::Result<(crate::cache::manager::DiskUsage, u64, u64)> {
    let dir = std::path::Path::new(path);
    let used = crate::cache::manager::dir_usage(dir)?;
    let capacity = crate::cache::capacity::filesystem_capacity_bytes(dir)?;
    let budget = crate::cache::capacity::percent_of_bytes(capacity, max_percent);
    Ok((used, capacity, budget))
}

// ---------------------------------------------------------------------------
// Aggregate status
// ---------------------------------------------------------------------------

fn aggregate_status(checks: &HealthChecks) -> HealthStatus {
    let all_ok = checks.valkey.ok && checks.ghe.ok && checks.disk.ok;
    let any_critical = !checks.valkey.ok || !checks.ghe.ok; // Valkey and upstream auth are required for operation

    if all_ok {
        HealthStatus::Ok
    } else if any_critical {
        HealthStatus::Unhealthy
    } else {
        HealthStatus::Degraded
    }
}

// ---------------------------------------------------------------------------
// Axum handler
// ---------------------------------------------------------------------------

/// `GET /healthz` handler.  Returns 200 on Ok/Degraded, 503 on Unhealthy.
pub async fn health_handler(State(state): State<HealthState>) -> impl IntoResponse {
    let (valkey, ghe, disk) = tokio::join!(
        check_valkey(&state.valkey),
        check_ghe(&state.http_client, &state.config),
        check_disk(&state.config),
    );

    let checks = HealthChecks { valkey, ghe, disk };
    let status = aggregate_status(&checks);
    let body = HealthResponse {
        status,
        version: crate::build_info::VERSION,
        git_revision: crate::build_info::GIT_REVISION,
        checks,
    };

    let http_status = match status {
        HealthStatus::Ok | HealthStatus::Degraded => StatusCode::OK,
        HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };

    (http_status, Json(body))
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
        };

        assert_eq!(aggregate_status(&checks), HealthStatus::Unhealthy);
    }
}
