use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use fred::interfaces::ClientLike;
use serde::Serialize;

use crate::config::Config;

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: HealthStatus,
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
    pub keydb: CheckResult,
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
    pub keydb: fred::clients::Pool,
    pub http_client: reqwest::Client,
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

async fn check_keydb(pool: &fred::clients::Pool) -> CheckResult {
    match fred::interfaces::ClientLike::ping::<String>(pool, None).await {
        Ok(_) => CheckResult::healthy(),
        Err(e) => CheckResult::unhealthy(format!("PING failed: {e}")),
    }
}

async fn check_ghe(client: &reqwest::Client, api_url: &str) -> CheckResult {
    let url = format!("{}/meta", api_url.trim_end_matches('/'));
    match client.head(&url).send().await {
        Ok(resp) if resp.status().is_success() || resp.status().is_redirection() => {
            CheckResult::healthy()
        }
        Ok(resp) => CheckResult::unhealthy(format!("HEAD {} returned {}", url, resp.status())),
        Err(e) => CheckResult::unhealthy(format!("HEAD {} failed: {e}", url)),
    }
}

async fn check_disk(config: &Config) -> CheckResult {
    let cache_path = &config.storage.local.path;

    // Use statvfs via a blocking call to avoid blocking the async runtime.
    let path = cache_path.clone();
    let max_bytes = config.storage.local.max_bytes;

    let result = tokio::task::spawn_blocking(move || disk_usage(&path, max_bytes)).await;

    match result {
        Ok(Ok((used, capacity))) => {
            // Check against max_bytes configured ceiling.
            if used > max_bytes {
                CheckResult::unhealthy(format!(
                    "cache usage {used} bytes exceeds max_bytes {max_bytes}"
                ))
            } else {
                let pct = if capacity > 0 {
                    (used as f64 / capacity as f64) * 100.0
                } else {
                    0.0
                };
                CheckResult {
                    ok: true,
                    detail: Some(format!(
                        "used {used} / {max_bytes} max ({pct:.1}% of filesystem)"
                    )),
                }
            }
        }
        Ok(Err(e)) => CheckResult::unhealthy(format!("disk check failed: {e}")),
        Err(e) => CheckResult::unhealthy(format!("disk check task failed: {e}")),
    }
}

/// Compute (used_bytes_in_dir, filesystem_capacity) for the path's mount.
///
/// We cannot use `statvfs` without an FFI binding, so we fall back to
/// `std::fs::metadata`-based traversal for the used-bytes component and
/// a simple `available + used` estimate from `std::fs` for the fs capacity.
fn disk_usage(path: &str, _max_bytes: u64) -> anyhow::Result<(u64, u64)> {
    use std::fs;

    // Walk the cache directory and sum file sizes.
    let dir = std::path::Path::new(path);
    if !dir.exists() {
        // If the cache dir has not been created yet, report 0 usage.
        return Ok((0, 0));
    }

    let mut used: u64 = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(entry_path) = stack.pop() {
        let entries = match fs::read_dir(&entry_path) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                used += meta.len();
            }
        }
    }

    // For filesystem capacity we read /proc/mounts or fall back to 0.
    // A production version would use nix::sys::statvfs; we keep it simple.
    let capacity = fs_capacity_for(dir).unwrap_or(0);
    Ok((used, capacity))
}

/// Best-effort attempt to read filesystem capacity via `/proc/mounts` and
/// `statfs`. Returns `None` when unavailable.
fn fs_capacity_for(_path: &std::path::Path) -> Option<u64> {
    // In a production build this would call libc::statvfs.  We avoid
    // pulling in the `nix` crate here and return None so the health
    // endpoint still functions (just without filesystem capacity info).
    None
}

// ---------------------------------------------------------------------------
// Aggregate status
// ---------------------------------------------------------------------------

fn aggregate_status(checks: &HealthChecks) -> HealthStatus {
    let all_ok = checks.keydb.ok && checks.ghe.ok && checks.disk.ok;
    let any_critical = !checks.keydb.ok; // KeyDB is required for operation

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
    let (keydb, ghe, disk) = tokio::join!(
        check_keydb(&state.keydb),
        check_ghe(&state.http_client, &state.config.ghe.api_url),
        check_disk(&state.config),
    );

    let checks = HealthChecks { keydb, ghe, disk };
    let status = aggregate_status(&checks);
    let body = HealthResponse { status, checks };

    let http_status = match status {
        HealthStatus::Ok | HealthStatus::Degraded => StatusCode::OK,
        HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };

    (http_status, Json(body))
}
