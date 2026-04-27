use std::time::{Duration, Instant};

use tokio::time::sleep;
use tracing::info;

use crate::config::BackgroundWorkConfig;

#[derive(Debug, Clone)]
pub struct BackgroundWorkDeferReason {
    pub reason: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, Copy)]
struct CpuSnapshot {
    total: u64,
    idle: u64,
}

pub async fn wait_for_admission(
    state: &crate::AppState,
    kind: &'static str,
    repo: Option<&str>,
    active_clone_allowance: i64,
) -> bool {
    let started_at = Instant::now();
    let mut defer_count = 0_u32;

    loop {
        match defer_reason(state, active_clone_allowance).await {
            None => return true,
            Some(reason) => {
                defer_count = defer_count.saturating_add(1);
                let config = state.config();
                if defer_count >= config.background_work.max_defer_retries
                    || started_at.elapsed()
                        >= Duration::from_secs(config.background_work.max_defer_secs)
                {
                    info!(
                        kind,
                        repo = repo.unwrap_or(""),
                        reason = reason.reason,
                        detail = %reason.detail,
                        defer_count,
                        max_defer_retries = config.background_work.max_defer_retries,
                        deferred_secs = started_at.elapsed().as_secs(),
                        max_defer_secs = config.background_work.max_defer_secs,
                        "abandoning background work after repeated foreground clone/CPU pressure"
                    );
                    return false;
                }
                info!(
                    kind,
                    repo = repo.unwrap_or(""),
                    reason = reason.reason,
                    detail = %reason.detail,
                    defer_count,
                    retry_interval_secs = config.background_work.retry_interval_secs,
                    "deferring background work until foreground clone/CPU pressure drops"
                );
                sleep(Duration::from_secs(
                    config.background_work.retry_interval_secs,
                ))
                .await;
            }
        }
    }
}

pub async fn defer_reason(
    state: &crate::AppState,
    active_clone_allowance: i64,
) -> Option<BackgroundWorkDeferReason> {
    let config = state.config();
    let background = &config.background_work;
    if !background.enabled {
        return None;
    }

    let active_clones = state.active_clone_count();
    if background.defer_when_active_clones && active_clones > active_clone_allowance {
        return Some(BackgroundWorkDeferReason {
            reason: "active_clones",
            detail: format!("active_clones={active_clones}, allowance={active_clone_allowance}"),
        });
    }

    if let Some(reason) = cpu_busy_defer_reason(background).await {
        return Some(reason);
    }
    load_average_defer_reason(background)
}

async fn cpu_busy_defer_reason(config: &BackgroundWorkConfig) -> Option<BackgroundWorkDeferReason> {
    if config.cpu_busy_100ms_high_watermark <= 0.0 {
        return None;
    }

    let before = read_cpu_snapshot()?;
    sleep(Duration::from_millis(100)).await;
    let after = read_cpu_snapshot()?;
    let total_delta = after.total.saturating_sub(before.total);
    let idle_delta = after.idle.saturating_sub(before.idle);
    if total_delta == 0 {
        return None;
    }

    let busy_fraction = 1.0 - (idle_delta as f64 / total_delta as f64);
    if busy_fraction >= config.cpu_busy_100ms_high_watermark {
        return Some(BackgroundWorkDeferReason {
            reason: "cpu_busy_100ms",
            detail: format!(
                "busy_fraction={busy_fraction:.3}, threshold={:.3}",
                config.cpu_busy_100ms_high_watermark
            ),
        });
    }
    None
}

fn load_average_defer_reason(config: &BackgroundWorkConfig) -> Option<BackgroundWorkDeferReason> {
    if config.load_1m_per_cpu_high_watermark <= 0.0 {
        return None;
    }

    let load_1m = read_load_average_1m()?;
    let cpu_budget = effective_cpu_budget();
    if cpu_budget <= 0.0 {
        return None;
    }
    let load_fraction = load_1m / cpu_budget;
    if load_fraction >= config.load_1m_per_cpu_high_watermark {
        return Some(BackgroundWorkDeferReason {
            reason: "load_1m_per_cpu",
            detail: format!(
                "load_1m={load_1m:.2}, cpu_budget={cpu_budget:.2}, load_fraction={load_fraction:.3}, threshold={:.3}",
                config.load_1m_per_cpu_high_watermark
            ),
        });
    }
    None
}

fn read_cpu_snapshot() -> Option<CpuSnapshot> {
    let contents = std::fs::read_to_string("/proc/stat").ok()?;
    let line = contents.lines().find(|line| line.starts_with("cpu "))?;
    let values = line
        .split_whitespace()
        .skip(1)
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if values.len() < 4 {
        return None;
    }

    let idle = values.get(3).copied().unwrap_or(0) + values.get(4).copied().unwrap_or(0);
    let total = values.iter().copied().sum();
    Some(CpuSnapshot { total, idle })
}

fn read_load_average_1m() -> Option<f64> {
    let contents = std::fs::read_to_string("/proc/loadavg").ok()?;
    contents.split_whitespace().next()?.parse().ok()
}

fn effective_cpu_budget() -> f64 {
    cgroup_cpu_budget().unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1) as f64
    })
}

fn cgroup_cpu_budget() -> Option<f64> {
    let contents = std::fs::read_to_string("/sys/fs/cgroup/cpu.max").ok()?;
    let mut fields = contents.split_whitespace();
    let quota = fields.next()?;
    let period = fields.next()?.parse::<f64>().ok()?;
    if quota == "max" || period <= 0.0 {
        return None;
    }
    let quota = quota.parse::<f64>().ok()?;
    if quota <= 0.0 {
        return None;
    }
    let budget = quota / period;
    if budget.is_finite() && budget > 0.0 {
        Some(budget)
    } else {
        None
    }
}
