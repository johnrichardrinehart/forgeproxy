//! Upstream API rate-limit tracking.
//!
//! Reads `X-RateLimit-Remaining` / `X-RateLimit-Reset` (or the standardised
//! `RateLimit-Remaining` / `RateLimit-Reset`) from forge API responses and
//! decides whether to self-throttle before hitting the limit.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tracing::{debug, info};

/// Shared rate-limit state updated after every forge API response.
#[derive(Debug, Clone)]
pub struct RateLimitState {
    /// Remaining API calls before the rate limit resets.
    remaining: Arc<AtomicU64>,
    /// Unix timestamp at which the rate limit window resets.
    reset_at: Arc<AtomicU64>,
}

impl Default for RateLimitState {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimitState {
    pub fn new() -> Self {
        Self {
            remaining: Arc::new(AtomicU64::new(u64::MAX)),
            reset_at: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Current remaining calls.
    pub fn remaining(&self) -> u64 {
        self.remaining.load(Ordering::Relaxed)
    }

    /// Unix timestamp when the window resets.
    pub fn reset_at(&self) -> u64 {
        self.reset_at.load(Ordering::Relaxed)
    }

    /// Update state from HTTP response headers.
    ///
    /// Accepts both `X-RateLimit-*` (GitHub/Gitea) and `RateLimit-*`
    /// (IETF draft) header names.
    pub fn update_from_headers(&self, headers: &reqwest::header::HeaderMap) {
        let remaining = headers
            .get("X-RateLimit-Remaining")
            .or_else(|| headers.get("RateLimit-Remaining"))
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let reset = headers
            .get("X-RateLimit-Reset")
            .or_else(|| headers.get("RateLimit-Reset"))
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        if let Some(r) = remaining {
            self.remaining.store(r, Ordering::Relaxed);
        }
        if let Some(r) = reset {
            self.reset_at.store(r, Ordering::Relaxed);
        }
    }

    /// If the remaining calls are below `buffer`, sleep until the rate-limit
    /// window resets.  Returns `true` if the caller had to wait.
    pub async fn wait_if_needed(&self, buffer: u32) -> bool {
        let remaining = self.remaining.load(Ordering::Relaxed);
        let reset = self.reset_at.load(Ordering::Relaxed);

        if remaining < buffer as u64 && remaining != u64::MAX {
            let now = chrono::Utc::now().timestamp() as u64;
            if reset > now {
                let wait_secs = reset - now;
                info!(
                    remaining,
                    reset_in_secs = wait_secs,
                    buffer,
                    "self-throttling: rate limit approaching"
                );
                tokio::time::sleep(std::time::Duration::from_secs(wait_secs)).await;
                return true;
            }
        } else {
            debug!(remaining, buffer, "rate limit OK");
        }
        false
    }

    /// Return the number of seconds until the rate-limit window resets, or 0 if
    /// already reset.  Used for `Retry-After` HTTP response headers.
    pub fn retry_after_secs(&self) -> u64 {
        let reset = self.reset_at.load(Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp() as u64;
        reset.saturating_sub(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_remaining_is_max() {
        let state = RateLimitState::new();
        assert_eq!(state.remaining(), u64::MAX);
    }

    #[test]
    fn update_from_github_headers() {
        let state = RateLimitState::new();

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("X-RateLimit-Remaining", "42".parse().unwrap());
        headers.insert("X-RateLimit-Reset", "1700000000".parse().unwrap());

        state.update_from_headers(&headers);
        assert_eq!(state.remaining(), 42);
        assert_eq!(state.reset_at(), 1700000000);
    }

    #[test]
    fn update_from_ietf_headers() {
        let state = RateLimitState::new();

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("RateLimit-Remaining", "10".parse().unwrap());
        headers.insert("RateLimit-Reset", "1800000000".parse().unwrap());

        state.update_from_headers(&headers);
        assert_eq!(state.remaining(), 10);
        assert_eq!(state.reset_at(), 1800000000);
    }

    #[test]
    fn retry_after_when_future() {
        let state = RateLimitState::new();
        let future_ts = chrono::Utc::now().timestamp() as u64 + 30;
        state.reset_at.store(future_ts, Ordering::Relaxed);
        // Should be approximately 30 seconds (±1 for clock drift).
        let retry = state.retry_after_secs();
        assert!((29..=31).contains(&retry));
    }

    #[test]
    fn retry_after_when_past() {
        let state = RateLimitState::new();
        state.reset_at.store(0, Ordering::Relaxed);
        assert_eq!(state.retry_after_secs(), 0);
    }
}
