use std::time::{Duration, Instant};

use crate::config::Config;

#[derive(Clone, Copy, Debug)]
pub struct RequestBudget {
    started_at: Instant,
    global: Option<Duration>,
}

impl RequestBudget {
    pub fn from_config(config: &Config, started_at: Instant) -> Self {
        Self {
            started_at,
            global: duration_from_secs(config.clone.global_short_circuit_upstream_secs),
        }
    }

    pub fn remaining(self) -> Option<Duration> {
        self.global.map(|global| {
            let elapsed = self.started_at.elapsed();
            global.saturating_sub(elapsed)
        })
    }

    pub fn stage_timeout(self, stage: Option<Duration>) -> Option<Duration> {
        min_timeout(self.remaining(), stage)
    }

    pub fn stage_timeout_secs(self, stage_secs: u64) -> Option<Duration> {
        self.stage_timeout(duration_from_secs(stage_secs))
    }
}

pub fn duration_from_secs(secs: u64) -> Option<Duration> {
    (secs > 0).then(|| Duration::from_secs(secs))
}

pub fn min_timeout(left: Option<Duration>, right: Option<Duration>) -> Option<Duration> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(timeout), None) | (None, Some(timeout)) => Some(timeout),
        (None, None) => None,
    }
}

pub fn local_upload_pack_permit_timeout_after_optional_cache_wait(
    budget: Option<RequestBudget>,
    optional_cache_wait_timed_out: bool,
) -> Option<Duration> {
    if optional_cache_wait_timed_out {
        Some(Duration::ZERO)
    } else {
        budget.and_then(RequestBudget::remaining)
    }
}

pub fn local_upload_pack_first_byte_timeout_after_optional_cache_wait(
    budget: Option<RequestBudget>,
    first_byte_secs: u64,
    optional_cache_wait_timed_out: bool,
) -> Option<Duration> {
    if optional_cache_wait_timed_out {
        duration_from_secs(first_byte_secs)
    } else {
        budget.and_then(|budget| budget.stage_timeout_secs(first_byte_secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_seconds_disable_timeout() {
        assert_eq!(duration_from_secs(0), None);
        assert_eq!(duration_from_secs(3), Some(Duration::from_secs(3)));
    }

    #[test]
    fn min_timeout_uses_earliest_enabled_budget() {
        assert_eq!(
            min_timeout(Some(Duration::from_secs(10)), Some(Duration::from_secs(4))),
            Some(Duration::from_secs(4))
        );
        assert_eq!(
            min_timeout(Some(Duration::from_secs(10)), None),
            Some(Duration::from_secs(10))
        );
        assert_eq!(min_timeout(None, None), None);
    }

    #[test]
    fn optional_cache_timeout_still_tries_local_upload_pack_permit() {
        let budget = RequestBudget {
            started_at: Instant::now() - Duration::from_secs(30),
            global: Some(Duration::from_secs(15)),
        };

        assert_eq!(
            local_upload_pack_permit_timeout_after_optional_cache_wait(Some(budget), true),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn optional_cache_timeout_preserves_configured_local_first_byte_timeout() {
        let budget = RequestBudget {
            started_at: Instant::now() - Duration::from_secs(30),
            global: Some(Duration::from_secs(15)),
        };

        assert_eq!(
            local_upload_pack_first_byte_timeout_after_optional_cache_wait(Some(budget), 5, true),
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn local_upload_pack_timeouts_preserve_budget_without_optional_cache_timeout() {
        let budget = RequestBudget {
            started_at: Instant::now(),
            global: None,
        };

        assert_eq!(
            local_upload_pack_permit_timeout_after_optional_cache_wait(Some(budget), false),
            None
        );
        assert_eq!(
            local_upload_pack_first_byte_timeout_after_optional_cache_wait(Some(budget), 5, false),
            Some(Duration::from_secs(5))
        );
    }
}
