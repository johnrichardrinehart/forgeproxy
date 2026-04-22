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
}
