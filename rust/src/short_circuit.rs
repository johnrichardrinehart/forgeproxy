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
            global: Some(short_circuit_timeout_from_secs(
                config.clone.global_short_circuit_upstream_secs,
            )),
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
}

pub fn duration_from_secs(secs: u64) -> Option<Duration> {
    (secs > 0).then(|| Duration::from_secs(secs))
}

pub fn short_circuit_timeout_from_secs(secs: u64) -> Duration {
    Duration::from_secs(secs)
}

pub fn min_timeout(left: Option<Duration>, right: Option<Duration>) -> Option<Duration> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(timeout), None) | (None, Some(timeout)) => Some(timeout),
        (None, None) => None,
    }
}

pub fn forces_short_circuit_without_polling(timeout: Option<Duration>) -> bool {
    matches!(timeout, Some(timeout) if timeout.is_zero())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoricalLatencyEstimate {
    pub sample_count: u64,
    pub average: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LiveLatencyEstimate {
    pub stage: &'static str,
    pub request_shape: &'static str,
    pub historical_weight: f64,
    pub elapsed: Duration,
    pub estimated_total: Duration,
}

#[derive(Clone, Copy, Debug)]
pub struct FlexibleSloPolicy {
    pub enabled: bool,
    pub slo: Duration,
    pub estimate: Option<HistoricalLatencyEstimate>,
    pub live_estimate: Option<LiveLatencyEstimate>,
    pub min_sample_count: u64,
    pub near_miss_grace_fraction: f64,
    pub near_miss_grace: Duration,
    pub early_abort_overrun_fraction: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlexibleSloDecisionAction {
    ConfiguredTimeout,
    NearMissExtension,
    EarlyAbortEstimate,
    EarlyAbortElapsed,
}

impl FlexibleSloDecisionAction {
    pub fn as_label(self) -> &'static str {
        match self {
            Self::ConfiguredTimeout => "configured_timeout",
            Self::NearMissExtension => "near_miss_extension",
            Self::EarlyAbortEstimate => "early_abort_estimate",
            Self::EarlyAbortElapsed => "early_abort_elapsed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FlexibleSloDecision {
    pub timeout: Option<Duration>,
    pub action: FlexibleSloDecisionAction,
    pub historical_estimate: Option<Duration>,
    pub live_estimate: Option<LiveLatencyEstimate>,
    pub effective_estimate: Option<Duration>,
    pub near_miss_limit: Option<Duration>,
    pub early_abort_limit: Option<Duration>,
}

impl FlexibleSloDecision {
    fn configured(timeout: Option<Duration>) -> Self {
        Self {
            timeout,
            action: FlexibleSloDecisionAction::ConfiguredTimeout,
            historical_estimate: None,
            live_estimate: None,
            effective_estimate: None,
            near_miss_limit: None,
            early_abort_limit: None,
        }
    }

    pub fn is_early_abort(self) -> bool {
        matches!(
            self.action,
            FlexibleSloDecisionAction::EarlyAbortEstimate
                | FlexibleSloDecisionAction::EarlyAbortElapsed
        )
    }
}

pub fn flexible_slo_timeout_decision(
    configured_timeout: Option<Duration>,
    budget_limit: Option<Duration>,
    policy: Option<FlexibleSloPolicy>,
) -> FlexibleSloDecision {
    let Some(configured_timeout) = configured_timeout else {
        return FlexibleSloDecision::configured(None);
    };
    if configured_timeout.is_zero() {
        return FlexibleSloDecision::configured(Some(Duration::ZERO));
    }
    let Some(policy) = policy.filter(|policy| policy.enabled) else {
        return FlexibleSloDecision::configured(Some(configured_timeout));
    };
    let historical_estimate = policy
        .estimate
        .filter(|estimate| estimate.sample_count >= policy.min_sample_count)
        .map(|estimate| estimate.average);
    let live_estimate = policy.live_estimate;
    let Some(effective_estimate) = combined_latency_estimate(historical_estimate, live_estimate)
    else {
        return FlexibleSloDecision::configured(Some(configured_timeout));
    };

    let fractional_grace = policy.slo.mul_f64(policy.near_miss_grace_fraction);
    let near_miss_grace = policy.near_miss_grace.max(fractional_grace);
    let near_miss_limit = policy.slo.saturating_add(near_miss_grace);
    let early_abort_limit =
        near_miss_limit.saturating_add(policy.slo.mul_f64(policy.early_abort_overrun_fraction));

    let base = FlexibleSloDecision {
        timeout: Some(configured_timeout),
        action: FlexibleSloDecisionAction::ConfiguredTimeout,
        historical_estimate,
        live_estimate,
        effective_estimate: Some(effective_estimate),
        near_miss_limit: Some(near_miss_limit),
        early_abort_limit: Some(early_abort_limit),
    };

    if live_estimate.is_some_and(|estimate| estimate.elapsed >= early_abort_limit) {
        return FlexibleSloDecision {
            timeout: Some(Duration::ZERO),
            action: FlexibleSloDecisionAction::EarlyAbortElapsed,
            ..base
        };
    }
    if effective_estimate > early_abort_limit {
        return FlexibleSloDecision {
            timeout: Some(Duration::ZERO),
            action: FlexibleSloDecisionAction::EarlyAbortEstimate,
            ..base
        };
    }
    if let Some(live) = live_estimate {
        let early_abort_remaining = early_abort_limit.saturating_sub(live.elapsed);
        if early_abort_remaining < configured_timeout {
            return FlexibleSloDecision {
                timeout: Some(early_abort_remaining),
                action: FlexibleSloDecisionAction::EarlyAbortElapsed,
                ..base
            };
        }
    }
    if effective_estimate > near_miss_limit {
        return base;
    }
    if effective_estimate <= policy.slo {
        return base;
    }

    let near_miss_timeout = live_estimate.map_or(near_miss_limit, |estimate| {
        near_miss_limit.saturating_sub(estimate.elapsed)
    });
    let extended_timeout = match budget_limit {
        Some(limit) => near_miss_timeout.min(limit),
        None => near_miss_timeout,
    };
    FlexibleSloDecision {
        timeout: Some(configured_timeout.max(extended_timeout)),
        action: FlexibleSloDecisionAction::NearMissExtension,
        ..base
    }
}

fn combined_latency_estimate(
    historical_estimate: Option<Duration>,
    live_estimate: Option<LiveLatencyEstimate>,
) -> Option<Duration> {
    const LIVE_ESTIMATE_WEIGHT: f64 = 0.70;

    match (historical_estimate, live_estimate) {
        (Some(_historical), Some(live)) if live.historical_weight <= 0.0 => {
            Some(live.estimated_total)
        }
        (Some(historical), Some(live)) => {
            let live_weight = LIVE_ESTIMATE_WEIGHT.clamp(0.0, 1.0);
            let historical_weight = (1.0 - live_weight) * live.historical_weight.clamp(0.0, 1.0);
            Some(weighted_duration_with_weights(
                historical,
                historical_weight,
                live.estimated_total,
                live_weight,
            ))
        }
        (Some(historical), None) => Some(historical),
        (None, Some(live)) => Some(live.estimated_total),
        (None, None) => None,
    }
}

fn weighted_duration_with_weights(
    historical: Duration,
    historical_weight: f64,
    live: Duration,
    live_weight: f64,
) -> Duration {
    let historical_weight = historical_weight.max(0.0);
    let live_weight = live_weight.max(0.0);
    let total_weight = historical_weight + live_weight;
    if total_weight <= f64::EPSILON {
        return live;
    }

    historical
        .mul_f64(historical_weight / total_weight)
        .saturating_add(live.mul_f64(live_weight / total_weight))
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

pub fn local_upload_pack_first_byte_timeout_decision_after_optional_cache_wait_with_slo_policy(
    budget: Option<RequestBudget>,
    first_byte_secs: u64,
    optional_cache_wait_timed_out: bool,
    policy: Option<FlexibleSloPolicy>,
) -> FlexibleSloDecision {
    if optional_cache_wait_timed_out {
        flexible_slo_timeout_decision(
            Some(short_circuit_timeout_from_secs(first_byte_secs)),
            None,
            policy,
        )
    } else {
        let budget_limit = budget.and_then(RequestBudget::remaining);
        let configured_timeout = min_timeout(
            budget_limit,
            Some(short_circuit_timeout_from_secs(first_byte_secs)),
        );
        flexible_slo_timeout_decision(configured_timeout, budget_limit, policy)
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
    fn zero_seconds_force_short_circuit_timeout() {
        assert_eq!(short_circuit_timeout_from_secs(0), Duration::ZERO);
        assert_eq!(short_circuit_timeout_from_secs(3), Duration::from_secs(3));
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
    fn zero_timeout_forces_short_circuit_without_polling() {
        assert!(forces_short_circuit_without_polling(Some(Duration::ZERO)));
        assert!(!forces_short_circuit_without_polling(Some(
            Duration::from_nanos(1)
        )));
        assert!(!forces_short_circuit_without_polling(None));
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
            local_upload_pack_first_byte_timeout_decision_after_optional_cache_wait_with_slo_policy(
                Some(budget),
                5,
                true,
                None
            )
            .timeout,
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn zero_local_first_byte_timeout_forces_upstream_and_ignores_slo_policy() {
        let decision =
            local_upload_pack_first_byte_timeout_decision_after_optional_cache_wait_with_slo_policy(
                None,
                0,
                false,
                Some(FlexibleSloPolicy {
                    enabled: true,
                    slo: Duration::from_secs(5),
                    estimate: Some(HistoricalLatencyEstimate {
                        sample_count: 10,
                        average: Duration::from_secs(6),
                    }),
                    live_estimate: None,
                    min_sample_count: 5,
                    near_miss_grace_fraction: 0.10,
                    near_miss_grace: Duration::from_secs(3),
                    early_abort_overrun_fraction: 0.25,
                }),
            );

        assert_eq!(decision.timeout, Some(Duration::ZERO));
        assert_eq!(
            decision.action,
            FlexibleSloDecisionAction::ConfiguredTimeout
        );
        assert_eq!(decision.effective_estimate, None);
    }

    #[test]
    fn zero_global_budget_forces_upstream_and_ignores_slo_policy() {
        let budget = RequestBudget {
            started_at: Instant::now(),
            global: Some(Duration::ZERO),
        };
        let decision =
            local_upload_pack_first_byte_timeout_decision_after_optional_cache_wait_with_slo_policy(
                Some(budget),
                30,
                false,
                Some(FlexibleSloPolicy {
                    enabled: true,
                    slo: Duration::from_secs(5),
                    estimate: Some(HistoricalLatencyEstimate {
                        sample_count: 10,
                        average: Duration::from_secs(6),
                    }),
                    live_estimate: None,
                    min_sample_count: 5,
                    near_miss_grace_fraction: 0.10,
                    near_miss_grace: Duration::from_secs(3),
                    early_abort_overrun_fraction: 0.25,
                }),
            );

        assert_eq!(decision.timeout, Some(Duration::ZERO));
        assert_eq!(
            decision.action,
            FlexibleSloDecisionAction::ConfiguredTimeout
        );
        assert_eq!(decision.effective_estimate, None);
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
            local_upload_pack_first_byte_timeout_decision_after_optional_cache_wait_with_slo_policy(
                Some(budget),
                5,
                false,
                None
            )
            .timeout,
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn flexible_slo_timeout_extends_near_miss_within_budget() {
        let timeout = flexible_slo_timeout_decision(
            Some(Duration::from_secs(5)),
            Some(Duration::from_secs(10)),
            Some(FlexibleSloPolicy {
                enabled: true,
                slo: Duration::from_secs(5),
                estimate: Some(HistoricalLatencyEstimate {
                    sample_count: 10,
                    average: Duration::from_secs(7),
                }),
                live_estimate: None,
                min_sample_count: 5,
                near_miss_grace_fraction: 0.10,
                near_miss_grace: Duration::from_secs(3),
                early_abort_overrun_fraction: 0.25,
            }),
        )
        .timeout;

        assert_eq!(timeout, Some(Duration::from_secs(8)));
    }

    #[test]
    fn flexible_slo_timeout_does_not_extend_healthy_estimate() {
        let timeout = flexible_slo_timeout_decision(
            Some(Duration::from_secs(5)),
            Some(Duration::from_secs(10)),
            Some(FlexibleSloPolicy {
                enabled: true,
                slo: Duration::from_secs(5),
                estimate: Some(HistoricalLatencyEstimate {
                    sample_count: 10,
                    average: Duration::from_secs(1),
                }),
                live_estimate: None,
                min_sample_count: 5,
                near_miss_grace_fraction: 0.10,
                near_miss_grace: Duration::from_secs(3),
                early_abort_overrun_fraction: 0.25,
            }),
        )
        .timeout;

        assert_eq!(timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    fn flexible_slo_timeout_aborts_clear_overrun() {
        let timeout = flexible_slo_timeout_decision(
            Some(Duration::from_secs(5)),
            Some(Duration::from_secs(30)),
            Some(FlexibleSloPolicy {
                enabled: true,
                slo: Duration::from_secs(5),
                estimate: Some(HistoricalLatencyEstimate {
                    sample_count: 10,
                    average: Duration::from_secs(10),
                }),
                live_estimate: None,
                min_sample_count: 5,
                near_miss_grace_fraction: 0.10,
                near_miss_grace: Duration::from_secs(3),
                early_abort_overrun_fraction: 0.25,
            }),
        )
        .timeout;

        assert_eq!(timeout, Some(Duration::ZERO));
    }

    #[test]
    fn flexible_slo_timeout_ignores_insufficient_history() {
        let timeout = flexible_slo_timeout_decision(
            Some(Duration::from_secs(5)),
            Some(Duration::from_secs(30)),
            Some(FlexibleSloPolicy {
                enabled: true,
                slo: Duration::from_secs(5),
                estimate: Some(HistoricalLatencyEstimate {
                    sample_count: 4,
                    average: Duration::from_secs(7),
                }),
                live_estimate: None,
                min_sample_count: 5,
                near_miss_grace_fraction: 0.10,
                near_miss_grace: Duration::from_secs(3),
                early_abort_overrun_fraction: 0.25,
            }),
        )
        .timeout;

        assert_eq!(timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    fn flexible_slo_decision_uses_live_estimate_without_history() {
        let decision = flexible_slo_timeout_decision(
            Some(Duration::from_secs(5)),
            Some(Duration::from_secs(30)),
            Some(FlexibleSloPolicy {
                enabled: true,
                slo: Duration::from_secs(5),
                estimate: None,
                live_estimate: Some(LiveLatencyEstimate {
                    stage: "local_upload_pack_first_byte_wait",
                    request_shape: "multi_tip",
                    historical_weight: 1.0,
                    elapsed: Duration::from_secs(4),
                    estimated_total: Duration::from_secs(10),
                }),
                min_sample_count: 5,
                near_miss_grace_fraction: 0.10,
                near_miss_grace: Duration::from_secs(3),
                early_abort_overrun_fraction: 0.25,
            }),
        );

        assert_eq!(decision.timeout, Some(Duration::ZERO));
        assert_eq!(
            decision.action,
            FlexibleSloDecisionAction::EarlyAbortEstimate
        );
    }

    #[test]
    fn flexible_slo_decision_weights_live_estimate_toward_recent_request() {
        let decision = flexible_slo_timeout_decision(
            Some(Duration::from_secs(5)),
            Some(Duration::from_secs(30)),
            Some(FlexibleSloPolicy {
                enabled: true,
                slo: Duration::from_secs(5),
                estimate: Some(HistoricalLatencyEstimate {
                    sample_count: 10,
                    average: Duration::from_secs(4),
                }),
                live_estimate: Some(LiveLatencyEstimate {
                    stage: "local_upload_pack_first_byte_wait",
                    request_shape: "multi_tip",
                    historical_weight: 1.0,
                    elapsed: Duration::from_secs(4),
                    estimated_total: Duration::from_secs(10),
                }),
                min_sample_count: 5,
                near_miss_grace_fraction: 0.10,
                near_miss_grace: Duration::from_secs(3),
                early_abort_overrun_fraction: 0.25,
            }),
        );

        assert_eq!(decision.timeout, Some(Duration::from_secs(5)));
        assert_eq!(
            decision.action,
            FlexibleSloDecisionAction::ConfiguredTimeout
        );
        assert_eq!(
            decision.effective_estimate,
            Some(Duration::from_millis(8200))
        );
    }

    #[test]
    fn flexible_slo_decision_caps_long_wait_at_live_early_abort_deadline() {
        let decision = flexible_slo_timeout_decision(
            Some(Duration::from_secs(30)),
            Some(Duration::from_secs(30)),
            Some(FlexibleSloPolicy {
                enabled: true,
                slo: Duration::from_secs(5),
                estimate: Some(HistoricalLatencyEstimate {
                    sample_count: 10,
                    average: Duration::from_secs(4),
                }),
                live_estimate: Some(LiveLatencyEstimate {
                    stage: "local_upload_pack_first_byte_wait",
                    request_shape: "multi_tip",
                    historical_weight: 1.0,
                    elapsed: Duration::from_secs(4),
                    estimated_total: Duration::from_secs(4),
                }),
                min_sample_count: 5,
                near_miss_grace_fraction: 0.10,
                near_miss_grace: Duration::from_secs(3),
                early_abort_overrun_fraction: 0.25,
            }),
        );

        assert_eq!(decision.timeout, Some(Duration::from_millis(5250)));
        assert_eq!(
            decision.action,
            FlexibleSloDecisionAction::EarlyAbortElapsed
        );
    }

    #[test]
    fn flexible_slo_decision_does_not_abort_narrow_request_from_full_clone_history() {
        let decision = flexible_slo_timeout_decision(
            Some(Duration::from_secs(5)),
            Some(Duration::from_secs(30)),
            Some(FlexibleSloPolicy {
                enabled: true,
                slo: Duration::from_secs(5),
                estimate: Some(HistoricalLatencyEstimate {
                    sample_count: 10,
                    average: Duration::from_secs(20),
                }),
                live_estimate: Some(LiveLatencyEstimate {
                    stage: "local_upload_pack_first_byte_wait",
                    request_shape: "shallow",
                    historical_weight: 0.0,
                    elapsed: Duration::ZERO,
                    estimated_total: Duration::ZERO,
                }),
                min_sample_count: 5,
                near_miss_grace_fraction: 0.10,
                near_miss_grace: Duration::from_secs(3),
                early_abort_overrun_fraction: 0.25,
            }),
        );

        assert_eq!(decision.timeout, Some(Duration::from_secs(5)));
        assert_eq!(
            decision.action,
            FlexibleSloDecisionAction::ConfiguredTimeout
        );
    }
}
