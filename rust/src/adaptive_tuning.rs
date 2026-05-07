use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use fred::clients::Pool;
use fred::interfaces::{HashesInterface, KeysInterface};
use fred::types::Expiration;
use serde::{Deserialize, Serialize};
use tokio::sync::{AcquireError, Notify, OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::config::{
    AdaptiveTuningBoundsConfig, AdaptiveTuningConfig, AdaptiveTuningController,
    AdaptiveTuningDemandResourceConfig, AdaptiveTuningKnobBoundsConfig, AdaptiveTuningMode,
    AdaptiveTuningResourcePressureConfig, Config,
};

const AIMD_CONTROLLER_NAME: &str = "aimd";
const AIMD_CONTROLLER_VERSION: &str = "v2";
const DEMAND_RESOURCE_CONTROLLER_NAME: &str = "demand_resource";
const DEMAND_RESOURCE_CONTROLLER_VERSION: &str = "v1";
const FOREGROUND_HEADROOM_MIN: usize = 1;
const FOREGROUND_HEADROOM_MAX: usize = 4;
const BACKGROUND_HEADROOM_MIN: usize = 1;
const BACKGROUND_HEADROOM_MAX: usize = 4;
const DEMAND_RESOURCE_PRESSURE_SAMPLE_WINDOW: Duration = Duration::from_millis(100);
const ADAPTIVE_LOCAL_UPLOAD_PACK_FIRST_BYTE_MIN_SECS: usize = 1;

#[derive(Debug)]
pub struct ResizableGate {
    semaphore: Arc<Semaphore>,
    state: Mutex<ResizableGateState>,
    active_claims: AtomicUsize,
    event_notify: Option<Arc<Notify>>,
}

#[derive(Debug)]
struct ResizableGateState {
    target: usize,
    pending_shrink: usize,
}

#[derive(Debug)]
pub struct ResizableGatePermit {
    permit: Option<OwnedSemaphorePermit>,
    gate: Arc<ResizableGate>,
}

impl ResizableGate {
    pub fn new(initial: usize) -> Arc<Self> {
        Self::new_with_notify(initial, None)
    }

    fn new_with_notify(initial: usize, event_notify: Option<Arc<Notify>>) -> Arc<Self> {
        Arc::new(Self {
            semaphore: Arc::new(Semaphore::new(initial)),
            state: Mutex::new(ResizableGateState {
                target: initial,
                pending_shrink: 0,
            }),
            active_claims: AtomicUsize::new(0),
            event_notify,
        })
    }

    pub fn limit(&self) -> usize {
        self.state
            .lock()
            .expect("resizable gate lock poisoned")
            .target
    }

    pub fn active_claims(&self) -> usize {
        self.active_claims.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }

    pub fn resize(&self, next: usize) {
        let mut state = self.state.lock().expect("resizable gate lock poisoned");
        let current = state.target;
        if next == current {
            return;
        }

        if next > current {
            let mut increase = next - current;
            let cancelled = state.pending_shrink.min(increase);
            state.pending_shrink -= cancelled;
            increase -= cancelled;
            state.target = next;
            drop(state);
            if increase > 0 {
                self.semaphore.add_permits(increase);
            }
            return;
        }

        state.target = next;
        drop(state);
        self.retire_available(current - next);
    }

    pub fn try_acquire_owned(
        self: &Arc<Self>,
    ) -> std::result::Result<ResizableGatePermit, TryAcquireError> {
        let permit = self.semaphore.clone().try_acquire_owned()?;
        self.active_claims.fetch_add(1, Ordering::Relaxed);
        self.notify_resource_event();
        Ok(ResizableGatePermit {
            permit: Some(permit),
            gate: Arc::clone(self),
        })
    }

    pub async fn acquire_owned(
        self: &Arc<Self>,
    ) -> std::result::Result<ResizableGatePermit, AcquireError> {
        let permit = self.semaphore.clone().acquire_owned().await?;
        self.active_claims.fetch_add(1, Ordering::Relaxed);
        self.notify_resource_event();
        Ok(ResizableGatePermit {
            permit: Some(permit),
            gate: Arc::clone(self),
        })
    }

    pub fn try_confirm_idle(&self, permit_count: u32) -> IdleGateState {
        match self.semaphore.clone().try_acquire_many_owned(permit_count) {
            Ok(permit) => {
                drop(permit);
                self.retire_pending_available();
                IdleGateState::Idle
            }
            Err(TryAcquireError::NoPermits) => IdleGateState::Busy,
            Err(TryAcquireError::Closed) => IdleGateState::Closed,
        }
    }

    fn retire_available(&self, count: usize) {
        let mut retired = 0usize;
        for _ in 0..count {
            match self.semaphore.clone().try_acquire_owned() {
                Ok(permit) => {
                    permit.forget();
                    retired += 1;
                }
                Err(TryAcquireError::NoPermits | TryAcquireError::Closed) => break,
            }
        }
        let remaining = count.saturating_sub(retired);
        if remaining > 0 {
            self.state
                .lock()
                .expect("resizable gate lock poisoned")
                .pending_shrink += remaining;
        }
    }

    fn retire_pending_available(&self) {
        loop {
            let should_retire = {
                let mut state = self.state.lock().expect("resizable gate lock poisoned");
                if state.pending_shrink == 0 {
                    return;
                }
                state.pending_shrink -= 1;
                true
            };
            if !should_retire {
                return;
            }
            match self.semaphore.clone().try_acquire_owned() {
                Ok(permit) => permit.forget(),
                Err(TryAcquireError::NoPermits | TryAcquireError::Closed) => {
                    let mut state = self.state.lock().expect("resizable gate lock poisoned");
                    state.pending_shrink += 1;
                    return;
                }
            }
        }
    }

    fn notify_resource_event(&self) {
        if let Some(notify) = &self.event_notify {
            notify.notify_one();
        }
    }
}

impl Drop for ResizableGatePermit {
    fn drop(&mut self) {
        drop(self.permit.take());
        self.gate.active_claims.fetch_sub(1, Ordering::Relaxed);
        self.gate.retire_pending_available();
        self.gate.notify_resource_event();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdleGateState {
    Idle,
    Busy,
    Closed,
}

#[derive(Clone, Debug)]
pub struct CachedResizableGate {
    limit: usize,
    gate: Arc<ResizableGate>,
}

impl CachedResizableGate {
    pub fn for_limit(limit: usize) -> Self {
        Self {
            limit,
            gate: ResizableGate::new(limit),
        }
    }

    pub fn gate_for_limit(&mut self, limit: usize) -> Arc<ResizableGate> {
        if self.limit != limit {
            *self = Self::for_limit(limit);
        }
        Arc::clone(&self.gate)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectivePolicy {
    pub upstream_clone_concurrency: usize,
    pub upstream_fetch_concurrency: usize,
    pub upstream_clone_per_repo_per_instance: usize,
    pub upstream_clone_per_repo_across_instances: usize,
    pub tee_capture_concurrency: usize,
    pub tee_capture_per_repo: usize,
    pub local_upload_pack_concurrency: usize,
    pub local_upload_pack_per_repo: usize,
    pub deep_validation_concurrency: usize,
    pub prewarm_concurrency: usize,
    pub bundle_generation_concurrency: usize,
    pub pack_cache_request_delta_concurrency: usize,
    pub pack_cache_background_warming_concurrency: usize,
    pub bundle_pack_threads: usize,
    pub local_upload_pack_threads: usize,
    pub index_pack_threads: usize,
    pub request_wait_for_local_catch_up_secs: usize,
    pub request_time_s3_restore_secs: usize,
    pub generation_publish_secs: usize,
    pub local_upload_pack_first_byte_secs: usize,
}

impl EffectivePolicy {
    pub fn from_config(
        config: &Config,
        clone_concurrency_limit: usize,
        bundle_policy: crate::config::BundleExecutionPolicy,
    ) -> Self {
        Self {
            upstream_clone_concurrency: clone_concurrency_limit,
            upstream_fetch_concurrency: config.clone.max_concurrent_upstream_fetches,
            upstream_clone_per_repo_per_instance: config
                .clone
                .max_concurrent_upstream_clones_per_repo_per_instance,
            upstream_clone_per_repo_across_instances: config
                .clone
                .max_concurrent_upstream_clones_per_repo_across_instances,
            tee_capture_concurrency: config.clone.max_concurrent_tee_captures,
            tee_capture_per_repo: config
                .clone
                .max_concurrent_tee_captures_per_repo_per_instance,
            local_upload_pack_concurrency: config.clone.max_concurrent_local_upload_packs,
            local_upload_pack_per_repo: config.clone.max_concurrent_local_upload_packs_per_repo,
            deep_validation_concurrency: config.clone.max_concurrent_deep_validations,
            prewarm_concurrency: config.prewarm.max_concurrent,
            bundle_generation_concurrency: bundle_policy.max_concurrent_generations,
            pack_cache_request_delta_concurrency: config.pack_cache.max_concurrent_request_deltas,
            pack_cache_background_warming_concurrency: config
                .pack_cache
                .max_concurrent_background_warmings,
            bundle_pack_threads: bundle_policy.pack_threads,
            local_upload_pack_threads: config.clone.local_upload_pack_threads,
            index_pack_threads: config.clone.index_pack_threads,
            request_wait_for_local_catch_up_secs: config
                .clone
                .request_wait_for_local_catch_up_secs
                .try_into()
                .unwrap_or(usize::MAX),
            request_time_s3_restore_secs: config
                .clone
                .request_time_s3_restore_secs
                .try_into()
                .unwrap_or(usize::MAX),
            generation_publish_secs: config
                .clone
                .generation_publish_secs
                .try_into()
                .unwrap_or(usize::MAX),
            local_upload_pack_first_byte_secs: config
                .clone
                .local_upload_pack_first_byte_secs
                .try_into()
                .unwrap_or(usize::MAX),
        }
    }

    pub fn bounded(self, bounds: &AdaptiveTuningBoundsConfig) -> Self {
        Self {
            upstream_clone_concurrency: clamp(
                self.upstream_clone_concurrency,
                bounds.upstream_clone_concurrency,
            ),
            upstream_fetch_concurrency: clamp(
                self.upstream_fetch_concurrency,
                bounds.upstream_fetch_concurrency,
            ),
            upstream_clone_per_repo_per_instance: clamp(
                self.upstream_clone_per_repo_per_instance,
                bounds.upstream_clone_per_repo_per_instance,
            ),
            upstream_clone_per_repo_across_instances: clamp(
                self.upstream_clone_per_repo_across_instances,
                bounds.upstream_clone_per_repo_across_instances,
            ),
            tee_capture_concurrency: clamp(
                self.tee_capture_concurrency,
                bounds.tee_capture_concurrency,
            ),
            tee_capture_per_repo: clamp(self.tee_capture_per_repo, bounds.tee_capture_per_repo),
            local_upload_pack_concurrency: clamp(
                self.local_upload_pack_concurrency,
                bounds.local_upload_pack_concurrency,
            ),
            local_upload_pack_per_repo: clamp(
                self.local_upload_pack_per_repo,
                bounds.local_upload_pack_per_repo,
            ),
            deep_validation_concurrency: clamp(
                self.deep_validation_concurrency,
                bounds.deep_validation_concurrency,
            ),
            prewarm_concurrency: clamp(self.prewarm_concurrency, bounds.prewarm_concurrency),
            bundle_generation_concurrency: clamp(
                self.bundle_generation_concurrency,
                bounds.bundle_generation_concurrency,
            ),
            pack_cache_request_delta_concurrency: clamp(
                self.pack_cache_request_delta_concurrency,
                bounds.pack_cache_request_delta_concurrency,
            ),
            pack_cache_background_warming_concurrency: clamp(
                self.pack_cache_background_warming_concurrency,
                bounds.pack_cache_background_warming_concurrency,
            ),
            bundle_pack_threads: clamp(self.bundle_pack_threads, bounds.bundle_pack_threads),
            local_upload_pack_threads: clamp(
                self.local_upload_pack_threads,
                bounds.local_upload_pack_threads,
            ),
            index_pack_threads: clamp(self.index_pack_threads, bounds.index_pack_threads),
            request_wait_for_local_catch_up_secs: clamp(
                self.request_wait_for_local_catch_up_secs,
                bounds.request_wait_for_local_catch_up_secs,
            ),
            request_time_s3_restore_secs: clamp(
                self.request_time_s3_restore_secs,
                bounds.request_time_s3_restore_secs,
            ),
            generation_publish_secs: clamp(
                self.generation_publish_secs,
                bounds.generation_publish_secs,
            ),
            local_upload_pack_first_byte_secs: clamp(
                self.local_upload_pack_first_byte_secs,
                bounds.local_upload_pack_first_byte_secs,
            ),
        }
    }

    fn bounded_for_adaptive_recommendation(self, bounds: &AdaptiveTuningBoundsConfig) -> Self {
        let mut policy = self.bounded(bounds);
        policy.local_upload_pack_first_byte_secs = clamp_adaptive_first_byte_wait(
            self.local_upload_pack_first_byte_secs,
            bounds.local_upload_pack_first_byte_secs,
        );
        policy
    }

    fn changed_knobs(self, other: Self) -> Vec<&'static str> {
        let mut knobs = Vec::new();
        macro_rules! changed {
            ($field:ident, $name:literal) => {
                if self.$field != other.$field {
                    knobs.push($name);
                }
            };
        }
        changed!(upstream_clone_concurrency, "upstream_clone_concurrency");
        changed!(upstream_fetch_concurrency, "upstream_fetch_concurrency");
        changed!(
            upstream_clone_per_repo_per_instance,
            "upstream_clone_per_repo_per_instance"
        );
        changed!(
            upstream_clone_per_repo_across_instances,
            "upstream_clone_per_repo_across_instances"
        );
        changed!(tee_capture_concurrency, "tee_capture_concurrency");
        changed!(tee_capture_per_repo, "tee_capture_per_repo");
        changed!(
            local_upload_pack_concurrency,
            "local_upload_pack_concurrency"
        );
        changed!(local_upload_pack_per_repo, "local_upload_pack_per_repo");
        changed!(deep_validation_concurrency, "deep_validation_concurrency");
        changed!(prewarm_concurrency, "prewarm_concurrency");
        changed!(
            bundle_generation_concurrency,
            "bundle_generation_concurrency"
        );
        changed!(
            pack_cache_request_delta_concurrency,
            "pack_cache_request_delta_concurrency"
        );
        changed!(
            pack_cache_background_warming_concurrency,
            "pack_cache_background_warming_concurrency"
        );
        changed!(bundle_pack_threads, "bundle_pack_threads");
        changed!(local_upload_pack_threads, "local_upload_pack_threads");
        changed!(index_pack_threads, "index_pack_threads");
        changed!(
            request_wait_for_local_catch_up_secs,
            "request_wait_for_local_catch_up_secs"
        );
        changed!(request_time_s3_restore_secs, "request_time_s3_restore_secs");
        changed!(generation_publish_secs, "generation_publish_secs");
        changed!(
            local_upload_pack_first_byte_secs,
            "local_upload_pack_first_byte_secs"
        );
        knobs
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoAdaptivePolicy {
    pub request_wait_for_local_catch_up_secs: usize,
    pub request_time_s3_restore_secs: usize,
    pub generation_publish_secs: usize,
    pub local_upload_pack_first_byte_secs: usize,
    pub upstream_clone_per_repo_per_instance: usize,
    pub upstream_clone_per_repo_across_instances: usize,
    pub local_upload_pack_per_repo: usize,
    pub tee_capture_per_repo: usize,
}

impl RepoAdaptivePolicy {
    pub fn from_effective_policy(policy: EffectivePolicy) -> Self {
        Self {
            request_wait_for_local_catch_up_secs: policy.request_wait_for_local_catch_up_secs,
            request_time_s3_restore_secs: policy.request_time_s3_restore_secs,
            generation_publish_secs: policy.generation_publish_secs,
            local_upload_pack_first_byte_secs: policy.local_upload_pack_first_byte_secs,
            upstream_clone_per_repo_per_instance: policy.upstream_clone_per_repo_per_instance,
            upstream_clone_per_repo_across_instances: policy
                .upstream_clone_per_repo_across_instances,
            local_upload_pack_per_repo: policy.local_upload_pack_per_repo,
            tee_capture_per_repo: policy.tee_capture_per_repo,
        }
    }

    pub fn bounded(self, bounds: &AdaptiveTuningBoundsConfig) -> Self {
        Self {
            request_wait_for_local_catch_up_secs: clamp(
                self.request_wait_for_local_catch_up_secs,
                bounds.request_wait_for_local_catch_up_secs,
            ),
            request_time_s3_restore_secs: clamp(
                self.request_time_s3_restore_secs,
                bounds.request_time_s3_restore_secs,
            ),
            generation_publish_secs: clamp(
                self.generation_publish_secs,
                bounds.generation_publish_secs,
            ),
            local_upload_pack_first_byte_secs: clamp(
                self.local_upload_pack_first_byte_secs,
                bounds.local_upload_pack_first_byte_secs,
            ),
            upstream_clone_per_repo_per_instance: clamp(
                self.upstream_clone_per_repo_per_instance,
                bounds.upstream_clone_per_repo_per_instance,
            ),
            upstream_clone_per_repo_across_instances: clamp(
                self.upstream_clone_per_repo_across_instances,
                bounds.upstream_clone_per_repo_across_instances,
            ),
            local_upload_pack_per_repo: clamp(
                self.local_upload_pack_per_repo,
                bounds.local_upload_pack_per_repo,
            ),
            tee_capture_per_repo: clamp(self.tee_capture_per_repo, bounds.tee_capture_per_repo),
        }
    }

    fn bounded_for_adaptive_recommendation(self, bounds: &AdaptiveTuningBoundsConfig) -> Self {
        let mut policy = self.bounded(bounds);
        policy.local_upload_pack_first_byte_secs = clamp_adaptive_first_byte_wait(
            self.local_upload_pack_first_byte_secs,
            bounds.local_upload_pack_first_byte_secs,
        );
        policy
    }

    fn changed_knobs(self, other: Self) -> Vec<&'static str> {
        let mut knobs = Vec::new();
        macro_rules! changed {
            ($field:ident, $name:literal) => {
                if self.$field != other.$field {
                    knobs.push($name);
                }
            };
        }
        changed!(
            request_wait_for_local_catch_up_secs,
            "request_wait_for_local_catch_up_secs"
        );
        changed!(request_time_s3_restore_secs, "request_time_s3_restore_secs");
        changed!(generation_publish_secs, "generation_publish_secs");
        changed!(
            local_upload_pack_first_byte_secs,
            "local_upload_pack_first_byte_secs"
        );
        changed!(
            upstream_clone_per_repo_per_instance,
            "upstream_clone_per_repo_per_instance"
        );
        changed!(
            upstream_clone_per_repo_across_instances,
            "upstream_clone_per_repo_across_instances"
        );
        changed!(local_upload_pack_per_repo, "local_upload_pack_per_repo");
        changed!(tee_capture_per_repo, "tee_capture_per_repo");
        knobs
    }
}

fn clamp(value: usize, bounds: AdaptiveTuningKnobBoundsConfig) -> usize {
    value.clamp(bounds.min, bounds.max)
}

fn clamp_adaptive_first_byte_wait(value: usize, bounds: AdaptiveTuningKnobBoundsConfig) -> usize {
    let min = bounds
        .min
        .max(ADAPTIVE_LOCAL_UPLOAD_PACK_FIRST_BYTE_MIN_SECS);
    value.clamp(min, bounds.max.max(min))
}

fn bound_effective_adaptive_recommendation(
    policy: EffectivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
    preserve_operator_first_byte_zero: bool,
) -> EffectivePolicy {
    let mut policy = policy.bounded_for_adaptive_recommendation(bounds);
    if preserve_operator_first_byte_zero {
        policy.local_upload_pack_first_byte_secs = 0;
    }
    policy
}

fn bound_repo_adaptive_recommendation(
    policy: RepoAdaptivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
    preserve_operator_first_byte_zero: bool,
) -> RepoAdaptivePolicy {
    let mut policy = policy.bounded_for_adaptive_recommendation(bounds);
    if preserve_operator_first_byte_zero {
        policy.local_upload_pack_first_byte_secs = 0;
    }
    policy
}

#[derive(Debug)]
pub struct EffectivePolicyState {
    policy: EffectivePolicyAtomics,
    event_notify: Arc<Notify>,
    pub clone_gate: Arc<ResizableGate>,
    pub fetch_gate: Arc<ResizableGate>,
    pub low_priority_fetch_gate: Arc<ResizableGate>,
    pub tee_capture_gate: Arc<ResizableGate>,
    pub bundle_generation_gate: Arc<ResizableGate>,
    pub pack_cache_background_warming_gate: Arc<ResizableGate>,
    pub request_pack_delta_gate: Arc<ResizableGate>,
    pub local_upload_pack_gate: Arc<ResizableGate>,
    pub deep_validation_gate: Arc<ResizableGate>,
    pub prewarm_gate: Arc<ResizableGate>,
    repo_policy_overlays: RwLock<HashMap<String, RepoAdaptivePolicy>>,
    reserved_request_time_fetches: AtomicUsize,
}

#[derive(Debug)]
struct EffectivePolicyAtomics {
    upstream_clone_concurrency: AtomicUsize,
    upstream_fetch_concurrency: AtomicUsize,
    upstream_clone_per_repo_per_instance: AtomicUsize,
    upstream_clone_per_repo_across_instances: AtomicUsize,
    tee_capture_concurrency: AtomicUsize,
    tee_capture_per_repo: AtomicUsize,
    local_upload_pack_concurrency: AtomicUsize,
    local_upload_pack_per_repo: AtomicUsize,
    deep_validation_concurrency: AtomicUsize,
    prewarm_concurrency: AtomicUsize,
    bundle_generation_concurrency: AtomicUsize,
    pack_cache_request_delta_concurrency: AtomicUsize,
    pack_cache_background_warming_concurrency: AtomicUsize,
    bundle_pack_threads: AtomicUsize,
    local_upload_pack_threads: AtomicUsize,
    index_pack_threads: AtomicUsize,
    request_wait_for_local_catch_up_secs: AtomicUsize,
    request_time_s3_restore_secs: AtomicUsize,
    generation_publish_secs: AtomicUsize,
    local_upload_pack_first_byte_secs: AtomicUsize,
}

impl EffectivePolicyState {
    pub fn new(policy: EffectivePolicy, reserved_request_time_fetches: usize) -> Arc<Self> {
        let event_notify = Arc::new(Notify::new());
        Arc::new(Self {
            policy: EffectivePolicyAtomics::new(policy),
            event_notify: Arc::clone(&event_notify),
            clone_gate: ResizableGate::new_with_notify(
                policy.upstream_clone_concurrency,
                Some(Arc::clone(&event_notify)),
            ),
            fetch_gate: ResizableGate::new_with_notify(
                policy.upstream_fetch_concurrency,
                Some(Arc::clone(&event_notify)),
            ),
            low_priority_fetch_gate: ResizableGate::new_with_notify(
                policy
                    .upstream_fetch_concurrency
                    .saturating_sub(reserved_request_time_fetches),
                Some(Arc::clone(&event_notify)),
            ),
            tee_capture_gate: ResizableGate::new_with_notify(
                policy.tee_capture_concurrency,
                Some(Arc::clone(&event_notify)),
            ),
            bundle_generation_gate: ResizableGate::new_with_notify(
                policy.bundle_generation_concurrency,
                Some(Arc::clone(&event_notify)),
            ),
            pack_cache_background_warming_gate: ResizableGate::new_with_notify(
                policy.pack_cache_background_warming_concurrency,
                Some(Arc::clone(&event_notify)),
            ),
            request_pack_delta_gate: ResizableGate::new_with_notify(
                policy.pack_cache_request_delta_concurrency,
                Some(Arc::clone(&event_notify)),
            ),
            local_upload_pack_gate: ResizableGate::new_with_notify(
                policy.local_upload_pack_concurrency,
                Some(Arc::clone(&event_notify)),
            ),
            deep_validation_gate: ResizableGate::new_with_notify(
                policy.deep_validation_concurrency,
                Some(Arc::clone(&event_notify)),
            ),
            prewarm_gate: ResizableGate::new_with_notify(
                policy.prewarm_concurrency,
                Some(Arc::clone(&event_notify)),
            ),
            repo_policy_overlays: RwLock::new(HashMap::new()),
            reserved_request_time_fetches: AtomicUsize::new(reserved_request_time_fetches),
        })
    }

    pub fn event_notifier(&self) -> Arc<Notify> {
        Arc::clone(&self.event_notify)
    }

    pub fn demand_snapshot(&self) -> RuntimeDemandSnapshot {
        RuntimeDemandSnapshot {
            upstream_clone_claims: self.clone_gate.active_claims(),
            upstream_fetch_claims: self.fetch_gate.active_claims(),
            low_priority_fetch_claims: self.low_priority_fetch_gate.active_claims(),
            tee_capture_claims: self.tee_capture_gate.active_claims(),
            bundle_generation_claims: self.bundle_generation_gate.active_claims(),
            pack_cache_background_warming_claims: self
                .pack_cache_background_warming_gate
                .active_claims(),
            request_pack_delta_claims: self.request_pack_delta_gate.active_claims(),
            local_upload_pack_claims: self.local_upload_pack_gate.active_claims(),
            deep_validation_claims: self.deep_validation_gate.active_claims(),
            prewarm_claims: self.prewarm_gate.active_claims(),
        }
    }

    pub fn snapshot(&self) -> EffectivePolicy {
        self.policy.snapshot()
    }

    pub fn low_priority_fetch_limit(&self) -> usize {
        self.snapshot()
            .upstream_fetch_concurrency
            .saturating_sub(self.reserved_request_time_fetches.load(Ordering::Relaxed))
    }

    pub fn repo_policy(&self, owner_repo: &str) -> RepoAdaptivePolicy {
        let owner_repo = crate::repo_identity::canonicalize_owner_repo(owner_repo);
        if let Some(policy) = self
            .repo_policy_overlays
            .read()
            .expect("repo policy overlay lock poisoned")
            .get(&owner_repo)
            .copied()
        {
            return policy;
        }
        RepoAdaptivePolicy::from_effective_policy(self.snapshot())
    }

    pub fn apply_repo_policy(&self, owner_repo: &str, policy: RepoAdaptivePolicy) {
        let owner_repo = crate::repo_identity::canonicalize_owner_repo(owner_repo);
        self.repo_policy_overlays
            .write()
            .expect("repo policy overlay lock poisoned")
            .insert(owner_repo, policy);
    }

    pub fn apply(&self, policy: EffectivePolicy) {
        self.policy.store(policy);
        self.clone_gate.resize(policy.upstream_clone_concurrency);
        self.fetch_gate.resize(policy.upstream_fetch_concurrency);
        self.low_priority_fetch_gate.resize(
            policy
                .upstream_fetch_concurrency
                .saturating_sub(self.reserved_request_time_fetches.load(Ordering::Relaxed)),
        );
        self.bundle_generation_gate
            .resize(policy.bundle_generation_concurrency);
        self.tee_capture_gate.resize(policy.tee_capture_concurrency);
        self.pack_cache_background_warming_gate
            .resize(policy.pack_cache_background_warming_concurrency);
        self.request_pack_delta_gate
            .resize(policy.pack_cache_request_delta_concurrency);
        self.local_upload_pack_gate
            .resize(policy.local_upload_pack_concurrency);
        self.deep_validation_gate
            .resize(policy.deep_validation_concurrency);
        self.prewarm_gate.resize(policy.prewarm_concurrency);
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeDemandSnapshot {
    pub upstream_clone_claims: usize,
    pub upstream_fetch_claims: usize,
    pub low_priority_fetch_claims: usize,
    pub tee_capture_claims: usize,
    pub bundle_generation_claims: usize,
    pub pack_cache_background_warming_claims: usize,
    pub request_pack_delta_claims: usize,
    pub local_upload_pack_claims: usize,
    pub deep_validation_claims: usize,
    pub prewarm_claims: usize,
}

impl RuntimeDemandSnapshot {
    fn max_with(self, other: Self) -> Self {
        Self {
            upstream_clone_claims: self.upstream_clone_claims.max(other.upstream_clone_claims),
            upstream_fetch_claims: self.upstream_fetch_claims.max(other.upstream_fetch_claims),
            low_priority_fetch_claims: self
                .low_priority_fetch_claims
                .max(other.low_priority_fetch_claims),
            tee_capture_claims: self.tee_capture_claims.max(other.tee_capture_claims),
            bundle_generation_claims: self
                .bundle_generation_claims
                .max(other.bundle_generation_claims),
            pack_cache_background_warming_claims: self
                .pack_cache_background_warming_claims
                .max(other.pack_cache_background_warming_claims),
            request_pack_delta_claims: self
                .request_pack_delta_claims
                .max(other.request_pack_delta_claims),
            local_upload_pack_claims: self
                .local_upload_pack_claims
                .max(other.local_upload_pack_claims),
            deep_validation_claims: self
                .deep_validation_claims
                .max(other.deep_validation_claims),
            prewarm_claims: self.prewarm_claims.max(other.prewarm_claims),
        }
    }

    fn has_active_claims(self) -> bool {
        self.foreground_claims()
            .saturating_add(self.tee_capture_claims)
            .saturating_add(self.bundle_generation_claims)
            .saturating_add(self.pack_cache_background_warming_claims)
            .saturating_add(self.deep_validation_claims)
            .saturating_add(self.prewarm_claims)
            .saturating_add(self.low_priority_fetch_claims)
            > 0
    }

    fn foreground_claims(self) -> usize {
        self.upstream_clone_claims
            .saturating_add(
                self.upstream_fetch_claims
                    .saturating_sub(self.low_priority_fetch_claims),
            )
            .saturating_add(self.request_pack_delta_claims)
            .saturating_add(self.local_upload_pack_claims)
    }
}

impl EffectivePolicyAtomics {
    fn new(policy: EffectivePolicy) -> Self {
        Self {
            upstream_clone_concurrency: AtomicUsize::new(policy.upstream_clone_concurrency),
            upstream_fetch_concurrency: AtomicUsize::new(policy.upstream_fetch_concurrency),
            upstream_clone_per_repo_per_instance: AtomicUsize::new(
                policy.upstream_clone_per_repo_per_instance,
            ),
            upstream_clone_per_repo_across_instances: AtomicUsize::new(
                policy.upstream_clone_per_repo_across_instances,
            ),
            tee_capture_concurrency: AtomicUsize::new(policy.tee_capture_concurrency),
            tee_capture_per_repo: AtomicUsize::new(policy.tee_capture_per_repo),
            local_upload_pack_concurrency: AtomicUsize::new(policy.local_upload_pack_concurrency),
            local_upload_pack_per_repo: AtomicUsize::new(policy.local_upload_pack_per_repo),
            deep_validation_concurrency: AtomicUsize::new(policy.deep_validation_concurrency),
            prewarm_concurrency: AtomicUsize::new(policy.prewarm_concurrency),
            bundle_generation_concurrency: AtomicUsize::new(policy.bundle_generation_concurrency),
            pack_cache_request_delta_concurrency: AtomicUsize::new(
                policy.pack_cache_request_delta_concurrency,
            ),
            pack_cache_background_warming_concurrency: AtomicUsize::new(
                policy.pack_cache_background_warming_concurrency,
            ),
            bundle_pack_threads: AtomicUsize::new(policy.bundle_pack_threads),
            local_upload_pack_threads: AtomicUsize::new(policy.local_upload_pack_threads),
            index_pack_threads: AtomicUsize::new(policy.index_pack_threads),
            request_wait_for_local_catch_up_secs: AtomicUsize::new(
                policy.request_wait_for_local_catch_up_secs,
            ),
            request_time_s3_restore_secs: AtomicUsize::new(policy.request_time_s3_restore_secs),
            generation_publish_secs: AtomicUsize::new(policy.generation_publish_secs),
            local_upload_pack_first_byte_secs: AtomicUsize::new(
                policy.local_upload_pack_first_byte_secs,
            ),
        }
    }

    fn snapshot(&self) -> EffectivePolicy {
        EffectivePolicy {
            upstream_clone_concurrency: self.upstream_clone_concurrency.load(Ordering::Relaxed),
            upstream_fetch_concurrency: self.upstream_fetch_concurrency.load(Ordering::Relaxed),
            upstream_clone_per_repo_per_instance: self
                .upstream_clone_per_repo_per_instance
                .load(Ordering::Relaxed),
            upstream_clone_per_repo_across_instances: self
                .upstream_clone_per_repo_across_instances
                .load(Ordering::Relaxed),
            tee_capture_concurrency: self.tee_capture_concurrency.load(Ordering::Relaxed),
            tee_capture_per_repo: self.tee_capture_per_repo.load(Ordering::Relaxed),
            local_upload_pack_concurrency: self
                .local_upload_pack_concurrency
                .load(Ordering::Relaxed),
            local_upload_pack_per_repo: self.local_upload_pack_per_repo.load(Ordering::Relaxed),
            deep_validation_concurrency: self.deep_validation_concurrency.load(Ordering::Relaxed),
            prewarm_concurrency: self.prewarm_concurrency.load(Ordering::Relaxed),
            bundle_generation_concurrency: self
                .bundle_generation_concurrency
                .load(Ordering::Relaxed),
            pack_cache_request_delta_concurrency: self
                .pack_cache_request_delta_concurrency
                .load(Ordering::Relaxed),
            pack_cache_background_warming_concurrency: self
                .pack_cache_background_warming_concurrency
                .load(Ordering::Relaxed),
            bundle_pack_threads: self.bundle_pack_threads.load(Ordering::Relaxed),
            local_upload_pack_threads: self.local_upload_pack_threads.load(Ordering::Relaxed),
            index_pack_threads: self.index_pack_threads.load(Ordering::Relaxed),
            request_wait_for_local_catch_up_secs: self
                .request_wait_for_local_catch_up_secs
                .load(Ordering::Relaxed),
            request_time_s3_restore_secs: self.request_time_s3_restore_secs.load(Ordering::Relaxed),
            generation_publish_secs: self.generation_publish_secs.load(Ordering::Relaxed),
            local_upload_pack_first_byte_secs: self
                .local_upload_pack_first_byte_secs
                .load(Ordering::Relaxed),
        }
    }

    fn store(&self, policy: EffectivePolicy) {
        self.upstream_clone_concurrency
            .store(policy.upstream_clone_concurrency, Ordering::Relaxed);
        self.upstream_fetch_concurrency
            .store(policy.upstream_fetch_concurrency, Ordering::Relaxed);
        self.upstream_clone_per_repo_per_instance.store(
            policy.upstream_clone_per_repo_per_instance,
            Ordering::Relaxed,
        );
        self.upstream_clone_per_repo_across_instances.store(
            policy.upstream_clone_per_repo_across_instances,
            Ordering::Relaxed,
        );
        self.tee_capture_concurrency
            .store(policy.tee_capture_concurrency, Ordering::Relaxed);
        self.tee_capture_per_repo
            .store(policy.tee_capture_per_repo, Ordering::Relaxed);
        self.local_upload_pack_concurrency
            .store(policy.local_upload_pack_concurrency, Ordering::Relaxed);
        self.local_upload_pack_per_repo
            .store(policy.local_upload_pack_per_repo, Ordering::Relaxed);
        self.deep_validation_concurrency
            .store(policy.deep_validation_concurrency, Ordering::Relaxed);
        self.prewarm_concurrency
            .store(policy.prewarm_concurrency, Ordering::Relaxed);
        self.bundle_generation_concurrency
            .store(policy.bundle_generation_concurrency, Ordering::Relaxed);
        self.pack_cache_request_delta_concurrency.store(
            policy.pack_cache_request_delta_concurrency,
            Ordering::Relaxed,
        );
        self.pack_cache_background_warming_concurrency.store(
            policy.pack_cache_background_warming_concurrency,
            Ordering::Relaxed,
        );
        self.bundle_pack_threads
            .store(policy.bundle_pack_threads, Ordering::Relaxed);
        self.local_upload_pack_threads
            .store(policy.local_upload_pack_threads, Ordering::Relaxed);
        self.index_pack_threads
            .store(policy.index_pack_threads, Ordering::Relaxed);
        self.request_wait_for_local_catch_up_secs.store(
            policy.request_wait_for_local_catch_up_secs,
            Ordering::Relaxed,
        );
        self.request_time_s3_restore_secs
            .store(policy.request_time_s3_restore_secs, Ordering::Relaxed);
        self.generation_publish_secs
            .store(policy.generation_publish_secs, Ordering::Relaxed);
        self.local_upload_pack_first_byte_secs
            .store(policy.local_upload_pack_first_byte_secs, Ordering::Relaxed);
    }
}

#[derive(Debug, Default)]
pub struct AdaptiveObservationCounters {
    clone_samples: AtomicU64,
    clone_latency_millis_total: AtomicU64,
    first_byte_samples: AtomicU64,
    first_byte_latency_millis_total: AtomicU64,
    ttfb_stage_samples: AtomicU64,
    ttfb_stage_published_generation_lease_wait_millis_total: AtomicU64,
    ttfb_stage_pack_cache_lookup_wait_millis_total: AtomicU64,
    ttfb_stage_pack_cache_composite_wait_millis_total: AtomicU64,
    ttfb_stage_local_upload_pack_permit_wait_millis_total: AtomicU64,
    ttfb_stage_local_upload_pack_spawn_and_stdin_millis_total: AtomicU64,
    ttfb_stage_local_upload_pack_first_byte_wait_millis_total: AtomicU64,
    upstream_fallbacks: AtomicU64,
    fallback_local_upload_pack_permit: AtomicU64,
    fallback_local_upload_pack_first_byte: AtomicU64,
    fallback_local_catch_up: AtomicU64,
    fallback_published_generation_lease: AtomicU64,
    fallback_pack_cache_lookup: AtomicU64,
    fallback_upstream_clone_global: AtomicU64,
    fallback_upstream_clone_repo: AtomicU64,
    fallback_unknown: AtomicU64,
    repo_observations: Mutex<RepoObservationState>,
    event_notify: Notify,
}

#[derive(Debug, Default)]
struct RepoObservationState {
    totals: HashMap<String, ObservationTotals>,
    request_cost_totals: HashMap<String, RepoRequestCostObservationState>,
    changed_repos: HashSet<String>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ObservationTotals {
    pub clone_samples: u64,
    pub clone_latency_millis_total: u64,
    pub first_byte_samples: u64,
    pub first_byte_latency_millis_total: u64,
    pub ttfb_stage_samples: u64,
    pub ttfb_stage_millis_total: TtfbStageBreakdown,
    pub upstream_fallbacks: u64,
    pub fallback_local_upload_pack_permit: u64,
    pub fallback_local_upload_pack_first_byte: u64,
    pub fallback_local_catch_up: u64,
    pub fallback_published_generation_lease: u64,
    pub fallback_pack_cache_lookup: u64,
    pub fallback_upstream_clone_global: u64,
    pub fallback_upstream_clone_repo: u64,
    pub fallback_unknown: u64,
}

impl ObservationTotals {
    fn inc_fallback_target(&mut self, target: FallbackRecoveryTarget) {
        let counter = match target {
            FallbackRecoveryTarget::LocalUploadPackPermit => {
                &mut self.fallback_local_upload_pack_permit
            }
            FallbackRecoveryTarget::LocalUploadPackFirstByte => {
                &mut self.fallback_local_upload_pack_first_byte
            }
            FallbackRecoveryTarget::LocalCatchUp => &mut self.fallback_local_catch_up,
            FallbackRecoveryTarget::PublishedGenerationLease => {
                &mut self.fallback_published_generation_lease
            }
            FallbackRecoveryTarget::PackCacheLookup => &mut self.fallback_pack_cache_lookup,
            FallbackRecoveryTarget::UpstreamCloneGlobal => &mut self.fallback_upstream_clone_global,
            FallbackRecoveryTarget::UpstreamCloneRepo => &mut self.fallback_upstream_clone_repo,
            FallbackRecoveryTarget::Unknown => &mut self.fallback_unknown,
        };
        *counter = counter.saturating_add(1);
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestCostShape {
    pub want_width: RequestWantWidth,
    pub ref_shape: RequestRefShape,
    pub filter: RequestFilterShape,
    pub shallow: RequestShallowShape,
    pub negotiation: RequestNegotiationShape,
}

impl RequestCostShape {
    pub fn family_key(self) -> Self {
        Self {
            ref_shape: self.ref_shape.family_key(),
            ..self
        }
    }

    pub fn label(self) -> &'static str {
        match (self.want_width, self.filter, self.shallow, self.ref_shape) {
            (_, RequestFilterShape::BlobNone, _, _) => "blobless",
            (_, RequestFilterShape::TreeZero, _, _) => "treeless",
            (_, RequestFilterShape::BlobLimit, _, _) => "blob_limited",
            (_, RequestFilterShape::Other, _, _) => "filtered",
            (_, _, RequestShallowShape::Depth1, _) => "depth_1",
            (_, _, RequestShallowShape::DepthSmall, _) => "shallow_small",
            (_, _, RequestShallowShape::DepthLarge, _) => "shallow_large",
            (_, _, RequestShallowShape::SinceOrNot, _) => "shallow_time",
            (RequestWantWidth::One, _, _, RequestRefShape::DefaultBranch) => {
                "single_default_branch"
            }
            (RequestWantWidth::One, _, _, RequestRefShape::NamedBranch { .. }) => {
                "single_named_branch"
            }
            (RequestWantWidth::One, _, _, RequestRefShape::Tag { .. }) => "single_tag",
            (RequestWantWidth::One, _, _, RequestRefShape::PullRef { .. }) => "single_pull_ref",
            (RequestWantWidth::One, _, _, _) => "single_tip",
            (RequestWantWidth::Unknown, _, _, _) => "unknown",
            (RequestWantWidth::FullTipSet, _, _, _) => "full_tip_set",
            _ => "multi_tip",
        }
    }

    pub fn repo_fallback_history_weight(self) -> f64 {
        match (self.want_width, self.filter, self.shallow) {
            (RequestWantWidth::Unknown, _, _) => 1.0,
            (RequestWantWidth::FullTipSet, RequestFilterShape::None, RequestShallowShape::None) => {
                1.0
            }
            (_, RequestFilterShape::None, RequestShallowShape::None) => 0.35,
            (_, _, RequestShallowShape::Depth1) => 0.10,
            (_, _, _) => 0.20,
        }
    }

    pub fn intrinsic_pack_thread_fraction(self) -> f64 {
        if self.shallow == RequestShallowShape::Depth1 && self.want_width == RequestWantWidth::One {
            return 0.15;
        }
        if self.filter != RequestFilterShape::None || self.shallow != RequestShallowShape::None {
            return match self.want_width {
                RequestWantWidth::One => 0.25,
                RequestWantWidth::Few => 0.35,
                RequestWantWidth::Many => 0.50,
                RequestWantWidth::VeryMany | RequestWantWidth::FullTipSet => 0.70,
                RequestWantWidth::Unknown => 0.50,
            };
        }
        match self.want_width {
            RequestWantWidth::Unknown => 1.0,
            RequestWantWidth::One => 0.35,
            RequestWantWidth::Few => 0.50,
            RequestWantWidth::Many => 0.70,
            RequestWantWidth::VeryMany | RequestWantWidth::FullTipSet => 1.0,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestWantWidth {
    #[default]
    Unknown,
    One,
    Few,
    Many,
    VeryMany,
    FullTipSet,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestRefShape {
    #[default]
    Unknown,
    DefaultBranch,
    NamedBranch {
        fingerprint: u64,
    },
    Tag {
        fingerprint: u64,
    },
    PullRef {
        fingerprint: u64,
    },
    OtherRef {
        fingerprint: u64,
    },
    UnmatchedOid,
    MultiRefSet,
    FullTipSet,
}

impl RequestRefShape {
    fn family_key(self) -> Self {
        match self {
            Self::NamedBranch { .. } => Self::NamedBranch { fingerprint: 0 },
            Self::Tag { .. } => Self::Tag { fingerprint: 0 },
            Self::PullRef { .. } => Self::PullRef { fingerprint: 0 },
            Self::OtherRef { .. } => Self::OtherRef { fingerprint: 0 },
            other => other,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestFilterShape {
    #[default]
    None,
    BlobNone,
    TreeZero,
    BlobLimit,
    Other,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestShallowShape {
    #[default]
    None,
    Depth1,
    DepthSmall,
    DepthLarge,
    SinceOrNot,
    Other,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestNegotiationShape {
    #[default]
    Unknown,
    NoHaves,
    HasHaves,
}

#[derive(Clone, Copy, Debug, Default)]
struct RequestCostObservationTotals {
    first_byte_samples: u64,
    first_byte_latency_millis_total: u64,
    ttfb_stage_samples: u64,
    ttfb_stage_millis_total: TtfbStageBreakdown,
    local_upload_pack_first_byte_fallbacks: u64,
}

impl RequestCostObservationTotals {
    fn observe_first_byte(&mut self, elapsed: Duration) {
        self.first_byte_samples = self.first_byte_samples.saturating_add(1);
        self.first_byte_latency_millis_total = self
            .first_byte_latency_millis_total
            .saturating_add(duration_millis(elapsed));
    }

    fn observe_ttfb_breakdown(&mut self, breakdown: TtfbStageBreakdown) {
        self.ttfb_stage_samples = self.ttfb_stage_samples.saturating_add(1);
        for stage in TtfbStage::ALL {
            self.ttfb_stage_millis_total
                .add_stage_millis(stage, breakdown.stage_millis(stage));
        }
    }

    fn observe_local_upload_pack_first_byte_fallback(&mut self) {
        self.local_upload_pack_first_byte_fallbacks = self
            .local_upload_pack_first_byte_fallbacks
            .saturating_add(1);
    }

    fn first_byte_estimate(self) -> Option<crate::short_circuit::HistoricalLatencyEstimate> {
        latency_estimate(
            self.first_byte_samples,
            self.first_byte_latency_millis_total,
        )
    }

    fn ttfb_stage_estimate(self) -> Option<TtfbStageEstimate> {
        ttfb_stage_estimate(self.ttfb_stage_samples, self.ttfb_stage_millis_total)
    }
}

#[derive(Debug, Default)]
struct RepoRequestCostObservationState {
    exact: HashMap<RequestCostShape, RequestCostObservationTotals>,
    family: HashMap<RequestCostShape, RequestCostObservationTotals>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct WeightedTtfbStageEstimate {
    pub estimate: TtfbStageEstimate,
    pub historical_weight: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TtfbStage {
    PublishedGenerationLeaseWait,
    PackCacheLookupWait,
    PackCacheCompositeWait,
    LocalUploadPackPermitWait,
    LocalUploadPackSpawnAndStdin,
    LocalUploadPackFirstByteWait,
}

impl TtfbStage {
    pub const ALL: [Self; 6] = [
        Self::PublishedGenerationLeaseWait,
        Self::PackCacheLookupWait,
        Self::PackCacheCompositeWait,
        Self::LocalUploadPackPermitWait,
        Self::LocalUploadPackSpawnAndStdin,
        Self::LocalUploadPackFirstByteWait,
    ];

    pub fn as_label(self) -> &'static str {
        match self {
            Self::PublishedGenerationLeaseWait => "published_generation_lease_wait",
            Self::PackCacheLookupWait => "pack_cache_lookup_wait",
            Self::PackCacheCompositeWait => "pack_cache_composite_wait",
            Self::LocalUploadPackPermitWait => "local_upload_pack_permit_wait",
            Self::LocalUploadPackSpawnAndStdin => "local_upload_pack_spawn_and_stdin",
            Self::LocalUploadPackFirstByteWait => "local_upload_pack_first_byte_wait",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::PublishedGenerationLeaseWait => 0,
            Self::PackCacheLookupWait => 1,
            Self::PackCacheCompositeWait => 2,
            Self::LocalUploadPackPermitWait => 3,
            Self::LocalUploadPackSpawnAndStdin => 4,
            Self::LocalUploadPackFirstByteWait => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TtfbStageBreakdown {
    pub published_generation_lease_wait_millis_total: u64,
    pub pack_cache_lookup_wait_millis_total: u64,
    pub pack_cache_composite_wait_millis_total: u64,
    pub local_upload_pack_permit_wait_millis_total: u64,
    pub local_upload_pack_spawn_and_stdin_millis_total: u64,
    pub local_upload_pack_first_byte_wait_millis_total: u64,
}

impl TtfbStageBreakdown {
    pub fn add_stage(&mut self, stage: TtfbStage, elapsed: Duration) {
        self.add_stage_millis(stage, duration_millis(elapsed));
    }

    pub fn add_stage_millis(&mut self, stage: TtfbStage, millis: u64) {
        let target = match stage {
            TtfbStage::PublishedGenerationLeaseWait => {
                &mut self.published_generation_lease_wait_millis_total
            }
            TtfbStage::PackCacheLookupWait => &mut self.pack_cache_lookup_wait_millis_total,
            TtfbStage::PackCacheCompositeWait => &mut self.pack_cache_composite_wait_millis_total,
            TtfbStage::LocalUploadPackPermitWait => {
                &mut self.local_upload_pack_permit_wait_millis_total
            }
            TtfbStage::LocalUploadPackSpawnAndStdin => {
                &mut self.local_upload_pack_spawn_and_stdin_millis_total
            }
            TtfbStage::LocalUploadPackFirstByteWait => {
                &mut self.local_upload_pack_first_byte_wait_millis_total
            }
        };
        *target = target.saturating_add(millis);
    }

    pub fn stage_millis(self, stage: TtfbStage) -> u64 {
        match stage {
            TtfbStage::PublishedGenerationLeaseWait => {
                self.published_generation_lease_wait_millis_total
            }
            TtfbStage::PackCacheLookupWait => self.pack_cache_lookup_wait_millis_total,
            TtfbStage::PackCacheCompositeWait => self.pack_cache_composite_wait_millis_total,
            TtfbStage::LocalUploadPackPermitWait => self.local_upload_pack_permit_wait_millis_total,
            TtfbStage::LocalUploadPackSpawnAndStdin => {
                self.local_upload_pack_spawn_and_stdin_millis_total
            }
            TtfbStage::LocalUploadPackFirstByteWait => {
                self.local_upload_pack_first_byte_wait_millis_total
            }
        }
    }

    pub fn total_millis(self) -> u64 {
        TtfbStage::ALL
            .into_iter()
            .map(|stage| self.stage_millis(stage))
            .fold(0u64, u64::saturating_add)
    }

    fn saturating_sub(self, previous: Self) -> Self {
        Self {
            published_generation_lease_wait_millis_total: self
                .published_generation_lease_wait_millis_total
                .saturating_sub(previous.published_generation_lease_wait_millis_total),
            pack_cache_lookup_wait_millis_total: self
                .pack_cache_lookup_wait_millis_total
                .saturating_sub(previous.pack_cache_lookup_wait_millis_total),
            pack_cache_composite_wait_millis_total: self
                .pack_cache_composite_wait_millis_total
                .saturating_sub(previous.pack_cache_composite_wait_millis_total),
            local_upload_pack_permit_wait_millis_total: self
                .local_upload_pack_permit_wait_millis_total
                .saturating_sub(previous.local_upload_pack_permit_wait_millis_total),
            local_upload_pack_spawn_and_stdin_millis_total: self
                .local_upload_pack_spawn_and_stdin_millis_total
                .saturating_sub(previous.local_upload_pack_spawn_and_stdin_millis_total),
            local_upload_pack_first_byte_wait_millis_total: self
                .local_upload_pack_first_byte_wait_millis_total
                .saturating_sub(previous.local_upload_pack_first_byte_wait_millis_total),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TtfbStageEstimate {
    pub sample_count: u64,
    pub average: TtfbStageBreakdown,
}

impl TtfbStageEstimate {
    pub fn live_latency_estimate(
        self,
        completed: TtfbStageBreakdown,
        current_stage: TtfbStage,
        current_elapsed: Duration,
        historical_weight: f64,
        request_shape: &'static str,
    ) -> crate::short_circuit::LiveLatencyEstimate {
        let elapsed_millis = completed
            .total_millis()
            .saturating_add(duration_millis(current_elapsed));
        let historical_weight = historical_weight.clamp(0.0, 1.0);
        let weighted_stage_millis = |stage| {
            (self.average.stage_millis(stage) as f64 * historical_weight)
                .round()
                .min(u64::MAX as f64) as u64
        };
        let current_stage_millis =
            duration_millis(current_elapsed).max(weighted_stage_millis(current_stage));
        let mut estimated_millis = completed
            .total_millis()
            .saturating_add(current_stage_millis);
        for stage in TtfbStage::ALL {
            if stage.index() > current_stage.index() {
                estimated_millis = estimated_millis.saturating_add(weighted_stage_millis(stage));
            }
        }
        crate::short_circuit::LiveLatencyEstimate {
            stage: current_stage.as_label(),
            request_shape,
            historical_weight,
            elapsed: Duration::from_millis(elapsed_millis),
            estimated_total: Duration::from_millis(estimated_millis),
        }
    }
}

pub fn live_ttfb_latency_estimate(
    completed: TtfbStageBreakdown,
    current_stage: TtfbStage,
    current_elapsed: Duration,
    historical_stages: Option<TtfbStageEstimate>,
    min_historical_sample_count: u64,
    historical_weight: f64,
    request_shape: &'static str,
) -> crate::short_circuit::LiveLatencyEstimate {
    let historical_stages =
        historical_stages.filter(|estimate| estimate.sample_count >= min_historical_sample_count);

    historical_stages.map_or_else(
        || {
            let elapsed = Duration::from_millis(
                completed
                    .total_millis()
                    .saturating_add(duration_millis(current_elapsed)),
            );
            crate::short_circuit::LiveLatencyEstimate {
                stage: current_stage.as_label(),
                request_shape,
                historical_weight: historical_weight.clamp(0.0, 1.0),
                elapsed,
                estimated_total: elapsed,
            }
        },
        |estimate| {
            estimate.live_latency_estimate(
                completed,
                current_stage,
                current_elapsed,
                historical_weight,
                request_shape,
            )
        },
    )
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct DominantTtfbStage {
    pub stage: TtfbStage,
    pub avg_secs: f64,
    pub contribution: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackRecoveryTarget {
    LocalUploadPackPermit,
    LocalUploadPackFirstByte,
    LocalCatchUp,
    PublishedGenerationLease,
    PackCacheLookup,
    UpstreamCloneGlobal,
    UpstreamCloneRepo,
    Unknown,
}

fn fallback_target_for_reason(reason: &str) -> FallbackRecoveryTarget {
    match reason {
        "short_circuit_local_upload_pack_permit" | "local_upload_pack_permit" => {
            FallbackRecoveryTarget::LocalUploadPackPermit
        }
        "short_circuit_local_upload_pack_first_byte" | "local_upload_pack_first_byte" => {
            FallbackRecoveryTarget::LocalUploadPackFirstByte
        }
        "local_catch_up" => FallbackRecoveryTarget::LocalCatchUp,
        "short_circuit_published_generation_lease" | "published_generation_lease" => {
            FallbackRecoveryTarget::PublishedGenerationLease
        }
        "short_circuit_pack_cache_lookup"
        | "short_circuit_pack_cache_live_first_byte"
        | "pack_cache_lookup"
        | "pack_cache_live_first_byte" => FallbackRecoveryTarget::PackCacheLookup,
        "clone_global_saturated" => FallbackRecoveryTarget::UpstreamCloneGlobal,
        "clone_local_repo_saturated" | "clone_distributed_repo_saturated" => {
            FallbackRecoveryTarget::UpstreamCloneRepo
        }
        _ => FallbackRecoveryTarget::Unknown,
    }
}

impl AdaptiveObservationCounters {
    pub fn observe_clone_latency(&self, elapsed: Duration) {
        self.clone_samples.fetch_add(1, Ordering::Relaxed);
        self.clone_latency_millis_total
            .fetch_add(duration_millis(elapsed), Ordering::Relaxed);
        self.event_notify.notify_one();
    }

    pub fn observe_clone_latency_for_repo(&self, owner_repo: &str, elapsed: Duration) {
        let millis = duration_millis(elapsed);
        self.clone_samples.fetch_add(1, Ordering::Relaxed);
        self.clone_latency_millis_total
            .fetch_add(millis, Ordering::Relaxed);
        self.update_repo(owner_repo, |totals| {
            totals.clone_samples = totals.clone_samples.saturating_add(1);
            totals.clone_latency_millis_total =
                totals.clone_latency_millis_total.saturating_add(millis);
        });
        self.event_notify.notify_one();
    }

    pub fn observe_first_byte_latency(&self, elapsed: Duration) {
        self.first_byte_samples.fetch_add(1, Ordering::Relaxed);
        self.first_byte_latency_millis_total
            .fetch_add(duration_millis(elapsed), Ordering::Relaxed);
        self.event_notify.notify_one();
    }

    pub fn observe_first_byte_latency_for_repo(&self, owner_repo: &str, elapsed: Duration) {
        let millis = duration_millis(elapsed);
        self.first_byte_samples.fetch_add(1, Ordering::Relaxed);
        self.first_byte_latency_millis_total
            .fetch_add(millis, Ordering::Relaxed);
        self.update_repo(owner_repo, |totals| {
            totals.first_byte_samples = totals.first_byte_samples.saturating_add(1);
            totals.first_byte_latency_millis_total = totals
                .first_byte_latency_millis_total
                .saturating_add(millis);
        });
        self.event_notify.notify_one();
    }

    pub fn observe_first_byte_latency_and_ttfb_stage_breakdown_for_repo(
        &self,
        owner_repo: &str,
        elapsed: Duration,
        breakdown: TtfbStageBreakdown,
        request_cost_shape: Option<&RequestCostShape>,
    ) {
        let millis = duration_millis(elapsed);
        self.first_byte_samples.fetch_add(1, Ordering::Relaxed);
        self.first_byte_latency_millis_total
            .fetch_add(millis, Ordering::Relaxed);
        self.ttfb_stage_samples.fetch_add(1, Ordering::Relaxed);
        self.add_ttfb_breakdown(breakdown);
        self.update_repo(owner_repo, |totals| {
            totals.first_byte_samples = totals.first_byte_samples.saturating_add(1);
            totals.first_byte_latency_millis_total = totals
                .first_byte_latency_millis_total
                .saturating_add(millis);
            totals.ttfb_stage_samples = totals.ttfb_stage_samples.saturating_add(1);
            for stage in TtfbStage::ALL {
                totals
                    .ttfb_stage_millis_total
                    .add_stage_millis(stage, breakdown.stage_millis(stage));
            }
        });
        if let Some(shape) = request_cost_shape {
            self.update_request_cost(owner_repo, *shape, |totals| {
                totals.observe_first_byte(elapsed);
                totals.observe_ttfb_breakdown(breakdown);
            });
        }
        self.event_notify.notify_one();
    }

    pub fn observe_ttfb_stage_breakdown_for_repo(
        &self,
        owner_repo: &str,
        breakdown: TtfbStageBreakdown,
        request_cost_shape: Option<&RequestCostShape>,
    ) {
        self.ttfb_stage_samples.fetch_add(1, Ordering::Relaxed);
        self.add_ttfb_breakdown(breakdown);
        self.update_repo(owner_repo, |totals| {
            totals.ttfb_stage_samples = totals.ttfb_stage_samples.saturating_add(1);
            for stage in TtfbStage::ALL {
                totals
                    .ttfb_stage_millis_total
                    .add_stage_millis(stage, breakdown.stage_millis(stage));
            }
        });
        if let Some(shape) = request_cost_shape {
            self.update_request_cost(owner_repo, *shape, |totals| {
                totals.observe_ttfb_breakdown(breakdown);
            });
        }
        self.event_notify.notify_one();
    }

    pub fn inc_upstream_fallback(&self, reason: &str) {
        self.upstream_fallbacks.fetch_add(1, Ordering::Relaxed);
        self.inc_fallback_target(fallback_target_for_reason(reason));
        self.event_notify.notify_one();
    }

    pub fn inc_upstream_fallback_for_repo(&self, owner_repo: &str, reason: &str) {
        let target = fallback_target_for_reason(reason);
        self.upstream_fallbacks.fetch_add(1, Ordering::Relaxed);
        self.inc_fallback_target(target);
        self.update_repo(owner_repo, |totals| {
            totals.upstream_fallbacks = totals.upstream_fallbacks.saturating_add(1);
            totals.inc_fallback_target(target);
        });
        self.event_notify.notify_one();
    }

    pub async fn notified(&self) {
        self.event_notify.notified().await;
    }

    pub fn first_byte_latency_estimate_for_repo(
        &self,
        owner_repo: &str,
    ) -> Option<crate::short_circuit::HistoricalLatencyEstimate> {
        self.repo_observations
            .lock()
            .expect("adaptive observation repo totals lock poisoned")
            .totals
            .get(owner_repo)
            .and_then(|totals| {
                latency_estimate(
                    totals.first_byte_samples,
                    totals.first_byte_latency_millis_total,
                )
            })
    }

    pub fn ttfb_stage_estimate_for_repo(&self, owner_repo: &str) -> Option<TtfbStageEstimate> {
        self.repo_observations
            .lock()
            .expect("adaptive observation repo totals lock poisoned")
            .totals
            .get(owner_repo)
            .and_then(|totals| {
                ttfb_stage_estimate(totals.ttfb_stage_samples, totals.ttfb_stage_millis_total)
            })
    }

    pub fn observe_local_upload_pack_first_byte_fallback_for_request_cost(
        &self,
        owner_repo: &str,
        request_cost_shape: &RequestCostShape,
    ) {
        self.update_request_cost(owner_repo, *request_cost_shape, |totals| {
            totals.observe_local_upload_pack_first_byte_fallback();
        });
        self.event_notify.notify_one();
    }

    pub fn first_byte_latency_estimate_for_repo_and_request_cost(
        &self,
        owner_repo: &str,
        request_cost_shape: Option<&RequestCostShape>,
        min_sample_count: u64,
    ) -> Option<crate::short_circuit::HistoricalLatencyEstimate> {
        let repo_observations = self
            .repo_observations
            .lock()
            .expect("adaptive observation repo totals lock poisoned");
        let Some(shape) = request_cost_shape else {
            return repo_observations.totals.get(owner_repo).and_then(|totals| {
                latency_estimate(
                    totals.first_byte_samples,
                    totals.first_byte_latency_millis_total,
                )
            });
        };
        let repo_cost = repo_observations.request_cost_totals.get(owner_repo);
        estimate_with_min_samples(
            repo_cost
                .and_then(|repo| repo.exact.get(shape))
                .and_then(|totals| totals.first_byte_estimate()),
            min_sample_count,
        )
        .or_else(|| {
            estimate_with_min_samples(
                repo_cost
                    .and_then(|repo| repo.family.get(&shape.family_key()))
                    .and_then(|totals| totals.first_byte_estimate()),
                min_sample_count,
            )
        })
    }

    pub(crate) fn ttfb_stage_estimate_for_repo_and_request_cost(
        &self,
        owner_repo: &str,
        request_cost_shape: Option<&RequestCostShape>,
        min_sample_count: u64,
    ) -> Option<WeightedTtfbStageEstimate> {
        let repo_observations = self
            .repo_observations
            .lock()
            .expect("adaptive observation repo totals lock poisoned");
        let repo_cost = repo_observations.request_cost_totals.get(owner_repo);
        if let Some(shape) = request_cost_shape {
            if let Some(estimate) = estimate_with_min_samples(
                repo_cost
                    .and_then(|repo| repo.exact.get(shape))
                    .and_then(|totals| totals.ttfb_stage_estimate()),
                min_sample_count,
            ) {
                return Some(WeightedTtfbStageEstimate {
                    estimate,
                    historical_weight: 1.0,
                });
            }
            if let Some(estimate) = estimate_with_min_samples(
                repo_cost
                    .and_then(|repo| repo.family.get(&shape.family_key()))
                    .and_then(|totals| totals.ttfb_stage_estimate()),
                min_sample_count,
            ) {
                return Some(WeightedTtfbStageEstimate {
                    estimate,
                    historical_weight: 0.85,
                });
            }
        }
        repo_observations
            .totals
            .get(owner_repo)
            .and_then(|totals| {
                ttfb_stage_estimate(totals.ttfb_stage_samples, totals.ttfb_stage_millis_total)
            })
            .and_then(|estimate| estimate_with_min_samples(Some(estimate), min_sample_count))
            .map(|estimate| WeightedTtfbStageEstimate {
                estimate,
                historical_weight: request_cost_shape
                    .copied()
                    .map(RequestCostShape::repo_fallback_history_weight)
                    .unwrap_or(1.0),
            })
    }

    pub fn ttfb_stage_estimate_for_request_cost(
        &self,
        owner_repo: &str,
        request_cost_shape: Option<&RequestCostShape>,
        min_sample_count: u64,
    ) -> Option<TtfbStageEstimate> {
        let shape = request_cost_shape?;
        let repo_observations = self
            .repo_observations
            .lock()
            .expect("adaptive observation repo totals lock poisoned");
        let repo_cost = repo_observations.request_cost_totals.get(owner_repo);
        estimate_with_min_samples(
            repo_cost
                .and_then(|repo| repo.exact.get(shape))
                .and_then(|totals| totals.ttfb_stage_estimate()),
            min_sample_count,
        )
        .or_else(|| {
            estimate_with_min_samples(
                repo_cost
                    .and_then(|repo| repo.family.get(&shape.family_key()))
                    .and_then(|totals| totals.ttfb_stage_estimate()),
                min_sample_count,
            )
        })
    }

    pub fn local_upload_pack_first_byte_fallbacks_for_request_cost(
        &self,
        owner_repo: &str,
        request_cost_shape: Option<&RequestCostShape>,
    ) -> u64 {
        let Some(shape) = request_cost_shape else {
            return 0;
        };
        let repo_observations = self
            .repo_observations
            .lock()
            .expect("adaptive observation repo totals lock poisoned");
        let Some(repo_cost) = repo_observations.request_cost_totals.get(owner_repo) else {
            return 0;
        };
        repo_cost
            .exact
            .get(shape)
            .map(|totals| totals.local_upload_pack_first_byte_fallbacks)
            .or_else(|| {
                repo_cost
                    .family
                    .get(&shape.family_key())
                    .map(|totals| totals.local_upload_pack_first_byte_fallbacks)
            })
            .unwrap_or(0)
    }

    fn inc_fallback_target(&self, target: FallbackRecoveryTarget) {
        match target {
            FallbackRecoveryTarget::LocalUploadPackPermit => {
                &self.fallback_local_upload_pack_permit
            }
            FallbackRecoveryTarget::LocalUploadPackFirstByte => {
                &self.fallback_local_upload_pack_first_byte
            }
            FallbackRecoveryTarget::LocalCatchUp => &self.fallback_local_catch_up,
            FallbackRecoveryTarget::PublishedGenerationLease => {
                &self.fallback_published_generation_lease
            }
            FallbackRecoveryTarget::PackCacheLookup => &self.fallback_pack_cache_lookup,
            FallbackRecoveryTarget::UpstreamCloneGlobal => &self.fallback_upstream_clone_global,
            FallbackRecoveryTarget::UpstreamCloneRepo => &self.fallback_upstream_clone_repo,
            FallbackRecoveryTarget::Unknown => &self.fallback_unknown,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    fn add_ttfb_breakdown(&self, breakdown: TtfbStageBreakdown) {
        self.ttfb_stage_published_generation_lease_wait_millis_total
            .fetch_add(
                breakdown.stage_millis(TtfbStage::PublishedGenerationLeaseWait),
                Ordering::Relaxed,
            );
        self.ttfb_stage_pack_cache_lookup_wait_millis_total
            .fetch_add(
                breakdown.stage_millis(TtfbStage::PackCacheLookupWait),
                Ordering::Relaxed,
            );
        self.ttfb_stage_pack_cache_composite_wait_millis_total
            .fetch_add(
                breakdown.stage_millis(TtfbStage::PackCacheCompositeWait),
                Ordering::Relaxed,
            );
        self.ttfb_stage_local_upload_pack_permit_wait_millis_total
            .fetch_add(
                breakdown.stage_millis(TtfbStage::LocalUploadPackPermitWait),
                Ordering::Relaxed,
            );
        self.ttfb_stage_local_upload_pack_spawn_and_stdin_millis_total
            .fetch_add(
                breakdown.stage_millis(TtfbStage::LocalUploadPackSpawnAndStdin),
                Ordering::Relaxed,
            );
        self.ttfb_stage_local_upload_pack_first_byte_wait_millis_total
            .fetch_add(
                breakdown.stage_millis(TtfbStage::LocalUploadPackFirstByteWait),
                Ordering::Relaxed,
            );
    }

    pub fn snapshot(&self) -> ObservationTotals {
        ObservationTotals {
            clone_samples: self.clone_samples.load(Ordering::Relaxed),
            clone_latency_millis_total: self.clone_latency_millis_total.load(Ordering::Relaxed),
            first_byte_samples: self.first_byte_samples.load(Ordering::Relaxed),
            first_byte_latency_millis_total: self
                .first_byte_latency_millis_total
                .load(Ordering::Relaxed),
            ttfb_stage_samples: self.ttfb_stage_samples.load(Ordering::Relaxed),
            ttfb_stage_millis_total: TtfbStageBreakdown {
                published_generation_lease_wait_millis_total: self
                    .ttfb_stage_published_generation_lease_wait_millis_total
                    .load(Ordering::Relaxed),
                pack_cache_lookup_wait_millis_total: self
                    .ttfb_stage_pack_cache_lookup_wait_millis_total
                    .load(Ordering::Relaxed),
                pack_cache_composite_wait_millis_total: self
                    .ttfb_stage_pack_cache_composite_wait_millis_total
                    .load(Ordering::Relaxed),
                local_upload_pack_permit_wait_millis_total: self
                    .ttfb_stage_local_upload_pack_permit_wait_millis_total
                    .load(Ordering::Relaxed),
                local_upload_pack_spawn_and_stdin_millis_total: self
                    .ttfb_stage_local_upload_pack_spawn_and_stdin_millis_total
                    .load(Ordering::Relaxed),
                local_upload_pack_first_byte_wait_millis_total: self
                    .ttfb_stage_local_upload_pack_first_byte_wait_millis_total
                    .load(Ordering::Relaxed),
            },
            upstream_fallbacks: self.upstream_fallbacks.load(Ordering::Relaxed),
            fallback_local_upload_pack_permit: self
                .fallback_local_upload_pack_permit
                .load(Ordering::Relaxed),
            fallback_local_upload_pack_first_byte: self
                .fallback_local_upload_pack_first_byte
                .load(Ordering::Relaxed),
            fallback_local_catch_up: self.fallback_local_catch_up.load(Ordering::Relaxed),
            fallback_published_generation_lease: self
                .fallback_published_generation_lease
                .load(Ordering::Relaxed),
            fallback_pack_cache_lookup: self.fallback_pack_cache_lookup.load(Ordering::Relaxed),
            fallback_upstream_clone_global: self
                .fallback_upstream_clone_global
                .load(Ordering::Relaxed),
            fallback_upstream_clone_repo: self.fallback_upstream_clone_repo.load(Ordering::Relaxed),
            fallback_unknown: self.fallback_unknown.load(Ordering::Relaxed),
        }
    }

    pub fn repo_snapshot(&self) -> HashMap<String, ObservationTotals> {
        self.repo_observations
            .lock()
            .expect("repo adaptive observation lock poisoned")
            .totals
            .clone()
    }

    fn changed_repo_snapshot(&self) -> HashMap<String, ObservationTotals> {
        let mut repo_observations = self
            .repo_observations
            .lock()
            .expect("repo adaptive observation lock poisoned");
        let changed_repos = std::mem::take(&mut repo_observations.changed_repos);
        changed_repos
            .into_iter()
            .filter_map(|owner_repo| {
                repo_observations
                    .totals
                    .get(&owner_repo)
                    .copied()
                    .map(|totals| (owner_repo, totals))
            })
            .collect()
    }

    fn update_repo(&self, owner_repo: &str, update: impl FnOnce(&mut ObservationTotals)) {
        let owner_repo = crate::repo_identity::canonicalize_owner_repo(owner_repo);
        let mut repo_observations = self
            .repo_observations
            .lock()
            .expect("repo adaptive observation lock poisoned");
        update(
            repo_observations
                .totals
                .entry(owner_repo.clone())
                .or_default(),
        );
        repo_observations.changed_repos.insert(owner_repo);
    }

    fn update_request_cost(
        &self,
        owner_repo: &str,
        shape: RequestCostShape,
        mut update: impl FnMut(&mut RequestCostObservationTotals),
    ) {
        let owner_repo = crate::repo_identity::canonicalize_owner_repo(owner_repo);
        let mut repo_observations = self
            .repo_observations
            .lock()
            .expect("repo adaptive observation lock poisoned");
        let repo_cost = repo_observations
            .request_cost_totals
            .entry(owner_repo.clone())
            .or_default();
        update(repo_cost.exact.entry(shape).or_default());
        update(repo_cost.family.entry(shape.family_key()).or_default());
        repo_observations.changed_repos.insert(owner_repo);
    }
}

fn duration_millis(elapsed: Duration) -> u64 {
    let millis = elapsed.as_millis().min(u128::from(u64::MAX)) as u64;
    if millis == 0 && !elapsed.is_zero() {
        1
    } else {
        millis
    }
}

trait SampledEstimate {
    fn sample_count(&self) -> u64;
}

impl SampledEstimate for crate::short_circuit::HistoricalLatencyEstimate {
    fn sample_count(&self) -> u64 {
        self.sample_count
    }
}

impl SampledEstimate for TtfbStageEstimate {
    fn sample_count(&self) -> u64 {
        self.sample_count
    }
}

fn estimate_with_min_samples<T: SampledEstimate>(
    estimate: Option<T>,
    min_sample_count: u64,
) -> Option<T> {
    estimate.filter(|estimate| estimate.sample_count() >= min_sample_count)
}

pub fn pack_threads_for_request_cost(
    max_threads: usize,
    request_cost_shape: Option<RequestCostShape>,
    historical_stages: Option<TtfbStageEstimate>,
    has_local_upload_pack_first_byte_fallback: bool,
    first_byte_slo: Duration,
) -> usize {
    let max_threads = max_threads.max(1);
    if max_threads == 1 || has_local_upload_pack_first_byte_fallback {
        return max_threads;
    }

    let fraction = historical_stages
        .and_then(|estimate| {
            let cost_millis = estimate
                .average
                .stage_millis(TtfbStage::LocalUploadPackFirstByteWait);
            let slo_millis = duration_millis(first_byte_slo);
            (cost_millis > 0 && slo_millis > 0)
                .then(|| (cost_millis as f64 / slo_millis as f64).clamp(0.0, 1.0))
        })
        .unwrap_or_else(|| {
            request_cost_shape
                .map(RequestCostShape::intrinsic_pack_thread_fraction)
                .unwrap_or(1.0)
        });

    ((max_threads as f64 * fraction).ceil() as usize).clamp(1, max_threads)
}

fn latency_estimate(
    samples: u64,
    total_millis: u64,
) -> Option<crate::short_circuit::HistoricalLatencyEstimate> {
    (samples > 0).then(|| crate::short_circuit::HistoricalLatencyEstimate {
        sample_count: samples,
        average: Duration::from_millis(total_millis / samples),
    })
}

fn ttfb_stage_estimate(samples: u64, totals: TtfbStageBreakdown) -> Option<TtfbStageEstimate> {
    (samples > 0).then(|| {
        let mut average = TtfbStageBreakdown::default();
        for stage in TtfbStage::ALL {
            average.add_stage_millis(stage, totals.stage_millis(stage) / samples);
        }
        TtfbStageEstimate {
            sample_count: samples,
            average,
        }
    })
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct HostPressure {
    pub cpu_busy_fraction: Option<f64>,
    pub disk_busy_fraction: Option<f64>,
    pub memory_available_percent: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct ObservationSnapshot {
    pub sample_count: u64,
    pub clone_latency_secs_avg: Option<f64>,
    pub first_byte_latency_secs_avg: Option<f64>,
    pub dominant_ttfb_stage: Option<DominantTtfbStage>,
    pub fallback_rate: f64,
    pub dominant_fallback_target: Option<FallbackRecoveryTarget>,
    pub host_pressure: HostPressure,
    pub demand: RuntimeDemandSnapshot,
    pub host_cpu_threads: usize,
    pub current: EffectivePolicy,
    pub config: AdaptiveTuningConfig,
    pub warmup_complete: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecommendationSet {
    pub policy: EffectivePolicy,
    pub controller: String,
    pub controller_version: String,
    pub decision: String,
    pub reason: String,
    pub confidence: f64,
}

pub trait Controller: Send + Sync {
    fn observe(&self, snapshot: &ObservationSnapshot) -> RecommendationSet;
}

#[derive(Default)]
pub struct AimdController;

impl Controller for AimdController {
    fn observe(&self, snapshot: &ObservationSnapshot) -> RecommendationSet {
        if !snapshot.warmup_complete {
            return recommendation(
                snapshot.current,
                AIMD_CONTROLLER_NAME,
                AIMD_CONTROLLER_VERSION,
                "hold",
                "warmup",
                0.0,
            );
        }
        if snapshot.sample_count < snapshot.config.min_sample_count {
            return recommendation(
                snapshot.current,
                AIMD_CONTROLLER_NAME,
                AIMD_CONTROLLER_VERSION,
                "hold",
                "insufficient_samples",
                0.2,
            );
        }

        if let Some(reason) = pressure_reason(snapshot) {
            let policy = decrease_background_first(snapshot.current, &snapshot.config.bounds);
            return recommendation(
                policy,
                AIMD_CONTROLLER_NAME,
                AIMD_CONTROLLER_VERSION,
                "decrease",
                reason,
                0.8,
            );
        }

        if fallback_rate_exceeds_slo(snapshot) {
            let (policy, decision) = increase_fallback_recovery_capacity_or_waits(
                snapshot.current,
                &snapshot.config.bounds,
                snapshot.dominant_fallback_target,
            );
            return recommendation(
                policy,
                AIMD_CONTROLLER_NAME,
                AIMD_CONTROLLER_VERSION,
                decision,
                "fallback_rate_slo",
                0.9,
            );
        }

        if let Some(reason) = latency_slo_reason(snapshot) {
            let policy =
                decrease_foreground_and_background(snapshot.current, &snapshot.config.bounds);
            return recommendation(
                policy,
                AIMD_CONTROLLER_NAME,
                AIMD_CONTROLLER_VERSION,
                "decrease",
                reason,
                0.9,
            );
        }

        let policy = probe_capacity_and_tighten_waits(snapshot.current, &snapshot.config.bounds);
        recommendation(
            policy,
            AIMD_CONTROLLER_NAME,
            AIMD_CONTROLLER_VERSION,
            "probe",
            "healthy",
            0.7,
        )
    }
}

#[derive(Default)]
pub struct DemandResourceController;

impl Controller for DemandResourceController {
    fn observe(&self, snapshot: &ObservationSnapshot) -> RecommendationSet {
        if let Some(reason) = pressure_reason(snapshot) {
            let backed_off = decrease_background_first(snapshot.current, &snapshot.config.bounds);
            let policy = allocate_for_current_demand(
                backed_off,
                DemandAllocationInput {
                    bounds: &snapshot.config.bounds,
                    demand: snapshot.demand,
                    pressure: snapshot.host_pressure,
                    host_cpu_threads: snapshot.host_cpu_threads,
                    config: &snapshot.config.demand_resource,
                    resource_pressure: &snapshot.config.resource_pressure,
                    tighten_waits: false,
                    preserve_capacity: false,
                },
            );
            let policy = cap_capacity_at_policy(policy, backed_off);
            return demand_resource_recommendation(policy, "decrease", reason, 0.8);
        }

        if snapshot.sample_count >= snapshot.config.min_sample_count
            && fallback_rate_exceeds_slo(snapshot)
        {
            let (policy, decision) = increase_fallback_recovery_capacity_or_waits(
                snapshot.current,
                &snapshot.config.bounds,
                snapshot.dominant_fallback_target,
            );
            let policy = allocate_for_current_demand(
                policy,
                DemandAllocationInput {
                    bounds: &snapshot.config.bounds,
                    demand: snapshot.demand,
                    pressure: snapshot.host_pressure,
                    host_cpu_threads: snapshot.host_cpu_threads,
                    config: &snapshot.config.demand_resource,
                    resource_pressure: &snapshot.config.resource_pressure,
                    tighten_waits: false,
                    preserve_capacity: true,
                },
            );
            return demand_resource_recommendation(policy, decision, "fallback_rate_slo", 0.9);
        }

        if snapshot.sample_count >= snapshot.config.min_sample_count
            && let Some(reason) = latency_slo_reason(snapshot)
        {
            if reason == "first_byte_latency_slo"
                && let Some((policy, decision, stage_reason)) =
                    increase_ttfb_stage_capacity_or_waits(
                        snapshot.current,
                        &snapshot.config.bounds,
                        snapshot.dominant_ttfb_stage.map(|dominant| dominant.stage),
                    )
            {
                let policy = allocate_for_current_demand(
                    policy,
                    DemandAllocationInput {
                        bounds: &snapshot.config.bounds,
                        demand: snapshot.demand,
                        pressure: snapshot.host_pressure,
                        host_cpu_threads: snapshot.host_cpu_threads,
                        config: &snapshot.config.demand_resource,
                        resource_pressure: &snapshot.config.resource_pressure,
                        tighten_waits: false,
                        preserve_capacity: true,
                    },
                );
                return demand_resource_recommendation(policy, decision, stage_reason, 0.9);
            }
            let policy = allocate_for_current_demand(
                snapshot.current,
                DemandAllocationInput {
                    bounds: &snapshot.config.bounds,
                    demand: snapshot.demand,
                    pressure: snapshot.host_pressure,
                    host_cpu_threads: snapshot.host_cpu_threads,
                    config: &snapshot.config.demand_resource,
                    resource_pressure: &snapshot.config.resource_pressure,
                    tighten_waits: false,
                    preserve_capacity: true,
                },
            );
            return demand_resource_recommendation(policy, "rebalance", reason, 0.9);
        }

        let policy = allocate_for_current_demand(
            snapshot.current,
            DemandAllocationInput {
                bounds: &snapshot.config.bounds,
                demand: snapshot.demand,
                pressure: snapshot.host_pressure,
                host_cpu_threads: snapshot.host_cpu_threads,
                config: &snapshot.config.demand_resource,
                resource_pressure: &snapshot.config.resource_pressure,
                tighten_waits: snapshot.sample_count >= snapshot.config.min_sample_count,
                preserve_capacity: false,
            },
        );
        let decision = if snapshot.sample_count < snapshot.config.min_sample_count {
            "rebalance"
        } else {
            "healthy"
        };
        let reason = if snapshot.sample_count < snapshot.config.min_sample_count {
            "event_demand"
        } else {
            "slo_with_headroom"
        };
        demand_resource_recommendation(policy, decision, reason, 0.7)
    }
}

fn demand_resource_recommendation(
    policy: EffectivePolicy,
    decision: &'static str,
    reason: &'static str,
    confidence: f64,
) -> RecommendationSet {
    recommendation(
        policy,
        DEMAND_RESOURCE_CONTROLLER_NAME,
        DEMAND_RESOURCE_CONTROLLER_VERSION,
        decision,
        reason,
        confidence,
    )
}

fn recommendation(
    policy: EffectivePolicy,
    controller: &'static str,
    controller_version: &'static str,
    decision: &'static str,
    reason: &'static str,
    confidence: f64,
) -> RecommendationSet {
    RecommendationSet {
        policy,
        controller: controller.to_string(),
        controller_version: controller_version.to_string(),
        decision: decision.to_string(),
        reason: reason.to_string(),
        confidence,
    }
}

fn pressure_reason(snapshot: &ObservationSnapshot) -> Option<&'static str> {
    let pressure = snapshot.host_pressure;
    let resource = &snapshot.config.resource_pressure;
    if pressure
        .cpu_busy_fraction
        .is_some_and(|value| value >= resource.cpu_busy_high_watermark)
    {
        return Some("cpu_busy");
    }
    if pressure
        .memory_available_percent
        .is_some_and(|value| value < resource.memory_available_min_percent)
    {
        return Some("memory_pressure");
    }
    if pressure
        .disk_busy_fraction
        .is_some_and(|value| value >= resource.disk_busy_high_watermark)
    {
        return Some("disk_busy");
    }
    None
}

fn fallback_rate_exceeds_slo(snapshot: &ObservationSnapshot) -> bool {
    snapshot.fallback_rate >= snapshot.config.slo.fallback_rate
}

fn latency_slo_reason(snapshot: &ObservationSnapshot) -> Option<&'static str> {
    let slo = &snapshot.config.slo;
    if snapshot
        .clone_latency_secs_avg
        .is_some_and(|value| value >= slo.clone_latency_secs)
    {
        return Some("clone_latency_slo");
    }
    if snapshot
        .first_byte_latency_secs_avg
        .is_some_and(|value| value >= slo.first_byte_latency_secs)
    {
        return Some("first_byte_latency_slo");
    }
    None
}

fn probe_capacity_and_tighten_waits(
    policy: EffectivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
) -> EffectivePolicy {
    EffectivePolicy {
        upstream_clone_concurrency: step_up(
            policy.upstream_clone_concurrency,
            bounds.upstream_clone_concurrency,
        ),
        upstream_fetch_concurrency: step_up(
            policy.upstream_fetch_concurrency,
            bounds.upstream_fetch_concurrency,
        ),
        upstream_clone_per_repo_per_instance: step_up(
            policy.upstream_clone_per_repo_per_instance,
            bounds.upstream_clone_per_repo_per_instance,
        ),
        upstream_clone_per_repo_across_instances: step_up(
            policy.upstream_clone_per_repo_across_instances,
            bounds.upstream_clone_per_repo_across_instances,
        ),
        tee_capture_concurrency: step_up(
            policy.tee_capture_concurrency,
            bounds.tee_capture_concurrency,
        ),
        tee_capture_per_repo: step_up(policy.tee_capture_per_repo, bounds.tee_capture_per_repo),
        local_upload_pack_concurrency: step_up(
            policy.local_upload_pack_concurrency,
            bounds.local_upload_pack_concurrency,
        ),
        local_upload_pack_per_repo: step_up(
            policy.local_upload_pack_per_repo,
            bounds.local_upload_pack_per_repo,
        ),
        deep_validation_concurrency: step_up(
            policy.deep_validation_concurrency,
            bounds.deep_validation_concurrency,
        ),
        prewarm_concurrency: step_up(policy.prewarm_concurrency, bounds.prewarm_concurrency),
        bundle_generation_concurrency: step_up(
            policy.bundle_generation_concurrency,
            bounds.bundle_generation_concurrency,
        ),
        pack_cache_request_delta_concurrency: step_up(
            policy.pack_cache_request_delta_concurrency,
            bounds.pack_cache_request_delta_concurrency,
        ),
        pack_cache_background_warming_concurrency: step_up(
            policy.pack_cache_background_warming_concurrency,
            bounds.pack_cache_background_warming_concurrency,
        ),
        bundle_pack_threads: step_up(policy.bundle_pack_threads, bounds.bundle_pack_threads),
        local_upload_pack_threads: step_up(
            policy.local_upload_pack_threads,
            bounds.local_upload_pack_threads,
        ),
        index_pack_threads: step_up(policy.index_pack_threads, bounds.index_pack_threads),
        request_wait_for_local_catch_up_secs: step_down(
            policy.request_wait_for_local_catch_up_secs,
            bounds.request_wait_for_local_catch_up_secs,
        ),
        request_time_s3_restore_secs: step_down(
            policy.request_time_s3_restore_secs,
            bounds.request_time_s3_restore_secs,
        ),
        generation_publish_secs: step_down(
            policy.generation_publish_secs,
            bounds.generation_publish_secs,
        ),
        local_upload_pack_first_byte_secs: step_down(
            policy.local_upload_pack_first_byte_secs,
            bounds.local_upload_pack_first_byte_secs,
        ),
    }
}

struct DemandAllocationInput<'a> {
    bounds: &'a AdaptiveTuningBoundsConfig,
    demand: RuntimeDemandSnapshot,
    pressure: HostPressure,
    host_cpu_threads: usize,
    config: &'a AdaptiveTuningDemandResourceConfig,
    resource_pressure: &'a AdaptiveTuningResourcePressureConfig,
    tighten_waits: bool,
    preserve_capacity: bool,
}

fn allocate_for_current_demand(
    policy: EffectivePolicy,
    input: DemandAllocationInput<'_>,
) -> EffectivePolicy {
    let usable_threads = usable_cpu_threads(
        input.host_cpu_threads,
        input.pressure,
        input.config,
        input.resource_pressure,
    );
    let foreground_headroom = foreground_headroom(usable_threads, input.demand);
    let background_headroom = background_headroom(usable_threads, input.demand);
    let demand = input.demand;
    let bounds = input.bounds;
    let preserve_capacity = input.preserve_capacity;
    let tighten_waits = input.tighten_waits;
    let local_upload_pack_parallelism = demand
        .local_upload_pack_claims
        .saturating_add(foreground_headroom);
    let bundle_parallelism = demand
        .bundle_generation_claims
        .saturating_add(background_headroom)
        .saturating_add(foreground_headroom);
    let index_parallelism = demand
        .tee_capture_claims
        .saturating_add(demand.request_pack_delta_claims)
        .saturating_add(background_headroom)
        .saturating_add(foreground_headroom);

    EffectivePolicy {
        upstream_clone_concurrency: demand_bound(
            policy.upstream_clone_concurrency,
            demand.upstream_clone_claims,
            foreground_headroom,
            bounds.upstream_clone_concurrency,
            preserve_capacity,
        ),
        upstream_fetch_concurrency: demand_bound(
            policy.upstream_fetch_concurrency,
            demand.upstream_fetch_claims,
            foreground_headroom,
            bounds.upstream_fetch_concurrency,
            preserve_capacity,
        ),
        upstream_clone_per_repo_per_instance: demand_bound(
            policy.upstream_clone_per_repo_per_instance,
            demand.upstream_clone_claims,
            1,
            bounds.upstream_clone_per_repo_per_instance,
            preserve_capacity,
        ),
        upstream_clone_per_repo_across_instances: demand_bound(
            policy.upstream_clone_per_repo_across_instances,
            demand.upstream_clone_claims,
            foreground_headroom.max(1),
            bounds.upstream_clone_per_repo_across_instances,
            preserve_capacity,
        ),
        tee_capture_concurrency: demand_bound(
            policy.tee_capture_concurrency,
            demand.tee_capture_claims,
            background_headroom,
            bounds.tee_capture_concurrency,
            preserve_capacity,
        ),
        tee_capture_per_repo: demand_bound(
            policy.tee_capture_per_repo,
            demand.tee_capture_claims,
            1,
            bounds.tee_capture_per_repo,
            preserve_capacity,
        ),
        local_upload_pack_concurrency: demand_bound(
            policy.local_upload_pack_concurrency,
            demand.local_upload_pack_claims,
            foreground_headroom,
            bounds.local_upload_pack_concurrency,
            preserve_capacity,
        ),
        local_upload_pack_per_repo: demand_bound(
            policy.local_upload_pack_per_repo,
            demand.local_upload_pack_claims,
            1,
            bounds.local_upload_pack_per_repo,
            preserve_capacity,
        ),
        deep_validation_concurrency: demand_bound(
            policy.deep_validation_concurrency,
            demand.deep_validation_claims,
            background_headroom.min(1),
            bounds.deep_validation_concurrency,
            preserve_capacity,
        ),
        prewarm_concurrency: demand_bound(
            policy.prewarm_concurrency,
            demand.prewarm_claims,
            background_headroom,
            bounds.prewarm_concurrency,
            preserve_capacity,
        ),
        bundle_generation_concurrency: demand_bound(
            policy.bundle_generation_concurrency,
            demand.bundle_generation_claims,
            background_headroom,
            bounds.bundle_generation_concurrency,
            preserve_capacity,
        ),
        pack_cache_request_delta_concurrency: demand_bound(
            policy.pack_cache_request_delta_concurrency,
            demand.request_pack_delta_claims,
            foreground_headroom.min(2),
            bounds.pack_cache_request_delta_concurrency,
            preserve_capacity,
        ),
        pack_cache_background_warming_concurrency: demand_bound(
            policy.pack_cache_background_warming_concurrency,
            demand.pack_cache_background_warming_claims,
            background_headroom,
            bounds.pack_cache_background_warming_concurrency,
            preserve_capacity,
        ),
        bundle_pack_threads: per_operation_threads(
            policy.bundle_pack_threads,
            usable_threads,
            bundle_parallelism,
            bounds.bundle_pack_threads,
            preserve_capacity,
        ),
        local_upload_pack_threads: per_operation_threads(
            policy.local_upload_pack_threads,
            usable_threads,
            local_upload_pack_parallelism,
            bounds.local_upload_pack_threads,
            preserve_capacity,
        ),
        index_pack_threads: per_operation_threads(
            policy.index_pack_threads,
            usable_threads,
            index_parallelism,
            bounds.index_pack_threads,
            preserve_capacity,
        ),
        request_wait_for_local_catch_up_secs: maybe_tighten_wait(
            policy.request_wait_for_local_catch_up_secs,
            bounds.request_wait_for_local_catch_up_secs,
            tighten_waits,
        ),
        request_time_s3_restore_secs: maybe_tighten_wait(
            policy.request_time_s3_restore_secs,
            bounds.request_time_s3_restore_secs,
            tighten_waits,
        ),
        generation_publish_secs: maybe_tighten_wait(
            policy.generation_publish_secs,
            bounds.generation_publish_secs,
            tighten_waits,
        ),
        local_upload_pack_first_byte_secs: maybe_tighten_wait(
            policy.local_upload_pack_first_byte_secs,
            bounds.local_upload_pack_first_byte_secs,
            tighten_waits,
        ),
    }
}

fn demand_bound(
    current: usize,
    active_claims: usize,
    headroom: usize,
    bounds: AdaptiveTuningKnobBoundsConfig,
    preserve_capacity: bool,
) -> usize {
    let demand = active_claims.saturating_add(headroom);
    let target = if preserve_capacity {
        demand.max(current)
    } else {
        demand
    };
    target.clamp(bounds.min, bounds.max)
}

fn foreground_headroom(usable_threads: usize, demand: RuntimeDemandSnapshot) -> usize {
    let base = usable_threads / 8;
    let active_foreground = demand.foreground_claims();
    let reserved = if active_foreground == 0 {
        FOREGROUND_HEADROOM_MIN
    } else {
        FOREGROUND_HEADROOM_MIN.saturating_add(1)
    };
    base.max(reserved)
        .clamp(FOREGROUND_HEADROOM_MIN, FOREGROUND_HEADROOM_MAX)
}

fn background_headroom(usable_threads: usize, demand: RuntimeDemandSnapshot) -> usize {
    if demand.foreground_claims() > 0 {
        BACKGROUND_HEADROOM_MIN
    } else {
        (usable_threads / 12)
            .max(BACKGROUND_HEADROOM_MIN)
            .clamp(BACKGROUND_HEADROOM_MIN, BACKGROUND_HEADROOM_MAX)
    }
}

fn usable_cpu_threads(
    host_cpu_threads: usize,
    pressure: HostPressure,
    config: &AdaptiveTuningDemandResourceConfig,
    resource_pressure: &AdaptiveTuningResourcePressureConfig,
) -> usize {
    let host_cpu_threads = host_cpu_threads.max(1);
    let mut usable = provisioned_cpu_threads(host_cpu_threads, config.cpu_provisioning_fraction);
    if pressure
        .memory_available_percent
        .is_some_and(|value| value < resource_pressure.memory_available_min_percent)
    {
        usable = usable.min(provisioned_cpu_threads(
            host_cpu_threads,
            config.cpu_provisioning_fraction_when_memory_constrained,
        ));
    }
    usable
}

fn provisioned_cpu_threads(host_cpu_threads: usize, fraction: f64) -> usize {
    ((host_cpu_threads.max(1) as f64 * fraction).ceil() as usize).max(1)
}

fn per_operation_threads(
    current: usize,
    usable_threads: usize,
    operation_parallelism: usize,
    bounds: AdaptiveTuningKnobBoundsConfig,
    preserve_capacity: bool,
) -> usize {
    let parallelism = operation_parallelism.max(1);
    let fair_share = (usable_threads / parallelism).max(bounds.min);
    let target = if preserve_capacity {
        current.min(fair_share)
    } else {
        fair_share
    };
    target.clamp(bounds.min, bounds.max)
}

fn maybe_tighten_wait(
    value: usize,
    bounds: AdaptiveTuningKnobBoundsConfig,
    tighten_waits: bool,
) -> usize {
    if tighten_waits {
        step_down(value, bounds)
    } else {
        value.clamp(bounds.min, bounds.max)
    }
}

fn decrease_background_first(
    policy: EffectivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
) -> EffectivePolicy {
    EffectivePolicy {
        tee_capture_concurrency: step_down(
            policy.tee_capture_concurrency,
            bounds.tee_capture_concurrency,
        ),
        tee_capture_per_repo: step_down(policy.tee_capture_per_repo, bounds.tee_capture_per_repo),
        deep_validation_concurrency: step_down(
            policy.deep_validation_concurrency,
            bounds.deep_validation_concurrency,
        ),
        prewarm_concurrency: step_down(policy.prewarm_concurrency, bounds.prewarm_concurrency),
        bundle_generation_concurrency: step_down(
            policy.bundle_generation_concurrency,
            bounds.bundle_generation_concurrency,
        ),
        pack_cache_request_delta_concurrency: step_down(
            policy.pack_cache_request_delta_concurrency,
            bounds.pack_cache_request_delta_concurrency,
        ),
        pack_cache_background_warming_concurrency: step_down(
            policy.pack_cache_background_warming_concurrency,
            bounds.pack_cache_background_warming_concurrency,
        ),
        bundle_pack_threads: step_down(policy.bundle_pack_threads, bounds.bundle_pack_threads),
        index_pack_threads: step_down(policy.index_pack_threads, bounds.index_pack_threads),
        ..policy
    }
}

fn cap_capacity_at_policy(policy: EffectivePolicy, ceiling: EffectivePolicy) -> EffectivePolicy {
    EffectivePolicy {
        upstream_clone_concurrency: policy
            .upstream_clone_concurrency
            .min(ceiling.upstream_clone_concurrency),
        upstream_fetch_concurrency: policy
            .upstream_fetch_concurrency
            .min(ceiling.upstream_fetch_concurrency),
        upstream_clone_per_repo_per_instance: policy
            .upstream_clone_per_repo_per_instance
            .min(ceiling.upstream_clone_per_repo_per_instance),
        upstream_clone_per_repo_across_instances: policy
            .upstream_clone_per_repo_across_instances
            .min(ceiling.upstream_clone_per_repo_across_instances),
        tee_capture_concurrency: policy
            .tee_capture_concurrency
            .min(ceiling.tee_capture_concurrency),
        tee_capture_per_repo: policy
            .tee_capture_per_repo
            .min(ceiling.tee_capture_per_repo),
        local_upload_pack_concurrency: policy
            .local_upload_pack_concurrency
            .min(ceiling.local_upload_pack_concurrency),
        local_upload_pack_per_repo: policy
            .local_upload_pack_per_repo
            .min(ceiling.local_upload_pack_per_repo),
        deep_validation_concurrency: policy
            .deep_validation_concurrency
            .min(ceiling.deep_validation_concurrency),
        prewarm_concurrency: policy.prewarm_concurrency.min(ceiling.prewarm_concurrency),
        bundle_generation_concurrency: policy
            .bundle_generation_concurrency
            .min(ceiling.bundle_generation_concurrency),
        pack_cache_request_delta_concurrency: policy
            .pack_cache_request_delta_concurrency
            .min(ceiling.pack_cache_request_delta_concurrency),
        pack_cache_background_warming_concurrency: policy
            .pack_cache_background_warming_concurrency
            .min(ceiling.pack_cache_background_warming_concurrency),
        bundle_pack_threads: policy.bundle_pack_threads.min(ceiling.bundle_pack_threads),
        local_upload_pack_threads: policy
            .local_upload_pack_threads
            .min(ceiling.local_upload_pack_threads),
        index_pack_threads: policy.index_pack_threads.min(ceiling.index_pack_threads),
        request_wait_for_local_catch_up_secs: policy.request_wait_for_local_catch_up_secs,
        request_time_s3_restore_secs: policy.request_time_s3_restore_secs,
        generation_publish_secs: policy.generation_publish_secs,
        local_upload_pack_first_byte_secs: policy.local_upload_pack_first_byte_secs,
    }
}

fn increase_request_waits(
    policy: EffectivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
) -> EffectivePolicy {
    EffectivePolicy {
        request_wait_for_local_catch_up_secs: step_up(
            policy.request_wait_for_local_catch_up_secs,
            bounds.request_wait_for_local_catch_up_secs,
        ),
        request_time_s3_restore_secs: step_up(
            policy.request_time_s3_restore_secs,
            bounds.request_time_s3_restore_secs,
        ),
        generation_publish_secs: step_up(
            policy.generation_publish_secs,
            bounds.generation_publish_secs,
        ),
        local_upload_pack_first_byte_secs: step_up(
            policy.local_upload_pack_first_byte_secs,
            bounds.local_upload_pack_first_byte_secs,
        ),
        ..policy
    }
}

fn increase_fallback_recovery_capacity_or_waits(
    policy: EffectivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
    target: Option<FallbackRecoveryTarget>,
) -> (EffectivePolicy, &'static str) {
    let target = target.unwrap_or(FallbackRecoveryTarget::Unknown);
    if let Some(policy) = increase_capacity_for_fallback_target(policy, bounds, target) {
        return (policy, "increase_capacity");
    }

    if let Some(policy) = increase_waits_for_fallback_target(policy, bounds, target) {
        return (policy, "increase_timeouts");
    }

    (policy, "hold")
}

fn increase_ttfb_stage_capacity_or_waits(
    policy: EffectivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
    stage: Option<TtfbStage>,
) -> Option<(EffectivePolicy, &'static str, &'static str)> {
    let stage = stage?;
    let capacity_policy = match stage {
        TtfbStage::PublishedGenerationLeaseWait => {
            increase_generation_recovery_capacity(policy, bounds)
        }
        TtfbStage::PackCacheLookupWait | TtfbStage::PackCacheCompositeWait => {
            increase_pack_cache_lookup_capacity(policy, bounds)
        }
        TtfbStage::LocalUploadPackPermitWait => increase_local_upload_pack_capacity(policy, bounds),
        TtfbStage::LocalUploadPackSpawnAndStdin | TtfbStage::LocalUploadPackFirstByteWait => {
            increase_local_upload_pack_threads(policy, bounds)
                .or_else(|| increase_local_upload_pack_capacity(policy, bounds))
        }
    };
    if let Some(policy) = capacity_policy {
        return Some((policy, "increase_capacity", ttfb_stage_reason(stage)));
    }

    let wait_policy = match stage {
        TtfbStage::PublishedGenerationLeaseWait => Some(EffectivePolicy {
            generation_publish_secs: step_up(
                policy.generation_publish_secs,
                bounds.generation_publish_secs,
            ),
            ..policy
        }),
        TtfbStage::PackCacheLookupWait | TtfbStage::PackCacheCompositeWait => {
            Some(increase_request_waits(policy, bounds))
        }
        TtfbStage::LocalUploadPackPermitWait => None,
        TtfbStage::LocalUploadPackSpawnAndStdin | TtfbStage::LocalUploadPackFirstByteWait => {
            increase_waits_for_fallback_target(
                policy,
                bounds,
                FallbackRecoveryTarget::LocalUploadPackFirstByte,
            )
        }
    };
    wait_policy.map(|policy| (policy, "increase_timeouts", ttfb_stage_reason(stage)))
}

fn ttfb_stage_reason(stage: TtfbStage) -> &'static str {
    match stage {
        TtfbStage::PublishedGenerationLeaseWait => "ttfb_stage_published_generation_lease_wait",
        TtfbStage::PackCacheLookupWait => "ttfb_stage_pack_cache_lookup_wait",
        TtfbStage::PackCacheCompositeWait => "ttfb_stage_pack_cache_composite_wait",
        TtfbStage::LocalUploadPackPermitWait => "ttfb_stage_local_upload_pack_permit_wait",
        TtfbStage::LocalUploadPackSpawnAndStdin => "ttfb_stage_local_upload_pack_spawn_and_stdin",
        TtfbStage::LocalUploadPackFirstByteWait => "ttfb_stage_local_upload_pack_first_byte_wait",
    }
}

fn increase_capacity_for_fallback_target(
    policy: EffectivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
    target: FallbackRecoveryTarget,
) -> Option<EffectivePolicy> {
    match target {
        FallbackRecoveryTarget::LocalUploadPackPermit
        | FallbackRecoveryTarget::LocalUploadPackFirstByte => {
            increase_local_upload_pack_capacity(policy, bounds)
        }
        FallbackRecoveryTarget::PublishedGenerationLease => {
            increase_generation_recovery_capacity(policy, bounds)
        }
        FallbackRecoveryTarget::LocalCatchUp => None,
        FallbackRecoveryTarget::PackCacheLookup => {
            increase_pack_cache_lookup_capacity(policy, bounds)
        }
        FallbackRecoveryTarget::UpstreamCloneGlobal => {
            increase_upstream_clone_global_capacity(policy, bounds)
        }
        FallbackRecoveryTarget::UpstreamCloneRepo => {
            increase_upstream_clone_repo_capacity(policy, bounds)
        }
        FallbackRecoveryTarget::Unknown => increase_local_upload_pack_capacity(policy, bounds)
            .or_else(|| increase_upstream_clone_global_capacity(policy, bounds))
            .or_else(|| increase_upstream_clone_repo_capacity(policy, bounds))
            .or_else(|| increase_pack_cache_lookup_capacity(policy, bounds)),
    }
}

fn increase_local_upload_pack_capacity(
    policy: EffectivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
) -> Option<EffectivePolicy> {
    capacity_available([
        (
            policy.local_upload_pack_concurrency,
            bounds.local_upload_pack_concurrency,
        ),
        (
            policy.local_upload_pack_per_repo,
            bounds.local_upload_pack_per_repo,
        ),
        (
            policy.local_upload_pack_threads,
            bounds.local_upload_pack_threads,
        ),
    ])
    .then_some(EffectivePolicy {
        local_upload_pack_concurrency: step_up(
            policy.local_upload_pack_concurrency,
            bounds.local_upload_pack_concurrency,
        ),
        local_upload_pack_per_repo: step_up(
            policy.local_upload_pack_per_repo,
            bounds.local_upload_pack_per_repo,
        ),
        local_upload_pack_threads: step_up(
            policy.local_upload_pack_threads,
            bounds.local_upload_pack_threads,
        ),
        ..policy
    })
}

fn increase_local_upload_pack_threads(
    policy: EffectivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
) -> Option<EffectivePolicy> {
    (policy.local_upload_pack_threads < bounds.local_upload_pack_threads.max).then_some(
        EffectivePolicy {
            local_upload_pack_threads: step_up(
                policy.local_upload_pack_threads,
                bounds.local_upload_pack_threads,
            ),
            ..policy
        },
    )
}

fn increase_generation_recovery_capacity(
    policy: EffectivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
) -> Option<EffectivePolicy> {
    capacity_available([
        (
            policy.upstream_clone_concurrency,
            bounds.upstream_clone_concurrency,
        ),
        (
            policy.upstream_fetch_concurrency,
            bounds.upstream_fetch_concurrency,
        ),
        (
            policy.upstream_clone_per_repo_per_instance,
            bounds.upstream_clone_per_repo_per_instance,
        ),
        (
            policy.upstream_clone_per_repo_across_instances,
            bounds.upstream_clone_per_repo_across_instances,
        ),
    ])
    .then_some(EffectivePolicy {
        upstream_clone_concurrency: step_up(
            policy.upstream_clone_concurrency,
            bounds.upstream_clone_concurrency,
        ),
        upstream_fetch_concurrency: step_up(
            policy.upstream_fetch_concurrency,
            bounds.upstream_fetch_concurrency,
        ),
        upstream_clone_per_repo_per_instance: step_up(
            policy.upstream_clone_per_repo_per_instance,
            bounds.upstream_clone_per_repo_per_instance,
        ),
        upstream_clone_per_repo_across_instances: step_up(
            policy.upstream_clone_per_repo_across_instances,
            bounds.upstream_clone_per_repo_across_instances,
        ),
        ..policy
    })
}

fn increase_pack_cache_lookup_capacity(
    policy: EffectivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
) -> Option<EffectivePolicy> {
    capacity_available([(
        policy.pack_cache_request_delta_concurrency,
        bounds.pack_cache_request_delta_concurrency,
    )])
    .then_some(EffectivePolicy {
        pack_cache_request_delta_concurrency: step_up(
            policy.pack_cache_request_delta_concurrency,
            bounds.pack_cache_request_delta_concurrency,
        ),
        ..policy
    })
}

fn increase_upstream_clone_global_capacity(
    policy: EffectivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
) -> Option<EffectivePolicy> {
    capacity_available([(
        policy.upstream_clone_concurrency,
        bounds.upstream_clone_concurrency,
    )])
    .then_some(EffectivePolicy {
        upstream_clone_concurrency: step_up(
            policy.upstream_clone_concurrency,
            bounds.upstream_clone_concurrency,
        ),
        ..policy
    })
}

fn increase_upstream_clone_repo_capacity(
    policy: EffectivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
) -> Option<EffectivePolicy> {
    capacity_available([
        (
            policy.upstream_clone_per_repo_per_instance,
            bounds.upstream_clone_per_repo_per_instance,
        ),
        (
            policy.upstream_clone_per_repo_across_instances,
            bounds.upstream_clone_per_repo_across_instances,
        ),
    ])
    .then_some(EffectivePolicy {
        upstream_clone_per_repo_per_instance: step_up(
            policy.upstream_clone_per_repo_per_instance,
            bounds.upstream_clone_per_repo_per_instance,
        ),
        upstream_clone_per_repo_across_instances: step_up(
            policy.upstream_clone_per_repo_across_instances,
            bounds.upstream_clone_per_repo_across_instances,
        ),
        ..policy
    })
}

fn increase_waits_for_fallback_target(
    policy: EffectivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
    target: FallbackRecoveryTarget,
) -> Option<EffectivePolicy> {
    match target {
        FallbackRecoveryTarget::LocalUploadPackFirstByte => capacity_available([(
            policy.local_upload_pack_first_byte_secs,
            bounds.local_upload_pack_first_byte_secs,
        )])
        .then_some(EffectivePolicy {
            local_upload_pack_first_byte_secs: step_up(
                policy.local_upload_pack_first_byte_secs,
                bounds.local_upload_pack_first_byte_secs,
            ),
            ..policy
        }),
        FallbackRecoveryTarget::LocalCatchUp | FallbackRecoveryTarget::PublishedGenerationLease => {
            Some(increase_request_waits(policy, bounds))
        }
        FallbackRecoveryTarget::Unknown => Some(increase_request_waits(policy, bounds)),
        FallbackRecoveryTarget::LocalUploadPackPermit
        | FallbackRecoveryTarget::PackCacheLookup
        | FallbackRecoveryTarget::UpstreamCloneGlobal
        | FallbackRecoveryTarget::UpstreamCloneRepo => None,
    }
}

fn capacity_available<const N: usize>(knobs: [(usize, AdaptiveTuningKnobBoundsConfig); N]) -> bool {
    knobs.into_iter().any(|(value, bounds)| value < bounds.max)
}

fn decrease_foreground_and_background(
    policy: EffectivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
) -> EffectivePolicy {
    let background = decrease_background_first(policy, bounds);
    EffectivePolicy {
        upstream_clone_concurrency: step_down(
            background.upstream_clone_concurrency,
            bounds.upstream_clone_concurrency,
        ),
        upstream_fetch_concurrency: step_down(
            background.upstream_fetch_concurrency,
            bounds.upstream_fetch_concurrency,
        ),
        upstream_clone_per_repo_per_instance: step_down(
            background.upstream_clone_per_repo_per_instance,
            bounds.upstream_clone_per_repo_per_instance,
        ),
        upstream_clone_per_repo_across_instances: step_down(
            background.upstream_clone_per_repo_across_instances,
            bounds.upstream_clone_per_repo_across_instances,
        ),
        local_upload_pack_concurrency: step_down(
            background.local_upload_pack_concurrency,
            bounds.local_upload_pack_concurrency,
        ),
        local_upload_pack_per_repo: step_down(
            background.local_upload_pack_per_repo,
            bounds.local_upload_pack_per_repo,
        ),
        local_upload_pack_threads: step_down(
            background.local_upload_pack_threads,
            bounds.local_upload_pack_threads,
        ),
        ..background
    }
}

fn step_up(value: usize, bounds: AdaptiveTuningKnobBoundsConfig) -> usize {
    value
        .saturating_add(bounds.max_increase_step)
        .clamp(bounds.min, bounds.max)
}

fn step_down(value: usize, bounds: AdaptiveTuningKnobBoundsConfig) -> usize {
    value
        .saturating_sub(bounds.max_decrease_step)
        .clamp(bounds.min, bounds.max)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecommendationEnvelope {
    pub timestamp_unix_secs: u64,
    pub sample_window_secs: u64,
    pub confidence: f64,
    pub controller: String,
    pub controller_version: String,
    pub mode: String,
    pub recommendation: EffectivePolicy,
    pub input_summary: RecommendationInputSummary,
    pub bounds: AdaptiveTuningBoundsConfig,
    pub source_instance_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecommendationInputSummary {
    pub sample_count: u64,
    pub clone_latency_secs_avg: Option<f64>,
    pub first_byte_latency_secs_avg: Option<f64>,
    #[serde(default)]
    pub dominant_ttfb_stage: Option<DominantTtfbStage>,
    pub fallback_rate: f64,
    pub dominant_fallback_target: Option<FallbackRecoveryTarget>,
    pub host_pressure: HostPressure,
    pub decision: String,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct RepoObservationSnapshot {
    pub owner_repo: String,
    pub sample_count: u64,
    pub clone_latency_secs_avg: Option<f64>,
    pub first_byte_latency_secs_avg: Option<f64>,
    pub dominant_ttfb_stage: Option<DominantTtfbStage>,
    pub fallback_rate: f64,
    pub dominant_fallback_target: Option<FallbackRecoveryTarget>,
    pub host_pressure: HostPressure,
    pub current: RepoAdaptivePolicy,
    pub config: AdaptiveTuningConfig,
    pub warmup_complete: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepoRecommendationSet {
    pub policy: RepoAdaptivePolicy,
    pub controller: String,
    pub controller_version: String,
    pub decision: String,
    pub reason: String,
    pub confidence: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepoRecommendationEnvelope {
    pub timestamp_unix_secs: u64,
    pub sample_window_secs: u64,
    pub confidence: f64,
    pub controller: String,
    pub controller_version: String,
    pub mode: String,
    pub recommendation: RepoAdaptivePolicy,
    pub input_summary: RecommendationInputSummary,
    pub bounds: AdaptiveTuningBoundsConfig,
    pub source_instance_id: String,
    pub source_owner_repo: String,
}

pub fn global_recommendation_key(config: &Config, deployment: &str) -> String {
    format!(
        "forgeproxy:adaptive_tuning:recommendation:global:{}:{}",
        deployment, config.backend_type
    )
}

pub fn instance_recommendation_key(config: &Config, deployment: &str, instance_id: &str) -> String {
    format!(
        "forgeproxy:adaptive_tuning:recommendation:instance:{}:{}:{}",
        deployment, config.backend_type, instance_id
    )
}

pub fn repo_recommendation_key(config: &Config, deployment: &str, owner_repo: &str) -> String {
    format!(
        "forgeproxy:adaptive_tuning:recommendation:repo:{}:{}:{}",
        deployment,
        config.backend_type,
        crate::repo_identity::canonicalize_owner_repo(owner_repo)
    )
}

pub async fn load_startup_recommendation(
    valkey: &Pool,
    config: &Config,
    deployment: &str,
    instance_id: &str,
    fallback: EffectivePolicy,
) -> EffectivePolicy {
    let max_staleness = config.adaptive_tuning.recommendation_max_staleness_secs;
    let bounds = &config.adaptive_tuning.bounds;
    let expected_controller = config.adaptive_tuning.controller.as_label();
    let preserve_operator_first_byte_zero = config.clone.local_upload_pack_first_byte_secs == 0;
    let mut policy = fallback;
    let mut loaded_recommendation = false;

    for key in [
        global_recommendation_key(config, deployment),
        instance_recommendation_key(config, deployment, instance_id),
    ] {
        match load_recommendation_from_key(valkey, &key, max_staleness).await {
            Ok(Some(envelope)) => {
                if let Some(recommended_policy) = startup_recommendation_policy(
                    &envelope,
                    expected_controller,
                    bounds,
                    preserve_operator_first_byte_zero,
                ) {
                    policy = recommended_policy;
                    loaded_recommendation = true;
                    tracing::info!(
                        key,
                        controller = %envelope.controller,
                        confidence = envelope.confidence,
                        "loaded adaptive tuning startup recommendation from Valkey"
                    );
                } else {
                    tracing::info!(
                        key,
                        controller = %envelope.controller,
                        expected_controller,
                        confidence = envelope.confidence,
                        "ignoring adaptive tuning startup recommendation from different controller"
                    );
                }
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(
                    key,
                    error = %error,
                    "ignoring unusable adaptive tuning startup recommendation"
                );
            }
        }
    }

    if loaded_recommendation {
        bound_effective_adaptive_recommendation(policy, bounds, preserve_operator_first_byte_zero)
    } else {
        policy.bounded(bounds)
    }
}

fn startup_recommendation_policy(
    envelope: &RecommendationEnvelope,
    expected_controller: &str,
    bounds: &AdaptiveTuningBoundsConfig,
    preserve_operator_first_byte_zero: bool,
) -> Option<EffectivePolicy> {
    (envelope.controller == expected_controller).then(|| {
        bound_effective_adaptive_recommendation(
            envelope.recommendation,
            bounds,
            preserve_operator_first_byte_zero,
        )
    })
}

async fn load_recommendation_from_key(
    valkey: &Pool,
    key: &str,
    max_staleness_secs: u64,
) -> Result<Option<RecommendationEnvelope>> {
    let Some(value): Option<String> = valkey.get(key).await.context("Valkey GET failed")? else {
        return Ok(None);
    };
    let envelope: RecommendationEnvelope =
        serde_json::from_str(&value).context("parse adaptive recommendation")?;
    let now = unix_now_secs();
    anyhow::ensure!(
        now.saturating_sub(envelope.timestamp_unix_secs) <= max_staleness_secs,
        "adaptive recommendation is stale"
    );
    Ok(Some(envelope))
}

pub async fn persist_recommendation(
    valkey: &Pool,
    config: &Config,
    deployment: &str,
    instance_id: &str,
    envelope: &RecommendationEnvelope,
) -> Result<()> {
    let contents = serde_json::to_string(envelope).context("serialize adaptive recommendation")?;
    let ttl = config.adaptive_tuning.recommendation_ttl_secs as i64;
    for key in [
        global_recommendation_key(config, deployment),
        instance_recommendation_key(config, deployment, instance_id),
    ] {
        let _: () = valkey
            .set(
                &key,
                contents.clone(),
                Some(Expiration::EX(ttl)),
                None,
                false,
            )
            .await
            .context("Valkey SET adaptive recommendation failed")?;
    }
    Ok(())
}

pub async fn persist_observation(
    valkey: &Pool,
    deployment: &str,
    instance_id: &str,
    envelope: &RecommendationEnvelope,
    ttl_secs: u64,
) -> Result<()> {
    let key = format!(
        "forgeproxy:adaptive_tuning:observation:{}:{}:{}",
        deployment, instance_id, envelope.timestamp_unix_secs
    );
    let contents = serde_json::to_string(envelope).context("serialize adaptive observation")?;
    let _: () = valkey
        .set(
            &key,
            contents,
            Some(Expiration::EX(ttl_secs as i64)),
            None,
            false,
        )
        .await
        .context("Valkey SET adaptive observation failed")?;
    Ok(())
}

pub async fn load_repo_recommendations(
    valkey: &Pool,
    config: &Config,
    deployment: &str,
    owner_repo: &str,
) -> Result<Vec<RepoRecommendationEnvelope>> {
    let key = repo_recommendation_key(config, deployment, owner_repo);
    let map: HashMap<String, String> = valkey
        .hgetall(&key)
        .await
        .context("Valkey HGETALL repo adaptive recommendations failed")?;
    let now = unix_now_secs();
    let max_staleness = config.adaptive_tuning.recommendation_max_staleness_secs;
    let mut envelopes = Vec::new();
    for contents in map.values() {
        let envelope: RepoRecommendationEnvelope =
            serde_json::from_str(contents).context("parse repo adaptive recommendation")?;
        if now.saturating_sub(envelope.timestamp_unix_secs) <= max_staleness {
            envelopes.push(envelope);
        }
    }
    Ok(envelopes)
}

pub async fn persist_repo_recommendation(
    valkey: &Pool,
    config: &Config,
    deployment: &str,
    instance_id: &str,
    owner_repo: &str,
    envelope: &RepoRecommendationEnvelope,
) -> Result<()> {
    let key = repo_recommendation_key(config, deployment, owner_repo);
    let contents =
        serde_json::to_string(envelope).context("serialize repo adaptive recommendation")?;
    let _: () = valkey
        .hset(&key, vec![(instance_id.to_string(), contents)])
        .await
        .context("Valkey HSET repo adaptive recommendation failed")?;
    let _: () = valkey
        .expire(
            &key,
            config.adaptive_tuning.recommendation_ttl_secs as i64,
            None,
        )
        .await
        .context("Valkey EXPIRE repo adaptive recommendation failed")?;
    Ok(())
}

fn repo_recommendation(
    controller: &'static str,
    controller_version: &'static str,
    policy: RepoAdaptivePolicy,
    decision: &'static str,
    reason: &'static str,
    confidence: f64,
) -> RepoRecommendationSet {
    RepoRecommendationSet {
        policy,
        controller: controller.to_string(),
        controller_version: controller_version.to_string(),
        decision: decision.to_string(),
        reason: reason.to_string(),
        confidence,
    }
}

fn aimd_repo_recommendation(
    policy: RepoAdaptivePolicy,
    decision: &'static str,
    reason: &'static str,
    confidence: f64,
) -> RepoRecommendationSet {
    repo_recommendation(
        AIMD_CONTROLLER_NAME,
        AIMD_CONTROLLER_VERSION,
        policy,
        decision,
        reason,
        confidence,
    )
}

fn demand_resource_repo_recommendation(
    policy: RepoAdaptivePolicy,
    decision: &'static str,
    reason: &'static str,
    confidence: f64,
) -> RepoRecommendationSet {
    repo_recommendation(
        DEMAND_RESOURCE_CONTROLLER_NAME,
        DEMAND_RESOURCE_CONTROLLER_VERSION,
        policy,
        decision,
        reason,
        confidence,
    )
}

fn recommend_repo_policy(snapshot: &RepoObservationSnapshot) -> RepoRecommendationSet {
    match snapshot.config.controller {
        AdaptiveTuningController::Aimd => recommend_aimd_repo_policy(snapshot),
        AdaptiveTuningController::DemandResource => recommend_demand_resource_repo_policy(snapshot),
    }
}

fn recommend_aimd_repo_policy(snapshot: &RepoObservationSnapshot) -> RepoRecommendationSet {
    if !snapshot.warmup_complete {
        return aimd_repo_recommendation(snapshot.current, "hold", "warmup", 0.0);
    }
    if snapshot.sample_count < snapshot.config.min_sample_count {
        return aimd_repo_recommendation(snapshot.current, "hold", "insufficient_samples", 0.2);
    }

    if let Some(reason) = repo_pressure_reason(snapshot) {
        let policy = decrease_repo_capacity(snapshot.current, &snapshot.config.bounds);
        return aimd_repo_recommendation(policy, "decrease", reason, 0.8);
    }

    if snapshot.fallback_rate >= snapshot.config.slo.fallback_rate {
        let (policy, decision) = increase_repo_fallback_capacity_or_waits(
            snapshot.current,
            &snapshot.config.bounds,
            snapshot.dominant_fallback_target,
        );
        return aimd_repo_recommendation(policy, decision, "fallback_rate_slo", 0.9);
    }

    if snapshot
        .clone_latency_secs_avg
        .is_some_and(|value| value >= snapshot.config.slo.clone_latency_secs)
    {
        let policy = decrease_repo_capacity(snapshot.current, &snapshot.config.bounds);
        return aimd_repo_recommendation(policy, "decrease", "clone_latency_slo", 0.9);
    }

    if snapshot
        .first_byte_latency_secs_avg
        .is_some_and(|value| value >= snapshot.config.slo.first_byte_latency_secs)
    {
        let policy = decrease_repo_capacity(snapshot.current, &snapshot.config.bounds);
        return aimd_repo_recommendation(policy, "decrease", "first_byte_latency_slo", 0.9);
    }

    let policy =
        increase_repo_capacity_decrease_timeouts(snapshot.current, &snapshot.config.bounds);
    aimd_repo_recommendation(policy, "probe", "healthy", 0.7)
}

fn recommend_demand_resource_repo_policy(
    snapshot: &RepoObservationSnapshot,
) -> RepoRecommendationSet {
    if let Some(reason) = repo_pressure_reason(snapshot) {
        let policy = decrease_repo_capacity(snapshot.current, &snapshot.config.bounds);
        return demand_resource_repo_recommendation(policy, "decrease", reason, 0.8);
    }

    if snapshot.fallback_rate >= snapshot.config.slo.fallback_rate {
        if let Some(policy) = increase_repo_capacity_for_fallback_target(
            snapshot.current,
            &snapshot.config.bounds,
            snapshot
                .dominant_fallback_target
                .unwrap_or(FallbackRecoveryTarget::Unknown),
        ) {
            return demand_resource_repo_recommendation(
                policy,
                "increase_capacity",
                "fallback_rate_slo",
                0.9,
            );
        }
        if let Some(policy) = increase_repo_waits_for_fallback_target(
            snapshot.current,
            &snapshot.config.bounds,
            snapshot
                .dominant_fallback_target
                .unwrap_or(FallbackRecoveryTarget::Unknown),
        ) {
            return demand_resource_repo_recommendation(
                policy,
                "increase_timeouts",
                "fallback_rate_slo",
                0.8,
            );
        }
        return demand_resource_repo_recommendation(
            snapshot.current,
            "hold",
            "fallback_rate_slo",
            0.4,
        );
    }

    if snapshot
        .first_byte_latency_secs_avg
        .is_some_and(|value| value >= snapshot.config.slo.first_byte_latency_secs)
    {
        if let Some(stage) = snapshot.dominant_ttfb_stage.map(|dominant| dominant.stage)
            && let Some(policy) = increase_repo_capacity_for_ttfb_stage(
                snapshot.current,
                &snapshot.config.bounds,
                stage,
            )
        {
            return demand_resource_repo_recommendation(
                policy,
                "increase_capacity",
                ttfb_stage_reason(stage),
                0.9,
            );
        }
        if let Some(policy) =
            increase_repo_local_upload_pack_capacity(snapshot.current, &snapshot.config.bounds)
        {
            return demand_resource_repo_recommendation(
                policy,
                "increase_capacity",
                "first_byte_latency_slo",
                0.8,
            );
        }
        if let Some(policy) = increase_repo_waits_for_fallback_target(
            snapshot.current,
            &snapshot.config.bounds,
            FallbackRecoveryTarget::LocalUploadPackFirstByte,
        ) {
            return demand_resource_repo_recommendation(
                policy,
                "increase_timeouts",
                "first_byte_latency_slo",
                0.7,
            );
        }
        return demand_resource_repo_recommendation(
            snapshot.current,
            "hold",
            "first_byte_latency_slo",
            0.4,
        );
    }

    if snapshot
        .clone_latency_secs_avg
        .is_some_and(|value| value >= snapshot.config.slo.clone_latency_secs)
    {
        if let Some(policy) =
            increase_repo_upstream_clone_capacity(snapshot.current, &snapshot.config.bounds)
        {
            return demand_resource_repo_recommendation(
                policy,
                "increase_capacity",
                "clone_latency_slo",
                0.8,
            );
        }
        return demand_resource_repo_recommendation(
            snapshot.current,
            "hold",
            "clone_latency_slo",
            0.4,
        );
    }

    let policy = decrease_repo_capacity(snapshot.current, &snapshot.config.bounds);
    if policy != snapshot.current {
        return demand_resource_repo_recommendation(policy, "decrease", "low_repo_demand", 0.6);
    }
    demand_resource_repo_recommendation(snapshot.current, "hold", "low_repo_demand", 0.6)
}

fn repo_pressure_reason(snapshot: &RepoObservationSnapshot) -> Option<&'static str> {
    let pressure = snapshot.host_pressure;
    let resource = &snapshot.config.resource_pressure;
    if pressure
        .cpu_busy_fraction
        .is_some_and(|value| value >= resource.cpu_busy_high_watermark)
    {
        return Some("cpu_busy");
    }
    if pressure
        .memory_available_percent
        .is_some_and(|value| value < resource.memory_available_min_percent)
    {
        return Some("memory_pressure");
    }
    if pressure
        .disk_busy_fraction
        .is_some_and(|value| value >= resource.disk_busy_high_watermark)
    {
        return Some("disk_busy");
    }
    None
}

fn increase_repo_capacity_decrease_timeouts(
    policy: RepoAdaptivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
) -> RepoAdaptivePolicy {
    RepoAdaptivePolicy {
        request_wait_for_local_catch_up_secs: step_down(
            policy.request_wait_for_local_catch_up_secs,
            bounds.request_wait_for_local_catch_up_secs,
        ),
        request_time_s3_restore_secs: step_down(
            policy.request_time_s3_restore_secs,
            bounds.request_time_s3_restore_secs,
        ),
        generation_publish_secs: step_down(
            policy.generation_publish_secs,
            bounds.generation_publish_secs,
        ),
        local_upload_pack_first_byte_secs: step_down(
            policy.local_upload_pack_first_byte_secs,
            bounds.local_upload_pack_first_byte_secs,
        ),
        upstream_clone_per_repo_per_instance: step_up(
            policy.upstream_clone_per_repo_per_instance,
            bounds.upstream_clone_per_repo_per_instance,
        ),
        upstream_clone_per_repo_across_instances: step_up(
            policy.upstream_clone_per_repo_across_instances,
            bounds.upstream_clone_per_repo_across_instances,
        ),
        local_upload_pack_per_repo: step_up(
            policy.local_upload_pack_per_repo,
            bounds.local_upload_pack_per_repo,
        ),
        tee_capture_per_repo: step_up(policy.tee_capture_per_repo, bounds.tee_capture_per_repo),
    }
}

fn increase_repo_timeouts_preserve_capacity(
    policy: RepoAdaptivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
) -> RepoAdaptivePolicy {
    RepoAdaptivePolicy {
        request_wait_for_local_catch_up_secs: step_up(
            policy.request_wait_for_local_catch_up_secs,
            bounds.request_wait_for_local_catch_up_secs,
        ),
        request_time_s3_restore_secs: step_up(
            policy.request_time_s3_restore_secs,
            bounds.request_time_s3_restore_secs,
        ),
        generation_publish_secs: step_up(
            policy.generation_publish_secs,
            bounds.generation_publish_secs,
        ),
        local_upload_pack_first_byte_secs: step_up(
            policy.local_upload_pack_first_byte_secs,
            bounds.local_upload_pack_first_byte_secs,
        ),
        ..policy
    }
}

fn increase_repo_fallback_capacity_or_waits(
    policy: RepoAdaptivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
    target: Option<FallbackRecoveryTarget>,
) -> (RepoAdaptivePolicy, &'static str) {
    let target = target.unwrap_or(FallbackRecoveryTarget::Unknown);
    if let Some(policy) = increase_repo_capacity_for_fallback_target(policy, bounds, target) {
        return (policy, "increase_capacity");
    }

    if let Some(policy) = increase_repo_waits_for_fallback_target(policy, bounds, target) {
        return (policy, "increase_timeouts");
    }

    (policy, "hold")
}

fn increase_repo_capacity_for_fallback_target(
    policy: RepoAdaptivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
    target: FallbackRecoveryTarget,
) -> Option<RepoAdaptivePolicy> {
    match target {
        FallbackRecoveryTarget::LocalUploadPackPermit
        | FallbackRecoveryTarget::LocalUploadPackFirstByte => {
            increase_repo_local_upload_pack_capacity(policy, bounds)
        }
        FallbackRecoveryTarget::PublishedGenerationLease
        | FallbackRecoveryTarget::UpstreamCloneRepo => {
            increase_repo_upstream_clone_capacity(policy, bounds)
        }
        FallbackRecoveryTarget::LocalCatchUp => None,
        FallbackRecoveryTarget::UpstreamCloneGlobal => None,
        FallbackRecoveryTarget::PackCacheLookup => None,
        FallbackRecoveryTarget::Unknown => increase_repo_local_upload_pack_capacity(policy, bounds)
            .or_else(|| increase_repo_upstream_clone_capacity(policy, bounds)),
    }
}

fn increase_repo_capacity_for_ttfb_stage(
    policy: RepoAdaptivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
    stage: TtfbStage,
) -> Option<RepoAdaptivePolicy> {
    match stage {
        TtfbStage::LocalUploadPackPermitWait
        | TtfbStage::LocalUploadPackSpawnAndStdin
        | TtfbStage::LocalUploadPackFirstByteWait => {
            increase_repo_local_upload_pack_capacity(policy, bounds)
        }
        TtfbStage::PublishedGenerationLeaseWait => {
            increase_repo_upstream_clone_capacity(policy, bounds)
        }
        TtfbStage::PackCacheLookupWait | TtfbStage::PackCacheCompositeWait => None,
    }
}

fn increase_repo_local_upload_pack_capacity(
    policy: RepoAdaptivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
) -> Option<RepoAdaptivePolicy> {
    capacity_available([(
        policy.local_upload_pack_per_repo,
        bounds.local_upload_pack_per_repo,
    )])
    .then_some(RepoAdaptivePolicy {
        local_upload_pack_per_repo: step_up(
            policy.local_upload_pack_per_repo,
            bounds.local_upload_pack_per_repo,
        ),
        ..policy
    })
}

fn increase_repo_upstream_clone_capacity(
    policy: RepoAdaptivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
) -> Option<RepoAdaptivePolicy> {
    capacity_available([
        (
            policy.upstream_clone_per_repo_per_instance,
            bounds.upstream_clone_per_repo_per_instance,
        ),
        (
            policy.upstream_clone_per_repo_across_instances,
            bounds.upstream_clone_per_repo_across_instances,
        ),
    ])
    .then_some(RepoAdaptivePolicy {
        upstream_clone_per_repo_per_instance: step_up(
            policy.upstream_clone_per_repo_per_instance,
            bounds.upstream_clone_per_repo_per_instance,
        ),
        upstream_clone_per_repo_across_instances: step_up(
            policy.upstream_clone_per_repo_across_instances,
            bounds.upstream_clone_per_repo_across_instances,
        ),
        ..policy
    })
}

fn increase_repo_waits_for_fallback_target(
    policy: RepoAdaptivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
    target: FallbackRecoveryTarget,
) -> Option<RepoAdaptivePolicy> {
    match target {
        FallbackRecoveryTarget::LocalUploadPackFirstByte => capacity_available([(
            policy.local_upload_pack_first_byte_secs,
            bounds.local_upload_pack_first_byte_secs,
        )])
        .then_some(RepoAdaptivePolicy {
            local_upload_pack_first_byte_secs: step_up(
                policy.local_upload_pack_first_byte_secs,
                bounds.local_upload_pack_first_byte_secs,
            ),
            ..policy
        }),
        FallbackRecoveryTarget::LocalCatchUp
        | FallbackRecoveryTarget::PublishedGenerationLease
        | FallbackRecoveryTarget::Unknown => {
            Some(increase_repo_timeouts_preserve_capacity(policy, bounds))
        }
        FallbackRecoveryTarget::LocalUploadPackPermit
        | FallbackRecoveryTarget::PackCacheLookup
        | FallbackRecoveryTarget::UpstreamCloneGlobal
        | FallbackRecoveryTarget::UpstreamCloneRepo => None,
    }
}

fn decrease_repo_capacity(
    policy: RepoAdaptivePolicy,
    bounds: &AdaptiveTuningBoundsConfig,
) -> RepoAdaptivePolicy {
    RepoAdaptivePolicy {
        upstream_clone_per_repo_per_instance: step_down(
            policy.upstream_clone_per_repo_per_instance,
            bounds.upstream_clone_per_repo_per_instance,
        ),
        upstream_clone_per_repo_across_instances: step_down(
            policy.upstream_clone_per_repo_across_instances,
            bounds.upstream_clone_per_repo_across_instances,
        ),
        local_upload_pack_per_repo: step_down(
            policy.local_upload_pack_per_repo,
            bounds.local_upload_pack_per_repo,
        ),
        tee_capture_per_repo: step_down(policy.tee_capture_per_repo, bounds.tee_capture_per_repo),
        ..policy
    }
}

fn aggregate_repo_policies(
    policies: &[RepoAdaptivePolicy],
    bounds: &AdaptiveTuningBoundsConfig,
) -> Option<RepoAdaptivePolicy> {
    if policies.is_empty() {
        return None;
    }

    Some(
        RepoAdaptivePolicy {
            request_wait_for_local_catch_up_secs: median_usize(
                policies
                    .iter()
                    .map(|policy| policy.request_wait_for_local_catch_up_secs),
            ),
            request_time_s3_restore_secs: median_usize(
                policies
                    .iter()
                    .map(|policy| policy.request_time_s3_restore_secs),
            ),
            generation_publish_secs: median_usize(
                policies.iter().map(|policy| policy.generation_publish_secs),
            ),
            local_upload_pack_first_byte_secs: median_usize(
                policies
                    .iter()
                    .map(|policy| policy.local_upload_pack_first_byte_secs),
            ),
            upstream_clone_per_repo_per_instance: median_usize(
                policies
                    .iter()
                    .map(|policy| policy.upstream_clone_per_repo_per_instance),
            ),
            upstream_clone_per_repo_across_instances: median_usize(
                policies
                    .iter()
                    .map(|policy| policy.upstream_clone_per_repo_across_instances),
            ),
            local_upload_pack_per_repo: median_usize(
                policies
                    .iter()
                    .map(|policy| policy.local_upload_pack_per_repo),
            ),
            tee_capture_per_repo: median_usize(
                policies.iter().map(|policy| policy.tee_capture_per_repo),
            ),
        }
        .bounded_for_adaptive_recommendation(bounds),
    )
}

fn median_usize(values: impl Iterator<Item = usize>) -> usize {
    let mut values = values.collect::<Vec<_>>();
    values.sort_unstable();
    values[values.len() / 2]
}

pub struct RuntimeController {
    policy_state: Arc<EffectivePolicyState>,
    observations: Arc<AdaptiveObservationCounters>,
    deployment: String,
    instance_id: String,
    started_at: Instant,
    previous_totals: ObservationTotals,
    previous_repo_totals: HashMap<String, ObservationTotals>,
    previous_tick: Instant,
}

impl RuntimeController {
    pub fn new(
        policy_state: Arc<EffectivePolicyState>,
        observations: Arc<AdaptiveObservationCounters>,
        deployment: String,
        instance_id: String,
    ) -> Self {
        Self {
            policy_state,
            observations,
            deployment,
            instance_id,
            started_at: Instant::now(),
            previous_totals: ObservationTotals::default(),
            previous_repo_totals: HashMap::new(),
            previous_tick: Instant::now(),
        }
    }

    pub async fn run(mut self, state: crate::AppState) {
        let resource_events = self.policy_state.event_notifier();
        loop {
            let (interval, cpu_poll_interval, enabled, controller) = {
                let config = state.config();
                (
                    Duration::from_secs(config.adaptive_tuning.evaluation_interval_secs.max(1)),
                    config.adaptive_tuning.cpu_poll_interval_secs,
                    config.adaptive_tuning.enabled
                        && config.adaptive_tuning.mode != AdaptiveTuningMode::Disabled,
                    config.adaptive_tuning.controller,
                )
            };

            let (host_pressure, demand_snapshot) = match (enabled, controller) {
                (false, _) => {
                    tokio::time::sleep(interval).await;
                    continue;
                }
                (true, AdaptiveTuningController::Aimd) => (
                    sample_host_pressure(interval, cpu_poll_interval).await,
                    self.policy_state.demand_snapshot(),
                ),
                (true, AdaptiveTuningController::DemandResource) => {
                    tokio::select! {
                        _ = self.observations.notified() => {}
                        _ = resource_events.notified() => {}
                    };
                    let event_demand = self.policy_state.demand_snapshot();
                    if !event_demand.has_active_claims() {
                        continue;
                    }
                    let host_pressure = sample_event_host_pressure().await;
                    let demand_snapshot =
                        event_demand.max_with(self.policy_state.demand_snapshot());
                    (host_pressure, demand_snapshot)
                }
            };
            if let Err(error) = self.tick(&state, host_pressure, demand_snapshot).await {
                tracing::warn!(error = %error, "adaptive tuning tick failed");
            }
        }
    }

    async fn tick(
        &mut self,
        state: &crate::AppState,
        host_pressure: HostPressure,
        demand_snapshot: RuntimeDemandSnapshot,
    ) -> Result<()> {
        let config = state.config();
        if !config.adaptive_tuning.enabled
            || config.adaptive_tuning.mode == AdaptiveTuningMode::Disabled
        {
            return Ok(());
        }

        let now_totals = self.observations.snapshot();
        let window = delta(self.previous_totals, now_totals);
        self.previous_totals = now_totals;
        let model = observation_model(config.adaptive_tuning.controller, window, now_totals);
        let sample_count = observation_sample_count(model);
        let repo_totals = self.observations.changed_repo_snapshot();
        let repo_windows = repo_deltas(&mut self.previous_repo_totals, repo_totals.clone());
        let elapsed = self.previous_tick.elapsed();
        self.previous_tick = Instant::now();
        let sample_window_secs = match config.adaptive_tuning.controller {
            AdaptiveTuningController::Aimd => elapsed.as_secs(),
            AdaptiveTuningController::DemandResource => 0,
        };

        let snapshot = ObservationSnapshot {
            sample_count,
            clone_latency_secs_avg: avg_seconds(
                model.clone_latency_millis_total,
                model.clone_samples,
            ),
            first_byte_latency_secs_avg: avg_seconds(
                model.first_byte_latency_millis_total,
                model.first_byte_samples,
            ),
            dominant_ttfb_stage: dominant_ttfb_stage(model),
            fallback_rate: rate(model.upstream_fallbacks, sample_count),
            dominant_fallback_target: dominant_fallback_target(model),
            host_pressure,
            demand: demand_snapshot,
            host_cpu_threads: host_cpu_threads(),
            current: self.policy_state.snapshot(),
            config: config.adaptive_tuning.clone(),
            warmup_complete: self.started_at.elapsed()
                >= Duration::from_secs(config.adaptive_tuning.warmup_interval_secs),
        };

        let recommendation = match config.adaptive_tuning.controller {
            AdaptiveTuningController::Aimd => AimdController.observe(&snapshot),
            AdaptiveTuningController::DemandResource => DemandResourceController.observe(&snapshot),
        };
        let preserve_operator_first_byte_zero = config.clone.local_upload_pack_first_byte_secs == 0;
        let bounded = bound_effective_adaptive_recommendation(
            recommendation.policy,
            &config.adaptive_tuning.bounds,
            preserve_operator_first_byte_zero,
        );
        let recommendation = RecommendationSet {
            policy: bounded,
            ..recommendation
        };

        tracing::debug!(
            controller = %recommendation.controller,
            controller_version = %recommendation.controller_version,
            mode = config.adaptive_tuning.mode.as_label(),
            decision = %recommendation.decision,
            reason = %recommendation.reason,
            confidence = recommendation.confidence,
            sample_count = snapshot.sample_count,
            clone_latency_secs_avg = ?snapshot.clone_latency_secs_avg,
            first_byte_latency_secs_avg = ?snapshot.first_byte_latency_secs_avg,
            fallback_rate = snapshot.fallback_rate,
            dominant_fallback_target = ?snapshot.dominant_fallback_target,
            dominant_ttfb_stage = ?snapshot.dominant_ttfb_stage,
            host_cpu_threads = snapshot.host_cpu_threads,
            demand = ?snapshot.demand,
            cpu_busy_fraction = ?snapshot.host_pressure.cpu_busy_fraction,
            disk_busy_fraction = ?snapshot.host_pressure.disk_busy_fraction,
            memory_available_percent = ?snapshot.host_pressure.memory_available_percent,
            current_policy = ?snapshot.current,
            recommended_policy = ?recommendation.policy,
            "adaptive tuning controller decision"
        );

        crate::metrics::record_adaptive_recommendation(
            &state.metrics,
            config.adaptive_tuning.mode.as_label(),
            &recommendation,
            snapshot.current,
        );
        crate::metrics::record_adaptive_pressure(&state.metrics, snapshot.host_pressure);

        let envelope = RecommendationEnvelope {
            timestamp_unix_secs: unix_now_secs(),
            sample_window_secs,
            confidence: recommendation.confidence,
            controller: recommendation.controller.clone(),
            controller_version: recommendation.controller_version.clone(),
            mode: config.adaptive_tuning.mode.as_label().to_string(),
            recommendation: recommendation.policy,
            input_summary: RecommendationInputSummary {
                sample_count: snapshot.sample_count,
                clone_latency_secs_avg: snapshot.clone_latency_secs_avg,
                first_byte_latency_secs_avg: snapshot.first_byte_latency_secs_avg,
                dominant_ttfb_stage: snapshot.dominant_ttfb_stage,
                fallback_rate: snapshot.fallback_rate,
                dominant_fallback_target: snapshot.dominant_fallback_target,
                host_pressure: snapshot.host_pressure,
                decision: recommendation.decision.clone(),
                reason: recommendation.reason.clone(),
            },
            bounds: config.adaptive_tuning.bounds.clone(),
            source_instance_id: self.instance_id.clone(),
        };

        persist_observation(
            &state.valkey,
            &self.deployment,
            &self.instance_id,
            &envelope,
            config.adaptive_tuning.recommendation_ttl_secs,
        )
        .await?;

        self.tick_repo_policies(
            state,
            &config,
            snapshot.host_pressure,
            Duration::from_secs(sample_window_secs),
            repo_windows,
            repo_totals,
        )
        .await?;

        if config.adaptive_tuning.mode == AdaptiveTuningMode::Active {
            let previous = self.policy_state.snapshot();
            self.policy_state.apply(recommendation.policy);
            for knob in previous.changed_knobs(recommendation.policy) {
                tracing::info!(
                    knob,
                    decision = %recommendation.decision,
                    reason = %recommendation.reason,
                    "applied adaptive tuning recommendation"
                );
            }
            persist_recommendation(
                &state.valkey,
                &config,
                &self.deployment,
                &self.instance_id,
                &envelope,
            )
            .await?;
        }

        crate::metrics::record_adaptive_effective_policy(
            &state.metrics,
            self.policy_state.snapshot(),
        );
        Ok(())
    }

    async fn tick_repo_policies(
        &mut self,
        state: &crate::AppState,
        config: &Config,
        host_pressure: HostPressure,
        elapsed: Duration,
        repo_windows: HashMap<String, ObservationTotals>,
        repo_totals: HashMap<String, ObservationTotals>,
    ) -> Result<()> {
        for (owner_repo, window) in repo_windows {
            let model = match config.adaptive_tuning.controller {
                AdaptiveTuningController::Aimd => window,
                AdaptiveTuningController::DemandResource => {
                    repo_totals.get(&owner_repo).copied().unwrap_or(window)
                }
            };
            let sample_count = repo_sample_count(model);
            if sample_count == 0 {
                continue;
            }

            let current = self
                .policy_state
                .repo_policy(&owner_repo)
                .bounded(&config.adaptive_tuning.bounds);
            let snapshot = RepoObservationSnapshot {
                owner_repo: owner_repo.clone(),
                sample_count,
                clone_latency_secs_avg: avg_seconds(
                    model.clone_latency_millis_total,
                    model.clone_samples,
                ),
                first_byte_latency_secs_avg: avg_seconds(
                    model.first_byte_latency_millis_total,
                    model.first_byte_samples,
                ),
                dominant_ttfb_stage: dominant_ttfb_stage(model),
                fallback_rate: rate(model.upstream_fallbacks, sample_count),
                dominant_fallback_target: dominant_fallback_target(model),
                host_pressure,
                current,
                config: config.adaptive_tuning.clone(),
                warmup_complete: self.started_at.elapsed()
                    >= Duration::from_secs(config.adaptive_tuning.warmup_interval_secs),
            };
            let recommendation = recommend_repo_policy(&snapshot);
            let preserve_operator_first_byte_zero =
                config.clone.local_upload_pack_first_byte_secs == 0;
            let recommendation = RepoRecommendationSet {
                policy: bound_repo_adaptive_recommendation(
                    recommendation.policy,
                    &config.adaptive_tuning.bounds,
                    preserve_operator_first_byte_zero,
                ),
                ..recommendation
            };
            tracing::debug!(
                repo = %owner_repo,
                controller = %recommendation.controller,
                controller_version = %recommendation.controller_version,
                mode = config.adaptive_tuning.mode.as_label(),
                decision = %recommendation.decision,
                reason = %recommendation.reason,
                confidence = recommendation.confidence,
                sample_count = snapshot.sample_count,
                clone_latency_secs_avg = ?snapshot.clone_latency_secs_avg,
                first_byte_latency_secs_avg = ?snapshot.first_byte_latency_secs_avg,
                fallback_rate = snapshot.fallback_rate,
                dominant_fallback_target = ?snapshot.dominant_fallback_target,
                dominant_ttfb_stage = ?snapshot.dominant_ttfb_stage,
                cpu_busy_fraction = ?snapshot.host_pressure.cpu_busy_fraction,
                disk_busy_fraction = ?snapshot.host_pressure.disk_busy_fraction,
                memory_available_percent = ?snapshot.host_pressure.memory_available_percent,
                current_repo_policy = ?snapshot.current,
                recommended_repo_policy = ?recommendation.policy,
                "repo adaptive tuning controller decision"
            );
            let envelope = RepoRecommendationEnvelope {
                timestamp_unix_secs: unix_now_secs(),
                sample_window_secs: elapsed.as_secs(),
                confidence: recommendation.confidence,
                controller: recommendation.controller.clone(),
                controller_version: recommendation.controller_version.clone(),
                mode: config.adaptive_tuning.mode.as_label().to_string(),
                recommendation: recommendation.policy,
                input_summary: RecommendationInputSummary {
                    sample_count: snapshot.sample_count,
                    clone_latency_secs_avg: snapshot.clone_latency_secs_avg,
                    first_byte_latency_secs_avg: snapshot.first_byte_latency_secs_avg,
                    dominant_ttfb_stage: snapshot.dominant_ttfb_stage,
                    fallback_rate: snapshot.fallback_rate,
                    dominant_fallback_target: snapshot.dominant_fallback_target,
                    host_pressure: snapshot.host_pressure,
                    decision: recommendation.decision.clone(),
                    reason: recommendation.reason.clone(),
                },
                bounds: config.adaptive_tuning.bounds.clone(),
                source_instance_id: self.instance_id.clone(),
                source_owner_repo: snapshot.owner_repo.clone(),
            };

            persist_repo_recommendation(
                &state.valkey,
                config,
                &self.deployment,
                &self.instance_id,
                &owner_repo,
                &envelope,
            )
            .await?;

            if config.adaptive_tuning.mode != AdaptiveTuningMode::Active {
                continue;
            }

            let mut policies =
                load_repo_recommendations(&state.valkey, config, &self.deployment, &owner_repo)
                    .await?
                    .into_iter()
                    .filter(|envelope| envelope.controller == recommendation.controller)
                    .map(|envelope| {
                        bound_repo_adaptive_recommendation(
                            envelope.recommendation,
                            &config.adaptive_tuning.bounds,
                            preserve_operator_first_byte_zero,
                        )
                    })
                    .collect::<Vec<_>>();
            if policies.is_empty() {
                policies.push(recommendation.policy);
            }

            let Some(aggregate) =
                aggregate_repo_policies(&policies, &config.adaptive_tuning.bounds)
            else {
                continue;
            };
            let aggregate = bound_repo_adaptive_recommendation(
                aggregate,
                &config.adaptive_tuning.bounds,
                preserve_operator_first_byte_zero,
            );
            let previous = self.policy_state.repo_policy(&owner_repo);
            tracing::debug!(
                repo = %owner_repo,
                peers = policies.len(),
                controller = %recommendation.controller,
                decision = %recommendation.decision,
                reason = %recommendation.reason,
                previous_repo_policy = ?previous,
                local_recommended_repo_policy = ?recommendation.policy,
                aggregated_repo_policy = ?aggregate,
                "repo adaptive tuning peer aggregation decision"
            );
            self.policy_state.apply_repo_policy(&owner_repo, aggregate);
            for knob in previous.changed_knobs(aggregate) {
                tracing::info!(
                    repo = %owner_repo,
                    knob,
                    decision = %recommendation.decision,
                    reason = %recommendation.reason,
                    peers = policies.len(),
                    "applied repo adaptive tuning recommendation"
                );
            }
        }
        Ok(())
    }
}

fn delta(previous: ObservationTotals, next: ObservationTotals) -> ObservationTotals {
    ObservationTotals {
        clone_samples: next.clone_samples.saturating_sub(previous.clone_samples),
        clone_latency_millis_total: next
            .clone_latency_millis_total
            .saturating_sub(previous.clone_latency_millis_total),
        first_byte_samples: next
            .first_byte_samples
            .saturating_sub(previous.first_byte_samples),
        first_byte_latency_millis_total: next
            .first_byte_latency_millis_total
            .saturating_sub(previous.first_byte_latency_millis_total),
        ttfb_stage_samples: next
            .ttfb_stage_samples
            .saturating_sub(previous.ttfb_stage_samples),
        ttfb_stage_millis_total: next
            .ttfb_stage_millis_total
            .saturating_sub(previous.ttfb_stage_millis_total),
        upstream_fallbacks: next
            .upstream_fallbacks
            .saturating_sub(previous.upstream_fallbacks),
        fallback_local_upload_pack_permit: next
            .fallback_local_upload_pack_permit
            .saturating_sub(previous.fallback_local_upload_pack_permit),
        fallback_local_upload_pack_first_byte: next
            .fallback_local_upload_pack_first_byte
            .saturating_sub(previous.fallback_local_upload_pack_first_byte),
        fallback_local_catch_up: next
            .fallback_local_catch_up
            .saturating_sub(previous.fallback_local_catch_up),
        fallback_published_generation_lease: next
            .fallback_published_generation_lease
            .saturating_sub(previous.fallback_published_generation_lease),
        fallback_pack_cache_lookup: next
            .fallback_pack_cache_lookup
            .saturating_sub(previous.fallback_pack_cache_lookup),
        fallback_upstream_clone_global: next
            .fallback_upstream_clone_global
            .saturating_sub(previous.fallback_upstream_clone_global),
        fallback_upstream_clone_repo: next
            .fallback_upstream_clone_repo
            .saturating_sub(previous.fallback_upstream_clone_repo),
        fallback_unknown: next
            .fallback_unknown
            .saturating_sub(previous.fallback_unknown),
    }
}

fn repo_deltas(
    previous: &mut HashMap<String, ObservationTotals>,
    next: HashMap<String, ObservationTotals>,
) -> HashMap<String, ObservationTotals> {
    let mut windows = HashMap::new();
    for (owner_repo, next_totals) in next {
        let previous_totals = previous
            .insert(owner_repo.clone(), next_totals)
            .unwrap_or_default();
        windows.insert(owner_repo, delta(previous_totals, next_totals));
    }
    windows
}

fn observation_model(
    controller: AdaptiveTuningController,
    window: ObservationTotals,
    totals: ObservationTotals,
) -> ObservationTotals {
    match controller {
        AdaptiveTuningController::Aimd => window,
        AdaptiveTuningController::DemandResource => totals,
    }
}

fn observation_sample_count(window: ObservationTotals) -> u64 {
    window
        .clone_samples
        .max(window.first_byte_samples)
        .max(window.ttfb_stage_samples)
        .max(window.upstream_fallbacks)
}

fn repo_sample_count(window: ObservationTotals) -> u64 {
    observation_sample_count(window)
}

fn dominant_fallback_target(window: ObservationTotals) -> Option<FallbackRecoveryTarget> {
    [
        (
            FallbackRecoveryTarget::LocalUploadPackPermit,
            window.fallback_local_upload_pack_permit,
        ),
        (
            FallbackRecoveryTarget::LocalUploadPackFirstByte,
            window.fallback_local_upload_pack_first_byte,
        ),
        (
            FallbackRecoveryTarget::LocalCatchUp,
            window.fallback_local_catch_up,
        ),
        (
            FallbackRecoveryTarget::PublishedGenerationLease,
            window.fallback_published_generation_lease,
        ),
        (
            FallbackRecoveryTarget::PackCacheLookup,
            window.fallback_pack_cache_lookup,
        ),
        (
            FallbackRecoveryTarget::UpstreamCloneGlobal,
            window.fallback_upstream_clone_global,
        ),
        (
            FallbackRecoveryTarget::UpstreamCloneRepo,
            window.fallback_upstream_clone_repo,
        ),
        (FallbackRecoveryTarget::Unknown, window.fallback_unknown),
    ]
    .into_iter()
    .max_by_key(|(_, count)| *count)
    .and_then(|(target, count)| (count > 0).then_some(target))
}

fn dominant_ttfb_stage(window: ObservationTotals) -> Option<DominantTtfbStage> {
    let total_millis = window.ttfb_stage_millis_total.total_millis();
    if window.ttfb_stage_samples == 0 || total_millis == 0 {
        return None;
    }

    TtfbStage::ALL
        .into_iter()
        .map(|stage| (stage, window.ttfb_stage_millis_total.stage_millis(stage)))
        .max_by_key(|(_, millis)| *millis)
        .and_then(|(stage, millis)| {
            (millis > 0).then_some(DominantTtfbStage {
                stage,
                avg_secs: millis as f64 / window.ttfb_stage_samples as f64 / 1000.0,
                contribution: millis as f64 / total_millis as f64,
            })
        })
}

fn avg_seconds(total_millis: u64, samples: u64) -> Option<f64> {
    (samples > 0).then_some(total_millis as f64 / samples as f64 / 1000.0)
}

fn rate(count: u64, samples: u64) -> f64 {
    if samples == 0 {
        0.0
    } else {
        count as f64 / samples as f64
    }
}

pub async fn sample_host_pressure(window: Duration, cpu_poll_interval_secs: u64) -> HostPressure {
    let (cpu_busy_fraction, disk_busy_fraction) =
        sample_cpu_and_disk_busy_fraction(window, cpu_poll_interval_secs).await;
    let memory_available_percent = read_mem_available_percent();

    HostPressure {
        cpu_busy_fraction,
        disk_busy_fraction,
        memory_available_percent,
    }
}

async fn sample_event_host_pressure() -> HostPressure {
    let (cpu_busy_fraction, disk_busy_fraction) =
        sample_cpu_and_disk_busy_fraction(DEMAND_RESOURCE_PRESSURE_SAMPLE_WINDOW, 1).await;
    let memory_available_percent = read_mem_available_percent();

    HostPressure {
        cpu_busy_fraction,
        disk_busy_fraction,
        memory_available_percent,
    }
}

fn host_cpu_threads() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
}

#[derive(Clone, Copy)]
struct CpuSnapshot {
    total: u64,
    idle_or_iowait: u64,
}

#[derive(Clone, Debug, Default)]
struct DiskSnapshot {
    io_ticks_by_device: HashMap<String, u64>,
}

fn read_cpu_snapshot() -> Option<CpuSnapshot> {
    let contents = std::fs::read_to_string("/proc/stat").ok()?;
    let line = contents.lines().find(|line| line.starts_with("cpu "))?;
    let values = line
        .split_whitespace()
        .skip(1)
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .ok()?;
    if values.len() < 4 {
        return None;
    }
    Some(CpuSnapshot {
        idle_or_iowait: values.get(3).copied().unwrap_or(0) + values.get(4).copied().unwrap_or(0),
        total: values.iter().sum(),
    })
}

fn read_disk_snapshot() -> Option<DiskSnapshot> {
    let contents = std::fs::read_to_string("/proc/diskstats").ok()?;
    let mut io_ticks_by_device = HashMap::new();
    for line in contents.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 13 {
            continue;
        }
        let device = fields[2];
        if is_virtual_or_memory_disk(device) {
            continue;
        }
        let Some(io_ticks) = fields[12].parse::<u64>().ok() else {
            continue;
        };
        io_ticks_by_device.insert(device.to_string(), io_ticks);
    }
    (!io_ticks_by_device.is_empty()).then_some(DiskSnapshot { io_ticks_by_device })
}

fn is_virtual_or_memory_disk(device: &str) -> bool {
    device.starts_with("loop")
        || device.starts_with("ram")
        || device.starts_with("zram")
        || device.starts_with("fd")
        || device.starts_with("sr")
}

async fn sample_cpu_and_disk_busy_fraction(
    window: Duration,
    cpu_poll_interval_secs: u64,
) -> (Option<f64>, Option<f64>) {
    let poll_interval = Duration::from_secs(cpu_poll_interval_secs.max(1));
    let start = Instant::now();
    let deadline = start + window;
    let mut next_poll = start;
    let mut cpu_total = 0.0;
    let mut cpu_count = 0usize;
    let mut disk_total = 0.0;
    let mut disk_count = 0usize;

    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        if now < next_poll {
            tokio::time::sleep((next_poll - now).min(deadline - now)).await;
            continue;
        }

        let before_cpu = read_cpu_snapshot();
        let before_disk = read_disk_snapshot();
        let sample_started = Instant::now();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let sample_elapsed = sample_started.elapsed();
        if let Some(value) = before_cpu
            .zip(read_cpu_snapshot())
            .and_then(|(before, after)| cpu_busy_fraction(before, after))
        {
            cpu_total += value;
            cpu_count += 1;
        }
        if let Some(value) = before_disk
            .zip(read_disk_snapshot())
            .and_then(|(before, after)| disk_busy_fraction(before, after, sample_elapsed))
        {
            disk_total += value;
            disk_count += 1;
        }
        next_poll += poll_interval;
    }

    (
        (cpu_count > 0).then_some(cpu_total / cpu_count as f64),
        (disk_count > 0).then_some(disk_total / disk_count as f64),
    )
}

fn cpu_busy_fraction(before: CpuSnapshot, after: CpuSnapshot) -> Option<f64> {
    let total_delta = after.total.saturating_sub(before.total);
    let idle_delta = after.idle_or_iowait.saturating_sub(before.idle_or_iowait);
    (total_delta > 0).then_some(1.0 - (idle_delta as f64 / total_delta as f64))
}

fn disk_busy_fraction(before: DiskSnapshot, after: DiskSnapshot, elapsed: Duration) -> Option<f64> {
    let elapsed_ms = elapsed.as_millis() as f64;
    if elapsed_ms <= 0.0 {
        return None;
    }
    let mut max_busy = None::<f64>;
    for (device, before_ticks) in before.io_ticks_by_device {
        let Some(after_ticks) = after.io_ticks_by_device.get(&device) else {
            continue;
        };
        let busy = after_ticks.saturating_sub(before_ticks) as f64 / elapsed_ms;
        max_busy = Some(max_busy.map_or(busy, |current| current.max(busy)));
    }
    max_busy.map(|value| value.clamp(0.0, 1.0))
}

fn read_mem_available_percent() -> Option<f64> {
    if let Some(percent) = read_cgroup_mem_available_percent() {
        return Some(percent);
    }

    let contents = std::fs::read_to_string("/proc/meminfo").ok()?;
    let mut available_kib = None;
    let mut total_kib = None;
    for line in contents.lines() {
        if let Some(value) = line.strip_prefix("MemAvailable:") {
            available_kib = value
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<u64>().ok());
        } else if let Some(value) = line.strip_prefix("MemTotal:") {
            total_kib = value
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<u64>().ok());
        }
    }
    let available_kib = available_kib?;
    let total_kib = total_kib?;
    (total_kib > 0).then_some(available_kib as f64 / total_kib as f64 * 100.0)
}

fn read_cgroup_mem_available_percent() -> Option<f64> {
    let max = read_cgroup_memory_value("/sys/fs/cgroup/memory.max")?;
    if max == 0 {
        return None;
    }
    let current = read_cgroup_memory_value("/sys/fs/cgroup/memory.current")?;
    let available = max.saturating_sub(current);
    Some(available as f64 / max as f64 * 100.0)
}

fn read_cgroup_memory_value(path: &str) -> Option<u64> {
    let contents = std::fs::read_to_string(path).ok()?;
    let value = contents.trim();
    if value == "max" {
        return None;
    }
    value.parse().ok()
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn deployment_label(attributes: &crate::runtime_resource::RuntimeResourceAttributes) -> String {
    attributes
        .deployment_environment
        .as_deref()
        .unwrap_or("default")
        .to_string()
}

pub fn instance_id(
    attributes: &crate::runtime_resource::RuntimeResourceAttributes,
    node_id: &str,
) -> String {
    attributes
        .service_instance_id
        .clone()
        .or_else(|| attributes.service_machine_id.clone())
        .unwrap_or_else(|| node_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> AdaptiveTuningConfig {
        AdaptiveTuningConfig {
            warmup_interval_secs: 1,
            min_sample_count: 10,
            ..AdaptiveTuningConfig::default()
        }
    }

    fn policy(value: usize) -> EffectivePolicy {
        EffectivePolicy {
            upstream_clone_concurrency: value,
            upstream_fetch_concurrency: value,
            upstream_clone_per_repo_per_instance: value,
            upstream_clone_per_repo_across_instances: value,
            tee_capture_concurrency: value,
            tee_capture_per_repo: value,
            local_upload_pack_concurrency: value,
            local_upload_pack_per_repo: value,
            deep_validation_concurrency: value,
            prewarm_concurrency: value,
            bundle_generation_concurrency: value,
            pack_cache_request_delta_concurrency: value,
            pack_cache_background_warming_concurrency: value,
            bundle_pack_threads: value,
            local_upload_pack_threads: value,
            index_pack_threads: value,
            request_wait_for_local_catch_up_secs: value,
            request_time_s3_restore_secs: value,
            generation_publish_secs: value,
            local_upload_pack_first_byte_secs: value,
        }
    }

    fn recommendation_envelope(
        controller: &str,
        recommendation: EffectivePolicy,
    ) -> RecommendationEnvelope {
        RecommendationEnvelope {
            timestamp_unix_secs: unix_now_secs(),
            sample_window_secs: 60,
            confidence: 0.9,
            controller: controller.to_string(),
            controller_version: "test".to_string(),
            mode: AdaptiveTuningMode::Active.as_label().to_string(),
            recommendation,
            input_summary: RecommendationInputSummary {
                sample_count: 10,
                clone_latency_secs_avg: None,
                first_byte_latency_secs_avg: None,
                dominant_ttfb_stage: None,
                fallback_rate: 0.0,
                dominant_fallback_target: None,
                host_pressure: HostPressure::default(),
                decision: "test".to_string(),
                reason: "test".to_string(),
            },
            bounds: AdaptiveTuningBoundsConfig::default(),
            source_instance_id: "instance-a".to_string(),
        }
    }

    #[test]
    fn startup_recommendation_policy_ignores_other_controller() {
        let bounds = AdaptiveTuningBoundsConfig::default();
        let envelope = recommendation_envelope(AIMD_CONTROLLER_NAME, policy(7));

        assert!(
            startup_recommendation_policy(
                &envelope,
                DEMAND_RESOURCE_CONTROLLER_NAME,
                &bounds,
                false,
            )
            .is_none()
        );
    }

    #[test]
    fn startup_recommendation_policy_accepts_current_controller() {
        let bounds = AdaptiveTuningBoundsConfig::default();
        let envelope = recommendation_envelope(DEMAND_RESOURCE_CONTROLLER_NAME, policy(7));

        assert_eq!(
            startup_recommendation_policy(
                &envelope,
                DEMAND_RESOURCE_CONTROLLER_NAME,
                &bounds,
                false,
            ),
            Some(policy(7))
        );
    }

    #[test]
    fn generic_policy_bounding_preserves_operator_first_byte_zero() {
        let bounds = AdaptiveTuningBoundsConfig::default();

        assert_eq!(
            policy(0).bounded(&bounds).local_upload_pack_first_byte_secs,
            0
        );
    }

    #[test]
    fn adaptive_recommendation_bounding_keeps_first_byte_wait_nonzero() {
        let bounds = AdaptiveTuningBoundsConfig::default();
        let bounded = policy(0).bounded_for_adaptive_recommendation(&bounds);

        assert_eq!(bounded.request_wait_for_local_catch_up_secs, 0);
        assert_eq!(bounded.request_time_s3_restore_secs, 0);
        assert_eq!(bounded.generation_publish_secs, 0);
        assert_eq!(bounded.local_upload_pack_first_byte_secs, 1);
    }

    #[test]
    fn startup_recommendation_policy_clamps_first_byte_wait_to_adaptive_floor() {
        let bounds = AdaptiveTuningBoundsConfig::default();
        let envelope = recommendation_envelope(DEMAND_RESOURCE_CONTROLLER_NAME, policy(0));
        let recommendation = startup_recommendation_policy(
            &envelope,
            DEMAND_RESOURCE_CONTROLLER_NAME,
            &bounds,
            false,
        )
        .expect("matching controller should produce a startup recommendation");

        assert_eq!(recommendation.local_upload_pack_first_byte_secs, 1);
    }

    #[test]
    fn adaptive_recommendation_bounding_preserves_operator_forced_first_byte_zero() {
        let bounds = AdaptiveTuningBoundsConfig::default();
        let bounded = bound_effective_adaptive_recommendation(policy(7), &bounds, true);

        assert_eq!(bounded.upstream_clone_concurrency, 7);
        assert_eq!(bounded.local_upload_pack_first_byte_secs, 0);
    }

    fn repo_policy(value: usize) -> RepoAdaptivePolicy {
        RepoAdaptivePolicy {
            request_wait_for_local_catch_up_secs: value,
            request_time_s3_restore_secs: value,
            generation_publish_secs: value,
            local_upload_pack_first_byte_secs: value,
            upstream_clone_per_repo_per_instance: value,
            upstream_clone_per_repo_across_instances: value,
            local_upload_pack_per_repo: value,
            tee_capture_per_repo: value,
        }
    }

    #[test]
    fn repo_policy_aggregation_clamps_first_byte_wait_to_adaptive_floor() {
        let bounds = AdaptiveTuningBoundsConfig::default();
        let aggregate =
            aggregate_repo_policies(&[repo_policy(0)], &bounds).expect("one policy aggregates");

        assert_eq!(aggregate.request_wait_for_local_catch_up_secs, 0);
        assert_eq!(aggregate.local_upload_pack_first_byte_secs, 1);
    }

    #[test]
    fn repo_adaptive_recommendation_bounding_preserves_operator_forced_first_byte_zero() {
        let bounds = AdaptiveTuningBoundsConfig::default();
        let bounded = bound_repo_adaptive_recommendation(repo_policy(7), &bounds, true);

        assert_eq!(bounded.upstream_clone_per_repo_per_instance, 7);
        assert_eq!(bounded.local_upload_pack_first_byte_secs, 0);
    }

    #[test]
    fn ttfb_stage_breakdown_preserves_submillisecond_work() {
        let mut breakdown = TtfbStageBreakdown::default();
        breakdown.add_stage(
            TtfbStage::LocalUploadPackFirstByteWait,
            Duration::from_nanos(1),
        );

        assert_eq!(
            breakdown.stage_millis(TtfbStage::LocalUploadPackFirstByteWait),
            1
        );
    }

    #[test]
    fn repo_policy_windows_only_include_repos_changed_since_last_drain() {
        let counters = AdaptiveObservationCounters::default();
        counters.observe_first_byte_latency_for_repo("acme/widgets", Duration::from_secs(1));
        counters.observe_clone_latency_for_repo("other/widgets", Duration::from_secs(2));

        let mut previous = HashMap::new();
        let first_windows = repo_deltas(&mut previous, counters.changed_repo_snapshot());

        assert_eq!(first_windows.len(), 2);
        assert_eq!(first_windows["acme/widgets"].first_byte_samples, 1);
        assert_eq!(first_windows["other/widgets"].clone_samples, 1);

        let idle_windows = repo_deltas(&mut previous, counters.changed_repo_snapshot());
        assert!(idle_windows.is_empty());

        let mut breakdown = TtfbStageBreakdown::default();
        breakdown.add_stage_millis(TtfbStage::LocalUploadPackFirstByteWait, 500);
        counters.observe_ttfb_stage_breakdown_for_repo("acme/widgets", breakdown, None);
        let second_windows = repo_deltas(&mut previous, counters.changed_repo_snapshot());

        assert_eq!(second_windows.len(), 1);
        assert!(second_windows.contains_key("acme/widgets"));
        assert_eq!(second_windows["acme/widgets"].first_byte_samples, 0);
        assert_eq!(second_windows["acme/widgets"].ttfb_stage_samples, 1);
        assert!(!second_windows.contains_key("other/widgets"));
    }

    #[test]
    fn demand_resource_global_model_keeps_fallbacks_across_event_windows() {
        let fallback_window = ObservationTotals {
            upstream_fallbacks: 1,
            fallback_upstream_clone_global: 1,
            ..ObservationTotals::default()
        };
        let clone_window = ObservationTotals {
            clone_samples: 1,
            clone_latency_millis_total: 2_000,
            ..ObservationTotals::default()
        };
        let totals_after_clone = ObservationTotals {
            clone_samples: 1,
            clone_latency_millis_total: 2_000,
            upstream_fallbacks: 1,
            fallback_upstream_clone_global: 1,
            ..ObservationTotals::default()
        };

        let fallback_model = observation_model(
            AdaptiveTuningController::DemandResource,
            fallback_window,
            fallback_window,
        );
        let fallback_sample_count = observation_sample_count(fallback_model);
        assert_eq!(fallback_sample_count, 1);
        assert_eq!(
            rate(fallback_model.upstream_fallbacks, fallback_sample_count),
            1.0
        );
        assert_eq!(
            dominant_fallback_target(fallback_model),
            Some(FallbackRecoveryTarget::UpstreamCloneGlobal)
        );

        let clone_model = observation_model(
            AdaptiveTuningController::DemandResource,
            clone_window,
            totals_after_clone,
        );
        let clone_sample_count = observation_sample_count(clone_model);
        assert_eq!(clone_sample_count, 1);
        assert_eq!(clone_model.upstream_fallbacks, 1);
        assert_eq!(
            rate(clone_model.upstream_fallbacks, clone_sample_count),
            1.0
        );

        let aimd_model = observation_model(
            AdaptiveTuningController::Aimd,
            clone_window,
            totals_after_clone,
        );
        assert_eq!(aimd_model.upstream_fallbacks, 0);
    }

    #[test]
    fn first_byte_latency_estimate_for_repo_does_not_fall_back_to_global_history() {
        let counters = AdaptiveObservationCounters::default();
        counters.observe_first_byte_latency(Duration::from_secs(10));

        assert_eq!(
            counters.first_byte_latency_estimate_for_repo("acme/widgets"),
            None
        );
    }

    #[test]
    fn ttfb_stage_estimate_for_repo_does_not_fall_back_to_global_history() {
        let counters = AdaptiveObservationCounters::default();
        let mut breakdown = TtfbStageBreakdown::default();
        breakdown.add_stage_millis(TtfbStage::LocalUploadPackFirstByteWait, 10_000);
        counters.observe_ttfb_stage_breakdown_for_repo("other/widgets", breakdown, None);

        assert_eq!(counters.ttfb_stage_estimate_for_repo("acme/widgets"), None);
    }

    fn demand_repo_snapshot(current: RepoAdaptivePolicy) -> RepoObservationSnapshot {
        let mut cfg = config();
        cfg.controller = AdaptiveTuningController::DemandResource;
        RepoObservationSnapshot {
            owner_repo: "acme/widgets".to_string(),
            sample_count: 1,
            clone_latency_secs_avg: Some(1.0),
            first_byte_latency_secs_avg: Some(0.2),
            dominant_ttfb_stage: None,
            fallback_rate: 0.0,
            dominant_fallback_target: None,
            host_pressure: HostPressure::default(),
            current,
            config: cfg,
            warmup_complete: false,
        }
    }

    fn snapshot(current: EffectivePolicy) -> ObservationSnapshot {
        ObservationSnapshot {
            sample_count: 20,
            clone_latency_secs_avg: Some(1.0),
            first_byte_latency_secs_avg: Some(0.2),
            dominant_ttfb_stage: None,
            fallback_rate: 0.0,
            dominant_fallback_target: None,
            host_pressure: HostPressure::default(),
            demand: RuntimeDemandSnapshot::default(),
            host_cpu_threads: 16,
            current,
            config: config(),
            warmup_complete: true,
        }
    }

    #[test]
    fn aimd_controller_preserves_interval_probe_behavior() {
        let recommendation = AimdController.observe(&snapshot(policy(2)));

        assert_eq!(recommendation.controller, "aimd");
        assert_eq!(recommendation.controller_version, "v2");
        assert_eq!(recommendation.decision, "probe");
        assert_eq!(recommendation.reason, "healthy");
        assert_eq!(recommendation.policy.upstream_clone_concurrency, 3);
        assert_eq!(recommendation.policy.bundle_pack_threads, 3);
        assert_eq!(
            recommendation.policy.request_wait_for_local_catch_up_secs,
            0
        );
    }

    #[test]
    fn healthy_window_rebalances_to_current_demand_and_headroom() {
        let recommendation = DemandResourceController.observe(&snapshot(policy(2)));
        assert_eq!(recommendation.controller, "demand_resource");
        assert_eq!(recommendation.controller_version, "v1");
        assert_eq!(recommendation.decision, "healthy");
        assert_eq!(recommendation.policy.upstream_clone_concurrency, 3);
        assert_eq!(recommendation.policy.bundle_pack_threads, 4);
        assert_eq!(
            recommendation.policy.request_wait_for_local_catch_up_secs,
            0
        );
        assert_eq!(recommendation.policy.local_upload_pack_first_byte_secs, 0);
    }

    #[test]
    fn clone_slo_breach_preserves_capacity_and_request_patience() {
        let mut observed = snapshot(policy(5));
        observed.clone_latency_secs_avg = Some(60.0);
        let recommendation = DemandResourceController.observe(&observed);
        assert_eq!(recommendation.decision, "rebalance");
        assert_eq!(recommendation.reason, "clone_latency_slo");
        assert_eq!(recommendation.policy.upstream_clone_concurrency, 5);
        assert_eq!(recommendation.policy.bundle_generation_concurrency, 5);
        assert_eq!(
            recommendation.policy.request_wait_for_local_catch_up_secs,
            5
        );
        assert_eq!(recommendation.policy.local_upload_pack_first_byte_secs, 5);
    }

    #[test]
    fn first_byte_slo_preserves_request_patience() {
        let mut observed = snapshot(policy(30));
        observed.first_byte_latency_secs_avg = Some(60.0);

        let recommendation = DemandResourceController.observe(&observed);

        assert_eq!(recommendation.decision, "rebalance");
        assert_eq!(recommendation.reason, "first_byte_latency_slo");
        assert_eq!(recommendation.policy.local_upload_pack_concurrency, 30);
        assert_eq!(recommendation.policy.local_upload_pack_threads, 8);
        assert_eq!(
            recommendation.policy.request_wait_for_local_catch_up_secs,
            30
        );
        assert_eq!(recommendation.policy.request_time_s3_restore_secs, 30);
        assert_eq!(recommendation.policy.generation_publish_secs, 30);
        assert_eq!(recommendation.policy.local_upload_pack_first_byte_secs, 30);
    }

    #[test]
    fn first_byte_slo_uses_pack_cache_stage_to_increase_pack_cache_capacity() {
        let mut observed = snapshot(policy(5));
        observed.first_byte_latency_secs_avg = Some(60.0);
        observed.dominant_ttfb_stage = Some(DominantTtfbStage {
            stage: TtfbStage::PackCacheLookupWait,
            avg_secs: 30.0,
            contribution: 0.75,
        });

        let recommendation = DemandResourceController.observe(&observed);

        assert_eq!(recommendation.decision, "increase_capacity");
        assert_eq!(recommendation.reason, "ttfb_stage_pack_cache_lookup_wait");
        assert_eq!(
            recommendation.policy.pack_cache_request_delta_concurrency,
            6
        );
        assert_eq!(recommendation.policy.local_upload_pack_concurrency, 5);
    }

    #[test]
    fn first_byte_slo_uses_upload_pack_stage_to_increase_upload_pack_threads() {
        let mut observed = snapshot(policy(5));
        observed.first_byte_latency_secs_avg = Some(60.0);
        observed.dominant_ttfb_stage = Some(DominantTtfbStage {
            stage: TtfbStage::LocalUploadPackFirstByteWait,
            avg_secs: 30.0,
            contribution: 0.8,
        });

        let recommendation = DemandResourceController.observe(&observed);

        assert_eq!(recommendation.decision, "increase_capacity");
        assert_eq!(
            recommendation.reason,
            "ttfb_stage_local_upload_pack_first_byte_wait"
        );
        assert_eq!(recommendation.policy.local_upload_pack_threads, 6);
        assert_eq!(recommendation.policy.local_upload_pack_concurrency, 5);
    }

    #[test]
    fn ttfb_stage_breakdown_tracks_dominant_stage() {
        let counters = AdaptiveObservationCounters::default();
        let mut breakdown = TtfbStageBreakdown::default();
        breakdown.add_stage_millis(TtfbStage::PackCacheLookupWait, 100);
        breakdown.add_stage_millis(TtfbStage::LocalUploadPackFirstByteWait, 900);

        counters.observe_ttfb_stage_breakdown_for_repo("acme/widgets", breakdown, None);
        let snapshot = counters.snapshot();
        let dominant = dominant_ttfb_stage(snapshot).unwrap();

        assert_eq!(snapshot.ttfb_stage_samples, 1);
        assert_eq!(dominant.stage, TtfbStage::LocalUploadPackFirstByteWait);
        assert_eq!(dominant.avg_secs, 0.9);
        assert_eq!(dominant.contribution, 0.9);
        assert_eq!(
            counters
                .repo_snapshot()
                .get("acme/widgets")
                .unwrap()
                .ttfb_stage_millis_total
                .stage_millis(TtfbStage::PackCacheLookupWait),
            100
        );
    }

    #[test]
    fn live_ttfb_estimate_includes_weighted_current_stage_history() {
        let mut average = TtfbStageBreakdown::default();
        average.add_stage_millis(TtfbStage::LocalUploadPackFirstByteWait, 10_000);
        let estimate = TtfbStageEstimate {
            sample_count: 10,
            average,
        };

        let full_request = estimate.live_latency_estimate(
            TtfbStageBreakdown::default(),
            TtfbStage::LocalUploadPackFirstByteWait,
            Duration::ZERO,
            1.0,
            "multi_tip",
        );
        let narrow_request = estimate.live_latency_estimate(
            TtfbStageBreakdown::default(),
            TtfbStage::LocalUploadPackFirstByteWait,
            Duration::ZERO,
            0.0,
            "shallow",
        );

        assert_eq!(full_request.estimated_total, Duration::from_secs(10));
        assert_eq!(narrow_request.estimated_total, Duration::ZERO);
    }

    #[test]
    fn request_cost_history_keeps_single_branch_separate_from_full_clone() {
        let counters = AdaptiveObservationCounters::default();
        let full_shape = RequestCostShape {
            want_width: RequestWantWidth::FullTipSet,
            ref_shape: RequestRefShape::FullTipSet,
            filter: RequestFilterShape::None,
            shallow: RequestShallowShape::None,
            negotiation: RequestNegotiationShape::NoHaves,
        };
        let single_branch_shape = RequestCostShape {
            want_width: RequestWantWidth::One,
            ref_shape: RequestRefShape::NamedBranch { fingerprint: 42 },
            filter: RequestFilterShape::None,
            shallow: RequestShallowShape::None,
            negotiation: RequestNegotiationShape::NoHaves,
        };
        let mut full_breakdown = TtfbStageBreakdown::default();
        full_breakdown.add_stage_millis(TtfbStage::LocalUploadPackFirstByteWait, 10_000);
        let mut single_breakdown = TtfbStageBreakdown::default();
        single_breakdown.add_stage_millis(TtfbStage::LocalUploadPackFirstByteWait, 500);

        for _ in 0..5 {
            counters.observe_first_byte_latency_and_ttfb_stage_breakdown_for_repo(
                "acme/widgets",
                Duration::from_secs(10),
                full_breakdown,
                Some(&full_shape),
            );
            counters.observe_first_byte_latency_and_ttfb_stage_breakdown_for_repo(
                "acme/widgets",
                Duration::from_millis(500),
                single_breakdown,
                Some(&single_branch_shape),
            );
        }

        let full_estimate = counters
            .ttfb_stage_estimate_for_repo_and_request_cost("acme/widgets", Some(&full_shape), 5)
            .unwrap();
        let single_estimate = counters
            .ttfb_stage_estimate_for_repo_and_request_cost(
                "acme/widgets",
                Some(&single_branch_shape),
                5,
            )
            .unwrap();

        assert_eq!(
            full_estimate
                .estimate
                .average
                .stage_millis(TtfbStage::LocalUploadPackFirstByteWait),
            10_000
        );
        assert_eq!(
            single_estimate
                .estimate
                .average
                .stage_millis(TtfbStage::LocalUploadPackFirstByteWait),
            500
        );
        assert_eq!(full_estimate.historical_weight, 1.0);
        assert_eq!(single_estimate.historical_weight, 1.0);

        let unseen_shallow_shape = RequestCostShape {
            want_width: RequestWantWidth::One,
            ref_shape: RequestRefShape::DefaultBranch,
            filter: RequestFilterShape::None,
            shallow: RequestShallowShape::Depth1,
            negotiation: RequestNegotiationShape::NoHaves,
        };
        assert!(
            counters
                .ttfb_stage_estimate_for_request_cost(
                    "acme/widgets",
                    Some(&unseen_shallow_shape),
                    5,
                )
                .is_none()
        );
    }

    #[test]
    fn pack_threads_for_request_cost_prefers_full_clone_over_shallow_single_branch() {
        let full_shape = RequestCostShape {
            want_width: RequestWantWidth::FullTipSet,
            ref_shape: RequestRefShape::FullTipSet,
            filter: RequestFilterShape::None,
            shallow: RequestShallowShape::None,
            negotiation: RequestNegotiationShape::NoHaves,
        };
        let shallow_single_shape = RequestCostShape {
            want_width: RequestWantWidth::One,
            ref_shape: RequestRefShape::DefaultBranch,
            filter: RequestFilterShape::None,
            shallow: RequestShallowShape::Depth1,
            negotiation: RequestNegotiationShape::NoHaves,
        };

        let full_threads = pack_threads_for_request_cost(
            8,
            Some(full_shape),
            None,
            false,
            Duration::from_secs(10),
        );
        let shallow_threads = pack_threads_for_request_cost(
            8,
            Some(shallow_single_shape),
            None,
            false,
            Duration::from_secs(10),
        );

        assert_eq!(full_threads, 8);
        assert_eq!(shallow_threads, 2);
    }

    #[test]
    fn pack_threads_for_request_cost_uses_repo_shape_history_and_fallback_pressure() {
        let shape = RequestCostShape {
            want_width: RequestWantWidth::One,
            ref_shape: RequestRefShape::NamedBranch { fingerprint: 42 },
            filter: RequestFilterShape::None,
            shallow: RequestShallowShape::None,
            negotiation: RequestNegotiationShape::NoHaves,
        };
        let mut cheap_average = TtfbStageBreakdown::default();
        cheap_average.add_stage_millis(TtfbStage::LocalUploadPackFirstByteWait, 1_000);
        let cheap_estimate = TtfbStageEstimate {
            sample_count: 5,
            average: cheap_average,
        };

        assert_eq!(
            pack_threads_for_request_cost(
                8,
                Some(shape),
                Some(cheap_estimate),
                false,
                Duration::from_secs(10),
            ),
            1
        );
        assert_eq!(
            pack_threads_for_request_cost(
                8,
                Some(shape),
                Some(cheap_estimate),
                true,
                Duration::from_secs(10),
            ),
            8
        );
    }

    #[test]
    fn live_ttfb_estimate_ignores_under_sampled_stage_history() {
        let mut average = TtfbStageBreakdown::default();
        average.add_stage_millis(TtfbStage::LocalUploadPackFirstByteWait, 10_000);
        let estimate = TtfbStageEstimate {
            sample_count: 4,
            average,
        };

        let live_estimate = live_ttfb_latency_estimate(
            TtfbStageBreakdown::default(),
            TtfbStage::LocalUploadPackFirstByteWait,
            Duration::ZERO,
            Some(estimate),
            5,
            1.0,
            "multi_tip",
        );

        assert_eq!(live_estimate.elapsed, Duration::ZERO);
        assert_eq!(live_estimate.estimated_total, Duration::ZERO);
    }

    #[test]
    fn recommendation_input_summary_defaults_missing_dominant_ttfb_stage() {
        let summary: RecommendationInputSummary = serde_json::from_value(serde_json::json!({
            "sample_count": 20,
            "clone_latency_secs_avg": 1.0,
            "first_byte_latency_secs_avg": 0.2,
            "fallback_rate": 0.0,
            "dominant_fallback_target": null,
            "host_pressure": {},
            "decision": "hold",
            "reason": "healthy"
        }))
        .unwrap();

        assert!(summary.dominant_ttfb_stage.is_none());
    }

    #[test]
    fn host_pressure_preserves_request_patience() {
        let mut observed = snapshot(policy(30));
        observed.host_pressure.memory_available_percent = Some(0.0);

        let recommendation = DemandResourceController.observe(&observed);

        assert_eq!(recommendation.decision, "decrease");
        assert_eq!(recommendation.reason, "memory_pressure");
        assert_eq!(recommendation.policy.bundle_generation_concurrency, 1);
        assert_eq!(recommendation.policy.upstream_clone_concurrency, 1);
        assert_eq!(
            recommendation.policy.request_wait_for_local_catch_up_secs,
            30
        );
        assert_eq!(recommendation.policy.local_upload_pack_first_byte_secs, 30);
    }

    #[test]
    fn demand_resource_decreases_on_cpu_pressure() {
        let mut observed = snapshot(policy(30));
        observed.host_pressure.cpu_busy_fraction = Some(1.0);

        let recommendation = DemandResourceController.observe(&observed);

        assert_eq!(recommendation.decision, "decrease");
        assert_eq!(recommendation.reason, "cpu_busy");
        assert!(recommendation.policy.bundle_generation_concurrency < 30);
        assert!(recommendation.policy.upstream_clone_concurrency < 30);
    }

    #[test]
    fn demand_resource_pressure_does_not_grow_active_foreground_limits() {
        let mut observed = snapshot(policy(1));
        observed.host_pressure.cpu_busy_fraction = Some(1.0);
        observed.host_cpu_threads = 128;
        observed.demand.upstream_clone_claims = 1;

        let recommendation = DemandResourceController.observe(&observed);

        assert_eq!(recommendation.decision, "decrease");
        assert_eq!(recommendation.reason, "cpu_busy");
        assert_eq!(recommendation.policy.upstream_clone_concurrency, 1);
        assert_eq!(
            recommendation.policy.upstream_clone_per_repo_per_instance,
            1
        );
        assert_eq!(
            recommendation
                .policy
                .upstream_clone_per_repo_across_instances,
            1
        );
    }

    #[test]
    fn demand_resource_decreases_on_disk_pressure() {
        let mut observed = snapshot(policy(30));
        observed.host_pressure.disk_busy_fraction = Some(1.0);

        let recommendation = DemandResourceController.observe(&observed);

        assert_eq!(recommendation.decision, "decrease");
        assert_eq!(recommendation.reason, "disk_busy");
        assert!(recommendation.policy.bundle_generation_concurrency < 30);
        assert!(recommendation.policy.upstream_clone_concurrency < 30);
    }

    #[test]
    fn local_upload_pack_fallback_increases_local_capacity_before_waits() {
        let mut observed = snapshot(policy(5));
        observed.fallback_rate = 1.0;
        observed.dominant_fallback_target = Some(FallbackRecoveryTarget::LocalUploadPackPermit);
        observed.first_byte_latency_secs_avg = Some(60.0);

        let recommendation = DemandResourceController.observe(&observed);

        assert_eq!(recommendation.decision, "increase_capacity");
        assert_eq!(recommendation.reason, "fallback_rate_slo");
        assert_eq!(recommendation.policy.upstream_clone_concurrency, 5);
        assert_eq!(recommendation.policy.local_upload_pack_concurrency, 6);
        assert_eq!(recommendation.policy.local_upload_pack_threads, 6);
        assert_eq!(
            recommendation.policy.request_wait_for_local_catch_up_secs,
            5
        );
        assert_eq!(recommendation.policy.local_upload_pack_first_byte_secs, 5);
    }

    #[test]
    fn nginx_fallback_increases_upstream_clone_capacity_not_local_capacity() {
        let mut observed = snapshot(policy(5));
        observed.fallback_rate = 1.0;
        observed.dominant_fallback_target = Some(FallbackRecoveryTarget::UpstreamCloneGlobal);

        let recommendation = DemandResourceController.observe(&observed);

        assert_eq!(recommendation.decision, "increase_capacity");
        assert_eq!(recommendation.reason, "fallback_rate_slo");
        assert_eq!(recommendation.policy.upstream_clone_concurrency, 6);
        assert_eq!(recommendation.policy.local_upload_pack_concurrency, 5);
        assert_eq!(recommendation.policy.local_upload_pack_threads, 5);
    }

    #[test]
    fn local_first_byte_fallback_increases_waits_after_local_capacity_is_maxed() {
        let mut observed = snapshot(policy(5));
        observed.fallback_rate = 1.0;
        observed.dominant_fallback_target = Some(FallbackRecoveryTarget::LocalUploadPackFirstByte);
        observed.config.bounds.local_upload_pack_concurrency.max = 5;
        observed.config.bounds.local_upload_pack_per_repo.max = 5;
        observed.config.bounds.local_upload_pack_threads.max = 5;

        let recommendation = DemandResourceController.observe(&observed);

        assert_eq!(recommendation.decision, "increase_timeouts");
        assert_eq!(recommendation.reason, "fallback_rate_slo");
        assert_eq!(recommendation.policy.upstream_clone_concurrency, 5);
        assert_eq!(recommendation.policy.local_upload_pack_concurrency, 5);
        assert_eq!(recommendation.policy.local_upload_pack_threads, 5);
        assert_eq!(
            recommendation.policy.request_wait_for_local_catch_up_secs,
            5
        );
        assert_eq!(
            recommendation.policy.local_upload_pack_first_byte_secs,
            step_up(5, observed.config.bounds.local_upload_pack_first_byte_secs)
        );
    }

    #[test]
    fn insufficient_samples_still_rebalance_on_claim_events() {
        let mut observed = snapshot(policy(5));
        observed.sample_count = 2;
        observed.demand.local_upload_pack_claims = 3;
        let recommendation = DemandResourceController.observe(&observed);
        assert_eq!(recommendation.decision, "rebalance");
        assert_eq!(recommendation.reason, "event_demand");
        assert_eq!(recommendation.policy.local_upload_pack_concurrency, 6);
    }

    #[test]
    fn low_priority_fetches_do_not_count_as_foreground_demand() {
        let demand = RuntimeDemandSnapshot {
            upstream_fetch_claims: 4,
            low_priority_fetch_claims: 4,
            ..RuntimeDemandSnapshot::default()
        };

        assert_eq!(demand.foreground_claims(), 0);
        assert_eq!(foreground_headroom(8, demand), FOREGROUND_HEADROOM_MIN);
        assert_eq!(background_headroom(24, demand), 2);

        let mixed_demand = RuntimeDemandSnapshot {
            upstream_fetch_claims: 5,
            low_priority_fetch_claims: 2,
            ..RuntimeDemandSnapshot::default()
        };

        assert_eq!(mixed_demand.foreground_claims(), 3);
    }

    #[test]
    fn demand_snapshot_max_preserves_short_lived_claims() {
        let event = RuntimeDemandSnapshot {
            upstream_clone_claims: 1,
            ..RuntimeDemandSnapshot::default()
        };
        let after_pressure = RuntimeDemandSnapshot {
            deep_validation_claims: 1,
            ..RuntimeDemandSnapshot::default()
        };

        let demand = event.max_with(after_pressure);

        assert_eq!(demand.upstream_clone_claims, 1);
        assert_eq!(demand.deep_validation_claims, 1);
        assert_eq!(demand.foreground_claims(), 1);
    }

    #[test]
    fn host_headroom_prevents_allocating_every_vcpu_to_one_clone() {
        let mut observed = snapshot(policy(64));
        observed.host_cpu_threads = 64;
        observed.demand.upstream_clone_claims = 1;
        observed.config.bounds.upstream_clone_concurrency.max = 64;
        let recommendation = DemandResourceController.observe(&observed);
        assert_eq!(recommendation.policy.upstream_clone_concurrency, 5);
        assert_eq!(recommendation.policy.bundle_pack_threads, 19);

        let mut observed = snapshot(policy(1));
        observed.clone_latency_secs_avg = Some(60.0);
        let recommendation = DemandResourceController.observe(&observed);
        assert_eq!(recommendation.policy.upstream_clone_concurrency, 3);
    }

    #[tokio::test]
    async fn dynamic_gate_grows_and_shrinks_without_interrupting_work() {
        let gate = ResizableGate::new(2);
        let first = gate.acquire_owned().await.unwrap();
        let second = gate.acquire_owned().await.unwrap();
        assert_eq!(gate.available_permits(), 0);

        gate.resize(3);
        assert_eq!(gate.available_permits(), 1);
        let third = gate.try_acquire_owned().unwrap();

        gate.resize(1);
        assert_eq!(gate.limit(), 1);
        drop(third);
        assert_eq!(gate.available_permits(), 0);
        drop(second);
        assert_eq!(gate.available_permits(), 0);
        drop(first);
        assert_eq!(gate.available_permits(), 1);
    }

    #[tokio::test]
    async fn applying_policy_does_not_emit_resource_event() {
        let state = EffectivePolicyState::new(policy(2), 0);
        let resource_events = state.event_notifier();

        state.apply(policy(3));

        assert!(
            tokio::time::timeout(Duration::from_millis(10), resource_events.notified())
                .await
                .is_err()
        );

        let permit = state.clone_gate.acquire_owned().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), resource_events.notified())
            .await
            .expect("gate acquire should emit a resource event");

        drop(permit);
        tokio::time::timeout(Duration::from_secs(1), resource_events.notified())
            .await
            .expect("gate release should emit a resource event");
    }

    #[test]
    fn repo_overlay_falls_back_to_global_policy_until_applied() {
        let state = EffectivePolicyState::new(policy(4), 0);
        assert_eq!(state.repo_policy("acme/widgets"), repo_policy(4));

        state.apply_repo_policy("acme/widgets", repo_policy(7));

        assert_eq!(state.repo_policy("acme/widgets"), repo_policy(7));
        assert_eq!(state.repo_policy("other/widgets"), repo_policy(4));
    }

    #[test]
    fn demand_resource_heavy_repo_gets_more_per_repo_upload_pack_capacity() {
        let mut observed = demand_repo_snapshot(repo_policy(2));
        observed.first_byte_latency_secs_avg = Some(60.0);
        observed.dominant_ttfb_stage = Some(DominantTtfbStage {
            stage: TtfbStage::LocalUploadPackFirstByteWait,
            avg_secs: 30.0,
            contribution: 0.8,
        });

        let recommendation = recommend_repo_policy(&observed);

        assert_eq!(recommendation.controller, "demand_resource");
        assert_eq!(recommendation.decision, "increase_capacity");
        assert_eq!(
            recommendation.reason,
            "ttfb_stage_local_upload_pack_first_byte_wait"
        );
        assert_eq!(recommendation.policy.local_upload_pack_per_repo, 3);
        assert_eq!(
            recommendation.policy.upstream_clone_per_repo_per_instance,
            2
        );
    }

    #[test]
    fn demand_resource_light_repo_gets_lower_per_repo_capacity() {
        let observed = demand_repo_snapshot(repo_policy(4));

        let recommendation = recommend_repo_policy(&observed);

        assert_eq!(recommendation.controller, "demand_resource");
        assert_eq!(recommendation.decision, "decrease");
        assert_eq!(recommendation.reason, "low_repo_demand");
        assert_eq!(recommendation.policy.local_upload_pack_per_repo, 2);
        assert_eq!(
            recommendation.policy.upstream_clone_per_repo_per_instance,
            2
        );
        assert_eq!(recommendation.policy.tee_capture_per_repo, 2);
    }

    #[test]
    fn demand_resource_host_pressure_prevents_heavy_repo_growth() {
        let mut observed = demand_repo_snapshot(repo_policy(4));
        observed.first_byte_latency_secs_avg = Some(60.0);
        observed.dominant_ttfb_stage = Some(DominantTtfbStage {
            stage: TtfbStage::LocalUploadPackFirstByteWait,
            avg_secs: 30.0,
            contribution: 0.8,
        });
        observed.host_pressure.memory_available_percent = Some(0.0);

        let recommendation = recommend_repo_policy(&observed);

        assert_eq!(recommendation.controller, "demand_resource");
        assert_eq!(recommendation.decision, "decrease");
        assert_eq!(recommendation.reason, "memory_pressure");
        assert_eq!(recommendation.policy.local_upload_pack_per_repo, 2);
    }

    #[test]
    fn demand_resource_repo_decreases_on_cpu_or_disk_pressure() {
        let mut cpu_observed = demand_repo_snapshot(repo_policy(4));
        cpu_observed.host_pressure.cpu_busy_fraction = Some(1.0);
        let cpu_recommendation = recommend_repo_policy(&cpu_observed);

        assert_eq!(cpu_recommendation.decision, "decrease");
        assert_eq!(cpu_recommendation.reason, "cpu_busy");
        assert_eq!(cpu_recommendation.policy.local_upload_pack_per_repo, 2);

        let mut disk_observed = demand_repo_snapshot(repo_policy(4));
        disk_observed.host_pressure.disk_busy_fraction = Some(1.0);
        let disk_recommendation = recommend_repo_policy(&disk_observed);

        assert_eq!(disk_recommendation.decision, "decrease");
        assert_eq!(disk_recommendation.reason, "disk_busy");
        assert_eq!(disk_recommendation.policy.local_upload_pack_per_repo, 2);
    }

    #[test]
    fn repo_fallback_pressure_increases_capacity_before_timeouts() {
        let observed = RepoObservationSnapshot {
            owner_repo: "acme/widgets".to_string(),
            sample_count: 20,
            clone_latency_secs_avg: Some(1.0),
            first_byte_latency_secs_avg: Some(0.2),
            dominant_ttfb_stage: None,
            fallback_rate: 1.0,
            dominant_fallback_target: Some(FallbackRecoveryTarget::LocalUploadPackPermit),
            host_pressure: HostPressure::default(),
            current: repo_policy(5),
            config: config(),
            warmup_complete: true,
        };

        let recommendation = recommend_repo_policy(&observed);

        assert_eq!(recommendation.decision, "increase_capacity");
        assert_eq!(
            recommendation.policy.request_wait_for_local_catch_up_secs,
            5
        );
        assert_eq!(recommendation.policy.local_upload_pack_first_byte_secs, 5);
        assert_eq!(
            recommendation.policy.upstream_clone_per_repo_per_instance,
            5
        );
        assert_eq!(recommendation.policy.local_upload_pack_per_repo, 6);
    }

    #[test]
    fn local_catch_up_reason_maps_to_timeout_target() {
        assert_eq!(
            fallback_target_for_reason("local_catch_up"),
            FallbackRecoveryTarget::LocalCatchUp
        );
        assert_eq!(
            fallback_target_for_reason("short_circuit_pack_cache_live_first_byte"),
            FallbackRecoveryTarget::PackCacheLookup
        );
    }

    #[test]
    fn repo_local_catch_up_fallback_increases_timeouts_before_capacity() {
        let observed = RepoObservationSnapshot {
            owner_repo: "acme/widgets".to_string(),
            sample_count: 20,
            clone_latency_secs_avg: Some(1.0),
            first_byte_latency_secs_avg: Some(0.2),
            dominant_ttfb_stage: None,
            fallback_rate: 1.0,
            dominant_fallback_target: Some(FallbackRecoveryTarget::LocalCatchUp),
            host_pressure: HostPressure::default(),
            current: repo_policy(5),
            config: config(),
            warmup_complete: true,
        };

        let recommendation = recommend_repo_policy(&observed);

        assert_eq!(recommendation.decision, "increase_timeouts");
        assert_eq!(
            recommendation.policy.request_wait_for_local_catch_up_secs,
            10
        );
        assert_eq!(recommendation.policy.generation_publish_secs, 10);
        assert_eq!(
            recommendation.policy.upstream_clone_per_repo_per_instance,
            5
        );
        assert_eq!(recommendation.policy.local_upload_pack_per_repo, 5);
    }

    #[test]
    fn repo_aggregation_uses_median_peer_value() {
        let mut cfg = config();
        cfg.bounds.request_wait_for_local_catch_up_secs.max = 100;
        let aggregate = aggregate_repo_policies(
            &[repo_policy(2), repo_policy(20), repo_policy(6)],
            &cfg.bounds,
        )
        .unwrap();

        assert_eq!(aggregate.request_wait_for_local_catch_up_secs, 6);
        assert_eq!(aggregate.upstream_clone_per_repo_per_instance, 6);
    }
}
