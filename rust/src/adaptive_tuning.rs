use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use fred::clients::Pool;
use fred::interfaces::{HashesInterface, KeysInterface};
use fred::types::Expiration;
use serde::{Deserialize, Serialize};
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::config::{
    AdaptiveTuningBoundsConfig, AdaptiveTuningConfig, AdaptiveTuningKnobBoundsConfig,
    AdaptiveTuningMode, Config,
};

const CONTROLLER_NAME: &str = "aimd";
const CONTROLLER_VERSION: &str = "v1";

#[derive(Debug)]
pub struct ResizableGate {
    semaphore: Arc<Semaphore>,
    state: Mutex<ResizableGateState>,
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
        Arc::new(Self {
            semaphore: Arc::new(Semaphore::new(initial)),
            state: Mutex::new(ResizableGateState {
                target: initial,
                pending_shrink: 0,
            }),
        })
    }

    pub fn limit(&self) -> usize {
        self.state
            .lock()
            .expect("resizable gate lock poisoned")
            .target
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
        Ok(ResizableGatePermit {
            permit: Some(permit),
            gate: Arc::clone(self),
        })
    }

    pub async fn acquire_owned(
        self: &Arc<Self>,
    ) -> std::result::Result<ResizableGatePermit, AcquireError> {
        let permit = self.semaphore.clone().acquire_owned().await?;
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
}

impl Drop for ResizableGatePermit {
    fn drop(&mut self) {
        drop(self.permit.take());
        self.gate.retire_pending_available();
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

#[derive(Debug)]
pub struct EffectivePolicyState {
    policy: EffectivePolicyAtomics,
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
        Arc::new(Self {
            policy: EffectivePolicyAtomics::new(policy),
            clone_gate: ResizableGate::new(policy.upstream_clone_concurrency),
            fetch_gate: ResizableGate::new(policy.upstream_fetch_concurrency),
            low_priority_fetch_gate: ResizableGate::new(
                policy
                    .upstream_fetch_concurrency
                    .saturating_sub(reserved_request_time_fetches),
            ),
            tee_capture_gate: ResizableGate::new(policy.tee_capture_concurrency),
            bundle_generation_gate: ResizableGate::new(policy.bundle_generation_concurrency),
            pack_cache_background_warming_gate: ResizableGate::new(
                policy.pack_cache_background_warming_concurrency,
            ),
            request_pack_delta_gate: ResizableGate::new(
                policy.pack_cache_request_delta_concurrency,
            ),
            local_upload_pack_gate: ResizableGate::new(policy.local_upload_pack_concurrency),
            deep_validation_gate: ResizableGate::new(policy.deep_validation_concurrency),
            prewarm_gate: ResizableGate::new(policy.prewarm_concurrency),
            repo_policy_overlays: RwLock::new(HashMap::new()),
            reserved_request_time_fetches: AtomicUsize::new(reserved_request_time_fetches),
        })
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
    upstream_fallbacks: AtomicU64,
    repo_totals: Mutex<HashMap<String, ObservationTotals>>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ObservationTotals {
    pub clone_samples: u64,
    pub clone_latency_millis_total: u64,
    pub first_byte_samples: u64,
    pub first_byte_latency_millis_total: u64,
    pub upstream_fallbacks: u64,
}

impl AdaptiveObservationCounters {
    pub fn observe_clone_latency(&self, elapsed: Duration) {
        self.clone_samples.fetch_add(1, Ordering::Relaxed);
        self.clone_latency_millis_total
            .fetch_add(duration_millis(elapsed), Ordering::Relaxed);
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
    }

    pub fn observe_first_byte_latency(&self, elapsed: Duration) {
        self.first_byte_samples.fetch_add(1, Ordering::Relaxed);
        self.first_byte_latency_millis_total
            .fetch_add(duration_millis(elapsed), Ordering::Relaxed);
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
    }

    pub fn inc_upstream_fallback(&self) {
        self.upstream_fallbacks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_upstream_fallback_for_repo(&self, owner_repo: &str) {
        self.upstream_fallbacks.fetch_add(1, Ordering::Relaxed);
        self.update_repo(owner_repo, |totals| {
            totals.upstream_fallbacks = totals.upstream_fallbacks.saturating_add(1);
        });
    }

    pub fn snapshot(&self) -> ObservationTotals {
        ObservationTotals {
            clone_samples: self.clone_samples.load(Ordering::Relaxed),
            clone_latency_millis_total: self.clone_latency_millis_total.load(Ordering::Relaxed),
            first_byte_samples: self.first_byte_samples.load(Ordering::Relaxed),
            first_byte_latency_millis_total: self
                .first_byte_latency_millis_total
                .load(Ordering::Relaxed),
            upstream_fallbacks: self.upstream_fallbacks.load(Ordering::Relaxed),
        }
    }

    pub fn repo_snapshot(&self) -> HashMap<String, ObservationTotals> {
        self.repo_totals
            .lock()
            .expect("repo adaptive observation lock poisoned")
            .clone()
    }

    fn update_repo(&self, owner_repo: &str, update: impl FnOnce(&mut ObservationTotals)) {
        let owner_repo = crate::repo_identity::canonicalize_owner_repo(owner_repo);
        let mut repo_totals = self
            .repo_totals
            .lock()
            .expect("repo adaptive observation lock poisoned");
        update(repo_totals.entry(owner_repo).or_default());
    }
}

fn duration_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
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
    pub fallback_rate: f64,
    pub host_pressure: HostPressure,
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
            return recommendation(snapshot.current, "hold", "warmup", 0.0);
        }
        if snapshot.sample_count < snapshot.config.min_sample_count {
            return recommendation(snapshot.current, "hold", "insufficient_samples", 0.2);
        }

        if let Some(reason) = pressure_reason(snapshot) {
            let policy = decrease_background_first(snapshot.current, &snapshot.config.bounds);
            return recommendation(policy, "decrease", reason, 0.8);
        }

        if let Some(reason) = slo_reason(snapshot) {
            let policy =
                decrease_foreground_and_background(snapshot.current, &snapshot.config.bounds);
            return recommendation(policy, "decrease", reason, 0.9);
        }

        let policy = increase_gradually(snapshot.current, &snapshot.config.bounds);
        recommendation(policy, "increase", "healthy", 0.7)
    }
}

fn recommendation(
    policy: EffectivePolicy,
    decision: &'static str,
    reason: &'static str,
    confidence: f64,
) -> RecommendationSet {
    RecommendationSet {
        policy,
        controller: CONTROLLER_NAME.to_string(),
        controller_version: CONTROLLER_VERSION.to_string(),
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

fn slo_reason(snapshot: &ObservationSnapshot) -> Option<&'static str> {
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
    if snapshot.fallback_rate >= slo.fallback_rate {
        return Some("fallback_rate_slo");
    }
    None
}

fn increase_gradually(
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
        request_wait_for_local_catch_up_secs: step_down(
            background.request_wait_for_local_catch_up_secs,
            bounds.request_wait_for_local_catch_up_secs,
        ),
        request_time_s3_restore_secs: step_down(
            background.request_time_s3_restore_secs,
            bounds.request_time_s3_restore_secs,
        ),
        generation_publish_secs: step_down(
            background.generation_publish_secs,
            bounds.generation_publish_secs,
        ),
        local_upload_pack_first_byte_secs: step_down(
            background.local_upload_pack_first_byte_secs,
            bounds.local_upload_pack_first_byte_secs,
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
    pub fallback_rate: f64,
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
    pub fallback_rate: f64,
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
    let mut policy = fallback;

    for key in [
        global_recommendation_key(config, deployment),
        instance_recommendation_key(config, deployment, instance_id),
    ] {
        match load_recommendation_from_key(valkey, &key, max_staleness).await {
            Ok(Some(envelope)) => {
                policy = envelope.recommendation.bounded(bounds);
                tracing::info!(
                    key,
                    controller = %envelope.controller,
                    confidence = envelope.confidence,
                    "loaded adaptive tuning startup recommendation from Valkey"
                );
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

    policy.bounded(bounds)
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
    policy: RepoAdaptivePolicy,
    decision: &'static str,
    reason: &'static str,
    confidence: f64,
) -> RepoRecommendationSet {
    RepoRecommendationSet {
        policy,
        controller: CONTROLLER_NAME.to_string(),
        controller_version: CONTROLLER_VERSION.to_string(),
        decision: decision.to_string(),
        reason: reason.to_string(),
        confidence,
    }
}

fn recommend_repo_policy(snapshot: &RepoObservationSnapshot) -> RepoRecommendationSet {
    if !snapshot.warmup_complete {
        return repo_recommendation(snapshot.current, "hold", "warmup", 0.0);
    }
    if snapshot.sample_count < snapshot.config.min_sample_count {
        return repo_recommendation(snapshot.current, "hold", "insufficient_samples", 0.2);
    }

    if let Some(reason) = repo_pressure_reason(snapshot) {
        let policy = decrease_repo_capacity(snapshot.current, &snapshot.config.bounds);
        return repo_recommendation(policy, "decrease", reason, 0.8);
    }

    if snapshot.fallback_rate >= snapshot.config.slo.fallback_rate {
        let policy =
            increase_repo_timeouts_decrease_capacity(snapshot.current, &snapshot.config.bounds);
        return repo_recommendation(policy, "increase_timeouts", "fallback_rate_slo", 0.9);
    }

    if snapshot
        .clone_latency_secs_avg
        .is_some_and(|value| value >= snapshot.config.slo.clone_latency_secs)
    {
        let policy = decrease_repo_capacity(snapshot.current, &snapshot.config.bounds);
        return repo_recommendation(policy, "decrease", "clone_latency_slo", 0.9);
    }

    if snapshot
        .first_byte_latency_secs_avg
        .is_some_and(|value| value >= snapshot.config.slo.first_byte_latency_secs)
    {
        let policy = decrease_repo_capacity(snapshot.current, &snapshot.config.bounds);
        return repo_recommendation(policy, "decrease", "first_byte_latency_slo", 0.9);
    }

    let policy =
        increase_repo_capacity_decrease_timeouts(snapshot.current, &snapshot.config.bounds);
    repo_recommendation(policy, "probe", "healthy", 0.7)
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

fn increase_repo_timeouts_decrease_capacity(
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
        ..decrease_repo_capacity(policy, bounds)
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
        .bounded(bounds),
    )
}

fn median_usize(values: impl Iterator<Item = usize>) -> usize {
    let mut values = values.collect::<Vec<_>>();
    values.sort_unstable();
    values[values.len() / 2]
}

pub struct RuntimeController {
    controller: AimdController,
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
            controller: AimdController,
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
        loop {
            let (interval, cpu_poll_interval, should_sample_pressure) = {
                let config = state.config();
                (
                    Duration::from_secs(config.adaptive_tuning.evaluation_interval_secs),
                    config.adaptive_tuning.cpu_poll_interval_secs,
                    config.adaptive_tuning.enabled
                        && config.adaptive_tuning.mode != AdaptiveTuningMode::Disabled,
                )
            };
            let host_pressure = if should_sample_pressure {
                sample_host_pressure(interval, cpu_poll_interval).await
            } else {
                tokio::time::sleep(interval).await;
                HostPressure::default()
            };
            if let Err(error) = self.tick(&state, host_pressure).await {
                tracing::warn!(error = %error, "adaptive tuning tick failed");
            }
        }
    }

    async fn tick(&mut self, state: &crate::AppState, host_pressure: HostPressure) -> Result<()> {
        let config = state.config();
        if !config.adaptive_tuning.enabled
            || config.adaptive_tuning.mode == AdaptiveTuningMode::Disabled
        {
            return Ok(());
        }

        let now_totals = self.observations.snapshot();
        let window = delta(self.previous_totals, now_totals);
        self.previous_totals = now_totals;
        let repo_windows = repo_deltas(
            &mut self.previous_repo_totals,
            self.observations.repo_snapshot(),
        );
        let elapsed = self.previous_tick.elapsed();
        self.previous_tick = Instant::now();

        let snapshot = ObservationSnapshot {
            sample_count: window.clone_samples,
            clone_latency_secs_avg: avg_seconds(
                window.clone_latency_millis_total,
                window.clone_samples,
            ),
            first_byte_latency_secs_avg: avg_seconds(
                window.first_byte_latency_millis_total,
                window.first_byte_samples,
            ),
            fallback_rate: rate(window.upstream_fallbacks, window.clone_samples),
            host_pressure,
            current: self.policy_state.snapshot(),
            config: config.adaptive_tuning.clone(),
            warmup_complete: self.started_at.elapsed()
                >= Duration::from_secs(config.adaptive_tuning.warmup_interval_secs),
        };

        let recommendation = self.controller.observe(&snapshot);
        let bounded = recommendation
            .policy
            .bounded(&config.adaptive_tuning.bounds);
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
                fallback_rate: snapshot.fallback_rate,
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
            elapsed,
            repo_windows,
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
    ) -> Result<()> {
        for (owner_repo, window) in repo_windows {
            let sample_count = repo_sample_count(window);
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
                    window.clone_latency_millis_total,
                    window.clone_samples,
                ),
                first_byte_latency_secs_avg: avg_seconds(
                    window.first_byte_latency_millis_total,
                    window.first_byte_samples,
                ),
                fallback_rate: rate(window.upstream_fallbacks, sample_count),
                host_pressure,
                current,
                config: config.adaptive_tuning.clone(),
                warmup_complete: self.started_at.elapsed()
                    >= Duration::from_secs(config.adaptive_tuning.warmup_interval_secs),
            };
            let recommendation = recommend_repo_policy(&snapshot);
            let recommendation = RepoRecommendationSet {
                policy: recommendation
                    .policy
                    .bounded(&config.adaptive_tuning.bounds),
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
                    fallback_rate: snapshot.fallback_rate,
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
                    .map(|envelope| {
                        envelope
                            .recommendation
                            .bounded(&config.adaptive_tuning.bounds)
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
        upstream_fallbacks: next
            .upstream_fallbacks
            .saturating_sub(previous.upstream_fallbacks),
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

fn repo_sample_count(window: ObservationTotals) -> u64 {
    window
        .clone_samples
        .max(window.first_byte_samples)
        .max(window.upstream_fallbacks)
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

    fn snapshot(current: EffectivePolicy) -> ObservationSnapshot {
        ObservationSnapshot {
            sample_count: 20,
            clone_latency_secs_avg: Some(1.0),
            first_byte_latency_secs_avg: Some(0.2),
            fallback_rate: 0.0,
            host_pressure: HostPressure::default(),
            current,
            config: config(),
            warmup_complete: true,
        }
    }

    #[test]
    fn healthy_window_increases_gradually() {
        let recommendation = AimdController.observe(&snapshot(policy(2)));
        assert_eq!(recommendation.decision, "increase");
        assert_eq!(recommendation.policy.upstream_clone_concurrency, 3);
        assert_eq!(recommendation.policy.bundle_pack_threads, 3);
    }

    #[test]
    fn slo_breach_decreases_quickly() {
        let mut observed = snapshot(policy(5));
        observed.clone_latency_secs_avg = Some(60.0);
        let recommendation = AimdController.observe(&observed);
        assert_eq!(recommendation.decision, "decrease");
        assert_eq!(recommendation.reason, "clone_latency_slo");
        assert_eq!(recommendation.policy.upstream_clone_concurrency, 3);
        assert_eq!(recommendation.policy.bundle_generation_concurrency, 3);
    }

    #[test]
    fn insufficient_samples_hold_current_values() {
        let mut observed = snapshot(policy(5));
        observed.sample_count = 2;
        let recommendation = AimdController.observe(&observed);
        assert_eq!(recommendation.decision, "hold");
        assert_eq!(recommendation.policy, policy(5));
    }

    #[test]
    fn bounds_and_step_sizes_are_enforced() {
        let mut observed = snapshot(policy(64));
        observed.config.bounds.upstream_clone_concurrency.max = 64;
        let recommendation = AimdController.observe(&observed);
        assert_eq!(recommendation.policy.upstream_clone_concurrency, 64);

        let mut observed = snapshot(policy(1));
        observed.fallback_rate = 1.0;
        let recommendation = AimdController.observe(&observed);
        assert_eq!(recommendation.policy.upstream_clone_concurrency, 1);
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

    #[test]
    fn repo_overlay_falls_back_to_global_policy_until_applied() {
        let state = EffectivePolicyState::new(policy(4), 0);
        assert_eq!(state.repo_policy("acme/widgets"), repo_policy(4));

        state.apply_repo_policy("acme/widgets", repo_policy(7));

        assert_eq!(state.repo_policy("acme/widgets"), repo_policy(7));
        assert_eq!(state.repo_policy("other/widgets"), repo_policy(4));
    }

    #[test]
    fn repo_fallback_pressure_increases_timeouts_and_decreases_capacity() {
        let observed = RepoObservationSnapshot {
            owner_repo: "acme/widgets".to_string(),
            sample_count: 20,
            clone_latency_secs_avg: Some(1.0),
            first_byte_latency_secs_avg: Some(0.2),
            fallback_rate: 1.0,
            host_pressure: HostPressure::default(),
            current: repo_policy(5),
            config: config(),
            warmup_complete: true,
        };

        let recommendation = recommend_repo_policy(&observed);

        assert_eq!(recommendation.decision, "increase_timeouts");
        assert_eq!(
            recommendation.policy.request_wait_for_local_catch_up_secs,
            step_up(
                5,
                observed.config.bounds.request_wait_for_local_catch_up_secs
            )
        );
        assert_eq!(
            recommendation.policy.local_upload_pack_first_byte_secs,
            step_up(5, observed.config.bounds.local_upload_pack_first_byte_secs)
        );
        assert_eq!(
            recommendation.policy.upstream_clone_per_repo_per_instance,
            3
        );
        assert_eq!(recommendation.policy.local_upload_pack_per_repo, 3);
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
