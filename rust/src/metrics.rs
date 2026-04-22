use std::fmt;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeLabelSet, EncodeLabelValue};
use prometheus_client::metrics::MetricType;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;

use crate::config::BackendType;

// ---------------------------------------------------------------------------
// OptionalGauge — omitted from /metrics until explicitly set
// ---------------------------------------------------------------------------

/// Shared gauge state that stays completely absent from `/metrics` until
/// [`OptionalGauge::set`] is called at least once.
#[derive(Clone)]
pub struct OptionalGauge {
    inner: Gauge,
    has_value: Arc<AtomicBool>,
}

impl fmt::Debug for OptionalGauge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OptionalGauge")
            .field("has_value", &self.has_value.load(Ordering::Relaxed))
            .field("value", &self.inner.get())
            .finish()
    }
}

impl Default for OptionalGauge {
    fn default() -> Self {
        Self {
            inner: Gauge::default(),
            has_value: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl OptionalGauge {
    pub fn set(&self, value: i64) {
        self.inner.set(value);
        self.has_value.store(true, Ordering::Release);
    }
}

#[derive(Clone, Debug)]
struct OptionalGaugeCollector {
    name: &'static str,
    help: &'static str,
    metric: OptionalGauge,
}

impl OptionalGaugeCollector {
    fn new(name: &'static str, help: &'static str, metric: OptionalGauge) -> Self {
        Self { name, help, metric }
    }
}

impl Collector for OptionalGaugeCollector {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), fmt::Error> {
        if !self.metric.has_value.load(Ordering::Acquire) {
            return Ok(());
        }

        let mut metric_encoder =
            encoder.encode_descriptor(self.name, self.help, None, MetricType::Gauge)?;
        metric_encoder.encode_gauge(&self.metric.inner.get())
    }
}

// ---------------------------------------------------------------------------
// Label types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct CloneLabels {
    pub protocol: Protocol,
    pub cache_status: CacheStatus,
    pub username: String,
    pub repo: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Protocol {
    Ssh,
    Https,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum CacheStatus {
    Hot,
    Warm,
    Cold,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct CloneDurationLabels {
    pub protocol: Protocol,
    pub username: String,
    pub repo: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct UploadPackDurationLabels {
    pub protocol: Protocol,
    pub source: CloneSource,
    pub repo: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct UploadPackFirstByteLabels {
    pub protocol: Protocol,
    pub source: String,
    pub cache_status: CacheStatus,
    pub repo: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ProtocolLabels {
    pub protocol: Protocol,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ActiveCloneLabels {
    pub protocol: Protocol,
    pub cache_status: CacheStatus,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct CloneUpstreamBytesLabels {
    pub protocol: Protocol,
    pub phase: ClonePhase,
    pub username: String,
    pub repo: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct CloneDownstreamBytesLabels {
    pub protocol: Protocol,
    pub phase: ClonePhase,
    pub source: CloneSource,
    pub username: String,
    pub repo: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum ClonePhase {
    InfoRefs,
    UploadPack,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum CloneSource {
    Local,
    Upstream,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct EndpointLabels {
    pub endpoint: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RepoLabels {
    pub repo: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct BundleUriAdvertisementLabels {
    pub repo: String,
    pub result: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct BundleListRequestLabels {
    pub repo: String,
    pub result: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct CacheSubtreeLabels {
    pub subtree: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct HydrationSkipLabels {
    pub reason: HydrationSkipReason,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct UpstreamFallbackLabels {
    pub protocol: Protocol,
    pub reason: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ShortCircuitUpstreamLabels {
    pub protocol: Protocol,
    pub stage: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PackCacheRequestLabels {
    pub protocol: Protocol,
    pub result: String,
    pub reason: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PackCacheInflightWaitLabels {
    pub protocol: Protocol,
    pub result: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PackCacheKeyBypassLabels {
    pub protocol: Protocol,
    pub owner_repo: String,
    pub reason: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PackCacheRecentEntriesLabels {
    pub owner_repo: String,
    pub kind: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PackCacheWarmingSkipLabels {
    pub owner_repo: String,
    pub reason: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PackCacheStitchLabels {
    pub owner_repo: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PackCacheStitchFailureLabels {
    pub owner_repo: String,
    pub reason: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PackCacheOnDemandCompositeStageLabels {
    pub protocol: Protocol,
    pub owner_repo: String,
    pub stage: String,
    pub result: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PackCacheOnDemandCompositeDetailLabels {
    pub protocol: Protocol,
    pub owner_repo: String,
    pub result: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct UploadPackCpuLabels {
    pub protocol: Protocol,
    pub source: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct BundleUriCommandLabels {
    pub result: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct BundlePresignLabels {
    pub result: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct BundleManifestEntriesLabels {
    pub bundle_kind: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct GenerationCoalescingLabels {
    pub result: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RequestTimeCatchUpLabels {
    pub result: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum AuthState {
    Anonymous,
    Unresolved,
    Resolved,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum HydrationSkipReason {
    SameNodeDedup,
    SemaphoreSaturated,
}

impl EncodeLabelValue for Protocol {
    fn encode(
        &self,
        encoder: &mut prometheus_client::encoding::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        match self {
            Self::Ssh => encoder.write_str("ssh")?,
            Self::Https => encoder.write_str("https")?,
        }
        Ok(())
    }
}

impl EncodeLabelValue for CacheStatus {
    fn encode(
        &self,
        encoder: &mut prometheus_client::encoding::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        match self {
            Self::Hot => encoder.write_str("hot")?,
            Self::Warm => encoder.write_str("warm")?,
            Self::Cold => encoder.write_str("cold")?,
        }
        Ok(())
    }
}

impl EncodeLabelValue for ClonePhase {
    fn encode(
        &self,
        encoder: &mut prometheus_client::encoding::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        match self {
            Self::InfoRefs => encoder.write_str("info_refs")?,
            Self::UploadPack => encoder.write_str("upload_pack")?,
        }
        Ok(())
    }
}

impl EncodeLabelValue for CloneSource {
    fn encode(
        &self,
        encoder: &mut prometheus_client::encoding::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        match self {
            Self::Local => encoder.write_str("local")?,
            Self::Upstream => encoder.write_str("upstream")?,
        }
        Ok(())
    }
}

impl EncodeLabelValue for AuthState {
    fn encode(
        &self,
        encoder: &mut prometheus_client::encoding::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        match self {
            Self::Anonymous => encoder.write_str("anonymous")?,
            Self::Unresolved => encoder.write_str("unresolved")?,
            Self::Resolved => encoder.write_str("resolved")?,
        }
        Ok(())
    }
}

impl EncodeLabelValue for HydrationSkipReason {
    fn encode(
        &self,
        encoder: &mut prometheus_client::encoding::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        match self {
            Self::SameNodeDedup => encoder.write_str("same_node_dedup")?,
            Self::SemaphoreSaturated => encoder.write_str("semaphore_saturated")?,
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct CloneSummaryLabels {
    pub protocol: Protocol,
    pub cache_status: CacheStatus,
    pub auth_state: AuthState,
    pub backend: String,
}

// ---------------------------------------------------------------------------
// Metrics struct
// ---------------------------------------------------------------------------

/// Central container for every Prometheus metric exposed by the proxy.
pub struct Metrics {
    // -- clone --
    pub clone_total: Family<CloneLabels, Counter>,
    pub clone_summary_total: Family<CloneSummaryLabels, Counter>,
    pub clone_duration_seconds: Family<CloneDurationLabels, Histogram>,
    pub upload_pack_duration_seconds: Family<UploadPackDurationLabels, Histogram>,
    pub upload_pack_first_byte_seconds: Family<UploadPackFirstByteLabels, Histogram>,
    pub clone_upstream_bytes: Family<CloneUpstreamBytesLabels, Counter>,
    pub clone_downstream_bytes: Family<CloneDownstreamBytesLabels, Counter>,

    // -- bundles --
    pub bundle_generation_total: Counter,
    pub bundle_generation_duration_seconds: Histogram,
    pub bundle_uri_advertisement_total: Family<BundleUriAdvertisementLabels, Counter>,
    pub bundle_list_request_total: Family<BundleListRequestLabels, Counter>,

    // -- auth --
    pub auth_cache_hits: Counter,
    pub auth_cache_misses: Counter,

    // -- locks --
    pub lock_acquisitions: Counter,
    pub lock_waits: Counter,
    pub lock_timeouts: Counter,

    // -- archive cache --
    pub archive_cache_hits_local: Counter,
    pub archive_cache_hits_s3: Counter,
    pub archive_cache_misses: Counter,

    // -- S3 --
    pub s3_upload_bytes: Counter,
    pub s3_download_bytes: Counter,

    // -- upstream API --
    pub upstream_api_calls: Family<EndpointLabels, Counter>,

    // -- rate limit --
    pub upstream_api_rate_limit_remaining: OptionalGauge,

    // -- gauges --
    pub active_connections: Family<ProtocolLabels, Gauge>,
    pub upload_pack_concurrent: Family<ProtocolLabels, Gauge>,
    pub active_clones: Family<ActiveCloneLabels, Gauge>,
    pub cache_apparent_usage_bytes: Gauge,
    pub cache_physical_usage_bytes: Gauge,
    pub cache_repos_total: Gauge,
    pub mirror_apparent_usage_bytes: Family<RepoLabels, Gauge>,
    pub mirror_physical_usage_bytes: Family<RepoLabels, Gauge>,
    pub cache_subtree_apparent_usage_bytes: Family<CacheSubtreeLabels, Gauge>,
    pub cache_subtree_physical_usage_bytes: Family<CacheSubtreeLabels, Gauge>,

    // -- hydration --
    pub hydration_skipped: Family<HydrationSkipLabels, Counter>,

    // -- upstream fallback --
    pub upstream_fallback: Family<UpstreamFallbackLabels, Counter>,
    pub short_circuit_upstream_total: Family<ShortCircuitUpstreamLabels, Counter>,

    // -- pack cache --
    pub pack_cache_requests_total: Family<PackCacheRequestLabels, Counter>,
    pub pack_cache_apparent_usage_bytes: Gauge,
    pub pack_cache_physical_usage_bytes: Gauge,
    pub pack_cache_inflight_waits_total: Family<PackCacheInflightWaitLabels, Counter>,
    pub pack_cache_key_bypasses_total: Family<PackCacheKeyBypassLabels, Counter>,
    pub pack_cache_recent_entries: Family<PackCacheRecentEntriesLabels, Gauge>,
    pub pack_cache_warming_skips_total: Family<PackCacheWarmingSkipLabels, Counter>,
    pub pack_cache_artifact_generation_duration_seconds: Histogram,
    pub pack_cache_stitch_attempts_total: Family<PackCacheStitchLabels, Counter>,
    pub pack_cache_stitch_duration_seconds: Family<PackCacheStitchLabels, Histogram>,
    pub pack_cache_stitch_failures_total: Family<PackCacheStitchFailureLabels, Counter>,
    pub pack_cache_on_demand_composite_stage_duration_seconds:
        Family<PackCacheOnDemandCompositeStageLabels, Histogram>,
    pub pack_cache_on_demand_composite_candidate_count:
        Family<PackCacheOnDemandCompositeDetailLabels, Histogram>,
    pub pack_cache_on_demand_composite_delta_objects:
        Family<PackCacheOnDemandCompositeDetailLabels, Histogram>,
    pub pack_cache_on_demand_composite_delta_bytes:
        Family<PackCacheOnDemandCompositeDetailLabels, Histogram>,
    pub upload_pack_cpu_seconds_total: Family<UploadPackCpuLabels, Counter>,

    // -- bundle URI / manifests --
    pub bundle_uri_command_total: Family<BundleUriCommandLabels, Counter>,
    pub bundle_presign_total: Family<BundlePresignLabels, Counter>,
    pub bundle_manifest_entries: Family<BundleManifestEntriesLabels, Gauge>,
    pub generation_coalescing_total: Family<GenerationCoalescingLabels, Counter>,
    pub request_time_catch_up_total: Family<RequestTimeCatchUpLabels, Counter>,
}

impl Metrics {
    /// Create a new [`Metrics`] instance and register every metric with the
    /// supplied `registry`.
    pub fn new(registry: &mut Registry) -> Self {
        let clone_total = Family::<CloneLabels, Counter>::default();
        registry.register(
            "forgeproxy_clone",
            "Total clone requests by protocol and cache status",
            clone_total.clone(),
        );

        let clone_summary_total = Family::<CloneSummaryLabels, Counter>::default();
        registry.register(
            "forgeproxy_clone_summary",
            "Total clone requests by protocol, cache status, auth state, and backend",
            clone_summary_total.clone(),
        );

        let clone_duration_seconds =
            Family::<CloneDurationLabels, Histogram>::new_with_constructor(|| {
                Histogram::new(exponential_buckets(0.01, 2.0, 14))
            });
        registry.register(
            "forgeproxy_clone_duration_seconds",
            "Clone request latency in seconds",
            clone_duration_seconds.clone(),
        );

        let upload_pack_duration_seconds =
            Family::<UploadPackDurationLabels, Histogram>::new_with_constructor(|| {
                Histogram::new(exponential_buckets(0.01, 2.0, 14))
            });
        registry.register(
            "forgeproxy_upload_pack_duration_seconds",
            "Upload-pack latency in seconds by protocol and source",
            upload_pack_duration_seconds.clone(),
        );

        let upload_pack_first_byte_seconds =
            Family::<UploadPackFirstByteLabels, Histogram>::new_with_constructor(|| {
                Histogram::new(exponential_buckets(0.001, 2.0, 19))
            });
        registry.register(
            "forgeproxy_upload_pack_first_byte_seconds",
            "Upload-pack latency to first downstream byte in seconds by protocol, source, cache status, and repo",
            upload_pack_first_byte_seconds.clone(),
        );

        let clone_upstream_bytes = Family::<CloneUpstreamBytesLabels, Counter>::default();
        registry.register(
            "forgeproxy_clone_upstream_bytes",
            "Bytes fetched from upstream to satisfy clone traffic, by protocol and phase",
            clone_upstream_bytes.clone(),
        );

        let clone_downstream_bytes = Family::<CloneDownstreamBytesLabels, Counter>::default();
        registry.register(
            "forgeproxy_clone_downstream_bytes",
            "Bytes sent downstream to clone clients, by protocol, phase, and source",
            clone_downstream_bytes.clone(),
        );

        let bundle_generation_total = Counter::default();
        registry.register(
            "forgeproxy_bundle_generation",
            "Total bundle generation operations",
            bundle_generation_total.clone(),
        );

        let bundle_generation_duration_seconds = Histogram::new(exponential_buckets(1.0, 2.0, 12));
        registry.register(
            "forgeproxy_bundle_generation_duration_seconds",
            "Bundle generation latency in seconds",
            bundle_generation_duration_seconds.clone(),
        );

        let bundle_uri_advertisement_total =
            Family::<BundleUriAdvertisementLabels, Counter>::default();
        registry.register(
            "forgeproxy_bundle_uri_advertisement",
            "Git protocol v2 info/refs responses by bundle-uri advertisement result",
            bundle_uri_advertisement_total.clone(),
        );

        let bundle_list_request_total = Family::<BundleListRequestLabels, Counter>::default();
        registry.register(
            "forgeproxy_bundle_list_request",
            "Bundle-list endpoint requests by outcome",
            bundle_list_request_total.clone(),
        );

        let auth_cache_hits = Counter::default();
        registry.register(
            "forgeproxy_auth_cache_hits",
            "Auth cache hits",
            auth_cache_hits.clone(),
        );

        let auth_cache_misses = Counter::default();
        registry.register(
            "forgeproxy_auth_cache_misses",
            "Auth cache misses",
            auth_cache_misses.clone(),
        );

        let lock_acquisitions = Counter::default();
        registry.register(
            "forgeproxy_lock_acquisitions",
            "Distributed lock acquisitions",
            lock_acquisitions.clone(),
        );

        let lock_waits = Counter::default();
        registry.register(
            "forgeproxy_lock_waits",
            "Distributed lock wait events",
            lock_waits.clone(),
        );

        let lock_timeouts = Counter::default();
        registry.register(
            "forgeproxy_lock_timeouts",
            "Distributed lock timeout events",
            lock_timeouts.clone(),
        );

        let archive_cache_hits_local = Counter::default();
        registry.register(
            "forgeproxy_archive_cache_hits_local",
            "Archive cache hits served from local disk",
            archive_cache_hits_local.clone(),
        );

        let archive_cache_hits_s3 = Counter::default();
        registry.register(
            "forgeproxy_archive_cache_hits_s3",
            "Archive cache hits served from S3",
            archive_cache_hits_s3.clone(),
        );

        let archive_cache_misses = Counter::default();
        registry.register(
            "forgeproxy_archive_cache_misses",
            "Archive cache misses fetched from upstream",
            archive_cache_misses.clone(),
        );

        let s3_upload_bytes = Counter::default();
        registry.register(
            "forgeproxy_s3_upload_bytes",
            "Total bytes uploaded to S3",
            s3_upload_bytes.clone(),
        );

        let s3_download_bytes = Counter::default();
        registry.register(
            "forgeproxy_s3_download_bytes",
            "Total bytes downloaded from S3",
            s3_download_bytes.clone(),
        );

        let upstream_api_calls = Family::<EndpointLabels, Counter>::default();
        registry.register(
            "forgeproxy_ghe_api_calls",
            "upstream API call count by endpoint",
            upstream_api_calls.clone(),
        );

        let upstream_api_rate_limit_remaining = OptionalGauge::default();
        registry.register_collector(Box::new(OptionalGaugeCollector::new(
            "forgeproxy_upstream_api_rate_limit_remaining",
            "Remaining upstream API calls before rate limit",
            upstream_api_rate_limit_remaining.clone(),
        )));

        let active_connections = Family::<ProtocolLabels, Gauge>::default();
        registry.register(
            "forgeproxy_active_connections",
            "Currently active connections by protocol",
            active_connections.clone(),
        );

        let upload_pack_concurrent = Family::<ProtocolLabels, Gauge>::default();
        registry.register(
            "forgeproxy_upload_pack_concurrent",
            "Currently running local git upload-pack subprocesses by protocol",
            upload_pack_concurrent.clone(),
        );

        let active_clones = Family::<ActiveCloneLabels, Gauge>::default();
        registry.register(
            "forgeproxy_active_clones",
            "Currently active clone streams by protocol and cache status",
            active_clones.clone(),
        );

        let cache_apparent_usage_bytes: Gauge = Gauge::default();
        registry.register(
            "forgeproxy_cache_apparent_usage_bytes",
            "Current local repo-cache apparent bytes across unique files",
            cache_apparent_usage_bytes.clone(),
        );

        let cache_physical_usage_bytes: Gauge = Gauge::default();
        registry.register(
            "forgeproxy_cache_physical_usage_bytes",
            "Current local repo-cache physically allocated bytes across unique files",
            cache_physical_usage_bytes.clone(),
        );

        let cache_repos_total: Gauge = Gauge::default();
        registry.register(
            "forgeproxy_cache_repos_total",
            "Number of repos currently cached locally",
            cache_repos_total.clone(),
        );

        let mirror_apparent_usage_bytes = Family::<RepoLabels, Gauge>::default();
        registry.register(
            "forgeproxy_mirror_apparent_usage_bytes",
            "Current apparent bytes for each mirrored repository",
            mirror_apparent_usage_bytes.clone(),
        );

        let mirror_physical_usage_bytes = Family::<RepoLabels, Gauge>::default();
        registry.register(
            "forgeproxy_mirror_physical_usage_bytes",
            "Current physically allocated bytes for each mirrored repository",
            mirror_physical_usage_bytes.clone(),
        );

        let cache_subtree_apparent_usage_bytes = Family::<CacheSubtreeLabels, Gauge>::default();
        registry.register(
            "forgeproxy_cache_subtree_apparent_usage_bytes",
            "Current apparent bytes for important forgeproxy cache subtrees",
            cache_subtree_apparent_usage_bytes.clone(),
        );

        let cache_subtree_physical_usage_bytes = Family::<CacheSubtreeLabels, Gauge>::default();
        registry.register(
            "forgeproxy_cache_subtree_physical_usage_bytes",
            "Current physically allocated bytes for important forgeproxy cache subtrees",
            cache_subtree_physical_usage_bytes.clone(),
        );

        let hydration_skipped = Family::<HydrationSkipLabels, Counter>::default();
        registry.register(
            "forgeproxy_hydration_skipped",
            "Hydration work skipped due to deduplication or concurrency limits",
            hydration_skipped.clone(),
        );

        let upstream_fallback = Family::<UpstreamFallbackLabels, Counter>::default();
        registry.register(
            "forgeproxy_upstream_fallback",
            "Requests handed off to the direct upstream path by reason",
            upstream_fallback.clone(),
        );

        let short_circuit_upstream_total = Family::<ShortCircuitUpstreamLabels, Counter>::default();
        registry.register(
            "forgeproxy_short_circuit_upstream",
            "Requests handed off to upstream because a forgeproxy request-path timing budget expired",
            short_circuit_upstream_total.clone(),
        );

        let pack_cache_requests_total = Family::<PackCacheRequestLabels, Counter>::default();
        registry.register(
            "forgeproxy_pack_cache_requests",
            "Pack response cache requests by result and reason",
            pack_cache_requests_total.clone(),
        );

        let pack_cache_apparent_usage_bytes = Gauge::default();
        registry.register(
            "forgeproxy_pack_cache_apparent_usage_bytes",
            "Current pack response cache apparent bytes across unique files",
            pack_cache_apparent_usage_bytes.clone(),
        );

        let pack_cache_physical_usage_bytes = Gauge::default();
        registry.register(
            "forgeproxy_pack_cache_physical_usage_bytes",
            "Current pack response cache physically allocated bytes across unique files",
            pack_cache_physical_usage_bytes.clone(),
        );

        let pack_cache_inflight_waits_total =
            Family::<PackCacheInflightWaitLabels, Counter>::default();
        registry.register(
            "forgeproxy_pack_cache_inflight_waits",
            "Pack response cache same-key in-flight waits by result",
            pack_cache_inflight_waits_total.clone(),
        );

        let pack_cache_key_bypasses_total = Family::<PackCacheKeyBypassLabels, Counter>::default();
        registry.register(
            "forgeproxy_pack_cache_key_bypasses",
            "Pack response cache key bypasses by protocol, repo, and reason",
            pack_cache_key_bypasses_total.clone(),
        );

        let pack_cache_recent_entries = Family::<PackCacheRecentEntriesLabels, Gauge>::default();
        registry.register(
            "forgeproxy_pack_cache_recent_entries",
            "Recent pack response cache entries retained for warming and on-demand composites by repo and kind",
            pack_cache_recent_entries.clone(),
        );

        let pack_cache_warming_skips_total =
            Family::<PackCacheWarmingSkipLabels, Counter>::default();
        registry.register(
            "forgeproxy_pack_cache_warming_skips",
            "Pack response cache proactive warming skips by repo and reason",
            pack_cache_warming_skips_total.clone(),
        );

        let pack_cache_artifact_generation_duration_seconds =
            Histogram::new(exponential_buckets(0.1, 2.0, 16));
        registry.register(
            "forgeproxy_pack_cache_artifact_generation_duration_seconds",
            "Pack response cache artifact generation latency in seconds",
            pack_cache_artifact_generation_duration_seconds.clone(),
        );

        let pack_cache_stitch_attempts_total = Family::<PackCacheStitchLabels, Counter>::default();
        registry.register(
            "forgeproxy_pack_cache_stitch_attempts",
            "Pack response cache proactive stitching attempts by repo",
            pack_cache_stitch_attempts_total.clone(),
        );

        let pack_cache_stitch_duration_seconds =
            Family::<PackCacheStitchLabels, Histogram>::new_with_constructor(|| {
                Histogram::new(exponential_buckets(0.01, 2.0, 16))
            });
        registry.register(
            "forgeproxy_pack_cache_stitch_duration_seconds",
            "Pack response cache proactive stitching latency in seconds",
            pack_cache_stitch_duration_seconds.clone(),
        );

        let pack_cache_stitch_failures_total =
            Family::<PackCacheStitchFailureLabels, Counter>::default();
        registry.register(
            "forgeproxy_pack_cache_stitch_failures",
            "Pack response cache proactive stitching failures by repo and reason",
            pack_cache_stitch_failures_total.clone(),
        );

        let pack_cache_on_demand_composite_stage_duration_seconds =
            Family::<PackCacheOnDemandCompositeStageLabels, Histogram>::new_with_constructor(
                || Histogram::new(exponential_buckets(0.001, 2.0, 18)),
            );
        registry.register(
            "forgeproxy_pack_cache_on_demand_composite_stage_duration_seconds",
            "Request-time pack response cache composite stage latency in seconds",
            pack_cache_on_demand_composite_stage_duration_seconds.clone(),
        );

        let pack_cache_on_demand_composite_candidate_count =
            Family::<PackCacheOnDemandCompositeDetailLabels, Histogram>::new_with_constructor(
                || Histogram::new(exponential_buckets(1.0, 2.0, 10)),
            );
        registry.register(
            "forgeproxy_pack_cache_on_demand_composite_candidate_count",
            "Request-time pack response cache composite base candidates by result",
            pack_cache_on_demand_composite_candidate_count.clone(),
        );

        let pack_cache_on_demand_composite_delta_objects =
            Family::<PackCacheOnDemandCompositeDetailLabels, Histogram>::new_with_constructor(
                || Histogram::new(exponential_buckets(1.0, 2.0, 24)),
            );
        registry.register(
            "forgeproxy_pack_cache_on_demand_composite_delta_objects",
            "Request-time pack response cache composite missing object counts by result",
            pack_cache_on_demand_composite_delta_objects.clone(),
        );

        let pack_cache_on_demand_composite_delta_bytes =
            Family::<PackCacheOnDemandCompositeDetailLabels, Histogram>::new_with_constructor(
                || Histogram::new(exponential_buckets(1024.0, 2.0, 24)),
            );
        registry.register(
            "forgeproxy_pack_cache_on_demand_composite_delta_bytes",
            "Request-time pack response cache composite delta pack bytes by result",
            pack_cache_on_demand_composite_delta_bytes.clone(),
        );

        let upload_pack_cpu_seconds_total = Family::<UploadPackCpuLabels, Counter>::default();
        registry.register(
            "forgeproxy_upload_pack_cpu_seconds",
            "Approximate local upload-pack CPU-seconds by protocol and source",
            upload_pack_cpu_seconds_total.clone(),
        );

        let bundle_uri_command_total = Family::<BundleUriCommandLabels, Counter>::default();
        registry.register(
            "forgeproxy_bundle_uri_command",
            "Protocol v2 bundle-uri command requests by result",
            bundle_uri_command_total.clone(),
        );

        let bundle_presign_total = Family::<BundlePresignLabels, Counter>::default();
        registry.register(
            "forgeproxy_bundle_presign",
            "Bundle presigned URL generation by result",
            bundle_presign_total.clone(),
        );

        let bundle_manifest_entries = Family::<BundleManifestEntriesLabels, Gauge>::default();
        registry.register(
            "forgeproxy_bundle_manifest_entries",
            "Current repo-global bundle manifest entries by bundle kind",
            bundle_manifest_entries.clone(),
        );

        let generation_coalescing_total = Family::<GenerationCoalescingLabels, Counter>::default();
        registry.register(
            "forgeproxy_generation_coalescing",
            "Published generation coalescing decisions by result",
            generation_coalescing_total.clone(),
        );

        let request_time_catch_up_total = Family::<RequestTimeCatchUpLabels, Counter>::default();
        registry.register(
            "forgeproxy_request_time_catch_up",
            "Request-time local catch-up decisions by result",
            request_time_catch_up_total.clone(),
        );

        Self {
            clone_total,
            clone_summary_total,
            clone_duration_seconds,
            upload_pack_duration_seconds,
            upload_pack_first_byte_seconds,
            clone_upstream_bytes,
            clone_downstream_bytes,
            bundle_generation_total,
            bundle_generation_duration_seconds,
            bundle_uri_advertisement_total,
            bundle_list_request_total,
            auth_cache_hits,
            auth_cache_misses,
            archive_cache_hits_local,
            archive_cache_hits_s3,
            archive_cache_misses,
            lock_acquisitions,
            lock_waits,
            lock_timeouts,
            s3_upload_bytes,
            s3_download_bytes,
            upstream_api_calls,
            upstream_api_rate_limit_remaining,
            active_connections,
            upload_pack_concurrent,
            active_clones,
            cache_apparent_usage_bytes,
            cache_physical_usage_bytes,
            cache_repos_total,
            mirror_apparent_usage_bytes,
            mirror_physical_usage_bytes,
            cache_subtree_apparent_usage_bytes,
            cache_subtree_physical_usage_bytes,
            hydration_skipped,
            upstream_fallback,
            short_circuit_upstream_total,
            pack_cache_requests_total,
            pack_cache_apparent_usage_bytes,
            pack_cache_physical_usage_bytes,
            pack_cache_inflight_waits_total,
            pack_cache_key_bypasses_total,
            pack_cache_recent_entries,
            pack_cache_warming_skips_total,
            pack_cache_artifact_generation_duration_seconds,
            pack_cache_stitch_attempts_total,
            pack_cache_stitch_duration_seconds,
            pack_cache_stitch_failures_total,
            pack_cache_on_demand_composite_stage_duration_seconds,
            pack_cache_on_demand_composite_candidate_count,
            pack_cache_on_demand_composite_delta_objects,
            pack_cache_on_demand_composite_delta_bytes,
            upload_pack_cpu_seconds_total,
            bundle_uri_command_total,
            bundle_presign_total,
            bundle_manifest_entries,
            generation_coalescing_total,
            request_time_catch_up_total,
        }
    }
}

// ---------------------------------------------------------------------------
// Shared handle
// ---------------------------------------------------------------------------

/// Thread-safe wrapper for the metrics registry, used in [`AppState`].
#[derive(Clone)]
pub struct MetricsRegistry {
    pub registry: Arc<Registry>,
    pub metrics: Arc<Metrics>,
    pub backend_label: Arc<str>,
}

impl MetricsRegistry {
    /// Build a fresh registry and pre-register all proxy metrics.
    pub fn new() -> Self {
        Self::with_backend_label("unknown")
    }

    pub fn with_backend(backend: BackendType) -> Self {
        Self::with_backend_label(backend.as_label())
    }

    fn with_backend_label(backend_label: &str) -> Self {
        let mut registry = Registry::default();
        let metrics = Metrics::new(&mut registry);
        Self {
            registry: Arc::new(registry),
            metrics: Arc::new(metrics),
            backend_label: Arc::<str>::from(backend_label),
        }
    }
}

pub fn record_clone_completion(
    metrics: &MetricsRegistry,
    protocol: Protocol,
    cache_status: CacheStatus,
    username: &str,
    repo: &str,
    elapsed: Duration,
) {
    metrics
        .metrics
        .clone_total
        .get_or_create(&CloneLabels {
            protocol: protocol.clone(),
            cache_status: cache_status.clone(),
            username: username.to_string(),
            repo: repo.to_string(),
        })
        .inc();
    metrics
        .metrics
        .clone_summary_total
        .get_or_create(&CloneSummaryLabels {
            protocol: protocol.clone(),
            cache_status: cache_status.clone(),
            auth_state: clone_metric_auth_state(username),
            backend: metrics.backend_label.to_string(),
        })
        .inc();
    metrics
        .metrics
        .clone_duration_seconds
        .get_or_create(&CloneDurationLabels {
            protocol,
            username: username.to_string(),
            repo: repo.to_string(),
        })
        .observe(elapsed.as_secs_f64());
}

pub fn clone_metric_auth_state(metric_username: &str) -> AuthState {
    match metric_username {
        "anonymous" => AuthState::Anonymous,
        "unresolved" => AuthState::Unresolved,
        _ => AuthState::Resolved,
    }
}

pub fn clone_metric_username(resolved_username: Option<&str>, auth_present: bool) -> String {
    match resolved_username
        .map(str::trim)
        .filter(|username| !username.is_empty())
    {
        Some(username) => username.to_string(),
        None if auth_present => "unresolved".to_string(),
        None => "anonymous".to_string(),
    }
}

pub fn inc_upstream_api_call(metrics: &MetricsRegistry, endpoint: &str) {
    metrics
        .metrics
        .upstream_api_calls
        .get_or_create(&EndpointLabels {
            endpoint: endpoint.to_string(),
        })
        .inc();
}

pub fn observe_upload_pack_duration(
    metrics: &MetricsRegistry,
    protocol: Protocol,
    source: CloneSource,
    repo: &str,
    elapsed: Duration,
) {
    metrics
        .metrics
        .upload_pack_duration_seconds
        .get_or_create(&UploadPackDurationLabels {
            protocol,
            source,
            repo: repo.to_string(),
        })
        .observe(elapsed.as_secs_f64());
}

pub fn observe_upload_pack_first_byte(
    metrics: &MetricsRegistry,
    protocol: Protocol,
    source: &str,
    cache_status: CacheStatus,
    repo: &str,
    elapsed: Duration,
) {
    metrics
        .metrics
        .upload_pack_first_byte_seconds
        .get_or_create(&UploadPackFirstByteLabels {
            protocol,
            source: source.to_string(),
            cache_status,
            repo: repo.to_string(),
        })
        .observe(elapsed.as_secs_f64());
}

pub fn inc_bundle_uri_advertisement(metrics: &MetricsRegistry, repo: &str, result: &str) {
    metrics
        .metrics
        .bundle_uri_advertisement_total
        .get_or_create(&BundleUriAdvertisementLabels {
            repo: repo.to_string(),
            result: result.to_string(),
        })
        .inc();
}

pub fn inc_bundle_list_request(metrics: &MetricsRegistry, repo: &str, result: &str) {
    metrics
        .metrics
        .bundle_list_request_total
        .get_or_create(&BundleListRequestLabels {
            repo: repo.to_string(),
            result: result.to_string(),
        })
        .inc();
}

pub fn set_upstream_api_rate_limit_remaining(metrics: &MetricsRegistry, remaining: u64) {
    if remaining == u64::MAX {
        return; // sentinel for "no API response yet" — keep the metric absent
    }
    metrics
        .metrics
        .upstream_api_rate_limit_remaining
        .set(remaining.min(i64::MAX as u64) as i64);
}

pub fn set_active_connections(metrics: &MetricsRegistry, protocol: Protocol, value: i64) {
    metrics
        .metrics
        .active_connections
        .get_or_create(&ProtocolLabels { protocol })
        .set(value.max(0));
}

pub fn set_upload_pack_concurrent(metrics: &MetricsRegistry, protocol: Protocol, value: i64) {
    metrics
        .metrics
        .upload_pack_concurrent
        .get_or_create(&ProtocolLabels { protocol })
        .set(value.max(0));
}

pub fn set_active_clones(
    metrics: &MetricsRegistry,
    protocol: Protocol,
    cache_status: CacheStatus,
    value: i64,
) {
    let labels = ActiveCloneLabels {
        protocol,
        cache_status,
    };
    let value = value.max(0);
    if value == 0 {
        metrics.metrics.active_clones.remove(&labels);
        return;
    }

    metrics
        .metrics
        .active_clones
        .get_or_create(&labels)
        .set(value);
}

pub fn set_cache_usage_bytes(
    metrics: &MetricsRegistry,
    apparent_usage_bytes: u64,
    physical_usage_bytes: u64,
) {
    metrics
        .metrics
        .cache_apparent_usage_bytes
        .set(apparent_usage_bytes.min(i64::MAX as u64) as i64);
    metrics
        .metrics
        .cache_physical_usage_bytes
        .set(physical_usage_bytes.min(i64::MAX as u64) as i64);
}

pub fn set_cache_repos_total(metrics: &MetricsRegistry, repo_count: usize) {
    metrics
        .metrics
        .cache_repos_total
        .set(repo_count.min(i64::MAX as usize) as i64);
}

pub fn replace_mirror_usage_bytes(
    metrics: &MetricsRegistry,
    apparent_sizes: &[(String, u64)],
    physical_sizes: &[(String, u64)],
) {
    metrics.metrics.mirror_apparent_usage_bytes.clear();
    for (repo, size_bytes) in apparent_sizes {
        metrics
            .metrics
            .mirror_apparent_usage_bytes
            .get_or_create(&RepoLabels { repo: repo.clone() })
            .set((*size_bytes).min(i64::MAX as u64) as i64);
    }

    metrics.metrics.mirror_physical_usage_bytes.clear();
    for (repo, size_bytes) in physical_sizes {
        metrics
            .metrics
            .mirror_physical_usage_bytes
            .get_or_create(&RepoLabels { repo: repo.clone() })
            .set((*size_bytes).min(i64::MAX as u64) as i64);
    }
}

pub fn replace_cache_subtree_usage_bytes(
    metrics: &MetricsRegistry,
    apparent_sizes: &[(String, u64)],
    physical_sizes: &[(String, u64)],
) {
    metrics.metrics.cache_subtree_apparent_usage_bytes.clear();
    for (subtree, size_bytes) in apparent_sizes {
        metrics
            .metrics
            .cache_subtree_apparent_usage_bytes
            .get_or_create(&CacheSubtreeLabels {
                subtree: subtree.clone(),
            })
            .set((*size_bytes).min(i64::MAX as u64) as i64);
    }

    metrics.metrics.cache_subtree_physical_usage_bytes.clear();
    for (subtree, size_bytes) in physical_sizes {
        metrics
            .metrics
            .cache_subtree_physical_usage_bytes
            .get_or_create(&CacheSubtreeLabels {
                subtree: subtree.clone(),
            })
            .set((*size_bytes).min(i64::MAX as u64) as i64);
    }
}

pub fn inc_hydration_skipped(metrics: &MetricsRegistry, reason: HydrationSkipReason) {
    metrics
        .metrics
        .hydration_skipped
        .get_or_create(&HydrationSkipLabels { reason })
        .inc();
}

pub fn inc_upstream_fallback(metrics: &MetricsRegistry, protocol: Protocol, reason: &str) {
    metrics
        .metrics
        .upstream_fallback
        .get_or_create(&UpstreamFallbackLabels {
            protocol,
            reason: reason.to_string(),
        })
        .inc();
}

pub fn inc_short_circuit_upstream(metrics: &MetricsRegistry, protocol: Protocol, stage: &str) {
    metrics
        .metrics
        .short_circuit_upstream_total
        .get_or_create(&ShortCircuitUpstreamLabels {
            protocol,
            stage: stage.to_string(),
        })
        .inc();
}

pub fn inc_pack_cache_request(
    metrics: &MetricsRegistry,
    protocol: Protocol,
    result: &str,
    reason: &str,
) {
    metrics
        .metrics
        .pack_cache_requests_total
        .get_or_create(&PackCacheRequestLabels {
            protocol,
            result: result.to_string(),
            reason: reason.to_string(),
        })
        .inc();
}

pub fn set_pack_cache_usage_bytes(
    metrics: &MetricsRegistry,
    apparent_usage_bytes: u64,
    physical_usage_bytes: u64,
) {
    metrics
        .metrics
        .pack_cache_apparent_usage_bytes
        .set(apparent_usage_bytes.min(i64::MAX as u64) as i64);
    metrics
        .metrics
        .pack_cache_physical_usage_bytes
        .set(physical_usage_bytes.min(i64::MAX as u64) as i64);
}

pub fn inc_pack_cache_inflight_wait(metrics: &MetricsRegistry, protocol: Protocol, result: &str) {
    metrics
        .metrics
        .pack_cache_inflight_waits_total
        .get_or_create(&PackCacheInflightWaitLabels {
            protocol,
            result: result.to_string(),
        })
        .inc();
}

pub fn inc_pack_cache_key_bypass(
    metrics: &MetricsRegistry,
    protocol: Protocol,
    owner_repo: &str,
    reason: &str,
) {
    let owner_repo = crate::repo_identity::canonicalize_owner_repo(owner_repo);
    metrics
        .metrics
        .pack_cache_key_bypasses_total
        .get_or_create(&PackCacheKeyBypassLabels {
            protocol,
            owner_repo,
            reason: reason.to_string(),
        })
        .inc();
}

pub fn replace_pack_cache_recent_entries(
    metrics: &MetricsRegistry,
    entries: &[(String, usize, usize)],
) {
    metrics.metrics.pack_cache_recent_entries.clear();
    for (owner_repo, total, full_tip) in entries {
        let owner_repo = crate::repo_identity::canonicalize_owner_repo(owner_repo);
        metrics
            .metrics
            .pack_cache_recent_entries
            .get_or_create(&PackCacheRecentEntriesLabels {
                owner_repo: owner_repo.clone(),
                kind: "all".to_string(),
            })
            .set((*total).min(i64::MAX as usize) as i64);
        metrics
            .metrics
            .pack_cache_recent_entries
            .get_or_create(&PackCacheRecentEntriesLabels {
                owner_repo,
                kind: "full_tip".to_string(),
            })
            .set((*full_tip).min(i64::MAX as usize) as i64);
    }
}

pub fn inc_pack_cache_warming_skip(metrics: &MetricsRegistry, owner_repo: &str, reason: &str) {
    let owner_repo = crate::repo_identity::canonicalize_owner_repo(owner_repo);
    metrics
        .metrics
        .pack_cache_warming_skips_total
        .get_or_create(&PackCacheWarmingSkipLabels {
            owner_repo,
            reason: reason.to_string(),
        })
        .inc();
}

pub fn observe_pack_cache_artifact_generation(metrics: &MetricsRegistry, elapsed: Duration) {
    metrics
        .metrics
        .pack_cache_artifact_generation_duration_seconds
        .observe(elapsed.as_secs_f64());
}

pub fn inc_pack_cache_stitch_attempt(metrics: &MetricsRegistry, owner_repo: &str) {
    let owner_repo = crate::repo_identity::canonicalize_owner_repo(owner_repo);
    metrics
        .metrics
        .pack_cache_stitch_attempts_total
        .get_or_create(&PackCacheStitchLabels { owner_repo })
        .inc();
}

pub fn observe_pack_cache_stitch_duration(
    metrics: &MetricsRegistry,
    owner_repo: &str,
    elapsed: Duration,
) {
    let owner_repo = crate::repo_identity::canonicalize_owner_repo(owner_repo);
    metrics
        .metrics
        .pack_cache_stitch_duration_seconds
        .get_or_create(&PackCacheStitchLabels { owner_repo })
        .observe(elapsed.as_secs_f64());
}

pub fn inc_pack_cache_stitch_failure(metrics: &MetricsRegistry, owner_repo: &str, reason: &str) {
    let owner_repo = crate::repo_identity::canonicalize_owner_repo(owner_repo);
    metrics
        .metrics
        .pack_cache_stitch_failures_total
        .get_or_create(&PackCacheStitchFailureLabels {
            owner_repo,
            reason: reason.to_string(),
        })
        .inc();
}

pub fn observe_pack_cache_on_demand_composite_stage(
    metrics: &MetricsRegistry,
    protocol: Protocol,
    owner_repo: &str,
    stage: &str,
    result: &str,
    elapsed: Duration,
) {
    let owner_repo = crate::repo_identity::canonicalize_owner_repo(owner_repo);
    metrics
        .metrics
        .pack_cache_on_demand_composite_stage_duration_seconds
        .get_or_create(&PackCacheOnDemandCompositeStageLabels {
            protocol,
            owner_repo,
            stage: stage.to_string(),
            result: result.to_string(),
        })
        .observe(elapsed.as_secs_f64());
}

pub fn observe_pack_cache_on_demand_composite_candidate_count(
    metrics: &MetricsRegistry,
    protocol: Protocol,
    owner_repo: &str,
    result: &str,
    count: usize,
) {
    let owner_repo = crate::repo_identity::canonicalize_owner_repo(owner_repo);
    metrics
        .metrics
        .pack_cache_on_demand_composite_candidate_count
        .get_or_create(&PackCacheOnDemandCompositeDetailLabels {
            protocol,
            owner_repo,
            result: result.to_string(),
        })
        .observe(count as f64);
}

pub fn observe_pack_cache_on_demand_composite_delta_objects(
    metrics: &MetricsRegistry,
    protocol: Protocol,
    owner_repo: &str,
    result: &str,
    count: usize,
) {
    let owner_repo = crate::repo_identity::canonicalize_owner_repo(owner_repo);
    metrics
        .metrics
        .pack_cache_on_demand_composite_delta_objects
        .get_or_create(&PackCacheOnDemandCompositeDetailLabels {
            protocol,
            owner_repo,
            result: result.to_string(),
        })
        .observe(count as f64);
}

pub fn observe_pack_cache_on_demand_composite_delta_bytes(
    metrics: &MetricsRegistry,
    protocol: Protocol,
    owner_repo: &str,
    result: &str,
    bytes: usize,
) {
    let owner_repo = crate::repo_identity::canonicalize_owner_repo(owner_repo);
    metrics
        .metrics
        .pack_cache_on_demand_composite_delta_bytes
        .get_or_create(&PackCacheOnDemandCompositeDetailLabels {
            protocol,
            owner_repo,
            result: result.to_string(),
        })
        .observe(bytes as f64);
}

pub fn inc_upload_pack_cpu_seconds(
    metrics: &MetricsRegistry,
    protocol: Protocol,
    source: &str,
    cpu_seconds: f64,
) {
    metrics
        .metrics
        .upload_pack_cpu_seconds_total
        .get_or_create(&UploadPackCpuLabels {
            protocol,
            source: source.to_string(),
        })
        .inc_by(cpu_seconds.max(0.0) as u64);
}

pub fn inc_bundle_uri_command(metrics: &MetricsRegistry, result: &str) {
    metrics
        .metrics
        .bundle_uri_command_total
        .get_or_create(&BundleUriCommandLabels {
            result: result.to_string(),
        })
        .inc();
}

pub fn inc_bundle_presign(metrics: &MetricsRegistry, result: &str) {
    metrics
        .metrics
        .bundle_presign_total
        .get_or_create(&BundlePresignLabels {
            result: result.to_string(),
        })
        .inc();
}

pub fn set_bundle_manifest_entries(metrics: &MetricsRegistry, bundle_kind: &str, count: usize) {
    metrics
        .metrics
        .bundle_manifest_entries
        .get_or_create(&BundleManifestEntriesLabels {
            bundle_kind: bundle_kind.to_string(),
        })
        .set(count.min(i64::MAX as usize) as i64);
}

#[allow(dead_code)]
pub fn inc_generation_coalescing(metrics: &MetricsRegistry, result: &str) {
    metrics
        .metrics
        .generation_coalescing_total
        .get_or_create(&GenerationCoalescingLabels {
            result: result.to_string(),
        })
        .inc();
}

pub fn inc_request_time_catch_up(metrics: &MetricsRegistry, result: &str) {
    metrics
        .metrics
        .request_time_catch_up_total
        .get_or_create(&RequestTimeCatchUpLabels {
            result: result.to_string(),
        })
        .inc();
}

pub struct ActiveConnectionGuard {
    metrics: MetricsRegistry,
    protocol: Protocol,
    counter: Arc<AtomicI64>,
}

impl ActiveConnectionGuard {
    pub fn new(metrics: MetricsRegistry, protocol: Protocol, counter: Arc<AtomicI64>) -> Self {
        let next = counter.fetch_add(1, Ordering::SeqCst) + 1;
        set_active_connections(&metrics, protocol.clone(), next);
        Self {
            metrics,
            protocol,
            counter,
        }
    }
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        let next = self.counter.fetch_sub(1, Ordering::SeqCst) - 1;
        set_active_connections(&self.metrics, self.protocol.clone(), next);
    }
}

pub struct UploadPackGuard {
    metrics: MetricsRegistry,
    protocol: Protocol,
    counter: Arc<AtomicI64>,
}

impl UploadPackGuard {
    pub fn new(metrics: MetricsRegistry, protocol: Protocol, counter: Arc<AtomicI64>) -> Self {
        let next = counter.fetch_add(1, Ordering::SeqCst) + 1;
        set_upload_pack_concurrent(&metrics, protocol.clone(), next);
        Self {
            metrics,
            protocol,
            counter,
        }
    }
}

impl Drop for UploadPackGuard {
    fn drop(&mut self) {
        let next = self.counter.fetch_sub(1, Ordering::SeqCst) - 1;
        set_upload_pack_concurrent(&self.metrics, self.protocol.clone(), next);
    }
}

pub struct ActiveCloneGuard {
    metrics: MetricsRegistry,
    protocol: Protocol,
    cache_status: CacheStatus,
    counter: Arc<AtomicI64>,
}

impl ActiveCloneGuard {
    pub fn new(
        metrics: MetricsRegistry,
        protocol: Protocol,
        cache_status: CacheStatus,
        counter: Arc<AtomicI64>,
    ) -> Self {
        let next = counter.fetch_add(1, Ordering::SeqCst) + 1;
        set_active_clones(&metrics, protocol.clone(), cache_status.clone(), next);
        Self {
            metrics,
            protocol,
            cache_status,
            counter,
        }
    }
}

impl Drop for ActiveCloneGuard {
    fn drop(&mut self) {
        let next = self.counter.fetch_sub(1, Ordering::SeqCst) - 1;
        set_active_clones(
            &self.metrics,
            self.protocol.clone(),
            self.cache_status.clone(),
            next,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_metrics(registry: &Registry) -> String {
        let mut encoded = String::new();
        prometheus_client::encoding::text::encode(&mut encoded, registry).unwrap();
        encoded
    }

    #[test]
    fn upstream_rate_limit_metric_is_fully_absent_until_first_value() {
        let metrics = MetricsRegistry::new();

        let encoded = encode_metrics(&metrics.registry);
        assert!(!encoded.contains("forgeproxy_upstream_api_rate_limit_remaining"));

        set_upstream_api_rate_limit_remaining(&metrics, 42);

        let encoded = encode_metrics(&metrics.registry);
        assert!(encoded.contains(
            "# HELP forgeproxy_upstream_api_rate_limit_remaining Remaining upstream API calls before rate limit"
        ));
        assert!(encoded.contains("# TYPE forgeproxy_upstream_api_rate_limit_remaining gauge"));
        assert!(encoded.contains("forgeproxy_upstream_api_rate_limit_remaining 42"));
    }

    #[test]
    fn clone_metric_auth_state_buckets_usernames() {
        assert_eq!(clone_metric_auth_state("anonymous"), AuthState::Anonymous);
        assert_eq!(clone_metric_auth_state("unresolved"), AuthState::Unresolved);
        assert_eq!(clone_metric_auth_state("octocat"), AuthState::Resolved);
    }

    #[test]
    fn replacing_cache_size_families_removes_stale_series() {
        let metrics = MetricsRegistry::new();

        replace_mirror_usage_bytes(
            &metrics,
            &[
                ("acme/widgets".to_string(), 12),
                ("acme/legacy".to_string(), 7),
            ],
            &[
                ("acme/widgets".to_string(), 8),
                ("acme/legacy".to_string(), 5),
            ],
        );
        replace_cache_subtree_usage_bytes(
            &metrics,
            &[("mirrors".to_string(), 12), ("snapshots".to_string(), 4)],
            &[("mirrors".to_string(), 8), ("snapshots".to_string(), 3)],
        );

        let encoded = encode_metrics(&metrics.registry);
        assert!(
            encoded.contains("forgeproxy_mirror_apparent_usage_bytes{repo=\"acme/widgets\"} 12")
        );
        assert!(encoded.contains("forgeproxy_mirror_physical_usage_bytes{repo=\"acme/legacy\"} 5"));
        assert!(
            encoded
                .contains("forgeproxy_cache_subtree_apparent_usage_bytes{subtree=\"mirrors\"} 12")
        );
        assert!(
            encoded
                .contains("forgeproxy_cache_subtree_physical_usage_bytes{subtree=\"snapshots\"} 3")
        );

        replace_mirror_usage_bytes(
            &metrics,
            &[("acme/widgets".to_string(), 9)],
            &[("acme/widgets".to_string(), 6)],
        );
        replace_cache_subtree_usage_bytes(
            &metrics,
            &[("mirrors".to_string(), 9)],
            &[("mirrors".to_string(), 6)],
        );

        let encoded = encode_metrics(&metrics.registry);
        assert!(
            encoded.contains("forgeproxy_mirror_apparent_usage_bytes{repo=\"acme/widgets\"} 9")
        );
        assert!(
            encoded.contains("forgeproxy_mirror_physical_usage_bytes{repo=\"acme/widgets\"} 6")
        );
        assert!(!encoded.contains("forgeproxy_mirror_apparent_usage_bytes{repo=\"acme/legacy\"}"));
        assert!(
            encoded
                .contains("forgeproxy_cache_subtree_apparent_usage_bytes{subtree=\"mirrors\"} 9")
        );
        assert!(
            !encoded
                .contains("forgeproxy_cache_subtree_physical_usage_bytes{subtree=\"snapshots\"}")
        );
    }

    #[test]
    fn upload_pack_metrics_encode_expected_labels() {
        let metrics = MetricsRegistry::new();

        observe_upload_pack_duration(
            &metrics,
            Protocol::Https,
            CloneSource::Local,
            "acme/widgets",
            Duration::from_millis(250),
        );
        observe_upload_pack_first_byte(
            &metrics,
            Protocol::Https,
            "local_upload_pack",
            CacheStatus::Warm,
            "acme/widgets",
            Duration::from_millis(125),
        );
        inc_bundle_uri_advertisement(&metrics, "acme/widgets", "injected");
        inc_bundle_list_request(&metrics, "acme/widgets", "served");
        inc_hydration_skipped(&metrics, HydrationSkipReason::SemaphoreSaturated);
        inc_request_time_catch_up(&metrics, "selected_fetch");
        inc_short_circuit_upstream(&metrics, Protocol::Https, "local_catch_up");

        let encoded = encode_metrics(&metrics.registry);
        assert!(encoded.contains("# HELP forgeproxy_upload_pack_duration_seconds"));
        assert!(encoded.lines().any(|line| {
            line.starts_with("forgeproxy_upload_pack_duration_seconds_sum{")
                && line.contains("repo=\"acme/widgets\"")
                && line.contains(" 0.25")
        }));
        assert!(encoded.lines().any(|line| {
            line.starts_with("forgeproxy_upload_pack_first_byte_seconds_sum{")
                && line.contains("cache_status=\"warm\"")
                && line.contains("repo=\"acme/widgets\"")
                && line.contains("source=\"local_upload_pack\"")
                && line.contains(" 0.125")
        }));
        assert!(encoded.lines().any(
            |line| line.starts_with("forgeproxy_hydration_skipped_total{") && line.ends_with(" 1")
        ));
        assert!(encoded.lines().any(|line| {
            line.starts_with("forgeproxy_request_time_catch_up_total{")
                && line.contains("result=\"selected_fetch\"")
                && line.ends_with(" 1")
        }));
        assert!(encoded.lines().any(|line| {
            line.starts_with("forgeproxy_short_circuit_upstream_total{")
                && line.contains("protocol=\"https\"")
                && line.contains("stage=\"local_catch_up\"")
                && line.ends_with(" 1")
        }));
        assert!(encoded.lines().any(|line| {
            line.starts_with("forgeproxy_bundle_uri_advertisement_total{")
                && line.contains("repo=\"acme/widgets\"")
                && line.contains("result=\"injected\"")
                && line.ends_with(" 1")
        }));
        assert!(encoded.lines().any(|line| {
            line.starts_with("forgeproxy_bundle_list_request_total{")
                && line.contains("repo=\"acme/widgets\"")
                && line.contains("result=\"served\"")
                && line.ends_with(" 1")
        }));
    }

    #[test]
    fn on_demand_composite_stage_metrics_encode_expected_labels() {
        let metrics = MetricsRegistry::new();

        observe_pack_cache_on_demand_composite_stage(
            &metrics,
            Protocol::Ssh,
            "acme/widgets.git",
            "semaphore_wait",
            "ok",
            Duration::from_millis(25),
        );
        observe_pack_cache_on_demand_composite_candidate_count(
            &metrics,
            Protocol::Ssh,
            "acme/widgets.git",
            "ok",
            3,
        );
        observe_pack_cache_on_demand_composite_delta_objects(
            &metrics,
            Protocol::Ssh,
            "acme/widgets.git",
            "composite",
            42,
        );
        observe_pack_cache_on_demand_composite_delta_bytes(
            &metrics,
            Protocol::Ssh,
            "acme/widgets.git",
            "composite",
            1024,
        );

        let encoded = encode_metrics(&metrics.registry);
        assert!(encoded.lines().any(|line| {
            line.starts_with(
                "forgeproxy_pack_cache_on_demand_composite_stage_duration_seconds_count{",
            ) && line.contains("owner_repo=\"acme/widgets\"")
                && line.contains("protocol=\"ssh\"")
                && line.contains("result=\"ok\"")
                && line.contains("stage=\"semaphore_wait\"")
                && line.ends_with(" 1")
        }));
        assert!(encoded.lines().any(|line| {
            line.starts_with("forgeproxy_pack_cache_on_demand_composite_candidate_count_count{")
                && line.contains("owner_repo=\"acme/widgets\"")
                && line.contains("result=\"ok\"")
                && line.ends_with(" 1")
        }));
        assert!(encoded.lines().any(|line| {
            line.starts_with("forgeproxy_pack_cache_on_demand_composite_delta_objects_sum{")
                && line.contains("owner_repo=\"acme/widgets\"")
                && line.contains("result=\"composite\"")
                && (line.ends_with(" 42") || line.ends_with(" 42.0"))
        }));
        assert!(encoded.lines().any(|line| {
            line.starts_with("forgeproxy_pack_cache_on_demand_composite_delta_bytes_sum{")
                && line.contains("owner_repo=\"acme/widgets\"")
                && line.contains("result=\"composite\"")
                && (line.ends_with(" 1024") || line.ends_with(" 1024.0"))
        }));
    }

    #[test]
    fn pack_cache_diagnostic_metrics_encode_expected_labels() {
        let metrics = MetricsRegistry::new();

        inc_pack_cache_key_bypass(&metrics, Protocol::Https, "acme/widgets.git", "filtered");
        inc_pack_cache_warming_skip(&metrics, "acme/widgets.git", "no_recent_full_tip");
        replace_pack_cache_recent_entries(&metrics, &[("acme/widgets.git".to_string(), 4, 2)]);

        let encoded = encode_metrics(&metrics.registry);
        assert!(encoded.lines().any(|line| {
            line.starts_with("forgeproxy_pack_cache_key_bypasses_total{")
                && line.contains("owner_repo=\"acme/widgets\"")
                && line.contains("protocol=\"https\"")
                && line.contains("reason=\"filtered\"")
                && line.ends_with(" 1")
        }));
        assert!(encoded.lines().any(|line| {
            line.starts_with("forgeproxy_pack_cache_warming_skips_total{")
                && line.contains("owner_repo=\"acme/widgets\"")
                && line.contains("reason=\"no_recent_full_tip\"")
                && line.ends_with(" 1")
        }));
        assert!(encoded.lines().any(|line| {
            line.starts_with("forgeproxy_pack_cache_recent_entries{")
                && line.contains("kind=\"all\"")
                && line.contains("owner_repo=\"acme/widgets\"")
                && line.ends_with(" 4")
        }));
        assert!(encoded.lines().any(|line| {
            line.starts_with("forgeproxy_pack_cache_recent_entries{")
                && line.contains("kind=\"full_tip\"")
                && line.contains("owner_repo=\"acme/widgets\"")
                && line.ends_with(" 2")
        }));
    }

    #[test]
    fn clone_metrics_encode_lowercase_label_values() {
        let metrics = MetricsRegistry::new();

        record_clone_completion(
            &metrics,
            Protocol::Ssh,
            CacheStatus::Hot,
            "octocat",
            "acme/widgets",
            Duration::from_secs(1),
        );

        let encoded = encode_metrics(&metrics.registry);
        assert!(encoded.lines().any(|line| {
            line.starts_with("forgeproxy_clone_total{")
                && line.contains("protocol=\"ssh\"")
                && line.contains("cache_status=\"hot\"")
        }));
        assert!(encoded.lines().any(|line| {
            line.starts_with("forgeproxy_clone_summary_total{")
                && line.contains("protocol=\"ssh\"")
                && line.contains("cache_status=\"hot\"")
                && line.contains("auth_state=\"resolved\"")
        }));
    }

    #[test]
    fn upload_pack_guard_updates_concurrency_gauge() {
        let metrics = MetricsRegistry::new();
        let counter = Arc::new(AtomicI64::new(0));

        {
            let _guard = UploadPackGuard::new(metrics.clone(), Protocol::Ssh, Arc::clone(&counter));
            let encoded = encode_metrics(&metrics.registry);
            assert!(encoded.lines().any(|line| {
                line.starts_with("forgeproxy_upload_pack_concurrent{") && line.ends_with(" 1")
            }));
        }

        let encoded = encode_metrics(&metrics.registry);
        assert!(encoded.lines().any(|line| {
            line.starts_with("forgeproxy_upload_pack_concurrent{") && line.ends_with(" 0")
        }));
    }

    #[test]
    fn active_clone_guard_omits_idle_series() {
        let metrics = MetricsRegistry::new();
        let counter = Arc::new(AtomicI64::new(0));

        {
            let _guard = ActiveCloneGuard::new(
                metrics.clone(),
                Protocol::Https,
                CacheStatus::Warm,
                Arc::clone(&counter),
            );
            let encoded = encode_metrics(&metrics.registry);
            assert!(encoded.lines().any(|line| {
                line.starts_with("forgeproxy_active_clones{")
                    && line.contains("protocol=\"https\"")
                    && line.contains("cache_status=\"warm\"")
                    && line.ends_with(" 1")
            }));
        }

        let encoded = encode_metrics(&metrics.registry);
        assert!(!encoded.contains("forgeproxy_active_clones{"));
    }
}
