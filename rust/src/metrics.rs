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
pub struct ProtocolLabels {
    pub protocol: Protocol,
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
pub struct CacheSubtreeLabels {
    pub subtree: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct HydrationSkipLabels {
    pub reason: HydrationSkipReason,
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
    pub clone_upstream_bytes: Family<CloneUpstreamBytesLabels, Counter>,
    pub clone_downstream_bytes: Family<CloneDownstreamBytesLabels, Counter>,

    // -- bundles --
    pub bundle_generation_total: Counter,
    pub bundle_generation_duration_seconds: Histogram,

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
    pub cache_size_bytes: Gauge,
    pub cache_repos_total: Gauge,
    pub mirror_size_bytes: Family<RepoLabels, Gauge>,
    pub cache_subtree_size_bytes: Family<CacheSubtreeLabels, Gauge>,

    // -- hydration --
    pub hydration_skipped: Family<HydrationSkipLabels, Counter>,
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

        let cache_size_bytes: Gauge = Gauge::default();
        registry.register(
            "forgeproxy_cache_size_bytes",
            "Current local cache disk usage in bytes",
            cache_size_bytes.clone(),
        );

        let cache_repos_total: Gauge = Gauge::default();
        registry.register(
            "forgeproxy_cache_repos_total",
            "Number of repos currently cached locally",
            cache_repos_total.clone(),
        );

        let mirror_size_bytes = Family::<RepoLabels, Gauge>::default();
        registry.register(
            "forgeproxy_mirror_size_bytes",
            "Current on-disk size in bytes for each mirrored repository",
            mirror_size_bytes.clone(),
        );

        let cache_subtree_size_bytes = Family::<CacheSubtreeLabels, Gauge>::default();
        registry.register(
            "forgeproxy_cache_subtree_size_bytes",
            "Current on-disk size in bytes for important forgeproxy cache subtrees",
            cache_subtree_size_bytes.clone(),
        );

        let hydration_skipped = Family::<HydrationSkipLabels, Counter>::default();
        registry.register(
            "forgeproxy_hydration_skipped",
            "Hydration work skipped due to deduplication or concurrency limits",
            hydration_skipped.clone(),
        );

        Self {
            clone_total,
            clone_summary_total,
            clone_duration_seconds,
            upload_pack_duration_seconds,
            clone_upstream_bytes,
            clone_downstream_bytes,
            bundle_generation_total,
            bundle_generation_duration_seconds,
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
            cache_size_bytes,
            cache_repos_total,
            mirror_size_bytes,
            cache_subtree_size_bytes,
            hydration_skipped,
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

pub fn set_cache_size_bytes(metrics: &MetricsRegistry, size_bytes: u64) {
    metrics
        .metrics
        .cache_size_bytes
        .set(size_bytes.min(i64::MAX as u64) as i64);
}

pub fn set_cache_repos_total(metrics: &MetricsRegistry, repo_count: usize) {
    metrics
        .metrics
        .cache_repos_total
        .set(repo_count.min(i64::MAX as usize) as i64);
}

pub fn replace_mirror_size_bytes(metrics: &MetricsRegistry, mirror_sizes: &[(String, u64)]) {
    metrics.metrics.mirror_size_bytes.clear();
    for (repo, size_bytes) in mirror_sizes {
        metrics
            .metrics
            .mirror_size_bytes
            .get_or_create(&RepoLabels { repo: repo.clone() })
            .set((*size_bytes).min(i64::MAX as u64) as i64);
    }
}

pub fn replace_cache_subtree_size_bytes(
    metrics: &MetricsRegistry,
    subtree_sizes: &[(String, u64)],
) {
    metrics.metrics.cache_subtree_size_bytes.clear();
    for (subtree, size_bytes) in subtree_sizes {
        metrics
            .metrics
            .cache_subtree_size_bytes
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

        replace_mirror_size_bytes(
            &metrics,
            &[
                ("acme/widgets".to_string(), 12),
                ("acme/legacy".to_string(), 7),
            ],
        );
        replace_cache_subtree_size_bytes(
            &metrics,
            &[("mirrors".to_string(), 12), ("snapshots".to_string(), 4)],
        );

        let encoded = encode_metrics(&metrics.registry);
        assert!(encoded.contains("forgeproxy_mirror_size_bytes{repo=\"acme/widgets\"} 12"));
        assert!(encoded.contains("forgeproxy_mirror_size_bytes{repo=\"acme/legacy\"} 7"));
        assert!(encoded.contains("forgeproxy_cache_subtree_size_bytes{subtree=\"mirrors\"} 12"));
        assert!(encoded.contains("forgeproxy_cache_subtree_size_bytes{subtree=\"snapshots\"} 4"));

        replace_mirror_size_bytes(&metrics, &[("acme/widgets".to_string(), 9)]);
        replace_cache_subtree_size_bytes(&metrics, &[("mirrors".to_string(), 9)]);

        let encoded = encode_metrics(&metrics.registry);
        assert!(encoded.contains("forgeproxy_mirror_size_bytes{repo=\"acme/widgets\"} 9"));
        assert!(!encoded.contains("forgeproxy_mirror_size_bytes{repo=\"acme/legacy\"}"));
        assert!(encoded.contains("forgeproxy_cache_subtree_size_bytes{subtree=\"mirrors\"} 9"));
        assert!(!encoded.contains("forgeproxy_cache_subtree_size_bytes{subtree=\"snapshots\"}"));
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
        inc_hydration_skipped(&metrics, HydrationSkipReason::SemaphoreSaturated);

        let encoded = encode_metrics(&metrics.registry);
        assert!(encoded.contains("# HELP forgeproxy_upload_pack_duration_seconds"));
        assert!(encoded.lines().any(|line| {
            line.starts_with("forgeproxy_upload_pack_duration_seconds_sum{")
                && line.contains("repo=\"acme/widgets\"")
                && line.contains(" 0.25")
        }));
        assert!(encoded.lines().any(
            |line| line.starts_with("forgeproxy_hydration_skipped_total{") && line.ends_with(" 1")
        ));
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
}
