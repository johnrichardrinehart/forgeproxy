use std::sync::Arc;

use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::Registry;

// ---------------------------------------------------------------------------
// Label types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct CloneLabels {
    pub protocol: Protocol,
    pub cache_status: CacheStatus,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum Protocol {
    Ssh,
    Https,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum CacheStatus {
    Hot,
    Warm,
    Cold,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ProtocolLabels {
    pub protocol: Protocol,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct EndpointLabels {
    pub endpoint: String,
}

// ---------------------------------------------------------------------------
// Metrics struct
// ---------------------------------------------------------------------------

/// Central container for every Prometheus metric exposed by the proxy.
pub struct Metrics {
    // -- clone --
    pub clone_total: Family<CloneLabels, Counter>,
    pub clone_duration_seconds: Family<ProtocolLabels, Histogram>,

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

    // -- S3 --
    pub s3_upload_bytes: Counter,
    pub s3_download_bytes: Counter,

    // -- upstream API --
    pub upstream_api_calls: Family<EndpointLabels, Counter>,

    // -- rate limit --
    pub upstream_api_rate_limit_remaining: Gauge,

    // -- gauges --
    pub active_connections: Family<ProtocolLabels, Gauge>,
    pub cache_size_bytes: Gauge,
    pub cache_repos_total: Gauge,
}

impl Metrics {
    /// Create a new [`Metrics`] instance and register every metric with the
    /// supplied `registry`.
    pub fn new(registry: &mut Registry) -> Self {
        let clone_total = Family::<CloneLabels, Counter>::default();
        registry.register(
            "forgecache_clone_total",
            "Total clone requests by protocol and cache status",
            clone_total.clone(),
        );

        let clone_duration_seconds =
            Family::<ProtocolLabels, Histogram>::new_with_constructor(|| {
                Histogram::new(exponential_buckets(0.01, 2.0, 14))
            });
        registry.register(
            "forgecache_clone_duration_seconds",
            "Clone request latency in seconds",
            clone_duration_seconds.clone(),
        );

        let bundle_generation_total = Counter::default();
        registry.register(
            "forgecache_bundle_generation_total",
            "Total bundle generation operations",
            bundle_generation_total.clone(),
        );

        let bundle_generation_duration_seconds = Histogram::new(exponential_buckets(1.0, 2.0, 12));
        registry.register(
            "forgecache_bundle_generation_duration_seconds",
            "Bundle generation latency in seconds",
            bundle_generation_duration_seconds.clone(),
        );

        let auth_cache_hits = Counter::default();
        registry.register(
            "forgecache_auth_cache_hits_total",
            "Auth cache hits",
            auth_cache_hits.clone(),
        );

        let auth_cache_misses = Counter::default();
        registry.register(
            "forgecache_auth_cache_misses_total",
            "Auth cache misses",
            auth_cache_misses.clone(),
        );

        let lock_acquisitions = Counter::default();
        registry.register(
            "forgecache_lock_acquisitions_total",
            "Distributed lock acquisitions",
            lock_acquisitions.clone(),
        );

        let lock_waits = Counter::default();
        registry.register(
            "forgecache_lock_waits_total",
            "Distributed lock wait events",
            lock_waits.clone(),
        );

        let lock_timeouts = Counter::default();
        registry.register(
            "forgecache_lock_timeouts_total",
            "Distributed lock timeout events",
            lock_timeouts.clone(),
        );

        let s3_upload_bytes = Counter::default();
        registry.register(
            "forgecache_s3_upload_bytes_total",
            "Total bytes uploaded to S3",
            s3_upload_bytes.clone(),
        );

        let s3_download_bytes = Counter::default();
        registry.register(
            "forgecache_s3_download_bytes_total",
            "Total bytes downloaded from S3",
            s3_download_bytes.clone(),
        );

        let upstream_api_calls = Family::<EndpointLabels, Counter>::default();
        registry.register(
            "forgecache_ghe_api_calls_total",
            "upstream API call count by endpoint",
            upstream_api_calls.clone(),
        );

        let upstream_api_rate_limit_remaining: Gauge = Gauge::default();
        registry.register(
            "forgecache_upstream_api_rate_limit_remaining",
            "Remaining upstream API calls before rate limit",
            upstream_api_rate_limit_remaining.clone(),
        );

        let active_connections = Family::<ProtocolLabels, Gauge>::default();
        registry.register(
            "forgecache_active_connections",
            "Currently active connections by protocol",
            active_connections.clone(),
        );

        let cache_size_bytes: Gauge = Gauge::default();
        registry.register(
            "forgecache_cache_size_bytes",
            "Current local cache disk usage in bytes",
            cache_size_bytes.clone(),
        );

        let cache_repos_total: Gauge = Gauge::default();
        registry.register(
            "forgecache_cache_repos_total",
            "Number of repos currently cached locally",
            cache_repos_total.clone(),
        );

        Self {
            clone_total,
            clone_duration_seconds,
            bundle_generation_total,
            bundle_generation_duration_seconds,
            auth_cache_hits,
            auth_cache_misses,
            lock_acquisitions,
            lock_waits,
            lock_timeouts,
            s3_upload_bytes,
            s3_download_bytes,
            upstream_api_calls,
            upstream_api_rate_limit_remaining,
            active_connections,
            cache_size_bytes,
            cache_repos_total,
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
}

impl MetricsRegistry {
    /// Build a fresh registry and pre-register all proxy metrics.
    pub fn new() -> Self {
        let mut registry = Registry::default();
        let metrics = Metrics::new(&mut registry);
        Self {
            registry: Arc::new(registry),
            metrics: Arc::new(metrics),
        }
    }
}
