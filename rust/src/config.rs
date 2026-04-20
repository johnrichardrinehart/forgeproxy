use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Backend type
// ---------------------------------------------------------------------------

/// Which upstream forge flavour to use.
///
/// This controls API URL construction, response parsing, webhook signature
/// verification, and header selection.
///
/// # SSH key resolution and cloud/SaaS forges
///
/// SSH fingerprint-to-username resolution requires **instance administrator**
/// API access.  This is only available on self-hosted deployments:
///
/// | Variant              | SSH key resolution | Notes                                                              |
/// |----------------------|--------------------|--------------------------------------------------------------------|
/// | `github-enterprise`  | Via sidecar        | No usable HTTP API; set `upstream.key_lookup_url` (ghe-key-lookup) |
/// | `github`             | Via sidecar        | No admin key lookup API; set `upstream.key_lookup_url`             |
/// | `gitlab`             | Supported          | Requires self-managed instance admin                               |
/// | `gitea` / `forgejo`  | Supported          | Requires instance admin token                                      |
///
/// For GitHub and GitHub Enterprise, SSH key resolution requires a
/// `ghe-key-lookup` sidecar reachable at `upstream.key_lookup_url`.
/// Without it, SSH authentication will be rejected with a configuration error.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackendType {
    /// GitHub Enterprise Server (self-hosted).  Full admin API available.
    #[default]
    GithubEnterprise,
    /// GitHub.com / GitHub Enterprise Cloud.  No admin SSH key endpoint.
    Github,
    /// GitLab (self-managed or GitLab.com).  SSH key resolution requires
    /// self-managed instance admin; on GitLab.com the `/keys` endpoint is
    /// inaccessible to non-admin users.
    Gitlab,
    /// Gitea (self-hosted).
    Gitea,
    /// Forgejo (self-hosted).  Same API as Gitea with different webhook headers.
    Forgejo,
}

impl BackendType {
    /// Returns the appropriate `Accept` header value for API requests to this backend.
    pub fn accept_header(&self) -> &'static str {
        match self {
            Self::GithubEnterprise | Self::Github => "application/vnd.github.v3+json",
            Self::Gitlab | Self::Gitea | Self::Forgejo => "application/json",
        }
    }

    pub fn as_label(&self) -> &'static str {
        match self {
            Self::GithubEnterprise => "github_enterprise",
            Self::Github => "github",
            Self::Gitlab => "gitlab",
            Self::Gitea => "gitea",
            Self::Forgejo => "forgejo",
        }
    }
}

impl fmt::Display for BackendType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_label())
    }
}

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub upstream: UpstreamConfig,
    #[serde(default)]
    pub backend_type: BackendType,
    pub upstream_credentials: UpstreamCredentials,
    pub proxy: ProxyConfig,
    pub valkey: ValkeyConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub clone: CloneConfig,
    #[serde(default)]
    pub fetch_schedule: FetchScheduleConfig,
    #[serde(default)]
    pub bundles: BundleConfig,
    #[serde(default)]
    pub pack_cache: PackCacheConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub repo_overrides: HashMap<String, RepoOverride>,
}

// ---------------------------------------------------------------------------
// Observability
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub logs: LogSignalConfig,
    #[serde(default)]
    pub traces: TraceConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    #[serde(default)]
    pub prometheus: PrometheusConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrometheusConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_metrics_refresh_interval_secs")]
    pub refresh_interval_secs: u64,
}

impl Default for PrometheusConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            refresh_interval_secs: default_metrics_refresh_interval_secs(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSignalConfig {
    #[serde(default)]
    pub journald: JournaldLogConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournaldLogConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for JournaldLogConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_trace_sample_ratio")]
    pub sample_ratio: f64,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sample_ratio: default_trace_sample_ratio(),
        }
    }
}

fn default_trace_sample_ratio() -> f64 {
    1.0
}

fn default_true() -> bool {
    true
}

fn default_metrics_refresh_interval_secs() -> u64 {
    60
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

// ---------------------------------------------------------------------------
// Upstream
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    /// Hostname of the upstream forge (e.g. `ghe.corp.example.com`).
    pub hostname: String,
    /// Full URL to the upstream API root (e.g. `https://ghe.corp.example.com/api/v3`).
    pub api_url: String,
    /// Base URL for upstream Git smart-HTTP traffic. Defaults to
    /// `https://<hostname>` when omitted.
    #[serde(default)]
    pub git_url_base: Option<String>,
    /// Name of the environment variable that holds the upstream admin PAT.
    ///
    /// This token is used for SSH fingerprint-to-username resolution and
    /// collaborator permission checks.  It requires **instance admin** privileges
    /// (e.g. `site_admin` scope on GitHub Enterprise Server, or an admin
    /// `PRIVATE-TOKEN` on self-managed GitLab).
    ///
    /// On cloud/SaaS forges (GitHub.com, GitLab.com) admin endpoints are not
    /// available; SSH key resolution will not work and clients must use HTTP
    /// token authentication instead.
    #[serde(default = "default_admin_token_env")]
    pub admin_token_env: String,
    /// Minimum number of API calls to keep in reserve before self-throttling.
    #[serde(default = "default_api_rate_limit_buffer")]
    pub api_rate_limit_buffer: u32,
    /// Number of leading and trailing secret characters to leave visible when
    /// logging authenticated upstream URLs.
    #[serde(default = "default_log_secret_unmask_chars")]
    pub log_secret_unmask_chars: usize,
    /// Base URL of a `ghe-key-lookup` sidecar for SSH fingerprint → username
    /// resolution (e.g. `http://ghe-key-lookup:3000`).
    ///
    /// When set, `resolve_ssh_user` calls
    /// `{key_lookup_url}/api/v3/users/keys/lookup?fingerprint=<fp>` instead of
    /// the built-in GHE admin SSH-keys endpoint.  The sidecar response omits
    /// the nested `user` object: the login is at `[0]["login"]` rather than
    /// `[0]["user"]["login"]`.
    #[serde(default)]
    pub key_lookup_url: Option<String>,
}

impl UpstreamConfig {
    pub fn git_url_base(&self) -> String {
        self.git_url_base
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.trim_end_matches('/').to_string())
            .unwrap_or_else(|| format!("https://{}", self.hostname))
    }
}

fn default_admin_token_env() -> String {
    "FORGE_ADMIN_TOKEN".to_string()
}

fn default_api_rate_limit_buffer() -> u32 {
    100
}

fn default_log_secret_unmask_chars() -> usize {
    4
}

// ---------------------------------------------------------------------------
// Upstream credentials
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamCredentials {
    /// Default credential mode used when no per-org override is present.
    #[serde(default = "default_credential_mode")]
    pub default_mode: CredentialMode,
    /// Per-organisation credential overrides.
    #[serde(default)]
    pub orgs: HashMap<String, OrgCredential>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialMode {
    Pat,
    Ssh,
}

fn default_credential_mode() -> CredentialMode {
    CredentialMode::Pat
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrgCredential {
    pub mode: CredentialMode,
    /// Key name stored in the Linux kernel keyring (`linux-keyutils`).
    pub keyring_key_name: String,
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// Socket address for the SSH listener (e.g. `0.0.0.0:2222`).
    pub ssh_listen: String,
    /// Socket address for the HTTP listener (e.g. `0.0.0.0:8443`).
    pub http_listen: String,
}

// ---------------------------------------------------------------------------
// Valkey / Redis
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValkeyConfig {
    /// Connection string (e.g. `rediss://valkey.local:6380`).
    pub endpoint: String,
    /// Enable TLS for the Valkey connection.
    #[serde(default = "bool_true")]
    pub tls: bool,
    /// Path to an additional CA certificate to trust (e.g. self-signed Valkey CA).
    pub ca_cert_file: Option<String>,
    /// Name of the environment variable that holds the Valkey auth token.
    #[serde(default = "default_valkey_auth_env")]
    pub auth_token_env: String,
}

fn bool_true() -> bool {
    true
}

fn default_valkey_auth_env() -> String {
    "VALKEY_AUTH_TOKEN".to_string()
}

// ---------------------------------------------------------------------------
// Auth cache TTLs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Positive SSH auth cache TTL in seconds.
    #[serde(default = "default_ssh_cache_ttl")]
    pub ssh_cache_ttl: u64,
    /// Positive HTTP auth cache TTL in seconds.
    #[serde(default = "default_http_cache_ttl")]
    pub http_cache_ttl: u64,
    /// Negative (failed) auth cache TTL in seconds.
    #[serde(default = "default_negative_cache_ttl")]
    pub negative_cache_ttl: u64,
    /// Name of the environment variable that holds the GitHub webhook secret.
    #[serde(default = "default_webhook_secret_env")]
    pub webhook_secret_env: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            ssh_cache_ttl: default_ssh_cache_ttl(),
            http_cache_ttl: default_http_cache_ttl(),
            negative_cache_ttl: default_negative_cache_ttl(),
            webhook_secret_env: default_webhook_secret_env(),
        }
    }
}

fn default_ssh_cache_ttl() -> u64 {
    300
}

fn default_http_cache_ttl() -> u64 {
    300
}

fn default_negative_cache_ttl() -> u64 {
    60
}

fn default_webhook_secret_env() -> String {
    "FORGE_WEBHOOK_SECRET".to_string()
}

// ---------------------------------------------------------------------------
// Clone behaviour
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloneConfig {
    /// TTL (seconds) of the distributed per-repo hydration semaphore lease in
    /// Valkey.
    #[serde(default = "default_lock_ttl")]
    pub lock_ttl: u64,
    /// Deprecated for initial clone coordination.
    #[serde(default = "default_lock_wait_timeout")]
    pub lock_wait_timeout: u64,
    /// Semaphore limit for concurrent full clones against upstream.
    #[serde(default = "default_max_concurrent_upstream_clones")]
    pub max_concurrent_upstream_clones: usize,
    /// Semaphore limit for concurrent fetches against upstream.
    #[serde(default = "default_max_concurrent_upstream_fetches")]
    pub max_concurrent_upstream_fetches: usize,
    /// Number of upstream fetch slots reserved for request-time local
    /// catch-up. Lower-priority refreshes and tee convergence can only use the
    /// remaining fetch capacity.
    #[serde(default = "default_reserved_request_time_upstream_fetches")]
    pub reserved_request_time_upstream_fetches: usize,
    /// Host-wide limit for simultaneous tee capture/import work.
    #[serde(default = "default_max_concurrent_tee_captures")]
    pub max_concurrent_tee_captures: usize,
    /// Per-repo per-host limit for simultaneous tee capture/import work.
    #[serde(default = "default_max_concurrent_tee_captures_per_repo_per_instance")]
    pub max_concurrent_tee_captures_per_repo_per_instance: usize,
    /// Maximum concurrent upstream hydrations for a single repo across all
    /// forgeproxy instances.
    #[serde(default = "default_max_concurrent_upstream_clones_per_repo_across_instances")]
    pub max_concurrent_upstream_clones_per_repo_across_instances: usize,
    /// Maximum concurrent upstream hydrations for a single repo within one
    /// forgeproxy instance.
    #[serde(default = "default_max_concurrent_upstream_clones_per_repo_per_instance")]
    pub max_concurrent_upstream_clones_per_repo_per_instance: usize,
    /// Maximum concurrent local `git upload-pack` subprocesses on this
    /// instance. This bounds pack-objects CPU even when many requests are
    /// served from warm local disk.
    #[serde(default = "default_max_concurrent_local_upload_packs")]
    pub max_concurrent_local_upload_packs: usize,
    /// Maximum concurrent local `git upload-pack` subprocesses for a single
    /// repository on this instance.
    #[serde(default = "default_max_concurrent_local_upload_packs_per_repo")]
    pub max_concurrent_local_upload_packs_per_repo: usize,
    /// Strategy used after tee capture successfully materializes the cloned
    /// pack into a staging generation.
    #[serde(default)]
    pub hydration_mode: HydrationMode,
    /// Whether staged published generations should be repacked with bitmap and
    /// multi-pack-index support before they are exposed to clone readers.
    #[serde(default)]
    pub prepare_published_generation_indexes: bool,
    /// Optional window during which lower-priority refreshes may keep serving
    /// the current published generation instead of publishing another one.
    #[serde(default)]
    pub generation_coalescing_window_secs: u64,
    /// Maximum time a client request should wait for a local mirror catch-up
    /// publish before falling back to proxying upstream.
    #[serde(default = "default_request_wait_for_local_catch_up_secs")]
    pub request_wait_for_local_catch_up_secs: u64,
    /// How often to scan `_tee` for abandoned captures.
    #[serde(default = "default_tee_cleanup_interval_secs")]
    pub tee_cleanup_interval_secs: u64,
    /// Maximum age of a tee capture before it is treated as abandoned and
    /// removed by the background janitor.
    #[serde(default = "default_tee_retention_secs")]
    pub tee_retention_secs: u64,
    /// Maximum time forgeproxy will wait for russh to flush pending upload-pack
    /// channel data before it sends exit-status, EOF, and CHANNEL_CLOSE.
    #[serde(default = "default_ssh_upload_pack_close_grace_secs")]
    pub ssh_upload_pack_close_grace_secs: u64,
}

impl Default for CloneConfig {
    fn default() -> Self {
        Self {
            lock_ttl: default_lock_ttl(),
            lock_wait_timeout: default_lock_wait_timeout(),
            max_concurrent_upstream_clones: default_max_concurrent_upstream_clones(),
            max_concurrent_upstream_fetches: default_max_concurrent_upstream_fetches(),
            reserved_request_time_upstream_fetches: default_reserved_request_time_upstream_fetches(
            ),
            max_concurrent_tee_captures: default_max_concurrent_tee_captures(),
            max_concurrent_tee_captures_per_repo_per_instance:
                default_max_concurrent_tee_captures_per_repo_per_instance(),
            max_concurrent_upstream_clones_per_repo_across_instances:
                default_max_concurrent_upstream_clones_per_repo_across_instances(),
            max_concurrent_upstream_clones_per_repo_per_instance:
                default_max_concurrent_upstream_clones_per_repo_per_instance(),
            max_concurrent_local_upload_packs: default_max_concurrent_local_upload_packs(),
            max_concurrent_local_upload_packs_per_repo:
                default_max_concurrent_local_upload_packs_per_repo(),
            hydration_mode: HydrationMode::default(),
            prepare_published_generation_indexes: false,
            generation_coalescing_window_secs: 0,
            request_wait_for_local_catch_up_secs: default_request_wait_for_local_catch_up_secs(),
            tee_cleanup_interval_secs: default_tee_cleanup_interval_secs(),
            tee_retention_secs: default_tee_retention_secs(),
            ssh_upload_pack_close_grace_secs: default_ssh_upload_pack_close_grace_secs(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HydrationMode {
    FollowOnFetch,
    #[default]
    PublishFromCapture,
}

fn default_lock_ttl() -> u64 {
    900
}

fn default_lock_wait_timeout() -> u64 {
    90
}

fn default_request_wait_for_local_catch_up_secs() -> u64 {
    30
}

fn default_tee_cleanup_interval_secs() -> u64 {
    60
}

fn default_tee_retention_secs() -> u64 {
    900
}

fn default_ssh_upload_pack_close_grace_secs() -> u64 {
    5
}

fn default_max_concurrent_upstream_clones() -> usize {
    4
}

fn default_max_concurrent_upstream_fetches() -> usize {
    8
}

fn default_reserved_request_time_upstream_fetches() -> usize {
    2
}

fn default_max_concurrent_tee_captures() -> usize {
    8
}

fn default_max_concurrent_tee_captures_per_repo_per_instance() -> usize {
    2
}

fn default_max_concurrent_upstream_clones_per_repo_across_instances() -> usize {
    10
}

fn default_max_concurrent_upstream_clones_per_repo_per_instance() -> usize {
    3
}

fn default_max_concurrent_local_upload_packs() -> usize {
    4
}

fn default_max_concurrent_local_upload_packs_per_repo() -> usize {
    1
}

// ---------------------------------------------------------------------------
// Adaptive fetch schedule
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchScheduleConfig {
    /// Default interval (seconds) between background re-fetches.
    #[serde(default = "default_fetch_interval")]
    pub default_interval: u64,
    /// Number of new commits that qualifies as a "large delta".
    #[serde(default = "default_delta_threshold")]
    pub delta_threshold: u64,
    /// Multiplicative backoff factor when a repo is idle.
    #[serde(default = "default_backoff_factor")]
    pub backoff_factor: f64,
    /// Upper bound (seconds) on the fetch interval after back-off.
    #[serde(default = "default_max_interval")]
    pub max_interval: u64,
    /// Rolling window (seconds) for evaluating clone frequency.
    #[serde(default = "default_rolling_window")]
    pub rolling_window: u64,
}

impl Default for FetchScheduleConfig {
    fn default() -> Self {
        Self {
            default_interval: default_fetch_interval(),
            delta_threshold: default_delta_threshold(),
            backoff_factor: default_backoff_factor(),
            max_interval: default_max_interval(),
            rolling_window: default_rolling_window(),
        }
    }
}

fn default_fetch_interval() -> u64 {
    300
}

fn default_delta_threshold() -> u64 {
    50
}

fn default_backoff_factor() -> f64 {
    2.0
}

fn default_max_interval() -> u64 {
    3600
}

fn default_rolling_window() -> u64 {
    3600
}

// ---------------------------------------------------------------------------
// Bundle generation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleConfig {
    /// Minimum number of clones a repo must have received before bundles are
    /// generated for it.
    #[serde(default = "default_min_clone_count")]
    pub min_clone_count_for_bundles: u64,
    /// TTL (seconds) of the distributed bundle-generation lock.
    #[serde(default = "default_bundle_lock_ttl")]
    pub bundle_lock_ttl: u64,
    /// Maximum number of repositories whose bundle-generation work may run in
    /// parallel on this instance during the periodic lifecycle tick.
    #[serde(default = "default_max_concurrent_generations")]
    pub max_concurrent_generations: usize,
    /// Number of `git pack-objects` threads to use for each generated bundle.
    ///
    /// When unset, forgeproxy derives a value from the host's CPU count and
    /// the resolved bundle-generation concurrency so the total pack thread
    /// budget stays roughly within the machine's parallelism.
    #[serde(default)]
    pub pack_threads: Option<usize>,
    /// Whether to produce filtered (blobless / treeless) bundle variants.
    #[serde(default)]
    pub generate_filtered_bundles: bool,
    /// Maximum incremental bundle entries retained in the repo-global bundle
    /// manifest. Incrementals are generated against the current base, so older
    /// incrementals are redundant for latest clones.
    #[serde(default = "default_max_incremental_bundles")]
    pub max_incremental_bundles: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleExecutionPolicy {
    pub max_concurrent_generations: usize,
    pub pack_threads: usize,
}

// ---------------------------------------------------------------------------
// Pack response cache
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackCacheConfig {
    /// Enable replay caching of local upload-pack responses for safe fresh
    /// clone requests.
    #[serde(default)]
    pub enabled: bool,
    /// Fraction of the local forgeproxy cache budget retained by the
    /// disk-backed pack response cache.
    #[serde(default = "default_pack_cache_max_percent")]
    pub max_percent: f64,
    /// Eviction starts when pack cache usage exceeds this fraction of its
    /// budget.
    #[serde(default = "default_high_water")]
    pub high_water_mark: f64,
    /// Eviction stops when pack cache usage drops to or below this fraction of
    /// its budget.
    #[serde(default = "default_low_water")]
    pub low_water_mark: f64,
    /// Eviction policy: `lru` or `lfu`.
    #[serde(default = "default_eviction_policy")]
    pub eviction_policy: EvictionPolicy,
    /// Maximum time a same-key request waits for an in-flight pack artifact
    /// before bypassing the cache and running its own local upload-pack.
    #[serde(default = "default_pack_cache_wait_for_inflight_secs")]
    pub wait_for_inflight_secs: u64,
    /// Do not store responses smaller than this threshold. Small requests do
    /// not justify cache bookkeeping.
    #[serde(default = "default_pack_cache_min_response_bytes")]
    pub min_response_bytes: u64,
}

impl Default for PackCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_percent: default_pack_cache_max_percent(),
            high_water_mark: default_high_water(),
            low_water_mark: default_low_water(),
            eviction_policy: default_eviction_policy(),
            wait_for_inflight_secs: default_pack_cache_wait_for_inflight_secs(),
            min_response_bytes: default_pack_cache_min_response_bytes(),
        }
    }
}

fn default_pack_cache_max_percent() -> f64 {
    0.20
}

fn default_pack_cache_wait_for_inflight_secs() -> u64 {
    120
}

fn default_pack_cache_min_response_bytes() -> u64 {
    64 * 1024 * 1024
}

impl Default for BundleConfig {
    fn default() -> Self {
        Self {
            min_clone_count_for_bundles: default_min_clone_count(),
            bundle_lock_ttl: default_bundle_lock_ttl(),
            max_concurrent_generations: default_max_concurrent_generations(),
            pack_threads: None,
            generate_filtered_bundles: false,
            max_incremental_bundles: default_max_incremental_bundles(),
        }
    }
}

impl BundleConfig {
    pub fn execution_policy(&self) -> BundleExecutionPolicy {
        let available_parallelism = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1);
        self.execution_policy_for_parallelism(available_parallelism)
    }

    fn execution_policy_for_parallelism(
        &self,
        available_parallelism: usize,
    ) -> BundleExecutionPolicy {
        let max_concurrent_generations = self.max_concurrent_generations;
        let pack_threads = self.pack_threads.unwrap_or_else(|| {
            default_pack_threads(available_parallelism, max_concurrent_generations)
        });

        BundleExecutionPolicy {
            max_concurrent_generations,
            pack_threads,
        }
    }
}

fn default_min_clone_count() -> u64 {
    5
}

fn default_bundle_lock_ttl() -> u64 {
    600
}

fn default_max_concurrent_generations() -> usize {
    2
}

fn default_max_incremental_bundles() -> usize {
    1
}

fn default_pack_threads(available_parallelism: usize, max_concurrent_generations: usize) -> usize {
    let available_parallelism = available_parallelism.max(1);
    let max_concurrent_generations = max_concurrent_generations.max(1);
    std::cmp::max(1, available_parallelism / max_concurrent_generations)
}

// ---------------------------------------------------------------------------
// Storage (local + S3)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    pub local: LocalStorageConfig,
    pub s3: S3StorageConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalStorageConfig {
    /// Root directory for bare repos and bundles.
    pub path: String,
    /// Fraction of the backing filesystem capacity usable by forgeproxy local
    /// cache state.
    pub max_percent: f64,
    /// Eviction starts when usage exceeds this fraction (0.0 .. 1.0).
    #[serde(default = "default_high_water")]
    pub high_water_mark: f64,
    /// Eviction stops when usage drops below this fraction.
    #[serde(default = "default_low_water")]
    pub low_water_mark: f64,
    /// Eviction policy: `lru` or `lfu`.
    #[serde(default = "default_eviction_policy")]
    pub eviction_policy: EvictionPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvictionPolicy {
    Lru,
    Lfu,
}

fn default_high_water() -> f64 {
    0.90
}

fn default_low_water() -> f64 {
    0.75
}

fn default_eviction_policy() -> EvictionPolicy {
    EvictionPolicy::Lru
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3StorageConfig {
    pub bucket: String,
    #[serde(default = "default_s3_prefix")]
    pub prefix: String,
    pub region: String,
    /// Optional custom S3-compatible endpoint URL for tests or non-AWS deployments.
    pub endpoint: Option<String>,
    /// Use the FIPS endpoints for S3 operations.
    #[serde(default)]
    pub use_fips: bool,
    /// TTL (seconds) for pre-signed download URLs.
    #[serde(default = "default_presigned_url_ttl")]
    pub presigned_url_ttl: u64,
}

fn default_s3_prefix() -> String {
    "forgeproxy/".to_string()
}

fn default_presigned_url_ttl() -> u64 {
    3600
}

// ---------------------------------------------------------------------------
// Per-repo overrides
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoOverride {
    /// Override fetch interval (seconds) for this repo.
    pub fetch_interval: Option<u64>,
    /// Force-disable bundle generation for this repo.
    pub disable_bundles: Option<bool>,
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

fn parse_config_str(contents: &str) -> Result<Config> {
    let config: Config = serde_yml::from_str(contents)?;
    validate_config(&config)?;
    Ok(config)
}

/// Load and validate a [`Config`] from a YAML file at `path`.
pub fn load_config<P: AsRef<Path>>(path: P) -> Result<Config> {
    let path = path.as_ref();
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;
    parse_config_str(&contents)
        .with_context(|| format!("failed to parse config file: {}", path.display()))
}

/// Basic sanity checks that cannot be expressed purely with serde.
fn validate_config(config: &Config) -> Result<()> {
    anyhow::ensure!(
        config.storage.local.high_water_mark > config.storage.local.low_water_mark,
        "storage.local.high_water_mark must be greater than storage.local.low_water_mark"
    );
    anyhow::ensure!(
        config.storage.local.high_water_mark <= 1.0 && config.storage.local.low_water_mark >= 0.0,
        "storage.local water marks must be in range [0.0, 1.0]"
    );
    anyhow::ensure!(
        config.storage.local.max_percent > 0.0 && config.storage.local.max_percent <= 1.0,
        "storage.local.max_percent must be in range (0.0, 1.0]"
    );
    anyhow::ensure!(
        config.bundles.max_concurrent_generations > 0,
        "max_concurrent_generations must be greater than 0"
    );
    anyhow::ensure!(
        config.bundles.pack_threads.is_none_or(|value| value > 0),
        "pack_threads must be greater than 0"
    );
    anyhow::ensure!(
        config.clone.max_concurrent_local_upload_packs > 0,
        "max_concurrent_local_upload_packs must be greater than 0"
    );
    anyhow::ensure!(
        config.clone.max_concurrent_local_upload_packs_per_repo > 0,
        "max_concurrent_local_upload_packs_per_repo must be greater than 0"
    );
    anyhow::ensure!(
        config.pack_cache.max_percent > 0.0 && config.pack_cache.max_percent <= 1.0,
        "pack_cache.max_percent must be in range (0.0, 1.0]"
    );
    anyhow::ensure!(
        config.pack_cache.high_water_mark > config.pack_cache.low_water_mark,
        "pack_cache.high_water_mark must be greater than pack_cache.low_water_mark"
    );
    anyhow::ensure!(
        config.pack_cache.high_water_mark <= 1.0 && config.pack_cache.low_water_mark >= 0.0,
        "pack_cache water marks must be in range [0.0, 1.0]"
    );
    anyhow::ensure!(
        (0.0..=1.0).contains(&config.observability.traces.sample_ratio),
        "observability.traces.sample_ratio must be in range [0.0, 1.0]"
    );
    anyhow::ensure!(
        config
            .observability
            .metrics
            .prometheus
            .refresh_interval_secs
            > 0,
        "observability.metrics.prometheus.refresh_interval_secs must be greater than 0"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{BackendType, BundleConfig, parse_config_str};

    #[test]
    fn bundle_execution_policy_defaults_single_core() {
        let policy = BundleConfig::default().execution_policy_for_parallelism(1);
        assert_eq!(policy.max_concurrent_generations, 2);
        assert_eq!(policy.pack_threads, 1);
    }

    #[test]
    fn bundle_execution_policy_defaults_spread_multi_core_hosts() {
        let policy = BundleConfig::default().execution_policy_for_parallelism(8);
        assert_eq!(policy.max_concurrent_generations, 2);
        assert_eq!(policy.pack_threads, 4);
    }

    #[test]
    fn bundle_execution_policy_respects_explicit_overrides() {
        let policy = BundleConfig {
            max_concurrent_generations: 2,
            pack_threads: Some(5),
            ..BundleConfig::default()
        }
        .execution_policy_for_parallelism(8);
        assert_eq!(policy.max_concurrent_generations, 2);
        assert_eq!(policy.pack_threads, 5);
    }

    #[test]
    fn config_example_parses() {
        parse_config_str(include_str!("../../config.example.yaml")).unwrap();
    }

    #[test]
    fn clone_config_accepts_published_generation_index_preparation() {
        let config = include_str!("../../config.example.yaml").replace(
            "  prepare_published_generation_indexes: false\n",
            "  prepare_published_generation_indexes: true\n",
        );
        let config = parse_config_str(&config).unwrap();
        assert!(config.clone.prepare_published_generation_indexes);
    }

    #[test]
    fn rejects_non_positive_metrics_refresh_interval() {
        let config = include_str!("../../config.example.yaml").replace(
            "  metrics:\n    prometheus:\n      enabled: true\n",
            "  metrics:\n    prometheus:\n      enabled: true\n      refresh_interval_secs: 0\n",
        );
        assert!(parse_config_str(&config).is_err());
    }

    #[test]
    fn rejects_legacy_local_max_bytes() {
        let config = include_str!("../../config.example.yaml")
            .replace("    max_percent: 0.80\n", "    max_bytes: 536870912000\n");
        assert!(parse_config_str(&config).is_err());
    }

    #[test]
    fn rejects_legacy_pack_cache_ttl() {
        let config = include_str!("../../config.example.yaml").replace(
            "  wait_for_inflight_secs: 120\n",
            "  ttl_secs: 900\n  wait_for_inflight_secs: 120\n",
        );
        assert!(parse_config_str(&config).is_err());
    }

    #[test]
    fn rejects_legacy_metrics_otlp_shape() {
        let config = include_str!("../../config.example.yaml").replace(
            "  metrics:\n    prometheus:\n      enabled: true\n",
            "  metrics:\n    prometheus:\n      enabled: true\n    otlp:\n      enabled: true\n      endpoint: \"https://ingest.metrics.foo.dev/vm/insert/0/opentelemetry/api/v1/push\"\n      protocol: \"http/protobuf\"\n      export_interval_secs: 60\n      auth:\n        basic:\n          username: \"foo\"\n          password: \"bar\"\n",
        );
        assert!(parse_config_str(&config).is_err());
    }

    #[test]
    fn rejects_legacy_observability_exporters_shape() {
        let config = include_str!("../../config.example.yaml").replace(
            "  traces:\n    enabled: false\n    sample_ratio: 1.0\n",
            "  traces:\n    enabled: false\n    sample_ratio: 1.0\n  exporters:\n    otlp:\n      metrics:\n        enabled: true\n        endpoint: \"https://ingest.metrics.foo.dev/vm/insert/0/opentelemetry/api/v1/push\"\n        protocol: \"http/protobuf\"\n        export_interval_secs: 60\n        auth:\n          basic:\n            username: \"foo\"\n            password: \"bar\"\n",
        );
        assert!(parse_config_str(&config).is_err());
    }

    #[test]
    fn rejects_legacy_ghe_alias() {
        let config = include_str!("../../config.example.yaml").replace("upstream:", "ghe:");
        assert!(parse_config_str(&config).is_err());
    }

    #[test]
    fn rejects_legacy_concurrency_aliases() {
        let config = include_str!("../../config.example.yaml")
            .replace(
                "max_concurrent_upstream_clones",
                "max_concurrent_ghe_clones",
            )
            .replace(
                "max_concurrent_upstream_fetches",
                "max_concurrent_ghe_fetches",
            );
        assert!(parse_config_str(&config).is_err());
    }

    #[test]
    fn backend_type_display_uses_lowercase_labels() {
        assert_eq!(
            BackendType::GithubEnterprise.to_string(),
            "github_enterprise"
        );
        assert_eq!(BackendType::Github.to_string(), "github");
        assert_eq!(BackendType::Gitlab.to_string(), "gitlab");
    }
}
