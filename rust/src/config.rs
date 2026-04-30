use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

pub const DEFAULT_INDEX_PACK_THREADS: usize = 2;

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

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub config_reload: ConfigReloadConfig,
    #[serde(default)]
    pub background_work: BackgroundWorkConfig,
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
    #[serde(default)]
    pub prewarm: PrewarmConfig,
    #[serde(default)]
    pub health: HealthConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub delegated_repositories: Vec<String>,
    #[serde(default)]
    pub repo_overrides: HashMap<String, RepoOverride>,
}

impl Config {
    pub fn repository_is_delegated(&self, owner_repo: &str) -> bool {
        let canonical = crate::repo_identity::canonicalize_owner_repo(owner_repo);
        self.delegated_repositories
            .iter()
            .any(|entry| crate::repo_identity::canonicalize_owner_repo(entry) == canonical)
    }
}

// ---------------------------------------------------------------------------
// Background work
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct BackgroundWorkConfig {
    /// Defer lower-priority cache/index/bundle work when the host is busy.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Defer background work while clone streams are active.
    #[serde(default = "default_true")]
    pub defer_when_active_clones: bool,
    /// Defer background work when the 100ms sampled CPU busy fraction is at or
    /// above this value. Set to `0.0` to disable CPU-busy sampling.
    #[serde(default = "default_background_cpu_busy_100ms_high_watermark")]
    pub cpu_busy_100ms_high_watermark: f64,
    /// Defer background work when one-minute load divided by the cgroup-aware
    /// CPU budget is at or above this value. Set to `0.0` to disable load checks.
    #[serde(default = "default_background_load_1m_per_cpu_high_watermark")]
    pub load_1m_per_cpu_high_watermark: f64,
    /// Seconds between retries while lower-priority work is deferred.
    #[serde(default = "default_background_work_retry_interval_secs")]
    pub retry_interval_secs: u64,
    /// Maximum number of pressure deferrals before abandoning one background
    /// task attempt.
    #[serde(default = "default_background_work_max_defer_retries")]
    pub max_defer_retries: u32,
    /// Maximum wall-clock seconds one background task attempt may remain
    /// deferred before it is abandoned.
    #[serde(default = "default_background_work_max_defer_secs")]
    pub max_defer_secs: u64,
}

impl Default for BackgroundWorkConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            defer_when_active_clones: default_true(),
            cpu_busy_100ms_high_watermark: default_background_cpu_busy_100ms_high_watermark(),
            load_1m_per_cpu_high_watermark: default_background_load_1m_per_cpu_high_watermark(),
            retry_interval_secs: default_background_work_retry_interval_secs(),
            max_defer_retries: default_background_work_max_defer_retries(),
            max_defer_secs: default_background_work_max_defer_secs(),
        }
    }
}

fn default_background_cpu_busy_100ms_high_watermark() -> f64 {
    0.80
}

fn default_background_load_1m_per_cpu_high_watermark() -> f64 {
    0.80
}

fn default_background_work_retry_interval_secs() -> u64 {
    60
}

fn default_background_work_max_defer_retries() -> u32 {
    10
}

fn default_background_work_max_defer_secs() -> u64 {
    30 * 60
}

// ---------------------------------------------------------------------------
// Config reload
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ConfigReloadConfig {
    /// Periodically re-read the config file and publish compatible changes to
    /// request handlers without restarting the process.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Maximum delay, in seconds, before a changed on-disk config is observed.
    #[serde(default = "default_config_reload_interval_secs")]
    pub interval_secs: u64,
}

impl Default for ConfigReloadConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            interval_secs: default_config_reload_interval_secs(),
        }
    }
}

fn default_config_reload_interval_secs() -> u64 {
    60
}

// ---------------------------------------------------------------------------
// Pre-warm
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PrewarmConfig {
    /// Best-effort initialize selected repositories during startup before
    /// `/readyz` reports ready.
    #[serde(default)]
    pub enabled: bool,
    /// Canonical `owner/repo` repository names to pre-warm on this instance.
    #[serde(default)]
    pub repos: Vec<String>,
    /// Maximum repositories to pre-warm concurrently.
    #[serde(default = "default_prewarm_max_concurrent")]
    pub max_concurrent: usize,
    /// Upper bound on how long startup pre-warm is allowed to hold `/readyz`
    /// closed before readiness force-opens and `/healthz` reports degradation.
    #[serde(default = "default_prewarm_force_open_secs")]
    pub force_open_secs: u64,
}

impl Default for PrewarmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            repos: Vec::new(),
            max_concurrent: default_prewarm_max_concurrent(),
            force_open_secs: default_prewarm_force_open_secs(),
        }
    }
}

fn default_prewarm_max_concurrent() -> usize {
    2
}

fn default_prewarm_force_open_secs() -> u64 {
    1500
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HealthConfig {
    /// Per-check timeout for `/healthz` and `/readyz` probe checks.
    #[serde(default = "default_health_check_timeout_secs")]
    pub check_timeout_secs: u64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            check_timeout_secs: default_health_check_timeout_secs(),
        }
    }
}

fn default_health_check_timeout_secs() -> u64 {
    5
}

// ---------------------------------------------------------------------------
// Observability
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub logs: LogSignalConfig,
    #[serde(default)]
    pub traces: TraceConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct MetricsConfig {
    #[serde(default)]
    pub prometheus: PrometheusConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct LogSignalConfig {
    #[serde(default)]
    pub journald: JournaldLogConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OrgCredential {
    pub mode: CredentialMode,
    /// Key name stored in the Linux kernel keyring (`linux-keyutils`).
    pub keyring_key_name: String,
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ProxyConfig {
    /// Socket address for the SSH listener (e.g. `0.0.0.0:2222`).
    pub ssh_listen: String,
    /// Socket address for the HTTP listener (e.g. `0.0.0.0:8443`).
    pub http_listen: String,
}

// ---------------------------------------------------------------------------
// Valkey / Redis
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Deserialize)]
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
    /// Request path: maximum concurrent local `git upload-pack` subprocesses
    /// on this instance. This bounds pack-objects CPU even when many requests
    /// are served from warm local disk.
    #[serde(default = "default_max_concurrent_local_upload_packs")]
    pub max_concurrent_local_upload_packs: usize,
    /// Request path: maximum concurrent local `git upload-pack` subprocesses
    /// for a single repository on this instance.
    #[serde(default = "default_max_concurrent_local_upload_packs_per_repo")]
    pub max_concurrent_local_upload_packs_per_repo: usize,
    /// Request path: number of worker threads local `git upload-pack`
    /// subprocesses may use for pack generation.
    ///
    /// Forgeproxy applies this as `git -c pack.threads=<n> upload-pack` so
    /// upload-pack's internal `pack-objects` child inherits the setting.
    #[serde(default = "default_local_upload_pack_threads")]
    pub local_upload_pack_threads: usize,
    /// Request-adjacent CPU: number of worker threads allowed for local
    /// `git index-pack` subprocesses.
    ///
    /// Tee imports and pack-cache indexing can be triggered by client traffic
    /// and run while clients are active. `index-pack` otherwise auto-scales to
    /// many cores on large packs, which can starve live upload-pack work on
    /// busy instances.
    #[serde(default = "default_index_pack_threads")]
    pub index_pack_threads: usize,
    /// Maximum concurrent background deep validations (`git fsck
    /// --connectivity-only`) that may run on this instance.
    #[serde(default = "default_max_concurrent_deep_validations")]
    pub max_concurrent_deep_validations: usize,
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
    /// Request path: coarse maximum time a client request may spend waiting on
    /// forgeproxy-local work before it proxies upstream. Zero disables the
    /// coarse budget.
    #[serde(default)]
    pub global_short_circuit_upstream_secs: u64,
    /// Maximum time a client request should wait for a local mirror catch-up
    /// publish before falling back to proxying upstream.
    #[serde(default = "default_request_wait_for_local_catch_up_secs")]
    pub request_wait_for_local_catch_up_secs: u64,
    /// Request path: maximum time a client request should wait when a same-repo
    /// request-time catch-up is actively running. This longer deadline prevents
    /// a slow-but-useful delta fetch from causing a herd of full upstream
    /// fallbacks that can saturate disk and starve local hydration.
    #[serde(default = "default_request_wait_for_active_local_catch_up_secs")]
    pub request_wait_for_active_local_catch_up_secs: u64,
    /// Request path: maximum time the client waits for request-triggered S3
    /// restore work before proxying upstream. The restore continues in the
    /// background. Zero disables this stage-specific budget.
    #[serde(default)]
    pub request_time_s3_restore_secs: u64,
    /// Request path: maximum time the client waits for request-triggered
    /// generation publication before proxying upstream. Publication continues
    /// in the background. Zero disables this stage-specific budget.
    #[serde(default)]
    pub generation_publish_secs: u64,
    /// Request path: maximum time the client waits for the first byte from a
    /// local git upload-pack subprocess before proxying upstream. Zero disables
    /// this stage-specific budget.
    #[serde(default)]
    pub local_upload_pack_first_byte_secs: u64,
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
            local_upload_pack_threads: default_local_upload_pack_threads(),
            index_pack_threads: default_index_pack_threads(),
            max_concurrent_deep_validations: default_max_concurrent_deep_validations(),
            hydration_mode: HydrationMode::default(),
            prepare_published_generation_indexes: false,
            generation_coalescing_window_secs: 0,
            global_short_circuit_upstream_secs: 0,
            request_wait_for_local_catch_up_secs: default_request_wait_for_local_catch_up_secs(),
            request_wait_for_active_local_catch_up_secs:
                default_request_wait_for_active_local_catch_up_secs(),
            request_time_s3_restore_secs: 0,
            generation_publish_secs: 0,
            local_upload_pack_first_byte_secs: 0,
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

fn default_request_wait_for_active_local_catch_up_secs() -> u64 {
    360
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

fn default_index_pack_threads() -> usize {
    DEFAULT_INDEX_PACK_THREADS
}

fn default_max_concurrent_deep_validations() -> usize {
    1
}

fn default_local_upload_pack_threads() -> usize {
    DEFAULT_INDEX_PACK_THREADS
}

// ---------------------------------------------------------------------------
// Adaptive fetch schedule
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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
    /// Number of Git pack worker threads to use for bundle generation,
    /// background bitmap/MIDX preparation, and pack-cache composite deltas.
    ///
    /// When unset, forgeproxy derives a value from the host's CPU count and
    /// the resolved bundle-generation concurrency so the total pack thread
    /// budget stays roughly within the machine's parallelism.
    ///
    /// Request path: request-time pack-cache composite delta generation also
    /// uses this thread budget, so this is not only a background bundle knob.
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

#[derive(Debug, Clone, PartialEq, Deserialize)]
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
    /// Request path: maximum time a client waits for an on-demand pack-cache
    /// composite attempt before proxying upstream. The composite work continues
    /// in the background. Zero disables this stage-specific budget.
    #[serde(default)]
    pub on_demand_composite_total_secs: u64,
    /// Request path: maximum time a client waits for request-time delta
    /// pack-objects during on-demand composite construction. The composite work
    /// continues in the background. Zero disables this stage-specific budget.
    #[serde(default)]
    pub request_delta_pack_secs: u64,
    /// Maximum request-time composite delta packs that may be built in parallel.
    ///
    /// These foreground builds intentionally do not share the background bundle
    /// generation semaphore, so cache-miss clones do not queue behind proactive
    /// warming or index preparation.
    #[serde(default = "default_pack_cache_max_concurrent_request_deltas")]
    pub max_concurrent_request_deltas: usize,
    /// Maximum background pack-cache warm/composite delta packs that may be
    /// built in parallel.
    ///
    /// These background builds intentionally do not share the bitmap/MIDX
    /// generation semaphore, so pack-cache warming and index preparation do not
    /// block each other.
    #[serde(default = "default_pack_cache_max_concurrent_background_warmings")]
    pub max_concurrent_background_warmings: usize,
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
            on_demand_composite_total_secs: 0,
            request_delta_pack_secs: 0,
            max_concurrent_request_deltas: default_pack_cache_max_concurrent_request_deltas(),
            max_concurrent_background_warmings:
                default_pack_cache_max_concurrent_background_warmings(),
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

fn default_pack_cache_max_concurrent_request_deltas() -> usize {
    1
}

fn default_pack_cache_max_concurrent_background_warmings() -> usize {
    1
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

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct StorageConfig {
    pub local: LocalStorageConfig,
    pub s3: S3StorageConfig,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RepoOverride {
    /// Override fetch interval (seconds) for this repo.
    pub fetch_interval: Option<u64>,
    /// Force-disable bundle generation for this repo.
    pub disable_bundles: Option<bool>,
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigSchemaNode {
    Root,
    BackgroundWork,
    ConfigReload,
    Upstream,
    UpstreamCredentials,
    OrgCredential,
    Proxy,
    Valkey,
    Auth,
    Clone,
    FetchSchedule,
    Bundles,
    PackCache,
    Prewarm,
    Health,
    Storage,
    LocalStorage,
    S3Storage,
    Observability,
    Metrics,
    Prometheus,
    LogSignal,
    Journald,
    Trace,
    Logging,
    RepoOverride,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigSchemaChild {
    None,
    Object(ConfigSchemaNode),
    DynamicObjectValues(ConfigSchemaNode),
}

fn schema_allowed_fields(node: ConfigSchemaNode) -> &'static [&'static str] {
    match node {
        ConfigSchemaNode::Root => &[
            "config_reload",
            "background_work",
            "upstream",
            "backend_type",
            "upstream_credentials",
            "proxy",
            "valkey",
            "auth",
            "clone",
            "fetch_schedule",
            "bundles",
            "pack_cache",
            "prewarm",
            "health",
            "storage",
            "observability",
            "logging",
            "delegated_repositories",
            "repo_overrides",
        ],
        ConfigSchemaNode::BackgroundWork => &[
            "enabled",
            "defer_when_active_clones",
            "cpu_busy_100ms_high_watermark",
            "load_1m_per_cpu_high_watermark",
            "retry_interval_secs",
            "max_defer_retries",
            "max_defer_secs",
        ],
        ConfigSchemaNode::ConfigReload => &["enabled", "interval_secs"],
        ConfigSchemaNode::Upstream => &[
            "hostname",
            "api_url",
            "git_url_base",
            "admin_token_env",
            "api_rate_limit_buffer",
            "log_secret_unmask_chars",
            "key_lookup_url",
        ],
        ConfigSchemaNode::UpstreamCredentials => &["default_mode", "orgs"],
        ConfigSchemaNode::OrgCredential => &["mode", "keyring_key_name"],
        ConfigSchemaNode::Proxy => &["ssh_listen", "http_listen"],
        ConfigSchemaNode::Valkey => &["endpoint", "tls", "ca_cert_file", "auth_token_env"],
        ConfigSchemaNode::Auth => &[
            "ssh_cache_ttl",
            "http_cache_ttl",
            "negative_cache_ttl",
            "webhook_secret_env",
        ],
        ConfigSchemaNode::Clone => &[
            "lock_ttl",
            "lock_wait_timeout",
            "max_concurrent_upstream_clones",
            "max_concurrent_upstream_fetches",
            "reserved_request_time_upstream_fetches",
            "max_concurrent_tee_captures",
            "max_concurrent_tee_captures_per_repo_per_instance",
            "max_concurrent_upstream_clones_per_repo_across_instances",
            "max_concurrent_upstream_clones_per_repo_per_instance",
            "max_concurrent_local_upload_packs",
            "max_concurrent_local_upload_packs_per_repo",
            "local_upload_pack_threads",
            "index_pack_threads",
            "max_concurrent_deep_validations",
            "hydration_mode",
            "prepare_published_generation_indexes",
            "generation_coalescing_window_secs",
            "global_short_circuit_upstream_secs",
            "request_wait_for_local_catch_up_secs",
            "request_wait_for_active_local_catch_up_secs",
            "request_time_s3_restore_secs",
            "generation_publish_secs",
            "local_upload_pack_first_byte_secs",
            "tee_cleanup_interval_secs",
            "tee_retention_secs",
            "ssh_upload_pack_close_grace_secs",
        ],
        ConfigSchemaNode::FetchSchedule => &[
            "default_interval",
            "delta_threshold",
            "backoff_factor",
            "max_interval",
            "rolling_window",
        ],
        ConfigSchemaNode::Bundles => &[
            "min_clone_count_for_bundles",
            "bundle_lock_ttl",
            "max_concurrent_generations",
            "pack_threads",
            "generate_filtered_bundles",
            "max_incremental_bundles",
        ],
        ConfigSchemaNode::PackCache => &[
            "enabled",
            "max_percent",
            "high_water_mark",
            "low_water_mark",
            "eviction_policy",
            "wait_for_inflight_secs",
            "on_demand_composite_total_secs",
            "request_delta_pack_secs",
            "max_concurrent_request_deltas",
            "max_concurrent_background_warmings",
            "min_response_bytes",
        ],
        ConfigSchemaNode::Prewarm => &["enabled", "repos", "max_concurrent", "force_open_secs"],
        ConfigSchemaNode::Health => &["check_timeout_secs"],
        ConfigSchemaNode::Storage => &["local", "s3"],
        ConfigSchemaNode::LocalStorage => &[
            "path",
            "max_percent",
            "high_water_mark",
            "low_water_mark",
            "eviction_policy",
        ],
        ConfigSchemaNode::S3Storage => &[
            "bucket",
            "prefix",
            "region",
            "endpoint",
            "use_fips",
            "presigned_url_ttl",
        ],
        ConfigSchemaNode::Observability => &["metrics", "logs", "traces"],
        ConfigSchemaNode::Metrics => &["prometheus"],
        ConfigSchemaNode::Prometheus => &["enabled", "refresh_interval_secs"],
        ConfigSchemaNode::LogSignal => &["journald"],
        ConfigSchemaNode::Journald => &["enabled"],
        ConfigSchemaNode::Trace => &["enabled", "sample_ratio"],
        ConfigSchemaNode::Logging => &["level"],
        ConfigSchemaNode::RepoOverride => &["fetch_interval", "disable_bundles"],
    }
}

fn schema_child(node: ConfigSchemaNode, key: &str) -> ConfigSchemaChild {
    match (node, key) {
        (ConfigSchemaNode::Root, "config_reload") => {
            ConfigSchemaChild::Object(ConfigSchemaNode::ConfigReload)
        }
        (ConfigSchemaNode::Root, "background_work") => {
            ConfigSchemaChild::Object(ConfigSchemaNode::BackgroundWork)
        }
        (ConfigSchemaNode::Root, "upstream") => {
            ConfigSchemaChild::Object(ConfigSchemaNode::Upstream)
        }
        (ConfigSchemaNode::Root, "upstream_credentials") => {
            ConfigSchemaChild::Object(ConfigSchemaNode::UpstreamCredentials)
        }
        (ConfigSchemaNode::Root, "proxy") => ConfigSchemaChild::Object(ConfigSchemaNode::Proxy),
        (ConfigSchemaNode::Root, "valkey") => ConfigSchemaChild::Object(ConfigSchemaNode::Valkey),
        (ConfigSchemaNode::Root, "auth") => ConfigSchemaChild::Object(ConfigSchemaNode::Auth),
        (ConfigSchemaNode::Root, "clone") => ConfigSchemaChild::Object(ConfigSchemaNode::Clone),
        (ConfigSchemaNode::Root, "fetch_schedule") => {
            ConfigSchemaChild::Object(ConfigSchemaNode::FetchSchedule)
        }
        (ConfigSchemaNode::Root, "bundles") => ConfigSchemaChild::Object(ConfigSchemaNode::Bundles),
        (ConfigSchemaNode::Root, "pack_cache") => {
            ConfigSchemaChild::Object(ConfigSchemaNode::PackCache)
        }
        (ConfigSchemaNode::Root, "prewarm") => ConfigSchemaChild::Object(ConfigSchemaNode::Prewarm),
        (ConfigSchemaNode::Root, "health") => ConfigSchemaChild::Object(ConfigSchemaNode::Health),
        (ConfigSchemaNode::Root, "storage") => ConfigSchemaChild::Object(ConfigSchemaNode::Storage),
        (ConfigSchemaNode::Root, "observability") => {
            ConfigSchemaChild::Object(ConfigSchemaNode::Observability)
        }
        (ConfigSchemaNode::Root, "logging") => ConfigSchemaChild::Object(ConfigSchemaNode::Logging),
        (ConfigSchemaNode::Root, "repo_overrides") => {
            ConfigSchemaChild::DynamicObjectValues(ConfigSchemaNode::RepoOverride)
        }
        (ConfigSchemaNode::UpstreamCredentials, "orgs") => {
            ConfigSchemaChild::DynamicObjectValues(ConfigSchemaNode::OrgCredential)
        }
        (ConfigSchemaNode::Storage, "local") => {
            ConfigSchemaChild::Object(ConfigSchemaNode::LocalStorage)
        }
        (ConfigSchemaNode::Storage, "s3") => ConfigSchemaChild::Object(ConfigSchemaNode::S3Storage),
        (ConfigSchemaNode::Observability, "metrics") => {
            ConfigSchemaChild::Object(ConfigSchemaNode::Metrics)
        }
        (ConfigSchemaNode::Observability, "logs") => {
            ConfigSchemaChild::Object(ConfigSchemaNode::LogSignal)
        }
        (ConfigSchemaNode::Observability, "traces") => {
            ConfigSchemaChild::Object(ConfigSchemaNode::Trace)
        }
        (ConfigSchemaNode::Metrics, "prometheus") => {
            ConfigSchemaChild::Object(ConfigSchemaNode::Prometheus)
        }
        (ConfigSchemaNode::LogSignal, "journald") => {
            ConfigSchemaChild::Object(ConfigSchemaNode::Journald)
        }
        _ => ConfigSchemaChild::None,
    }
}

fn collect_unknown_config_fields(value: &serde_yml::Value) -> Vec<String> {
    fn visit_object(
        value: &serde_yml::Value,
        node: ConfigSchemaNode,
        path: &mut Vec<String>,
        warnings: &mut Vec<String>,
    ) {
        let serde_yml::Value::Mapping(mapping) = value else {
            return;
        };

        let allowed = schema_allowed_fields(node);
        for (raw_key, child_value) in mapping {
            let Some(key) = raw_key.as_str() else {
                continue;
            };
            path.push(key.to_string());

            if !allowed.contains(&key) {
                warnings.push(format!("unknown config field `{}`", path.join(".")));
                path.pop();
                continue;
            }

            match schema_child(node, key) {
                ConfigSchemaChild::None => {}
                ConfigSchemaChild::Object(child_node) => {
                    visit_object(child_value, child_node, path, warnings);
                }
                ConfigSchemaChild::DynamicObjectValues(child_node) => {
                    if let serde_yml::Value::Mapping(entries) = child_value {
                        for (raw_entry_key, entry_value) in entries {
                            let Some(entry_key) = raw_entry_key.as_str() else {
                                continue;
                            };
                            path.push(entry_key.to_string());
                            visit_object(entry_value, child_node, path, warnings);
                            path.pop();
                        }
                    }
                }
            }

            path.pop();
        }
    }

    let mut warnings = Vec::new();
    let mut path = Vec::new();
    visit_object(value, ConfigSchemaNode::Root, &mut path, &mut warnings);
    warnings
}

pub(crate) fn parse_config_str_with_warnings(contents: &str) -> Result<(Config, Vec<String>)> {
    let config_value: serde_yml::Value = serde_yml::from_str(contents)?;
    let warnings = collect_unknown_config_fields(&config_value);
    let config: Config = serde_yml::from_str(contents)?;
    validate_config(&config)?;
    Ok((config, warnings))
}

pub(crate) fn parse_config_str(contents: &str) -> Result<Config> {
    let (config, warnings) = parse_config_str_with_warnings(contents)?;
    for warning in warnings {
        eprintln!("forgeproxy: warning: {warning}");
    }
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

/// Load and validate a [`Config`] while also returning the exact file contents
/// that produced it. The reload loop keeps this content fingerprint so
/// metadata-only filesystem changes do not churn the live config handle.
pub fn load_config_with_contents<P: AsRef<Path>>(path: P) -> Result<(Config, String)> {
    let path = path.as_ref();
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;
    let config = parse_config_str(&contents)
        .with_context(|| format!("failed to parse config file: {}", path.display()))?;
    Ok((config, contents))
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
        config.background_work.cpu_busy_100ms_high_watermark >= 0.0
            && config.background_work.cpu_busy_100ms_high_watermark <= 1.0,
        "background_work.cpu_busy_100ms_high_watermark must be in range [0.0, 1.0]"
    );
    anyhow::ensure!(
        config.background_work.load_1m_per_cpu_high_watermark >= 0.0
            && config.background_work.load_1m_per_cpu_high_watermark <= 1.0,
        "background_work.load_1m_per_cpu_high_watermark must be in range [0.0, 1.0]"
    );
    anyhow::ensure!(
        config.background_work.retry_interval_secs > 0,
        "background_work.retry_interval_secs must be greater than 0"
    );
    anyhow::ensure!(
        config.background_work.max_defer_retries > 0,
        "background_work.max_defer_retries must be greater than 0"
    );
    anyhow::ensure!(
        config.background_work.max_defer_secs > 0,
        "background_work.max_defer_secs must be greater than 0"
    );
    anyhow::ensure!(
        config.health.check_timeout_secs > 0,
        "health.check_timeout_secs must be greater than 0"
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
        config.clone.local_upload_pack_threads > 0,
        "clone.local_upload_pack_threads must be greater than 0"
    );
    anyhow::ensure!(
        config.clone.index_pack_threads > 0,
        "clone.index_pack_threads must be greater than 0"
    );
    anyhow::ensure!(
        config.clone.max_concurrent_deep_validations > 0,
        "clone.max_concurrent_deep_validations must be greater than 0"
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
        config.pack_cache.max_concurrent_request_deltas > 0,
        "pack_cache.max_concurrent_request_deltas must be greater than 0"
    );
    anyhow::ensure!(
        config.pack_cache.max_concurrent_background_warmings > 0,
        "pack_cache.max_concurrent_background_warmings must be greater than 0"
    );
    anyhow::ensure!(
        config.prewarm.max_concurrent > 0,
        "prewarm.max_concurrent must be greater than 0"
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
    anyhow::ensure!(
        config.config_reload.interval_secs > 0,
        "config_reload.interval_secs must be greater than 0"
    );
    for repo in &config.delegated_repositories {
        let canonical = crate::repo_identity::canonicalize_owner_repo(repo);
        let Some((owner, repo_name)) = canonical.split_once('/') else {
            anyhow::bail!("delegated_repositories entries must use owner/repo form: {repo:?}");
        };
        anyhow::ensure!(
            !owner.is_empty()
                && !repo_name.is_empty()
                && !canonical.contains("..")
                && !canonical.contains('\0'),
            "delegated_repositories entries must be valid owner/repo slugs: {repo:?}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{BackendType, BundleConfig, parse_config_str, parse_config_str_with_warnings};

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
        let config = parse_config_str(include_str!("../../config.example.yaml")).unwrap();
        assert_eq!(
            config.clone.request_wait_for_active_local_catch_up_secs,
            360
        );
        assert!(config.config_reload.enabled);
        assert_eq!(config.config_reload.interval_secs, 60);
        assert!(config.background_work.enabled);
        assert!(config.background_work.defer_when_active_clones);
        assert_eq!(config.background_work.cpu_busy_100ms_high_watermark, 0.80);
        assert_eq!(config.background_work.load_1m_per_cpu_high_watermark, 0.80);
        assert_eq!(config.background_work.retry_interval_secs, 60);
        assert_eq!(config.background_work.max_defer_retries, 10);
        assert_eq!(config.background_work.max_defer_secs, 1800);
        assert!(config.repository_is_delegated("org/problem-repo.git"));
    }

    #[test]
    fn rejects_invalid_delegated_repository_entries() {
        let config = include_str!("../../config.example.yaml")
            .replace("  - \"org/problem-repo\"\n", "  - \"problem-repo\"\n");
        assert!(parse_config_str(&config).is_err());
    }

    #[test]
    fn rejects_non_positive_config_reload_interval() {
        let config = include_str!("../../config.example.yaml").replace(
            "config_reload:\n  enabled: true\n  interval_secs: 60\n",
            "config_reload:\n  enabled: true\n  interval_secs: 0\n",
        );
        assert!(parse_config_str(&config).is_err());
    }

    #[test]
    fn rejects_background_work_thresholds_outside_unit_range() {
        let config = include_str!("../../config.example.yaml").replace(
            "  cpu_busy_100ms_high_watermark: 0.80\n",
            "  cpu_busy_100ms_high_watermark: 1.01\n",
        );
        assert!(parse_config_str(&config).is_err());

        let config = include_str!("../../config.example.yaml").replace(
            "  load_1m_per_cpu_high_watermark: 0.80\n",
            "  load_1m_per_cpu_high_watermark: -0.01\n",
        );
        assert!(parse_config_str(&config).is_err());
    }

    #[test]
    fn rejects_non_positive_background_work_retry_limits() {
        let config = include_str!("../../config.example.yaml")
            .replace("  retry_interval_secs: 60\n", "  retry_interval_secs: 0\n");
        assert!(parse_config_str(&config).is_err());

        let config = include_str!("../../config.example.yaml")
            .replace("  max_defer_retries: 10\n", "  max_defer_retries: 0\n");
        assert!(parse_config_str(&config).is_err());

        let config = include_str!("../../config.example.yaml")
            .replace("  max_defer_secs: 1800\n", "  max_defer_secs: 0\n");
        assert!(parse_config_str(&config).is_err());
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
    fn rejects_zero_pack_cache_request_delta_concurrency() {
        let config = include_str!("../../config.example.yaml").replace(
            "  max_concurrent_request_deltas: 1\n",
            "  max_concurrent_request_deltas: 0\n",
        );
        assert!(parse_config_str(&config).is_err());
    }

    #[test]
    fn rejects_zero_pack_cache_background_warming_concurrency() {
        let config = include_str!("../../config.example.yaml").replace(
            "  max_concurrent_background_warmings: 1\n",
            "  max_concurrent_background_warmings: 0\n",
        );
        assert!(parse_config_str(&config).is_err());
    }

    #[test]
    fn rejects_zero_index_pack_threads() {
        let config = include_str!("../../config.example.yaml")
            .replace("  index_pack_threads: 2\n", "  index_pack_threads: 0\n");
        assert!(parse_config_str(&config).is_err());
    }

    #[test]
    fn rejects_zero_local_upload_pack_threads() {
        let config = include_str!("../../config.example.yaml").replace(
            "  local_upload_pack_threads: 2\n",
            "  local_upload_pack_threads: 0\n",
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
    fn warns_on_extra_legacy_local_max_bytes_field() {
        let config = include_str!("../../config.example.yaml").replace(
            "    max_percent: 0.80\n",
            "    max_percent: 0.80\n    max_bytes: 536870912000\n",
        );
        let (_parsed, warnings) = parse_config_str_with_warnings(&config).unwrap();
        assert_eq!(
            warnings,
            vec!["unknown config field `storage.local.max_bytes`".to_string()]
        );
    }

    #[test]
    fn rejects_legacy_pack_cache_ttl() {
        let config = include_str!("../../config.example.yaml").replace(
            "  wait_for_inflight_secs: 120\n",
            "  ttl_secs: 900\n  wait_for_inflight_secs: 120\n",
        );
        let (_parsed, warnings) = parse_config_str_with_warnings(&config).unwrap();
        assert_eq!(
            warnings,
            vec!["unknown config field `pack_cache.ttl_secs`".to_string()]
        );
    }

    #[test]
    fn rejects_legacy_metrics_otlp_shape() {
        let config = include_str!("../../config.example.yaml").replace(
            "  metrics:\n    prometheus:\n      enabled: true\n",
            "  metrics:\n    prometheus:\n      enabled: true\n    otlp:\n      enabled: true\n      endpoint: \"https://ingest.metrics.foo.dev/vm/insert/0/opentelemetry/api/v1/push\"\n      protocol: \"http/protobuf\"\n      export_interval_secs: 60\n      auth:\n        basic:\n          username: \"foo\"\n          password: \"bar\"\n",
        );
        let (_parsed, warnings) = parse_config_str_with_warnings(&config).unwrap();
        assert_eq!(
            warnings,
            vec!["unknown config field `observability.metrics.otlp`".to_string()]
        );
    }

    #[test]
    fn rejects_legacy_observability_exporters_shape() {
        let config = include_str!("../../config.example.yaml").replace(
            "  traces:\n    enabled: false\n    sample_ratio: 1.0\n",
            "  traces:\n    enabled: false\n    sample_ratio: 1.0\n  exporters:\n    otlp:\n      metrics:\n        enabled: true\n        endpoint: \"https://ingest.metrics.foo.dev/vm/insert/0/opentelemetry/api/v1/push\"\n        protocol: \"http/protobuf\"\n        export_interval_secs: 60\n        auth:\n          basic:\n            username: \"foo\"\n            password: \"bar\"\n",
        );
        let (_parsed, warnings) = parse_config_str_with_warnings(&config).unwrap();
        assert_eq!(
            warnings,
            vec!["unknown config field `observability.exporters`".to_string()]
        );
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
        let (parsed, warnings) = parse_config_str_with_warnings(&config).unwrap();
        assert_eq!(
            warnings,
            vec![
                "unknown config field `clone.max_concurrent_ghe_clones`".to_string(),
                "unknown config field `clone.max_concurrent_ghe_fetches`".to_string(),
            ]
        );
        assert_eq!(
            parsed.clone.max_concurrent_upstream_clones,
            super::default_max_concurrent_upstream_clones()
        );
        assert_eq!(
            parsed.clone.max_concurrent_upstream_fetches,
            super::default_max_concurrent_upstream_fetches()
        );
    }

    #[test]
    fn warns_on_forward_compatible_unknown_fields() {
        let config = include_str!("../../config.example.yaml").replace(
            "prewarm:\n  enabled: false\n  repos: []\n  max_concurrent: 2\n",
            "prewarm:\n  enabled: false\n  repos: []\n  max_concurrent: 2\n  future_mode: \"best_effort\"\n",
        );
        let (_parsed, warnings) = parse_config_str_with_warnings(&config).unwrap();
        assert_eq!(
            warnings,
            vec!["unknown config field `prewarm.future_mode`".to_string()]
        );
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
