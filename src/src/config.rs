use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub ghe: GheConfig,
    pub upstream_credentials: UpstreamCredentials,
    pub proxy: ProxyConfig,
    pub keydb: KeyDbConfig,
    pub auth: AuthConfig,
    pub clone: CloneConfig,
    pub fetch_schedule: FetchScheduleConfig,
    pub bundles: BundleConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub repo_overrides: HashMap<String, RepoOverride>,
}

// ---------------------------------------------------------------------------
// GHE
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct GheConfig {
    /// Hostname of the GHE appliance (e.g. `ghe.corp.example.com`).
    pub hostname: String,
    /// Full URL to the GHE API root (e.g. `https://ghe.corp.example.com/api/v3`).
    pub api_url: String,
    /// Name of the environment variable that holds the GHE admin PAT.
    #[serde(default = "default_admin_token_env")]
    pub admin_token_env: String,
    /// Minimum number of API calls to keep in reserve before self-throttling.
    #[serde(default = "default_api_rate_limit_buffer")]
    pub api_rate_limit_buffer: u32,
}

fn default_admin_token_env() -> String {
    "GHE_ADMIN_TOKEN".to_string()
}

fn default_api_rate_limit_buffer() -> u32 {
    100
}

// ---------------------------------------------------------------------------
// Upstream credentials
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
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
pub struct OrgCredential {
    pub mode: CredentialMode,
    /// Key name stored in the Linux kernel keyring (`linux-keyutils`).
    pub keyring_key_name: String,
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    /// Socket address for the SSH listener (e.g. `0.0.0.0:2222`).
    pub ssh_listen: String,
    /// Socket address for the HTTP listener (e.g. `0.0.0.0:8443`).
    pub http_listen: String,
    /// Public base URL served by the bundle-URI endpoint.
    pub bundle_uri_base_url: String,
}

// ---------------------------------------------------------------------------
// KeyDB / Redis
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct KeyDbConfig {
    /// Connection string (e.g. `rediss://keydb.local:6380`).
    pub endpoint: String,
    /// Enable TLS for the KeyDB connection.
    #[serde(default = "bool_true")]
    pub tls: bool,
    /// Name of the environment variable that holds the KeyDB auth token.
    #[serde(default = "default_keydb_auth_env")]
    pub auth_token_env: String,
}

fn bool_true() -> bool {
    true
}

fn default_keydb_auth_env() -> String {
    "KEYDB_AUTH_TOKEN".to_string()
}

// ---------------------------------------------------------------------------
// Auth cache TTLs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
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
    "GHE_WEBHOOK_SECRET".to_string()
}

// ---------------------------------------------------------------------------
// Clone behaviour
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct CloneConfig {
    /// Maximum age (seconds) of the local bare clone before a re-fetch is
    /// required to serve it.
    #[serde(default = "default_freshness_threshold")]
    pub freshness_threshold: u64,
    /// TTL (seconds) of the distributed clone/fetch lock in KeyDB.
    #[serde(default = "default_lock_ttl")]
    pub lock_ttl: u64,
    /// How long (seconds) a waiter will block for the lock before giving up.
    #[serde(default = "default_lock_wait_timeout")]
    pub lock_wait_timeout: u64,
    /// Semaphore limit for concurrent full clones against GHE.
    #[serde(default = "default_max_concurrent_ghe_clones")]
    pub max_concurrent_ghe_clones: usize,
    /// Semaphore limit for concurrent fetches against GHE.
    #[serde(default = "default_max_concurrent_ghe_fetches")]
    pub max_concurrent_ghe_fetches: usize,
}

fn default_freshness_threshold() -> u64 {
    600
}

fn default_lock_ttl() -> u64 {
    120
}

fn default_lock_wait_timeout() -> u64 {
    90
}

fn default_max_concurrent_ghe_clones() -> usize {
    4
}

fn default_max_concurrent_ghe_fetches() -> usize {
    8
}

// ---------------------------------------------------------------------------
// Adaptive fetch schedule
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
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
pub struct BundleConfig {
    /// Hour (0-23 UTC) at which the daily consolidation job runs.
    #[serde(default = "default_daily_hour")]
    pub daily_consolidation_hour: u8,
    /// ISO weekday (1 = Monday .. 7 = Sunday) for the weekly consolidation.
    #[serde(default = "default_weekly_day")]
    pub weekly_consolidation_day: u8,
    /// Minimum number of clones a repo must have received before bundles are
    /// generated for it.
    #[serde(default = "default_min_clone_count")]
    pub min_clone_count_for_bundles: u64,
    /// TTL (seconds) of the distributed bundle-generation lock.
    #[serde(default = "default_bundle_lock_ttl")]
    pub bundle_lock_ttl: u64,
    /// Whether to produce filtered (blobless / treeless) bundle variants.
    #[serde(default)]
    pub generate_filtered_bundles: bool,
}

fn default_daily_hour() -> u8 {
    3
}

fn default_weekly_day() -> u8 {
    7
}

fn default_min_clone_count() -> u64 {
    5
}

fn default_bundle_lock_ttl() -> u64 {
    600
}

// ---------------------------------------------------------------------------
// Storage (local + S3)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    pub local: LocalStorageConfig,
    pub s3: S3StorageConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LocalStorageConfig {
    /// Root directory for bare repos and bundles.
    pub path: String,
    /// Hard ceiling for local cache usage in bytes.
    pub max_bytes: u64,
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
pub struct S3StorageConfig {
    pub bucket: String,
    #[serde(default = "default_s3_prefix")]
    pub prefix: String,
    pub region: String,
    /// Use the FIPS endpoints for S3 operations.
    #[serde(default)]
    pub use_fips: bool,
    /// TTL (seconds) for pre-signed download URLs.
    #[serde(default = "default_presigned_url_ttl")]
    pub presigned_url_ttl: u64,
}

fn default_s3_prefix() -> String {
    "gheproxy/".to_string()
}

fn default_presigned_url_ttl() -> u64 {
    3600
}

// ---------------------------------------------------------------------------
// Per-repo overrides
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct RepoOverride {
    /// Override fetch interval (seconds) for this repo.
    pub fetch_interval: Option<u64>,
    /// Override freshness threshold (seconds) for this repo.
    pub freshness_threshold: Option<u64>,
    /// Force-disable bundle generation for this repo.
    pub disable_bundles: Option<bool>,
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

/// Load and validate a [`Config`] from a YAML file at `path`.
pub fn load_config<P: AsRef<Path>>(path: P) -> Result<Config> {
    let path = path.as_ref();
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;
    let config: Config = serde_yaml::from_str(&contents)
        .with_context(|| format!("failed to parse config file: {}", path.display()))?;
    validate_config(&config)?;
    Ok(config)
}

/// Basic sanity checks that cannot be expressed purely with serde.
fn validate_config(config: &Config) -> Result<()> {
    anyhow::ensure!(
        config.storage.local.high_water_mark > config.storage.local.low_water_mark,
        "high_water_mark must be greater than low_water_mark"
    );
    anyhow::ensure!(
        config.storage.local.high_water_mark <= 1.0 && config.storage.local.low_water_mark >= 0.0,
        "water marks must be in range [0.0, 1.0]"
    );
    anyhow::ensure!(
        config.bundles.daily_consolidation_hour < 24,
        "daily_consolidation_hour must be 0-23"
    );
    anyhow::ensure!(
        (1..=7).contains(&config.bundles.weekly_consolidation_day),
        "weekly_consolidation_day must be 1-7"
    );
    Ok(())
}
