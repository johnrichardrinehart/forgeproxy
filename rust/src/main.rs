mod auth;
mod build_info;
mod bundleuri;
mod cache;
mod clone_support;
mod config;
mod coordination;
mod credentials;
mod forge;
mod git;
mod health;
mod http;
mod metrics;
mod runtime_resource;
mod ssh;
mod storage;
mod tee_hydration;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use fred::clients::Pool;
use fred::interfaces::ClientLike;
use fred::interfaces::KeysInterface;
use fred::types::config::{Config as FredConfig, ReconnectPolicy, ServerConfig, TlsConnector};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use tokio::signal;
use tokio::sync::{Mutex, Semaphore, watch};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::Config;
use crate::metrics::{ActiveConnectionGuard, MetricsRegistry, Protocol};
use crate::runtime_resource::RuntimeResourceAttributes;

const CLONE_CAPTURE_MEMORY_HEADROOM_BYTES: u64 = 1024 * 1024 * 1024;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "forgeproxy",
    about = "Git Caching Reverse Proxy",
    version = crate::build_info::VERSION,
    long_version = crate::build_info::LONG_VERSION
)]
struct Cli {
    /// Path to the YAML configuration file.
    #[arg(short, long, default_value = "/run/forgeproxy/config.yaml")]
    config: String,

    #[arg(
        long,
        hide = true,
        default_value = "/run/forgeproxy/runtime-resource-attributes.json"
    )]
    runtime_resource_file: String,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run bundle lifecycle work on demand without waiting for the scheduler.
    #[cfg(feature = "dev")]
    Bundle {
        /// Suppress the final one-shot summary log.
        #[arg(long)]
        no_summary: bool,
    },
    #[command(name = "write-runtime-resource-attributes", hide = true)]
    WriteRuntimeResourceAttributes {
        #[arg(long)]
        output: String,
    },
}

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

/// Global state shared across all request handlers and background tasks.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub valkey: Pool,
    pub s3_client: aws_sdk_s3::Client,
    pub metrics: MetricsRegistry,
    pub http_client: reqwest::Client,
    pub cache_manager: cache::CacheManager,
    pub node_id: String,
    pub runtime_resource_attributes: RuntimeResourceAttributes,
    pub bundle_publisher_id: String,
    /// Forge-specific API backend (GitHub, GitLab, Gitea, etc.).
    pub forge: Arc<dyn forge::ForgeBackend>,
    /// Upstream API rate-limit state shared across all callers.
    pub rate_limit: forge::rate_limit::RateLimitState,
    /// Semaphore limiting concurrent full clones against upstream.
    pub clone_semaphore: Arc<Semaphore>,
    /// Semaphore limiting concurrent fetches against upstream.
    pub fetch_semaphore: Arc<Semaphore>,
    /// Semaphore limiting concurrent CPU-heavy bundle-generation subprocesses.
    pub bundle_generation_semaphore: Arc<Semaphore>,
    /// Resolved maximum number of repos to process concurrently during the
    /// bundle lifecycle tick.
    pub bundle_max_concurrency: usize,
    /// Resolved `git pack-objects` thread budget per bundle generation.
    pub bundle_pack_threads: usize,
    /// Per-repo local semaphore cache limiting concurrent hydrations for the
    /// same repository within this instance.
    pub repo_clone_semaphores: Arc<Mutex<std::collections::HashMap<String, Arc<Semaphore>>>>,
    /// Per-repo local mutex cache serializing publish/prune and immediate
    /// generation mutation work while allowing clone/fetch hydration to run
    /// concurrently up to the configured per-repo limits.
    pub repo_publish_mutexes: Arc<Mutex<std::collections::HashMap<String, Arc<Mutex<()>>>>>,
    /// Per-repo refcounts for published reader generations currently in use by
    /// local clone/fetch handlers on this node.
    pub published_generation_leases: Arc<
        std::sync::Mutex<
            std::collections::HashMap<String, std::collections::HashMap<std::path::PathBuf, usize>>,
        >,
    >,
    /// Most recent advertised ref metadata we proxied for a repo. HTTP clones
    /// do not give us a stable request-scoped handle across the advertisement
    /// and fetch POST, so we keep a short-lived in-memory copy.
    pub recent_advertised_refs: Arc<Mutex<std::collections::HashMap<String, RecentAdvertisedRefs>>>,
    pub active_https_connections: Arc<AtomicI64>,
    pub active_ssh_connections: Arc<AtomicI64>,
    pub draining: Arc<AtomicBool>,
}

#[derive(Clone)]
pub struct RecentAdvertisedRefs {
    pub captured_at: Instant,
    pub session_id: String,
    pub advertised_refs: crate::coordination::registry::RequestAdvertisedRefs,
}

impl AppState {
    pub fn begin_active_connection(&self, protocol: Protocol) -> ActiveConnectionGuard {
        let counter = match protocol {
            Protocol::Https => Arc::clone(&self.active_https_connections),
            Protocol::Ssh => Arc::clone(&self.active_ssh_connections),
        };
        ActiveConnectionGuard::new(self.metrics.clone(), protocol, counter)
    }

    pub fn start_draining(&self) {
        self.draining.store(true, Ordering::SeqCst);
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    pub fn refresh_live_metrics(&self) {
        if let Ok(size_bytes) = self.cache_manager.total_size_bytes() {
            crate::metrics::set_cache_size_bytes(&self.metrics, size_bytes);
        }
        if let Ok(repos) = self.cache_manager.list_repos() {
            crate::metrics::set_cache_repos_total(&self.metrics, repos.len());
        }
        crate::metrics::set_upstream_api_rate_limit_remaining(
            &self.metrics,
            self.rate_limit.remaining(),
        );
    }

    pub async fn remember_recent_advertised_refs(
        &self,
        owner_repo: impl Into<String>,
        client_fingerprint: impl AsRef<str>,
        session_id: impl Into<String>,
        advertised_refs: crate::coordination::registry::RequestAdvertisedRefs,
    ) {
        self.recent_advertised_refs.lock().await.insert(
            format!("{}|{}", owner_repo.into(), client_fingerprint.as_ref()),
            RecentAdvertisedRefs {
                captured_at: Instant::now(),
                session_id: session_id.into(),
                advertised_refs,
            },
        );
    }

    pub async fn recent_advertised_refs(
        &self,
        owner_repo: &str,
        client_fingerprint: &str,
    ) -> Option<RecentAdvertisedRefs> {
        self.recent_advertised_refs
            .lock()
            .await
            .get(&format!("{owner_repo}|{client_fingerprint}"))
            .and_then(|recent_advertised_refs| {
                if recent_advertised_refs.captured_at.elapsed() > Duration::from_secs(60) {
                    None
                } else {
                    Some(recent_advertised_refs.clone())
                }
            })
    }
}

// ---------------------------------------------------------------------------
// Valkey pool setup
// ---------------------------------------------------------------------------

async fn build_valkey_pool(config: &Config) -> Result<Pool> {
    let auth_token =
        crate::credentials::keyring::resolve_secret(&config.valkey.auth_token_env).await;

    let endpoint = config
        .valkey
        .endpoint
        .trim_start_matches("rediss://")
        .trim_start_matches("redis://");
    let (host, port) = coordination::redis::parse_host_port(endpoint)?;
    let server_config = ServerConfig::new_centralized(host, port);

    let mut fred_config = FredConfig {
        server: server_config,
        ..FredConfig::default()
    };

    if config.valkey.tls {
        let mut root_store = rustls::RootCertStore::empty();

        // Load native system root certificates.
        for cert in rustls_native_certs::load_native_certs().certs {
            root_store.add(cert).ok();
        }

        // Load an additional CA cert (e.g. self-signed Valkey CA) if configured.
        if let Some(ref path) = config.valkey.ca_cert_file {
            let pem = std::fs::read(path)
                .with_context(|| format!("failed to read CA cert file: {path}"))?;
            let certs = rustls_pemfile::certs(&mut pem.as_slice())
                .collect::<Result<Vec<_>, _>>()
                .with_context(|| format!("failed to parse PEM certs from: {path}"))?;
            for cert in certs {
                root_store
                    .add(cert)
                    .with_context(|| format!("failed to add CA cert from: {path}"))?;
            }
        }

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        fred_config.tls = Some(TlsConnector::from(tls_config).into());
    }

    if let Some(ref token) = auth_token {
        fred_config.password = Some(token.clone());
    }

    let mut builder = fred::types::Builder::from_config(fred_config);
    builder.set_policy(ReconnectPolicy::new_exponential(0, 100, 30_000, 2));

    let pool = builder.build_pool(3)?;
    pool.init().await.context("failed to connect to Valkey")?;

    tracing::info!("Valkey pool initialised");
    Ok(pool)
}

// ---------------------------------------------------------------------------
// S3 client setup
// ---------------------------------------------------------------------------

async fn build_s3_client(config: &Config) -> Result<aws_sdk_s3::Client> {
    let mut aws_config_loader =
        aws_config::from_env().region(aws_config::Region::new(config.storage.s3.region.clone()));

    if config.storage.s3.use_fips {
        aws_config_loader = aws_config_loader.use_fips(true);
    }

    let aws_config = aws_config_loader.load().await;

    let mut s3_config = aws_sdk_s3::config::Builder::from(&aws_config).force_path_style(true);

    if let Some(endpoint) = &config.storage.s3.endpoint {
        s3_config = s3_config.endpoint_url(endpoint);
    }

    let s3_config = s3_config.build();

    let client = aws_sdk_s3::Client::from_conf(s3_config);
    tracing::info!(
        bucket = %config.storage.s3.bucket,
        region = %config.storage.s3.region,
        endpoint = config
            .storage
            .s3
            .endpoint
            .as_deref()
            .unwrap_or("unprovided endpoint value - using AWS SDK default"),
        fips = config.storage.s3.use_fips,
        "S3 client initialised"
    );
    Ok(client)
}

fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent("forgeproxy/0.1")
        .build()
        .context("failed to build reqwest client")
}

fn format_error_chain(error: &anyhow::Error) -> String {
    error
        .chain()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

fn join_s3_key(prefix: &str, suffix: &str) -> String {
    if prefix.is_empty() {
        suffix.to_string()
    } else if prefix.ends_with('/') {
        format!("{prefix}{suffix}")
    } else {
        format!("{prefix}/{suffix}")
    }
}

fn detect_mem_available_bytes() -> Result<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").context("read /proc/meminfo")?;
    let available_kib = meminfo
        .lines()
        .find_map(|line| {
            let value = line.strip_prefix("MemAvailable:")?.trim();
            let amount = value.split_whitespace().next()?.parse::<u64>().ok()?;
            Some(amount)
        })
        .context("MemAvailable not found in /proc/meminfo")?;
    Ok(available_kib * 1024)
}

fn resolve_clone_concurrency_limit(config: &Config) -> usize {
    let configured = config.clone.max_concurrent_upstream_clones;
    let available_bytes = match detect_mem_available_bytes() {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(
                error = %error,
                configured,
                "failed to detect available memory; using configured clone concurrency"
            );
            return configured;
        }
    };

    let memory_budget = available_bytes.saturating_sub(CLONE_CAPTURE_MEMORY_HEADROOM_BYTES);
    let memory_limited =
        (memory_budget / crate::tee_hydration::CAPTURE_BUFFER_BYTES as u64) as usize;
    let resolved = if configured == 0 {
        0
    } else {
        configured.min(memory_limited.max(1))
    };

    tracing::info!(
        configured,
        available_bytes,
        memory_headroom_bytes = CLONE_CAPTURE_MEMORY_HEADROOM_BYTES,
        capture_buffer_bytes = crate::tee_hydration::CAPTURE_BUFFER_BYTES,
        memory_limited,
        resolved,
        "resolved clone concurrency limit from startup memory snapshot"
    );

    if configured > 0 && memory_limited == 0 {
        tracing::warn!(
            configured,
            available_bytes,
            "startup memory budget cannot satisfy the requested 1 GiB tee-capture headroom; allowing a single clone hydration permit so cache miss hydration still works"
        );
    }

    if resolved == 0 {
        tracing::warn!(
            configured,
            available_bytes,
            "startup memory budget leaves no room for buffered tee hydration; upstream clone hydration will be disabled until restart"
        );
    }

    resolved
}

async fn probe_valkey(config: &Config) -> Result<()> {
    let pool = build_valkey_pool(config).await?;
    let _: String = ClientLike::ping::<String>(&pool, None)
        .await
        .context("Valkey PING probe failed")?;

    let key = format!("forgeproxy:init:{}", uuid::Uuid::new_v4());
    let _: () = pool
        .set(
            &key,
            "ok",
            Some(fred::types::Expiration::EX(30)),
            None,
            false,
        )
        .await
        .context("Valkey SET probe failed")?;
    let _: () = pool.del(&key).await.context("Valkey DEL probe failed")?;

    Ok(())
}

async fn probe_s3(config: &Config) -> Result<()> {
    let client = build_s3_client(config).await?;
    let key = join_s3_key(
        &config.storage.s3.prefix,
        &format!("init/{}.txt", uuid::Uuid::new_v4()),
    );

    client
        .put_object()
        .bucket(&config.storage.s3.bucket)
        .key(&key)
        .body(aws_sdk_s3::primitives::ByteStream::from_static(
            b"forgeproxy-startup-init",
        ))
        .send()
        .await
        .context("S3 PutObject startup probe failed")?;

    client
        .delete_object()
        .bucket(&config.storage.s3.bucket)
        .key(&key)
        .send()
        .await
        .context("S3 DeleteObject startup probe failed")?;

    Ok(())
}

async fn probe_upstream(config: &Config) -> Result<()> {
    let http_client = build_http_client()?;
    let forge = forge::build_backend(config);
    let rate_limit = forge::rate_limit::RateLimitState::new();
    forge
        .startup_probe(&http_client, &rate_limit)
        .await
        .context("upstream startup probe failed")
}

async fn run_startup_init(config: &Config) -> usize {
    tracing::info!(
        backend = ?config.backend_type,
        bucket = %config.storage.s3.bucket,
        valkey_endpoint = %config.valkey.endpoint,
        upstream_api_url = %config.upstream.api_url,
        "starting startup dependency init probes"
    );

    let (valkey_result, upstream_result, s3_result) = tokio::join!(
        probe_valkey(config),
        probe_upstream(config),
        probe_s3(config),
    );

    let mut error_count = 0usize;

    match valkey_result {
        Ok(()) => tracing::info!("startup init probe succeeded for Valkey"),
        Err(error) => {
            error_count += 1;
            tracing::error!(
                error = %error,
                error_chain = %format_error_chain(&error),
                "startup init probe failed for Valkey"
            );
        }
    }

    match upstream_result {
        Ok(()) => tracing::info!("startup init probe succeeded for upstream"),
        Err(error) => {
            error_count += 1;
            tracing::error!(
                error = %error,
                error_chain = %format_error_chain(&error),
                "startup init probe failed for upstream"
            );
        }
    }

    match s3_result {
        Ok(()) => tracing::info!("startup init probe succeeded for S3"),
        Err(error) => {
            error_count += 1;
            tracing::error!(
                error = %error,
                error_chain = %format_error_chain(&error),
                "startup init probe failed for S3"
            );
        }
    }

    if error_count == 0 {
        tracing::info!("startup dependency init probes completed successfully");
    } else {
        tracing::error!(
            error_count,
            exit_code = error_count.min(u8::MAX as usize),
            "startup dependency init probes failed"
        );
    }

    error_count
}

// ---------------------------------------------------------------------------
// HTTP server (axum)
// ---------------------------------------------------------------------------

async fn run_http_server(state: AppState, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
    let app = http::handler::create_router(Arc::new(state.clone()));

    let listen_addr: std::net::SocketAddr = state
        .config
        .proxy
        .http_listen
        .parse()
        .context("invalid http_listen address")?;

    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind HTTP listener on {listen_addr}"))?;

    tracing::info!(%listen_addr, "HTTP server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            if *shutdown_rx.borrow() {
                tracing::info!("HTTP listener received drain signal before serving");
                return;
            }
            while shutdown_rx.changed().await.is_ok() {
                if *shutdown_rx.borrow() {
                    tracing::info!("HTTP listener entering graceful shutdown");
                    break;
                }
            }
        })
        .await
        .context("HTTP server error")?;

    tracing::info!("HTTP server exited cleanly");
    Ok(())
}

// ---------------------------------------------------------------------------
// Background tasks
// ---------------------------------------------------------------------------

async fn run_ssh_server(state: AppState, shutdown_rx: watch::Receiver<bool>) -> Result<()> {
    crate::ssh::start_ssh_server(Arc::new(state), shutdown_rx).await
}

async fn run_bundle_lifecycle(state: AppState) -> Result<()> {
    let state = Arc::new(state);
    let lifecycle_handle =
        tokio::spawn(async move { bundleuri::lifecycle::run_bundle_lifecycle(state).await });
    let _ = lifecycle_handle.await;
    Ok(())
}

async fn run_node_heartbeat(state: AppState) -> Result<()> {
    coordination::node::run_heartbeat(state.valkey.clone(), state.node_id.clone()).await;
    Ok(())
}

#[cfg(feature = "dev")]
async fn run_dev_command(state: AppState, command: Command) -> Result<()> {
    match command {
        Command::Bundle { no_summary } => {
            let started_at = Instant::now();
            tracing::info!("running dev bundle command");
            let summary = crate::bundleuri::lifecycle::tick_with_summary(&state).await?;
            if !no_summary {
                tracing::info!(
                    elapsed_secs = started_at.elapsed().as_secs_f64(),
                    repos_scanned = summary.repos_scanned,
                    repos_completed = summary.repos_completed,
                    skipped_not_due = summary.skipped_not_due,
                    skipped_below_min_clone_count = summary.skipped_below_min_clone_count,
                    skipped_lock_held = summary.skipped_lock_held,
                    skipped_not_cached = summary.skipped_not_cached,
                    fetch_succeeded = summary.fetch_succeeded,
                    fetch_failed = summary.fetch_failed,
                    bundles_generated = summary.bundles_generated,
                    bundle_generation_failed = summary.bundle_generation_failed,
                    bundle_upload_failed = summary.bundle_upload_failed,
                    filtered_bundles_generated = summary.filtered_bundles_generated,
                    filtered_bundle_upload_failed = summary.filtered_bundle_upload_failed,
                    repos_published = summary.repos_published,
                    repo_errors = summary.repo_errors,
                    "dev bundle command summary"
                );
            }
            Ok(())
        }
        Command::WriteRuntimeResourceAttributes { .. } => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------

async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => tracing::info!("received SIGINT"),
        () = terminate => tracing::info!("received SIGTERM"),
    }
}

fn build_tracing_filter(config: &Config) -> EnvFilter {
    EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(config.logging.level.clone()))
        .unwrap_or_else(|_| EnvFilter::new("info"))
}

const LOCAL_OTLP_TRACE_COLLECTOR_ENDPOINT: &str = "http://127.0.0.1:4317";
const READYZ_DRAIN_OBSERVATION_WINDOW: Duration = Duration::from_secs(1);

fn build_trace_provider(
    config: &Config,
    runtime_resource_attributes: &RuntimeResourceAttributes,
) -> Result<Option<SdkTracerProvider>> {
    if !config.observability.traces.enabled {
        return Ok(None);
    }

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(LOCAL_OTLP_TRACE_COLLECTOR_ENDPOINT)
        .build()?;

    let sampler = match config.observability.traces.sample_ratio {
        ratio if ratio <= 0.0 => Sampler::AlwaysOff,
        ratio if ratio >= 1.0 => Sampler::AlwaysOn,
        ratio => Sampler::TraceIdRatioBased(ratio),
    };
    let resource = Resource::builder_empty()
        .with_attributes(runtime_resource_attributes.to_otel_resource_attributes())
        .build();

    Ok(Some(
        SdkTracerProvider::builder()
            .with_sampler(sampler)
            .with_resource(resource)
            .with_batch_exporter(exporter)
            .build(),
    ))
}

fn init_tracing(
    config: &Config,
    runtime_resource_attributes: &RuntimeResourceAttributes,
) -> Result<Option<SdkTracerProvider>> {
    let trace_provider = build_trace_provider(config, runtime_resource_attributes)?;
    let otel_layer = trace_provider
        .as_ref()
        .map(|provider| tracing_opentelemetry::layer().with_tracer(provider.tracer("forgeproxy")));

    tracing_subscriber::registry()
        .with(build_tracing_filter(config))
        .with(tracing_subscriber::fmt::layer().json())
        .with(otel_layer)
        .init();

    Ok(trace_provider)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    // ---- TLS crypto provider (must be installed before any rustls usage) ----
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls CryptoProvider");

    // ---- CLI ----
    let cli = Cli::parse();

    if let Some(Command::WriteRuntimeResourceAttributes { output }) = &cli.command {
        let detection = crate::runtime_resource::write_runtime_resource_attributes_file(
            std::path::Path::new(output),
            crate::build_info::VERSION,
        )
        .await?;
        for warning in detection.warnings {
            eprintln!("forgeproxy: warning: {warning}");
        }
        return Ok(());
    }

    // ---- Config ----
    let loaded_config = config::load_config(&cli.config)?;
    let ignored_config_fields = loaded_config.ignored_fields.clone();
    let config = Arc::new(loaded_config.config);
    let runtime_resource_detection =
        crate::runtime_resource::load_or_detect_runtime_resource_attributes(
            std::path::Path::new(&cli.runtime_resource_file),
            crate::build_info::VERSION,
        )
        .await;

    // ---- Tracing ----
    let trace_provider = init_tracing(config.as_ref(), &runtime_resource_detection.attributes)?;

    for ignored_field in &ignored_config_fields {
        tracing::warn!(
            config_path = %cli.config,
            ignored_field = %ignored_field,
            "unknown config field ignored during startup"
        );
    }
    for warning in &runtime_resource_detection.warnings {
        tracing::warn!(
            runtime_resource_file = %cli.runtime_resource_file,
            warning = %warning,
            "runtime resource detection warning"
        );
    }

    tracing::info!(
        config_path = %cli.config,
        version = crate::build_info::VERSION,
        git_revision = crate::build_info::GIT_REVISION,
        service_instance_id = runtime_resource_detection
            .attributes
            .service_instance_id
            .as_deref()
            .unwrap_or("unknown"),
        service_ip_address = runtime_resource_detection
            .attributes
            .service_ip_address
            .as_deref()
            .unwrap_or("unknown"),
        service_machine_id = runtime_resource_detection
            .attributes
            .service_machine_id
            .as_deref()
            .unwrap_or("unknown"),
        cloud_provider = runtime_resource_detection
            .attributes
            .cloud_provider
            .as_deref()
            .unwrap_or("unknown"),
        cloud_region = runtime_resource_detection
            .attributes
            .cloud_region
            .as_deref()
            .unwrap_or("unknown"),
        "starting forgeproxy"
    );

    #[cfg(feature = "dev")]
    if let Some(Command::Bundle { no_summary }) = cli.command {
        let state = build_app_state(
            Arc::clone(&config),
            runtime_resource_detection.attributes.clone(),
        )
        .await?;
        return run_dev_command(state, Command::Bundle { no_summary }).await;
    }

    let startup_init_errors = run_startup_init(config.as_ref()).await;
    if startup_init_errors > 0 {
        std::process::exit(startup_init_errors.min(u8::MAX as usize) as i32);
    }

    let state = build_app_state(
        Arc::clone(&config),
        runtime_resource_detection.attributes.clone(),
    )
    .await?;
    let (http_shutdown_tx, http_shutdown_rx) = watch::channel(false);
    let (ssh_shutdown_tx, ssh_shutdown_rx) = watch::channel(false);

    // ---- Telemetry buffer ----
    let telemetry_buffer = cache::telemetry::TelemetryBuffer::new();

    // ---- Spawn services ----
    let telemetry_handle = tokio::spawn({
        let s = Arc::new(state.clone());
        let buf = telemetry_buffer.clone();
        async move { cache::telemetry::run_telemetry_flusher(s, buf).await }
    });

    let http_handle = tokio::spawn({
        let s = state.clone();
        let shutdown_rx = http_shutdown_rx.clone();
        async move {
            if let Err(e) = run_http_server(s, shutdown_rx).await {
                tracing::error!(error = %e, "HTTP server failed");
            }
        }
    });

    let ssh_handle = tokio::spawn({
        let s = state.clone();
        let shutdown_rx = ssh_shutdown_rx.clone();
        async move {
            if let Err(e) = run_ssh_server(s, shutdown_rx).await {
                tracing::error!(error = %e, "SSH server failed");
            }
        }
    });

    let bundle_handle = tokio::spawn({
        let s = state.clone();
        async move {
            if let Err(e) = run_bundle_lifecycle(s).await {
                tracing::error!(error = %e, "bundle lifecycle scheduler failed");
            }
        }
    });

    let tee_cleanup_handle = tokio::spawn({
        let base_path = state.cache_manager.base_path.clone();
        let interval = std::time::Duration::from_secs(state.config.clone.tee_cleanup_interval_secs);
        let retention = std::time::Duration::from_secs(state.config.clone.tee_retention_secs);
        async move {
            if let Err(e) =
                crate::tee_hydration::run_tee_cleanup_loop(base_path, interval, retention).await
            {
                tracing::error!(error = %e, "tee cleanup janitor failed");
            }
        }
    });

    let heartbeat_handle = tokio::spawn({
        let s = state.clone();
        async move {
            if let Err(e) = run_node_heartbeat(s).await {
                tracing::error!(error = %e, "node heartbeat failed");
            }
        }
    });

    // ---- Await shutdown ----
    // Wait for a shutdown signal or for any task to exit unexpectedly.
    // On shutdown, abort all remaining tasks so the process exits promptly.
    let abort_handles = [
        bundle_handle.abort_handle(),
        tee_cleanup_handle.abort_handle(),
        heartbeat_handle.abort_handle(),
        telemetry_handle.abort_handle(),
    ];
    let abort_handles = abort_handles.to_vec();
    tokio::pin!(
        http_handle,
        ssh_handle,
        bundle_handle,
        tee_cleanup_handle,
        heartbeat_handle,
        telemetry_handle
    );
    tokio::select! {
        _ = wait_for_shutdown_signal() => {
            tracing::info!("forgeproxy entering drain mode");
            state.start_draining();
            let _ = ssh_shutdown_tx.send(true);
            tracing::info!(
                active_https_connections = state.active_https_connections.load(Ordering::SeqCst),
                active_ssh_connections = state.active_ssh_connections.load(Ordering::SeqCst),
                "drain signal broadcast to listeners"
            );
            for h in &abort_handles { h.abort(); }
            tracing::info!("awaiting SSH server drain completion");
            let _ = (&mut ssh_handle).await;
            tracing::info!("SSH server drain completed");
            tracing::info!(
                readyz_hold_secs = READYZ_DRAIN_OBSERVATION_WINDOW.as_secs_f64(),
                "holding HTTP listener in draining state before shutdown so readiness probes can observe /readyz=503"
            );
            tokio::time::sleep(READYZ_DRAIN_OBSERVATION_WINDOW).await;
            tracing::info!("signaling HTTP listener shutdown after request drain");
            let _ = http_shutdown_tx.send(true);
            tracing::info!("awaiting HTTP server drain completion");
            let _ = (&mut http_handle).await;
            tracing::info!("HTTP server drain completed");
        }
        _ = async {
            let _ = tokio::try_join!(
                &mut http_handle,
                &mut ssh_handle,
                &mut bundle_handle,
                &mut heartbeat_handle,
                &mut telemetry_handle
            );
        } => {
            for h in &abort_handles { h.abort(); }
        }
    }

    tracing::info!("forgeproxy shut down cleanly");
    if let Some(trace_provider) = trace_provider
        && let Err(error) = trace_provider.shutdown()
    {
        eprintln!("failed to shut down OTLP trace exporter cleanly: {error}");
    }
    Ok(())
}

async fn build_app_state(
    config: Arc<Config>,
    runtime_resource_attributes: RuntimeResourceAttributes,
) -> Result<AppState> {
    tokio::fs::create_dir_all(&config.storage.local.path)
        .await
        .with_context(|| {
            format!(
                "failed to create local cache dir: {}",
                config.storage.local.path
            )
        })?;

    let valkey = build_valkey_pool(&config).await?;
    let s3 = build_s3_client(&config).await?;
    let http_client = build_http_client()?;
    let metrics = MetricsRegistry::new();
    let cache_manager = cache::CacheManager::new(&config.storage.local);
    let node_id = coordination::node::node_id();
    tracing::info!(%node_id, "node identity established");

    let forge: Arc<dyn forge::ForgeBackend> = Arc::from(forge::build_backend(&config));
    tracing::info!(backend = ?config.backend_type, "forge backend initialised");

    if matches!(config.backend_type, crate::config::BackendType::Github) {
        tracing::warn!(
            backend = ?config.backend_type,
            "SSH key resolution is not supported with cloud/SaaS forge backends — \
             SSH authentication will not work. Use HTTP token authentication instead."
        );
    }

    let rate_limit = forge::rate_limit::RateLimitState::with_metrics(metrics.clone());
    let clone_concurrency_limit = resolve_clone_concurrency_limit(&config);
    let bundle_execution_policy = config.bundles.execution_policy();
    tracing::info!(
        max_concurrent_generations = bundle_execution_policy.max_concurrent_generations,
        pack_threads = bundle_execution_policy.pack_threads,
        "resolved bundle execution policy"
    );

    let bundle_publisher_id = runtime_resource_attributes
        .service_instance_id
        .clone()
        .or_else(|| runtime_resource_attributes.service_machine_id.clone())
        .unwrap_or_else(|| node_id.clone());

    let state = AppState {
        config: Arc::clone(&config),
        valkey,
        s3_client: s3,
        metrics,
        http_client,
        cache_manager,
        node_id,
        runtime_resource_attributes,
        bundle_publisher_id,
        forge,
        rate_limit,
        clone_semaphore: Arc::new(Semaphore::new(clone_concurrency_limit)),
        fetch_semaphore: Arc::new(Semaphore::new(config.clone.max_concurrent_upstream_fetches)),
        bundle_generation_semaphore: Arc::new(Semaphore::new(
            bundle_execution_policy.max_concurrent_generations,
        )),
        bundle_max_concurrency: bundle_execution_policy.max_concurrent_generations,
        bundle_pack_threads: bundle_execution_policy.pack_threads,
        repo_clone_semaphores: Arc::new(Mutex::new(std::collections::HashMap::new())),
        repo_publish_mutexes: Arc::new(Mutex::new(std::collections::HashMap::new())),
        published_generation_leases: Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
        recent_advertised_refs: Arc::new(Mutex::new(std::collections::HashMap::new())),
        active_https_connections: Arc::new(AtomicI64::new(0)),
        active_ssh_connections: Arc::new(AtomicI64::new(0)),
        draining: Arc::new(AtomicBool::new(false)),
    };
    state.refresh_live_metrics();
    Ok(state)
}
