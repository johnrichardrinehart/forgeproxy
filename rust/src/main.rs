mod auth;
mod bundleuri;
mod cache;
mod config;
mod coordination;
mod credentials;
mod forge;
mod git;
mod health;
mod http;
mod metrics;
mod ssh;
mod storage;
mod tee_hydration;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use fred::clients::Pool;
use fred::interfaces::ClientLike;
use fred::types::config::{Config as FredConfig, ReconnectPolicy, ServerConfig, TlsConnector};
use tokio::signal;
use tokio::sync::Semaphore;
use tokio::time::MissedTickBehavior;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::Config;
use crate::metrics::MetricsRegistry;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "forgeproxy", about = "Git Caching Reverse Proxy")]
struct Cli {
    /// Path to the YAML configuration file.
    #[arg(short, long, default_value = "/run/forgeproxy/config.yaml")]
    config: String,

    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Subcommand, Debug)]
enum CliCommand {
    /// Validate on-disk cached repos and remove invalid local copies.
    ScrubCache,
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
    /// Forge-specific API backend (GitHub, GitLab, Gitea, etc.).
    pub forge: Arc<dyn forge::ForgeBackend>,
    /// Upstream API rate-limit state shared across all callers.
    pub rate_limit: forge::rate_limit::RateLimitState,
    /// Semaphore limiting concurrent full clones against upstream.
    pub clone_semaphore: Arc<Semaphore>,
    /// Semaphore limiting concurrent fetches against upstream.
    pub fetch_semaphore: Arc<Semaphore>,
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

    let s3_config = aws_sdk_s3::config::Builder::from(&aws_config)
        .force_path_style(true)
        .build();

    let client = aws_sdk_s3::Client::from_conf(s3_config);
    tracing::info!(
        bucket = %config.storage.s3.bucket,
        region = %config.storage.s3.region,
        fips = config.storage.s3.use_fips,
        "S3 client initialised"
    );
    Ok(client)
}

// ---------------------------------------------------------------------------
// HTTP server (axum)
// ---------------------------------------------------------------------------

async fn run_http_server(state: AppState) -> Result<()> {
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
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server error")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Background tasks
// ---------------------------------------------------------------------------

async fn run_ssh_server(state: AppState) -> Result<()> {
    crate::ssh::start_ssh_server(Arc::new(state)).await
}

async fn run_bundle_lifecycle(state: AppState) -> Result<()> {
    let state = Arc::new(state);
    let lifecycle_handle = tokio::spawn({
        let s = Arc::clone(&state);
        async move { bundleuri::lifecycle::run_bundle_lifecycle(s).await }
    });
    let daily_handle = tokio::spawn({
        let s = Arc::clone(&state);
        async move { bundleuri::lifecycle::run_daily_consolidation(s).await }
    });
    let weekly_handle = tokio::spawn({
        let s = Arc::clone(&state);
        async move { bundleuri::lifecycle::run_weekly_consolidation(s).await }
    });
    let _ = tokio::try_join!(lifecycle_handle, daily_handle, weekly_handle);
    Ok(())
}

async fn run_node_heartbeat(state: AppState) -> Result<()> {
    coordination::node::run_heartbeat(state.valkey.clone(), state.node_id.clone()).await;
    Ok(())
}

async fn scrub_cached_repos(state: &AppState) -> Result<()> {
    let repos = state.cache_manager.list_repo_dirs()?;
    let mut checked = 0usize;
    let mut removed = 0usize;

    for (owner_repo, repo_path) in repos {
        checked += 1;
        if !state.cache_manager.has_repo(&owner_repo) {
            warn!(
                repo = %owner_repo,
                path = %repo_path.display(),
                "removing invalid cached repo that failed the bare-repo usability check"
            );
            tokio::fs::remove_dir_all(&repo_path)
                .await
                .with_context(|| {
                    format!("failed to remove invalid repo at {}", repo_path.display())
                })?;
            let _ = coordination::registry::update_repo_field(
                &state.valkey,
                &owner_repo,
                "local_cached",
                "false",
            )
            .await;
            removed += 1;
            continue;
        }

        if let Err(error) = crate::git::commands::git_fsck_full(&repo_path).await {
            warn!(
                repo = %owner_repo,
                path = %repo_path.display(),
                error = %error,
                "removing invalid cached repo after full validation failure"
            );
            tokio::fs::remove_dir_all(&repo_path)
                .await
                .with_context(|| {
                    format!("failed to remove invalid repo at {}", repo_path.display())
                })?;
            let _ = coordination::registry::update_repo_field(
                &state.valkey,
                &owner_repo,
                "local_cached",
                "false",
            )
            .await;
            removed += 1;
        }
    }

    info!(checked, removed, "cache scrub completed");
    Ok(())
}

fn periodic_full_fsck_interval() -> Result<Option<Duration>> {
    let raw = match std::env::var("FORGEPROXY_PERIODIC_FULL_FSCK_INTERVAL_SECS") {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(error) => {
            return Err(anyhow::anyhow!(
                "failed reading FORGEPROXY_PERIODIC_FULL_FSCK_INTERVAL_SECS: {error}"
            ));
        }
    };

    if raw.trim().is_empty() {
        return Ok(None);
    }

    let secs: u64 = raw.parse().with_context(|| {
        format!("invalid FORGEPROXY_PERIODIC_FULL_FSCK_INTERVAL_SECS value: {raw}")
    })?;

    if secs == 0 {
        return Ok(None);
    }

    Ok(Some(Duration::from_secs(secs)))
}

async fn run_periodic_cache_scrubber(state: AppState, interval: Duration) -> Result<()> {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ticker.tick().await;

    loop {
        ticker.tick().await;
        if let Err(error) = scrub_cached_repos(&state).await {
            warn!(error = %error, "periodic cache scrub failed");
        }
    }
}

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------

async fn shutdown_signal() {
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

    // ---- Config ----
    let config = config::load_config(&cli.config)?;
    let config = Arc::new(config);

    // ---- Tracing ----
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    tracing::info!(config_path = %cli.config, "starting forgeproxy");
    let state = build_app_state(Arc::clone(&config)).await?;

    if matches!(cli.command, Some(CliCommand::ScrubCache)) {
        scrub_cached_repos(&state).await?;
        return Ok(());
    }

    // ---- Telemetry buffer ----
    let telemetry_buffer = cache::telemetry::TelemetryBuffer::new();
    let periodic_scrub_interval = periodic_full_fsck_interval()?;

    // ---- Spawn services ----
    let telemetry_handle = tokio::spawn({
        let s = Arc::new(state.clone());
        let buf = telemetry_buffer.clone();
        async move { cache::telemetry::run_telemetry_flusher(s, buf).await }
    });

    let http_handle = tokio::spawn({
        let s = state.clone();
        async move {
            if let Err(e) = run_http_server(s).await {
                tracing::error!(error = %e, "HTTP server failed");
            }
        }
    });

    let ssh_handle = tokio::spawn({
        let s = state.clone();
        async move {
            if let Err(e) = run_ssh_server(s).await {
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

    let heartbeat_handle = tokio::spawn({
        let s = state.clone();
        async move {
            if let Err(e) = run_node_heartbeat(s).await {
                tracing::error!(error = %e, "node heartbeat failed");
            }
        }
    });

    let scrub_handle = periodic_scrub_interval.map(|interval| {
        tokio::spawn({
            let s = state.clone();
            async move {
                if let Err(error) = run_periodic_cache_scrubber(s, interval).await {
                    tracing::error!(error = %error, "periodic cache scrubber failed");
                }
            }
        })
    });

    // ---- Await shutdown ----
    // Wait for a shutdown signal or for any task to exit unexpectedly.
    // On shutdown, abort all remaining tasks so the process exits promptly.
    let abort_handles = [
        http_handle.abort_handle(),
        ssh_handle.abort_handle(),
        bundle_handle.abort_handle(),
        heartbeat_handle.abort_handle(),
        telemetry_handle.abort_handle(),
    ];
    let mut abort_handles = abort_handles.to_vec();
    if let Some(handle) = &scrub_handle {
        abort_handles.push(handle.abort_handle());
    }
    tokio::select! {
        _ = shutdown_signal() => {
            for h in &abort_handles { h.abort(); }
        }
        _ = async {
            match scrub_handle {
                Some(scrub_handle) => {
                    let _ = tokio::try_join!(
                        http_handle,
                        ssh_handle,
                        bundle_handle,
                        heartbeat_handle,
                        telemetry_handle,
                        scrub_handle
                    );
                }
                None => {
                    let _ = tokio::try_join!(
                        http_handle,
                        ssh_handle,
                        bundle_handle,
                        heartbeat_handle,
                        telemetry_handle
                    );
                }
            }
        } => {}
    }

    tracing::info!("forgeproxy shut down cleanly");
    Ok(())
}

async fn build_app_state(config: Arc<Config>) -> Result<AppState> {
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
    let http_client = reqwest::Client::builder()
        .user_agent("forgeproxy/0.1")
        .build()
        .context("failed to build reqwest client")?;
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

    let rate_limit = forge::rate_limit::RateLimitState::new();

    Ok(AppState {
        config: Arc::clone(&config),
        valkey,
        s3_client: s3,
        metrics,
        http_client,
        cache_manager,
        node_id,
        forge,
        rate_limit,
        clone_semaphore: Arc::new(Semaphore::new(config.clone.max_concurrent_upstream_clones)),
        fetch_semaphore: Arc::new(Semaphore::new(config.clone.max_concurrent_upstream_fetches)),
    })
}
