// Many modules expose pub API surfaces (e.g. coordination, bundleuri, git,
// storage, credentials) whose functions are wired up incrementally.  Allow
// dead_code crate-wide until the full call graph is connected.
#![allow(dead_code)]

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

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use fred::clients::Pool;
use fred::interfaces::ClientLike;
use fred::types::config::{Config as FredConfig, ReconnectPolicy, ServerConfig, TlsConnector};
use tokio::signal;
use tokio::sync::Semaphore;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::metrics::MetricsRegistry;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "forgecache", about = "Git Caching Reverse Proxy")]
struct Cli {
    /// Path to the YAML configuration file.
    #[arg(short, long, default_value = "/etc/forgecache/config.yaml")]
    config: String,
}

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

/// Global state shared across all request handlers and background tasks.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub keydb: Pool,
    pub s3_client: aws_sdk_s3::Client,
    pub metrics: MetricsRegistry,
    pub http_client: reqwest::Client,
    pub cache_manager: cache::CacheManager,
    pub node_id: String,
    /// Forge-specific API backend (GitHub, GitLab, Gitea, etc.).
    pub forge: Arc<dyn forge::ForgeBackend>,
    /// Semaphore limiting concurrent full clones against upstream.
    pub clone_semaphore: Arc<Semaphore>,
    /// Semaphore limiting concurrent fetches against upstream.
    pub fetch_semaphore: Arc<Semaphore>,
}

// ---------------------------------------------------------------------------
// KeyDB pool setup
// ---------------------------------------------------------------------------

async fn build_keydb_pool(config: &Config) -> Result<Pool> {
    let auth_token = std::env::var(&config.keydb.auth_token_env).ok();

    let endpoint = config
        .keydb
        .endpoint
        .trim_start_matches("rediss://")
        .trim_start_matches("redis://");
    let (host, port) = coordination::redis::parse_host_port(endpoint)?;
    let server_config = ServerConfig::new_centralized(host, port);

    let mut fred_config = FredConfig {
        server: server_config,
        ..FredConfig::default()
    };

    if config.keydb.tls {
        fred_config.tls = Some(TlsConnector::default_rustls()?.into());
    }

    if let Some(ref token) = auth_token {
        fred_config.password = Some(token.clone());
    }

    let mut builder = fred::types::Builder::from_config(fred_config);
    builder.set_policy(ReconnectPolicy::new_exponential(0, 100, 30_000, 2));

    let pool = builder.build_pool(3)?;
    pool.init().await.context("failed to connect to KeyDB")?;

    tracing::info!("KeyDB pool initialised");
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
// Background tasks (stubs)
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
    coordination::node::run_heartbeat(state.keydb.clone(), state.node_id.clone()).await;
    Ok(())
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

    tracing::info!(config_path = %cli.config, "starting forgecache");

    // ---- Ensure local cache directory exists ----
    tokio::fs::create_dir_all(&config.storage.local.path)
        .await
        .with_context(|| {
            format!(
                "failed to create local cache dir: {}",
                config.storage.local.path
            )
        })?;

    // ---- Infrastructure clients ----
    let keydb = build_keydb_pool(&config).await?;
    let s3 = build_s3_client(&config).await?;

    let http_client = reqwest::Client::builder()
        .user_agent("forgecache/0.1")
        .build()
        .context("failed to build reqwest client")?;

    // ---- Metrics ----
    let metrics = MetricsRegistry::new();

    // ---- Cache manager ----
    let cache_manager = cache::CacheManager::new(&config.storage.local);

    // ---- Node ID ----
    let node_id = coordination::node::node_id();
    tracing::info!(%node_id, "node identity established");

    // ---- Forge backend ----
    let forge: Arc<dyn forge::ForgeBackend> = Arc::from(forge::build_backend(&config));
    tracing::info!(backend = ?config.backend_type, "forge backend initialised");

    // ---- App state ----
    let state = AppState {
        config: Arc::clone(&config),
        keydb,
        s3_client: s3,
        metrics,
        http_client,
        cache_manager,
        node_id,
        forge,
        clone_semaphore: Arc::new(Semaphore::new(config.clone.max_concurrent_upstream_clones)),
        fetch_semaphore: Arc::new(Semaphore::new(config.clone.max_concurrent_upstream_fetches)),
    };

    // ---- Spawn services ----
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

    // ---- Await shutdown ----
    // We wait for ALL tasks; when the shutdown signal fires each task will
    // see it through its own `shutdown_signal()` future and wind down.
    let _ = tokio::try_join!(http_handle, ssh_handle, bundle_handle, heartbeat_handle);

    tracing::info!("forgecache shut down cleanly");
    Ok(())
}
