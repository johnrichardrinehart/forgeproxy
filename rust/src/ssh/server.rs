//! SSH server bootstrap and the [`russh::server::Server`] implementation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use russh::keys::ssh_key::rand_core::OsRng;
use russh::keys::{self, Algorithm, PrivateKey};
use russh::server::{self, Server};
use russh::{MethodKind, MethodSet};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{info, warn};

use super::session::SshSession;
use crate::AppState;

// ---------------------------------------------------------------------------
// Server type
// ---------------------------------------------------------------------------

/// Top-level SSH server that hands off each incoming connection to an
/// [`SshSession`] handler.
pub struct SshServer {
    state: Arc<AppState>,
}

impl SshServer {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

impl server::Server for SshServer {
    type Handler = SshSession;

    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> Self::Handler {
        info!(
            peer = ?peer_addr,
            "new SSH client connection",
        );
        SshSession::new(Arc::clone(&self.state), peer_addr)
    }
}

// ---------------------------------------------------------------------------
// Server key loading
// ---------------------------------------------------------------------------

/// Attempt to load the SSH host key from the Linux kernel keyring.  Falls back
/// to generating an ephemeral Ed25519 key if the keyring entry is absent.
fn load_or_generate_host_key() -> PrivateKey {
    // Try the kernel keyring first.
    match load_host_key_from_keyring() {
        Ok(kp) => {
            info!("loaded SSH host key from kernel keyring");
            kp
        }
        Err(e) => {
            warn!(
                error = %e,
                "failed to load SSH host key from kernel keyring; generating ephemeral Ed25519 key",
            );
            PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
                .expect("failed to generate ephemeral Ed25519 host key")
        }
    }
}

/// Try to read a PEM-encoded private key stored in the user keyring under
/// the well-known description `forgeproxy:ssh_host_key`.
fn load_host_key_from_keyring() -> Result<PrivateKey> {
    use linux_keyutils::{KeyRing, KeyRingIdentifier};

    let ring = KeyRing::from_special_id(KeyRingIdentifier::User, false)
        .map_err(|e| anyhow::anyhow!("failed to open user keyring: {e:?}"))?;

    let key = ring
        .search("forgeproxy:ssh_host_key")
        .map_err(|e| anyhow::anyhow!("SSH host key not found in kernel keyring: {e:?}"))?;

    let buf = key
        .read_to_vec()
        .map_err(|e| anyhow::anyhow!("failed to read SSH host key payload from keyring: {e:?}"))?;

    let pem = std::str::from_utf8(&buf).context("SSH host key payload is not valid UTF-8")?;

    keys::decode_secret_key(pem, None).context("failed to decode SSH host key from keyring payload")
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Start the SSH listener.  This function runs until the server is shut down
/// or an unrecoverable error occurs.
pub async fn start_ssh_server(
    state: Arc<AppState>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let listen_addr: SocketAddr = state.config.proxy.ssh_listen.parse().with_context(|| {
        format!(
            "invalid SSH listen address: {:?}",
            state.config.proxy.ssh_listen
        )
    })?;

    // -- Build russh server config ----------------------------------------

    let host_key = load_or_generate_host_key();

    let config = Arc::new(server::Config {
        keys: vec![host_key],
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        // Preferred algorithms -- FIPS-aligned choices where available.
        preferred: russh::Preferred::DEFAULT,
        inactivity_timeout: Some(Duration::from_secs(600)),
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        max_auth_attempts: 3,
        ..Default::default()
    });

    // -- Start serving ----------------------------------------------------

    info!(address = %listen_addr, "starting SSH server");

    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind SSH listener on {listen_addr}"))?;
    let (error_tx, mut error_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut ssh_server = SshServer::new(Arc::clone(&state));

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    info!("SSH listener entering drain mode");
                    break;
                }
            }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((socket, _)) => {
                        if state.is_draining() {
                            info!(
                                peer = ?socket.peer_addr().ok(),
                                "rejecting new SSH connection because forgeproxy is draining"
                            );
                            drop(socket);
                            continue;
                        }
                        let config = Arc::clone(&config);
                        let handler = ssh_server.new_client(socket.peer_addr().ok());
                        let error_tx = error_tx.clone();
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            info!(
                                active_ssh_connections = state.active_ssh_connections.load(std::sync::atomic::Ordering::SeqCst),
                                "spawned SSH session task"
                            );
                            let session = match russh::server::run_stream(config, socket, handler).await {
                                Ok(session) => session,
                                Err(error) => {
                                    let _ = error_tx.send(error);
                                    return;
                                }
                            };
                            if let Err(error) = session.await {
                                let _ = error_tx.send(error);
                            }
                            info!(
                                active_ssh_connections = state.active_ssh_connections.load(std::sync::atomic::Ordering::SeqCst),
                                "SSH session task completed"
                            );
                        });
                    }
                    Err(error) => return Err(error).context("SSH accept loop failed"),
                }
            }
            Some(error) = error_rx.recv() => {
                ssh_server.handle_session_error(error);
            }
        }
    }

    info!("waiting for active SSH sessions to finish");
    let mut wait_logged_at = std::time::Instant::now();
    while state
        .active_ssh_connections
        .load(std::sync::atomic::Ordering::SeqCst)
        > 0
    {
        if wait_logged_at.elapsed() >= Duration::from_secs(1) {
            info!(
                active_ssh_connections = state
                    .active_ssh_connections
                    .load(std::sync::atomic::Ordering::SeqCst),
                "still waiting for active SSH sessions to finish"
            );
            wait_logged_at = std::time::Instant::now();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    info!("all active SSH sessions drained");

    Ok(())
}
