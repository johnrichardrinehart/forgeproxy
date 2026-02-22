//! SSH server bootstrap and the [`russh::server::Server`] implementation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use russh::MethodSet;
use russh::server::{self, Server};
use russh_keys::key::KeyPair;
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
fn load_or_generate_host_key() -> KeyPair {
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
            KeyPair::generate_ed25519()
        }
    }
}

/// Try to read a PEM-encoded private key stored in the user keyring under
/// the well-known description `forgeproxy:ssh_host_key`.
fn load_host_key_from_keyring() -> Result<KeyPair> {
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

    russh_keys::decode_secret_key(pem, None)
        .context("failed to decode SSH host key from keyring payload")
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Start the SSH listener.  This function runs until the server is shut down
/// or an unrecoverable error occurs.
pub async fn start_ssh_server(state: Arc<AppState>) -> Result<()> {
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
        methods: MethodSet::PUBLICKEY,
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

    let mut ssh_server = SshServer::new(state);
    ssh_server
        .run_on_address(config, listen_addr)
        .await
        .context("SSH server exited with error")?;

    Ok(())
}
