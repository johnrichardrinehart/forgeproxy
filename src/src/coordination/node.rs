use std::time::Duration;

use anyhow::{Context, Result};
use fred::interfaces::{ClientLike, HashesInterface, KeysInterface};
use fred::types::CustomCommand;
use tracing::{debug, error, info};

/// Derive a stable-ish node identifier.
///
/// Prefers the `EC2_INSTANCE_ID` environment variable (set via user-data or
/// IMDSv2 on EC2 instances).  Falls back to `<hostname>-<random-8-chars>` so
/// that every process gets a unique id even on the same host.
pub fn node_id() -> String {
    std::env::var("EC2_INSTANCE_ID").unwrap_or_else(|_| {
        let hostname = gethostname::gethostname().to_string_lossy().into_owned();
        let suffix = &uuid::Uuid::new_v4().to_string()[..8];
        format!("{hostname}-{suffix}")
    })
}

/// Run the heartbeat loop.
///
/// This writes a HASH at `forgecache:node:{node_id}` with a 30-second TTL
/// every 10 seconds.  If the process crashes the key will expire and the
/// node will no longer appear in the active-node list.
///
/// This function never returns under normal operation.
pub async fn run_heartbeat(pool: fred::clients::Pool, node_id: String) {
    info!(%node_id, "starting heartbeat loop");
    loop {
        let key = format!("forgecache:node:{node_id}");
        if let Err(e) = heartbeat_once(&pool, &key).await {
            error!(error = %e, %node_id, "heartbeat tick failed");
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

async fn heartbeat_once(pool: &fred::clients::Pool, key: &str) -> Result<()> {
    let now = chrono::Utc::now().timestamp().to_string();
    let _: () = pool
        .hset(
            key,
            vec![
                ("last_seen".to_string(), now),
                ("status".to_string(), "active".to_string()),
            ],
        )
        .await
        .context("HSET heartbeat")?;
    let _: bool = pool
        .expire(key, 30, None)
        .await
        .context("EXPIRE heartbeat key")?;
    debug!(%key, "heartbeat tick");
    Ok(())
}

/// Remove this node's heartbeat key immediately (graceful shutdown).
pub async fn deregister_node(pool: &fred::clients::Pool, node_id: &str) -> Result<()> {
    let key = format!("forgecache:node:{node_id}");
    let _: i64 = pool.del(&key).await.context("DEL node key")?;
    info!(%node_id, "node deregistered");
    Ok(())
}

/// Return the IDs of all nodes whose heartbeat key still exists.
///
/// Uses the `KEYS` command with the `forgecache:node:*` pattern.  This is
/// acceptable because the number of proxy nodes is small (typically < 100).
/// For very large fleets, replace with an incremental `SCAN`.
pub async fn list_active_nodes(pool: &fred::clients::Pool) -> Result<Vec<String>> {
    let keys: Vec<String> = ClientLike::custom(
        pool,
        CustomCommand::new_static("KEYS", None::<u16>, false),
        vec!["forgecache:node:*".to_string()],
    )
    .await
    .context("KEYS forgecache:node:*")?;

    let nodes: Vec<String> = keys
        .into_iter()
        .filter_map(|k: String| k.strip_prefix("forgecache:node:").map(String::from))
        .collect();

    debug!(count = nodes.len(), "listed active nodes");
    Ok(nodes)
}

/// Check whether a specific node is still alive (its key exists and has not
/// expired).
pub async fn is_node_alive(pool: &fred::clients::Pool, node_id: &str) -> Result<bool> {
    let key = format!("forgecache:node:{node_id}");
    let exists: bool = pool.exists(&key).await.context("EXISTS node key")?;
    Ok(exists)
}
