use anyhow::{Context, Result};
use fred::interfaces::PubsubInterface;
use tracing::debug;

/// Publish a "ready" notification for a repository.
///
/// Other nodes (or request-handler tasks on the same node) that are waiting
/// for a clone / bundle to become available can subscribe to the
/// corresponding channel and react immediately.
///
/// Uses `pool.next()` to get a `Client` since `Pool` does not implement
/// `PubsubInterface` in fred v10.
pub async fn publish_ready(
    pool: &fred::clients::Pool,
    owner_repo: &str,
    node_id: &str,
) -> Result<()> {
    let channel = format!("forgeproxy:notify:repo:{owner_repo}");
    let message = format!("ready:{node_id}");
    let _: () = pool
        .next()
        .publish(&channel, message.as_str())
        .await
        .context("publish ready notification")?;
    debug!(%owner_repo, %node_id, "published ready notification");
    Ok(())
}
