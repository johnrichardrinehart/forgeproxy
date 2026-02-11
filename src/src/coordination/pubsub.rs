use std::time::Duration;

use anyhow::{Context, Result};
use fred::clients::SubscriberClient;
use fred::interfaces::{ClientLike, EventInterface, PubsubInterface};
use fred::types::CustomCommand;
use tokio::sync::mpsc;
use tracing::{debug, warn};

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
    let channel = format!("gheproxy:notify:repo:{owner_repo}");
    let message = format!("ready:{node_id}");
    let _: () = pool
        .next()
        .publish(&channel, message.as_str())
        .await
        .context("publish ready notification")?;
    debug!(%owner_repo, %node_id, "published ready notification");
    Ok(())
}

/// Subscribe to the repo notification channel and wait for a "ready" message.
///
/// Returns `Some(node_id)` if a `ready:<node_id>` message arrives before
/// `timeout` elapses, or `None` on timeout.
///
/// Creates a dedicated `SubscriberClient` for this subscription, since
/// `Pool` does not implement `PubsubInterface` or `EventInterface` in fred v10.
pub async fn subscribe_ready(
    pool: &fred::clients::Pool,
    owner_repo: &str,
    timeout: Duration,
) -> Result<Option<String>> {
    let channel = format!("gheproxy:notify:repo:{owner_repo}");

    // Create a dedicated subscriber client from the same config as the pool.
    let client = pool.next();
    let subscriber = SubscriberClient::new(
        client.client_config(),
        None,
        None,
        client.client_reconnect_policy(),
    );
    let _connect = subscriber.connect();
    subscriber
        .wait_for_connect()
        .await
        .context("subscriber connect")?;

    // Use a tokio channel to bridge the callback-based message handler.
    let (tx, mut rx) = mpsc::channel::<String>(4);

    // Subscribe to the channel.
    subscriber
        .subscribe(&channel)
        .await
        .context("subscribe to repo channel")?;

    // Spawn a task that forwards matching messages.
    let sub_clone = subscriber.clone();
    let chan = channel.clone();
    let handle = tokio::spawn(async move {
        let mut message_stream = sub_clone.message_rx();
        while let Ok(msg) = message_stream.recv().await {
            if let Some(payload) = msg.value.as_str() {
                if let Some(node_id) = payload.strip_prefix("ready:") {
                    let _ = tx.send(node_id.to_string()).await;
                    break;
                }
            }
        }
        // Unsubscribe and quit.
        let _ = sub_clone.unsubscribe(&chan).await;
        let _ = sub_clone.quit().await;
    });

    // Wait for a message or the timeout.
    let result = tokio::time::timeout(timeout, rx.recv()).await;

    match result {
        Ok(Some(node_id)) => {
            debug!(%owner_repo, %node_id, "received ready notification");
            Ok(Some(node_id))
        }
        _ => {
            warn!(%owner_repo, ?timeout, "timed out waiting for ready notification");
            // Clean up the spawned task.
            handle.abort();
            let _ = subscriber.unsubscribe(&channel).await;
            let _ = subscriber.quit().await;
            Ok(None)
        }
    }
}
