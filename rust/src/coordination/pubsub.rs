use anyhow::{Context, Result};
use fred::interfaces::PubsubInterface;
use tracing::{debug, warn};

const VALKEY_PUBLISH_RETRY_ATTEMPTS: usize = 5;
const VALKEY_PUBLISH_RETRY_BASE_DELAY_MS: u64 = 250;

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
    let mut last_error = None;
    for attempt in 0..VALKEY_PUBLISH_RETRY_ATTEMPTS {
        match pool
            .next()
            .publish(&channel, message.as_str())
            .await
            .context("publish ready notification")
        {
            Ok::<(), anyhow::Error>(()) => {
                debug!(%owner_repo, %node_id, "published ready notification");
                return Ok(());
            }
            Err(error) => {
                last_error = Some(error);
                if attempt + 1 == VALKEY_PUBLISH_RETRY_ATTEMPTS {
                    break;
                }

                let delay_ms = VALKEY_PUBLISH_RETRY_BASE_DELAY_MS * (1_u64 << attempt);
                warn!(
                    repo = %owner_repo,
                    %node_id,
                    attempt = attempt + 1,
                    delay_ms,
                    "publish ready notification failed; retrying"
                );
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
        }
    }

    Err(last_error.expect("retry loop must capture an error"))
}
