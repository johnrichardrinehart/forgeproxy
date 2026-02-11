//! Distributed coordination layer backed by KeyDB (Redis-compatible).
//!
//! Provides distributed locks, a shared repo/bundle registry, pub/sub
//! notifications for clone and bundle readiness, and node heartbeat
//! registration.  All state is stored in KeyDB so that multiple proxy
//! nodes can cooperate without local shared filesystems.

pub mod locks;
pub mod node;
pub mod pubsub;
pub mod redis;
pub mod registry;

pub use locks::{acquire_lock, extend_lock, release_lock, wait_for_lock};
pub use node::{deregister_node, list_active_nodes, node_id, run_heartbeat};
pub use pubsub::{publish_ready, subscribe_ready};
pub use redis::create_keydb_pool;
pub use registry::{
    deregister_node_for_repo, ensure_repo_cloned, get_fetch_schedule, get_repo_info,
    increment_clone_count, is_repo_cached_and_fresh, list_all_repos, register_node_for_repo,
    set_fetch_schedule, set_repo_info, update_repo_field, FetchSchedule, RepoInfo,
};
