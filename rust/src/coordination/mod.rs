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
