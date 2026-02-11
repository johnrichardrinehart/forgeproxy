//! Monotonic creation token management for Git bundle-URI.
//!
//! Each bundle in a bundle-list carries a `creationToken` that clients use to
//! determine which bundles they already have (from a previous clone or fetch)
//! and which they still need.  Tokens must be **strictly monotonically
//! increasing** within a given repository's bundle-list.
//!
//! This module provides two strategies for assigning tokens:
//!
//! 1. **Atomic counter** ([`next_creation_token`]) -- increments a per-repo
//!    counter in KeyDB by a fixed step (1000) to leave room for manual
//!    insertions.  This is the primary strategy used during incremental bundle
//!    generation.
//!
//! 2. **Deterministic timestamp-based** ([`creation_token_for_bundle_type`]) --
//!    derives a token from the bundle type and the current UTC timestamp.
//!    This is used for consolidation bundles where a predictable token value
//!    simplifies reasoning about ordering (base < daily < hourly).

use anyhow::{Context, Result};
use chrono::{DateTime, Datelike, Timelike, Utc};
use fred::interfaces::HashesInterface;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Logical type of a bundle, used to determine the creation-token range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleType {
    /// Base (full) bundle -- the lowest token tier.
    Base,
    /// Daily consolidation bundle -- mid-range tokens.
    Daily,
    /// Hourly incremental bundle -- highest token tier.
    Hourly,
}

// ---------------------------------------------------------------------------
// Atomic counter
// ---------------------------------------------------------------------------

/// Atomically allocate the next creation token for a repository.
///
/// Increments the `latest_creation_token` field in the repo's KeyDB hash
/// by 1000 and returns the new value.  The step of 1000 leaves room for
/// out-of-band insertions or manual corrections without risking collisions.
///
/// Key: `forgecache:repo:{owner_repo}`, field: `latest_creation_token`.
pub async fn next_creation_token(state: &crate::AppState, owner_repo: &str) -> Result<u64> {
    let key = format!("forgecache:repo:{owner_repo}");
    let new_val: i64 = HashesInterface::hincrby(&state.keydb, &key, "latest_creation_token", 1000)
        .await
        .with_context(|| format!("failed to increment creation token for {owner_repo}"))?;
    Ok(new_val as u64)
}

// ---------------------------------------------------------------------------
// Deterministic timestamp-based tokens
// ---------------------------------------------------------------------------

/// Compute a deterministic creation token for a given bundle type and
/// timestamp.
///
/// The token ranges are arranged so that base < daily < hourly, ensuring
/// clients always download bundles in the correct dependency order:
///
/// | Type   | Formula                                     | Range       |
/// |--------|---------------------------------------------|-------------|
/// | Base   | `1000`                                      | 1000        |
/// | Daily  | `2000 + day_of_year`                        | 2001 - 2366 |
/// | Hourly | `3000 + day_of_year * 24 + hour_of_day`     | 3000 - 11783|
///
/// These values are intentionally smaller than the atomic counter's step
/// size so they can coexist in the same bundle-list without collision.
pub fn creation_token_for_bundle_type(bundle_type: BundleType, timestamp: DateTime<Utc>) -> u64 {
    match bundle_type {
        BundleType::Base => 1000,
        BundleType::Daily => 2000 + timestamp.ordinal() as u64,
        BundleType::Hourly => 3000 + (timestamp.ordinal() as u64 * 24 + timestamp.hour() as u64),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn base_token_is_constant() {
        let t1 = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let t2 = Utc.with_ymd_and_hms(2025, 12, 31, 23, 59, 59).unwrap();
        assert_eq!(creation_token_for_bundle_type(BundleType::Base, t1), 1000);
        assert_eq!(creation_token_for_bundle_type(BundleType::Base, t2), 1000);
    }

    #[test]
    fn daily_token_incorporates_day_of_year() {
        let jan1 = Utc.with_ymd_and_hms(2025, 1, 1, 12, 0, 0).unwrap();
        let feb1 = Utc.with_ymd_and_hms(2025, 2, 1, 12, 0, 0).unwrap();
        let t1 = creation_token_for_bundle_type(BundleType::Daily, jan1);
        let t2 = creation_token_for_bundle_type(BundleType::Daily, feb1);
        assert_eq!(t1, 2001); // day 1
        assert_eq!(t2, 2032); // day 32
        assert!(t2 > t1);
    }

    #[test]
    fn hourly_token_incorporates_day_and_hour() {
        let t1 = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let t2 = Utc.with_ymd_and_hms(2025, 1, 1, 12, 0, 0).unwrap();
        let t3 = Utc.with_ymd_and_hms(2025, 1, 2, 0, 0, 0).unwrap();

        let tok1 = creation_token_for_bundle_type(BundleType::Hourly, t1);
        let tok2 = creation_token_for_bundle_type(BundleType::Hourly, t2);
        let tok3 = creation_token_for_bundle_type(BundleType::Hourly, t3);

        assert!(tok1 < tok2, "same day, later hour should be larger");
        assert!(tok2 < tok3, "next day should be larger");
    }

    #[test]
    fn ordering_base_lt_daily_lt_hourly() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 14, 30, 0).unwrap();
        let base = creation_token_for_bundle_type(BundleType::Base, ts);
        let daily = creation_token_for_bundle_type(BundleType::Daily, ts);
        let hourly = creation_token_for_bundle_type(BundleType::Hourly, ts);
        assert!(base < daily, "base ({base}) < daily ({daily})");
        assert!(daily < hourly, "daily ({daily}) < hourly ({hourly})");
    }
}
