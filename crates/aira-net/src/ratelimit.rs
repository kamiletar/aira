//! Connection tiers + GCRA rate limiting (governor crate).
//!
//! Tier 1 — Verified contacts: unlimited
//! Tier 2 — Known peers: 100 msg/min
//! Tier 3 — Strangers: 5 msg/min + `PoW` required
//!
//! See SPEC.md §11B.1.

use std::num::NonZeroU32;

use governor::{clock, state, Quota, RateLimiter as GovRateLimiter};

use crate::connection::PeerTier;

/// A rate limiter for a specific peer tier.
///
/// Uses GCRA (Generic Cell Rate Algorithm) via the `governor` crate.
pub type RateLimiter = GovRateLimiter<state::NotKeyed, state::InMemoryState, clock::DefaultClock>;

/// Create a rate limiter for the given peer tier.
///
/// Returns `None` for `Verified` peers (unlimited).
#[must_use]
pub fn limiter_for_tier(tier: PeerTier) -> Option<RateLimiter> {
    match tier {
        PeerTier::Verified => None,
        PeerTier::Known => {
            // 100 messages per minute
            let quota = Quota::per_minute(NonZeroU32::new(100).expect("nonzero"));
            Some(GovRateLimiter::direct(quota))
        }
        PeerTier::Stranger => {
            // 5 messages per minute
            let quota = Quota::per_minute(NonZeroU32::new(5).expect("nonzero"));
            Some(GovRateLimiter::direct(quota))
        }
    }
}

/// Check if a message is allowed by the rate limiter.
///
/// Returns `true` if allowed, `false` if rate-limited.
/// Always returns `true` if `limiter` is `None` (unlimited tier).
pub fn check_rate(limiter: &Option<RateLimiter>) -> bool {
    match limiter {
        None => true,
        Some(lim) => lim.check().is_ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verified_unlimited() {
        let limiter = limiter_for_tier(PeerTier::Verified);
        assert!(limiter.is_none());
        assert!(check_rate(&limiter));
    }

    #[test]
    fn test_stranger_rate_limited() {
        let limiter = limiter_for_tier(PeerTier::Stranger);
        assert!(limiter.is_some());

        // Burst should be allowed (governor allows a small burst)
        for _ in 0..5 {
            assert!(check_rate(&limiter));
        }

        // Next one should be rate-limited
        assert!(!check_rate(&limiter));
    }

    #[test]
    fn test_known_rate_limited() {
        let limiter = limiter_for_tier(PeerTier::Known);
        assert!(limiter.is_some());

        // First message should pass
        assert!(check_rate(&limiter));
    }
}
