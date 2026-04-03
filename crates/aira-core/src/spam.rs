//! Spam protection: `ContactRequest` + Proof-of-Work + rate limiting.
//!
//! Contact-first model: cannot message a stranger without their consent.
//! `PoW` (~1s on consumer CPU, 20 bits) prevents mass bot requests.
//! Rate limiter prevents flooding from accepted contacts.
//! See SPEC.md §13.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::proto::AiraError;

/// Difficulty for `ContactRequest` `PoW`: ~1 second on a consumer CPU.
pub const POW_DIFFICULTY_BITS: u8 = 20;

/// Max incoming `ContactRequest`s per minute from different keys (§13.2c).
pub const MAX_REQUESTS_PER_MINUTE: usize = 10;

/// Max requests from the same key per hour before auto-ban (§13.2c).
pub const MAX_REQUESTS_PER_KEY_PER_HOUR: usize = 3;

/// Auto-ban duration in seconds after rate limit exceeded (§13.2c).
pub const RATE_BAN_DURATION_SECS: u64 = 3600;

// ─── Contact Request ────────────────────────────────────────────────────────

/// A contact request with Proof-of-Work (SPEC.md §13.2a).
///
/// Sent to initiate communication with a stranger. The pseudonym pubkey (§12.6)
/// is used as `from` — not the identity key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactRequest {
    /// Sender's pseudonym public key (§12.6).
    pub from: Vec<u8>,
    /// Short introduction message (max 256 bytes).
    pub message: String,
    /// `PoW` nonce that satisfies the difficulty requirement.
    pub pow_nonce: u64,
    /// Required leading zero bits in `BLAKE3(request ‖ nonce)`.
    pub pow_difficulty: u8,
    /// ML-DSA signature over the serialized request (excluding signature field).
    pub signature: Vec<u8>,
}

impl ContactRequest {
    /// Serialize the request fields for `PoW` and signature computation.
    ///
    /// Excludes the `signature` field itself.
    #[must_use]
    pub fn to_pow_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.from);
        bytes.extend_from_slice(self.message.as_bytes());
        bytes.extend_from_slice(&self.pow_difficulty.to_le_bytes());
        bytes
    }

    /// Verify the `PoW` is valid for this request.
    #[must_use]
    pub fn verify_pow(&self) -> bool {
        verify_pow(&self.to_pow_bytes(), self.pow_nonce, self.pow_difficulty)
    }
}

// ─── Proof-of-Work ──────────────────────────────────────────────────────────

/// Verify a Proof-of-Work for a `ContactRequest`.
///
/// `BLAKE3(request_bytes ‖ nonce)` must have `difficulty` leading zero bits.
#[must_use]
pub fn verify_pow(request_bytes: &[u8], nonce: u64, difficulty: u8) -> bool {
    let mut input = request_bytes.to_vec();
    input.extend_from_slice(&nonce.to_le_bytes());
    let hash = blake3::hash(&input);
    leading_zero_bits(hash.as_bytes()) >= u32::from(difficulty)
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0u32;
    for &byte in bytes {
        let zeros = byte.leading_zeros();
        count += zeros;
        if zeros < 8 {
            break;
        }
    }
    count
}

/// Solve a `PoW` puzzle (blocking — run in a thread for UI responsiveness).
///
/// # Errors
///
/// Returns [`AiraError::Handshake`] if the entire `u64` nonce space is
/// exhausted without finding a valid proof (practically impossible).
pub fn solve_pow(request_bytes: &[u8], difficulty: u8) -> Result<u64, AiraError> {
    for nonce in 0u64.. {
        if verify_pow(request_bytes, nonce, difficulty) {
            return Ok(nonce);
        }
    }
    Err(AiraError::Handshake("PoW solve exhausted u64".into()))
}

// ─── Rate Limiter ───────────────────────────────────────────────────────────

/// Per-key rate limiter for incoming `ContactRequest`s (§13.2c).
///
/// Tracks timestamps of requests per public key and globally.
/// Returns whether a request should be accepted or rejected.
pub struct RateLimiter {
    /// Per-key: pubkey hash → list of timestamps (seconds).
    per_key: HashMap<u64, Vec<u64>>,
    /// Global: all request timestamps (seconds).
    global: Vec<u64>,
    /// Banned keys: pubkey hash → ban expiry (seconds).
    banned: HashMap<u64, u64>,
}

impl RateLimiter {
    /// Create a new rate limiter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            per_key: HashMap::new(),
            global: Vec::new(),
            banned: HashMap::new(),
        }
    }

    /// Check whether a request from `pubkey` at `now_secs` should be allowed.
    ///
    /// Returns `Ok(())` if allowed, `Err(reason)` if rate-limited.
    ///
    /// # Errors
    ///
    /// Returns a description of why the request was rejected.
    pub fn check(&mut self, pubkey: &[u8], now_secs: u64) -> Result<(), String> {
        let key_hash = key_hash(pubkey);

        // Check ban
        if let Some(&expiry) = self.banned.get(&key_hash) {
            if now_secs < expiry {
                return Err("temporarily banned".into());
            }
            self.banned.remove(&key_hash);
        }

        // Prune old entries
        let one_minute_ago = now_secs.saturating_sub(60);
        let one_hour_ago = now_secs.saturating_sub(3600);
        self.global.retain(|&t| t > one_minute_ago);

        // Global rate limit: max 10 requests/minute
        if self.global.len() >= MAX_REQUESTS_PER_MINUTE {
            return Err("global rate limit exceeded".into());
        }

        // Per-key rate limit: max 3 requests/hour
        let key_times = self.per_key.entry(key_hash).or_default();
        key_times.retain(|&t| t > one_hour_ago);
        if key_times.len() >= MAX_REQUESTS_PER_KEY_PER_HOUR {
            // Auto-ban this key for 1 hour
            self.banned
                .insert(key_hash, now_secs + RATE_BAN_DURATION_SECS);
            return Err("per-key rate limit exceeded, temporarily banned".into());
        }

        // Accept
        self.global.push(now_secs);
        key_times.push(now_secs);
        Ok(())
    }

    /// Check whether a pubkey is currently banned.
    #[must_use]
    pub fn is_banned(&self, pubkey: &[u8], now_secs: u64) -> bool {
        let key_hash = key_hash(pubkey);
        self.banned
            .get(&key_hash)
            .is_some_and(|&expiry| now_secs < expiry)
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash a pubkey to u64 for `HashMap` keys.
fn key_hash(pubkey: &[u8]) -> u64 {
    let h = blake3::hash(pubkey);
    let b = h.as_bytes();
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pow_verify_works() {
        let data = b"test contact request";
        let nonce = solve_pow(data, 8).unwrap(); // 8 bits — fast for tests
        assert!(verify_pow(data, nonce, 8));
        assert!(!verify_pow(data, nonce + 1, 8));
    }

    #[test]
    fn contact_request_pow_roundtrip() {
        let req = ContactRequest {
            from: vec![0xAA; 32],
            message: "Hello!".into(),
            pow_nonce: 0,
            pow_difficulty: 8,
            signature: vec![],
        };
        let nonce = solve_pow(&req.to_pow_bytes(), 8).unwrap();
        let req = ContactRequest {
            pow_nonce: nonce,
            ..req
        };
        assert!(req.verify_pow());
    }

    #[test]
    fn contact_request_serialization() {
        let req = ContactRequest {
            from: vec![0xBB; 32],
            message: "Hi".into(),
            pow_nonce: 42,
            pow_difficulty: 20,
            signature: vec![0xCC; 64],
        };
        let bytes = postcard::to_allocvec(&req).expect("serialize");
        let restored: ContactRequest = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(restored.from, req.from);
        assert_eq!(restored.message, "Hi");
        assert_eq!(restored.pow_nonce, 42);
    }

    #[test]
    fn rate_limiter_allows_normal_traffic() {
        let mut rl = RateLimiter::new();
        let pk = b"alice";
        assert!(rl.check(pk, 1000).is_ok());
        assert!(rl.check(pk, 1001).is_ok());
        assert!(rl.check(pk, 1002).is_ok());
    }

    #[test]
    fn rate_limiter_per_key_limit() {
        let mut rl = RateLimiter::new();
        let pk = b"spammer";
        // 3 requests in 1 hour = OK
        assert!(rl.check(pk, 1000).is_ok());
        assert!(rl.check(pk, 1001).is_ok());
        assert!(rl.check(pk, 1002).is_ok());
        // 4th = banned
        assert!(rl.check(pk, 1003).is_err());
        assert!(rl.is_banned(pk, 1003));
        // Still banned 30 min later
        assert!(rl.is_banned(pk, 1003 + 1800));
        // Unbanned after 1 hour
        assert!(!rl.is_banned(pk, 1003 + 3601));
    }

    #[test]
    fn rate_limiter_global_limit() {
        let mut rl = RateLimiter::new();
        // 10 different keys in 1 minute
        for i in 0u8..10 {
            assert!(rl.check(&[i], 1000).is_ok());
        }
        // 11th different key = global limit
        assert!(rl.check(b"overflow", 1000).is_err());
        // After 1 minute, global limit resets
        assert!(rl.check(b"overflow", 1061).is_ok());
    }

    #[test]
    fn rate_limiter_ban_boundary() {
        let mut rl = RateLimiter::new();
        let pk = b"edge";
        // Trigger ban
        assert!(rl.check(pk, 1000).is_ok());
        assert!(rl.check(pk, 1001).is_ok());
        assert!(rl.check(pk, 1002).is_ok());
        assert!(rl.check(pk, 1003).is_err()); // banned

        // At 3599s after ban (t=1003+3599=4602) — still banned
        assert!(rl.is_banned(pk, 4602));

        // At exactly 3600s (t=1003+3600=4603) — ban expired (< not <=)
        assert!(!rl.is_banned(pk, 4603));

        // Can send again after ban expires
        assert!(rl.check(pk, 4604).is_ok());
    }

    #[test]
    fn rate_limiter_different_keys_independent() {
        let mut rl = RateLimiter::new();
        let pk_a = b"alice";
        let pk_b = b"bob";
        // Both can send 3 each
        for _ in 0..3 {
            assert!(rl.check(pk_a, 1000).is_ok());
            assert!(rl.check(pk_b, 1000).is_ok());
        }
    }
}
