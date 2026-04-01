//! Spam protection: `ContactRequest` + Proof-of-Work.
//!
//! Contact-first model: cannot message a stranger without their consent.
//! `PoW` (~1s on consumer CPU, 20 bits) prevents mass bot requests.
//! See SPEC.md §13.
//!
//! TODO(M2/M5): implement when networking is ready

use crate::proto::AiraError;

/// Difficulty for `ContactRequest` `PoW`: ~1 second on a consumer CPU.
pub const POW_DIFFICULTY_BITS: u8 = 20;

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
}
