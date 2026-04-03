//! Safety Numbers for out-of-band key verification.
//!
//! Generates a 60-digit number (BLAKE3 of both public keys, sorted).
//! Both peers compute the same number; compare verbally or via QR.
//! See SPEC.md §6.9.

/// Compute a Safety Number for a pair of ML-DSA identity keys.
///
/// The result is a 60-digit decimal string grouped as 12 groups of 5.
///
/// # Example
/// ```
/// use aira_core::safety::safety_number;
///
/// let alice_key = [1u8; 32];
/// let bob_key = [2u8; 32];
/// let num = safety_number(&alice_key, &bob_key);
/// assert_eq!(num.len(), 71); // 60 digits + 11 spaces
/// ```
#[must_use]
pub fn safety_number(key_a: &[u8], key_b: &[u8]) -> String {
    // Sort keys so both peers get the same result regardless of who calls
    let (first, second) = if key_a < key_b {
        (key_a, key_b)
    } else {
        (key_b, key_a)
    };

    let mut input = Vec::with_capacity(first.len() + second.len());
    input.extend_from_slice(first);
    input.extend_from_slice(second);

    let hash = blake3::hash(&input);
    format_as_digits(hash.as_bytes(), 60)
}

/// Format a BLAKE3 hash as N decimal digits, grouped in 5s.
///
/// Uses BLAKE3 XOF (extendable output) and rejection sampling to produce
/// uniformly distributed digits (no modular bias).
fn format_as_digits(hash_bytes: &[u8; 32], count: usize) -> String {
    // Use BLAKE3 in XOF mode seeded from the hash to get enough random bytes.
    // Rejection sampling: accept byte < 250 (250 = 25*10), reject >= 250.
    // Worst case: need ~count * 256/250 ≈ count * 1.024 bytes.
    let mut hasher = blake3::Hasher::new();
    hasher.update(hash_bytes);
    let mut reader = hasher.finalize_xof();

    let mut digits = Vec::with_capacity(count);
    let mut buf = [0u8; 64];
    while digits.len() < count {
        reader.fill(&mut buf);
        for &byte in &buf {
            if digits.len() >= count {
                break;
            }
            // Rejection sampling: discard bytes >= 250 to avoid bias
            // 250 = 25 * 10, so byte % 10 is uniformly distributed for byte < 250
            if byte < 250 {
                digits.push(b'0' + (byte % 10));
            }
        }
    }

    // Group as 5-digit chunks separated by spaces
    digits
        .chunks(5)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or("?????").to_string())
        .collect::<Vec<_>>()
        .join(" ")
}
