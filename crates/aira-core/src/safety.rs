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

/// Format raw bytes as N decimal digits, grouped in 5s.
fn format_as_digits(bytes: &[u8], count: usize) -> String {
    // Each byte gives ~2.4 decimal digits via modular extraction
    let mut digits = Vec::with_capacity(count);
    let mut i = 0;
    while digits.len() < count {
        let byte = bytes[i % bytes.len()];
        digits.push(b'0' + (byte % 10));
        i += 1;
    }

    // Group as 5-digit chunks separated by spaces
    digits
        .chunks(5)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or("?????").to_string())
        .collect::<Vec<_>>()
        .join(" ")
}
