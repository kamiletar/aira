//! Message padding to fixed-size blocks (SPEC.md §6.6).
//!
//! Hides message length differences (e.g. `Typing` vs short `Text`).
//! Block sizes: 256, 512, 1024, 2048, 4096 bytes.
//!
//! Format: `[length_le16][plaintext][random_padding]`
//!
//! Random padding (not zeros) prevents ciphertext pattern analysis
//! even when the encryption layer is deterministic for a given input.

/// Fixed block sizes for message padding (SPEC.md §6.6).
const BLOCK_SIZES: [usize; 5] = [256, 512, 1024, 2048, 4096];

/// Maximum plaintext size that can be padded (4094 bytes = 4096 - 2 length bytes).
pub const MAX_PADDED_PLAINTEXT: usize = BLOCK_SIZES[BLOCK_SIZES.len() - 1] - 2;

/// Pad `plaintext` to the next fixed block size.
///
/// Returns `None` if plaintext exceeds [`MAX_PADDED_PLAINTEXT`] (4094 bytes).
/// For larger messages, use chunked transfer (SPEC.md §4.7).
///
/// # Example
///
/// ```
/// use aira_core::padding::{pad_message, unpad_message};
///
/// let msg = b"hello";
/// let padded = pad_message(msg).unwrap();
/// assert_eq!(padded.len(), 256);
/// assert_eq!(unpad_message(&padded).unwrap(), msg);
/// ```
#[must_use]
pub fn pad_message(plaintext: &[u8]) -> Option<Vec<u8>> {
    let needed = plaintext.len() + 2; // +2 for length prefix
    let target = BLOCK_SIZES.iter().find(|&&s| s >= needed)?;

    let mut padded = Vec::with_capacity(*target);
    // First 2 bytes: original length (little-endian)
    #[allow(clippy::cast_possible_truncation)]
    let len = plaintext.len() as u16;
    padded.extend_from_slice(&len.to_le_bytes());
    padded.extend_from_slice(plaintext);

    // Fill remainder with random bytes (not zeros) to prevent pattern analysis
    let remaining = *target - padded.len();
    if remaining > 0 {
        let mut fill = vec![0u8; remaining];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut fill);
        padded.extend_from_slice(&fill);
    }

    Some(padded)
}

/// Remove padding and return the original plaintext.
///
/// Returns `None` if the padded data is too short or the encoded length
/// exceeds the available data.
#[must_use]
pub fn unpad_message(padded: &[u8]) -> Option<&[u8]> {
    if padded.len() < 2 {
        return None;
    }
    let len = u16::from_le_bytes([padded[0], padded[1]]) as usize;
    padded.get(2..2 + len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_short_message() {
        let msg = b"hello";
        let padded = pad_message(msg).unwrap();
        assert_eq!(padded.len(), 256);
        assert_eq!(unpad_message(&padded).unwrap(), msg);
    }

    #[test]
    fn roundtrip_empty_message() {
        let msg = b"";
        let padded = pad_message(msg).unwrap();
        assert_eq!(padded.len(), 256);
        assert_eq!(unpad_message(&padded).unwrap(), msg);
    }

    #[test]
    fn block_size_selection() {
        // 254 bytes of plaintext + 2 = 256 → fits in 256
        let msg = vec![0x42u8; 254];
        assert_eq!(pad_message(&msg).unwrap().len(), 256);

        // 255 bytes + 2 = 257 → bumps to 512
        let msg = vec![0x42u8; 255];
        assert_eq!(pad_message(&msg).unwrap().len(), 512);

        // 510 bytes + 2 = 512 → fits in 512
        let msg = vec![0x42u8; 510];
        assert_eq!(pad_message(&msg).unwrap().len(), 512);

        // 511 bytes + 2 = 513 → bumps to 1024
        let msg = vec![0x42u8; 511];
        assert_eq!(pad_message(&msg).unwrap().len(), 1024);
    }

    #[test]
    fn max_size_fits() {
        let msg = vec![0x42u8; MAX_PADDED_PLAINTEXT];
        let padded = pad_message(&msg).unwrap();
        assert_eq!(padded.len(), 4096);
        assert_eq!(unpad_message(&padded).unwrap(), msg.as_slice());
    }

    #[test]
    fn oversized_returns_none() {
        let msg = vec![0x42u8; MAX_PADDED_PLAINTEXT + 1];
        assert!(pad_message(&msg).is_none());
    }

    #[test]
    fn unpad_too_short_returns_none() {
        assert!(unpad_message(&[]).is_none());
        assert!(unpad_message(&[0x01]).is_none());
    }

    #[test]
    fn unpad_corrupted_length_returns_none() {
        // Claim 1000 bytes but only provide 10
        let mut data = vec![0u8; 12];
        data[0] = 0xE8; // 1000 in LE
        data[1] = 0x03;
        assert!(unpad_message(&data).is_none());
    }

    #[test]
    fn padding_is_random_not_zero() {
        let msg = b"x";
        let p1 = pad_message(msg).unwrap();
        let p2 = pad_message(msg).unwrap();
        // Padding region starts at byte 3 (2 length + 1 payload)
        // With random fill, two pads should (almost certainly) differ
        assert_ne!(
            p1[3..],
            p2[3..],
            "random padding should differ between calls"
        );
    }
}
