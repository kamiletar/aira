//! Message padding to fixed-size blocks.
//!
//! Hides message length differences (e.g. Typing vs short Text).
//! Block sizes: 256, 512, 1024, 2048, 4096 bytes.
//! See SPEC.md §6.6.
//!
//! TODO(M1): full implementation

/// Pad `plaintext` to the next fixed block size.
#[must_use]
pub fn pad_message(plaintext: &[u8]) -> Vec<u8> {
    const BLOCK_SIZES: [usize; 5] = [256, 512, 1024, 2048, 4096];
    let target = BLOCK_SIZES
        .iter()
        .find(|&&s| s >= plaintext.len() + 2)
        .unwrap_or(&4096);
    let mut padded = Vec::with_capacity(*target);
    // First 2 bytes: original length (little-endian)
    #[allow(clippy::cast_possible_truncation)]
    let len = plaintext.len() as u16; // safe: max block is 4096 < u16::MAX
    padded.extend_from_slice(&len.to_le_bytes());
    padded.extend_from_slice(plaintext);
    padded.resize(*target, 0);
    padded
}

/// Remove padding and return the original plaintext.
#[must_use]
pub fn unpad_message(padded: &[u8]) -> Option<&[u8]> {
    if padded.len() < 2 {
        return None;
    }
    let len = u16::from_le_bytes([padded[0], padded[1]]) as usize;
    let data = padded.get(2..2 + len)?;
    Some(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_short_message() {
        let msg = b"hello";
        let padded = pad_message(msg);
        assert_eq!(padded.len(), 256);
        assert_eq!(unpad_message(&padded).unwrap(), msg);
    }

    #[test]
    fn roundtrip_empty_message() {
        let msg = b"";
        let padded = pad_message(msg);
        assert_eq!(unpad_message(&padded).unwrap(), msg);
    }
}
