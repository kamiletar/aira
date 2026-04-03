//! Fuzz target for protocol message deserialization.
//!
//! Ensures that arbitrary byte inputs never panic when parsed as
//! Message, GroupMessage, or EncryptedEnvelope.
//!
//! Run: `cargo fuzz run fuzz_parse_message`

#![no_main]

use aira_core::proto::{EncryptedEnvelope, PlainPayload};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must never panic on any input
    let _ = postcard::from_bytes::<PlainPayload>(data);
    let _ = postcard::from_bytes::<EncryptedEnvelope>(data);
});
