//! aira-ffi — `UniFFI` bindings for Android (and future mobile platforms).
//!
//! Exposes an `AiraRuntime` object that embeds the daemon logic in-process,
//! suitable for Android's Foreground Service architecture.
//!
//! See SPEC.md §15.3 for the Android architecture.

#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
// UniFFI-exported functions have FFI constraints that conflict with pedantic lints
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::needless_pass_by_value)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::useless_vec,
        clippy::implicit_clone
    )
)]

pub mod callbacks;
pub mod runtime;
pub mod types;

uniffi::setup_scaffolding!();
