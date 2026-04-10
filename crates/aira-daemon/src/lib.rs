//! aira-daemon library — shared types for IPC protocol.
//!
//! This module exposes the IPC types (`DaemonRequest`, `DaemonResponse`,
//! `DaemonEvent`, `ServerMessage`) so that clients like `aira-cli` can
//! import them without duplicating definitions.

#![warn(clippy::all, clippy::pedantic)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap,
        clippy::items_after_statements,
        clippy::redundant_closure_for_method_calls
    )
)]

pub mod client;
pub mod handler;
pub mod transfers;
pub mod types;
