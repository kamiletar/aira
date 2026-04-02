//! aira-daemon library — shared types for IPC protocol.
//!
//! This module exposes the IPC types (`DaemonRequest`, `DaemonResponse`,
//! `DaemonEvent`, `ServerMessage`) so that clients like `aira-cli` can
//! import them without duplicating definitions.

#![warn(clippy::all, clippy::pedantic)]

pub mod client;
pub mod handler;
pub mod transfers;
pub mod types;
