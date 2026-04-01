//! aira — CLI client (ratatui TUI).
//!
//! Thin client that communicates with aira-daemon via IPC.
//! All cryptography and networking happens in the daemon.
//!
//! See SPEC.md §9 for the CLI specification and command list.

#![warn(clippy::all, clippy::pedantic)]

use anyhow::Result;

mod commands;
mod ipc;
mod ui;

#[tokio::main]
async fn main() -> Result<()> {
    // TODO(M5): implement CLI main loop (Milestone 5)
    todo!("implement CLI (Milestone 5)")
}
