//! aira-daemon — background process managing network, crypto, and storage.
//!
//! Communicates with aira-cli (and future GUI) via IPC:
//! - Linux/macOS: Unix domain socket (~/.aira/daemon.sock)
//! - Windows:     Named pipe (\\.\pipe\aira-daemon)
//!
//! See SPEC.md §8 for the IPC API specification.

#![warn(clippy::all, clippy::pedantic)]

use anyhow::Result;

mod ipc;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("AIRA_LOG")
                .unwrap_or_else(|_| "aira=info".to_string())
                .as_str(),
        )
        .init();

    tracing::info!("aira-daemon starting");

    // TODO(M3): initialize storage, networking, IPC server
    todo!("implement daemon main loop (Milestone 3)")
}
