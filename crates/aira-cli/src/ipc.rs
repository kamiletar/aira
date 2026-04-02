//! IPC client — re-exported from `aira-daemon::client`.
//!
//! The shared implementation lives in `aira-daemon` so that both
//! `aira-cli` and `aira-bot` use the same IPC client code.

pub use aira_daemon::client::*;
