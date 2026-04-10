//! Aira Bot SDK — build bots for the Aira P2P messenger.
//!
//! A bot connects to the running `aira-daemon` via IPC and reacts to
//! incoming messages and events. Implement the [`Bot`] trait and pass
//! your bot to [`run_bot`] to start the event loop.
//!
//! # Quick start
//!
//! ```no_run
//! use aira_bot::{Bot, BotContext, BotError, IncomingMessage, run_bot};
//!
//! struct EchoBot;
//!
//! impl Bot for EchoBot {
//!     fn on_message(
//!         &self,
//!         ctx: &BotContext,
//!         msg: IncomingMessage,
//!     ) -> impl std::future::Future<Output = Result<(), BotError>> + Send {
//!         let text = format!("Echo: {}", msg.text);
//!         let to = msg.from.clone();
//!         let ctx = ctx.clone();
//!         async move { ctx.reply(&to, &text).await }
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     run_bot(EchoBot).await?;
//!     Ok(())
//! }
//! ```

#![warn(clippy::all, clippy::pedantic)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::items_after_statements
    )
)]

mod context;
mod runner;

pub use context::BotContext;
pub use runner::run_bot;

// Re-export commonly used daemon types for convenience.
pub use aira_daemon::types::{DaemonEvent, DaemonResponse};
pub use aira_storage::{ContactInfo, StoredMessage};

/// Bot SDK errors.
#[derive(Debug, thiserror::Error)]
pub enum BotError {
    /// IPC connection or communication error.
    #[error("IPC error: {0}")]
    Ipc(#[from] aira_daemon::client::IpcError),
    /// Daemon returned an error response.
    #[error("daemon error: {0}")]
    Daemon(String),
    /// Payload deserialization failed (corrupt or unknown format).
    #[error("payload deserialization error: {0}")]
    PayloadDeserialize(String),
}

/// An incoming direct message, already deserialized.
#[derive(Debug, Clone)]
pub struct IncomingMessage {
    /// Sender's ML-DSA public key.
    pub from: Vec<u8>,
    /// Message text (extracted from `PlainPayload::Text`).
    pub text: String,
}

/// An incoming group message, already deserialized.
#[derive(Debug, Clone)]
pub struct IncomingGroupMessage {
    /// Group ID (32 bytes).
    pub group_id: [u8; 32],
    /// Sender's ML-DSA public key.
    pub from: Vec<u8>,
    /// Message text (extracted from `PlainPayload::Text`).
    pub text: String,
}

/// Trait that bots implement to react to daemon events.
///
/// All methods have default no-op implementations. Override only the
/// events your bot cares about. A minimal echo bot only needs
/// [`Bot::on_message`].
///
/// # Note on object safety
///
/// This trait uses RPITIT (`impl Future + Send`) and is therefore
/// **not** object-safe. Use `impl Bot` or generics, not `dyn Bot`.
#[allow(unused_variables)]
pub trait Bot: Send + Sync + 'static {
    /// Called when a direct text message is received.
    fn on_message(
        &self,
        ctx: &BotContext,
        msg: IncomingMessage,
    ) -> impl std::future::Future<Output = Result<(), BotError>> + Send {
        async { Ok(()) }
    }

    /// Called when a group text message is received.
    fn on_group_message(
        &self,
        ctx: &BotContext,
        msg: IncomingGroupMessage,
    ) -> impl std::future::Future<Output = Result<(), BotError>> + Send {
        async { Ok(()) }
    }

    /// Called when a contact comes online.
    fn on_contact_online(
        &self,
        ctx: &BotContext,
        pubkey: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), BotError>> + Send {
        async { Ok(()) }
    }

    /// Called when a contact goes offline.
    fn on_contact_offline(
        &self,
        ctx: &BotContext,
        pubkey: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), BotError>> + Send {
        async { Ok(()) }
    }

    /// Called when a member joins a group.
    fn on_group_member_joined(
        &self,
        ctx: &BotContext,
        group_id: [u8; 32],
        member: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), BotError>> + Send {
        async { Ok(()) }
    }

    /// Called when a member leaves a group.
    fn on_group_member_left(
        &self,
        ctx: &BotContext,
        group_id: [u8; 32],
        member: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), BotError>> + Send {
        async { Ok(()) }
    }

    /// Called when we receive an invitation to join a group.
    fn on_group_invite(
        &self,
        ctx: &BotContext,
        group_id: [u8; 32],
        name: String,
        invited_by: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), BotError>> + Send {
        async { Ok(()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A no-op bot that uses all defaults.
    struct NoopBot;
    impl Bot for NoopBot {}

    /// Verify that a zero-impl bot compiles and satisfies Send + Sync.
    #[test]
    fn noop_bot_is_send_sync() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<NoopBot>();
    }

    #[test]
    fn incoming_message_debug() {
        let msg = IncomingMessage {
            from: vec![0xAA; 32],
            text: "hello".into(),
        };
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("hello"));
    }

    #[test]
    fn incoming_group_message_clone() {
        let msg = IncomingGroupMessage {
            group_id: [0x11; 32],
            from: vec![0xBB; 32],
            text: "hi group".into(),
        };
        let cloned = msg.clone();
        assert_eq!(cloned.group_id, [0x11; 32]);
        assert_eq!(cloned.text, "hi group");
    }

    #[test]
    fn bot_error_display() {
        let e = BotError::Daemon("not found".into());
        assert_eq!(e.to_string(), "daemon error: not found");
    }

    #[test]
    fn bot_error_from_ipc() {
        let ipc_err = aira_daemon::client::IpcError::ResponseChannelClosed;
        let bot_err: BotError = ipc_err.into();
        assert!(bot_err.to_string().contains("response channel closed"));
    }
}
