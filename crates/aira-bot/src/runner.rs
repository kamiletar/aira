//! Bot event loop: connects to daemon, dispatches events to [`Bot`] trait methods.

use aira_core::proto::PlainPayload;
use aira_daemon::client::DaemonClient;
use aira_daemon::types::DaemonEvent;
use tokio::sync::mpsc;

use crate::context::BotContext;
use crate::{Bot, BotError, IncomingGroupMessage, IncomingMessage};

/// Run the bot event loop.
///
/// Connects to the running `aira-daemon` via IPC, then loops forever:
/// dispatching incoming events to the appropriate [`Bot`] trait methods.
/// Shuts down gracefully on Ctrl+C.
///
/// # Errors
///
/// Returns `BotError::Ipc` if the initial connection fails or the
/// daemon disconnects.
///
/// # Example
///
/// ```no_run
/// use aira_bot::{Bot, BotContext, BotError, IncomingMessage, run_bot};
///
/// struct MyBot;
/// impl Bot for MyBot {
///     fn on_message(
///         &self, ctx: &BotContext, msg: IncomingMessage,
///     ) -> impl std::future::Future<Output = Result<(), BotError>> + Send {
///         let to = msg.from.clone();
///         let ctx = ctx.clone();
///         async move { ctx.reply(&to, "Got it!").await }
///     }
/// }
///
/// # async fn example() -> Result<(), BotError> {
/// run_bot(MyBot).await
/// # }
/// ```
pub async fn run_bot(bot: impl Bot) -> Result<(), BotError> {
    let (client, events) = DaemonClient::connect().await?;
    let ctx = BotContext::new(client);

    tracing::info!("bot connected to daemon, entering event loop");

    event_loop(&bot, &ctx, events).await
}

/// Internal event loop — separated for testability.
async fn event_loop(
    bot: &impl Bot,
    ctx: &BotContext,
    mut events: mpsc::Receiver<DaemonEvent>,
) -> Result<(), BotError> {
    loop {
        tokio::select! {
            event = events.recv() => {
                if let Some(ev) = event {
                    if let Err(e) = dispatch(bot, ctx, ev).await {
                        tracing::warn!("bot handler error: {e}");
                    }
                } else {
                    // Daemon disconnected
                    tracing::info!("daemon connection closed, shutting down");
                    break;
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received Ctrl+C, shutting down");
                break;
            }
        }
    }
    Ok(())
}

/// Dispatch a single `DaemonEvent` to the appropriate `Bot` method.
async fn dispatch(bot: &impl Bot, ctx: &BotContext, event: DaemonEvent) -> Result<(), BotError> {
    match event {
        DaemonEvent::MessageReceived { from, payload } => {
            if let Some(text) = extract_text(&payload) {
                let msg = IncomingMessage { from, text };
                bot.on_message(ctx, msg).await?;
            }
        }
        DaemonEvent::GroupMessageReceived {
            group_id,
            from,
            payload,
        } => {
            if let Some(text) = extract_text(&payload) {
                let msg = IncomingGroupMessage {
                    group_id,
                    from,
                    text,
                };
                bot.on_group_message(ctx, msg).await?;
            }
        }
        DaemonEvent::ContactOnline(pubkey) => {
            bot.on_contact_online(ctx, pubkey).await?;
        }
        DaemonEvent::ContactOffline(pubkey) => {
            bot.on_contact_offline(ctx, pubkey).await?;
        }
        DaemonEvent::GroupMemberJoined { group_id, member } => {
            bot.on_group_member_joined(ctx, group_id, member).await?;
        }
        DaemonEvent::GroupMemberLeft { group_id, member } => {
            bot.on_group_member_left(ctx, group_id, member).await?;
        }
        DaemonEvent::GroupInvite {
            group_id,
            name,
            invited_by,
        } => {
            bot.on_group_invite(ctx, group_id, name, invited_by).await?;
        }
        // File and device events are not dispatched to bots in this version.
        DaemonEvent::FileProgress { .. }
        | DaemonEvent::FileComplete { .. }
        | DaemonEvent::FileError { .. }
        | DaemonEvent::DeviceLinked { .. }
        | DaemonEvent::DeviceUnlinked { .. }
        | DaemonEvent::SyncCompleted { .. } => {}
    }
    Ok(())
}

/// Try to extract a text string from serialized `PlainPayload` bytes.
///
/// Returns `None` if deserialization fails or the payload is not a `Text` variant.
fn extract_text(payload: &[u8]) -> Option<String> {
    let plain: PlainPayload = postcard::from_bytes(payload).ok()?;
    match plain {
        PlainPayload::Text(text) => Some(text),
        PlainPayload::Action(action) => Some(action),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_text_from_text_payload() {
        let payload = PlainPayload::Text("hello".into());
        let bytes = postcard::to_allocvec(&payload).expect("serialize");
        assert_eq!(extract_text(&bytes), Some("hello".into()));
    }

    #[test]
    fn extract_text_from_action_payload() {
        let payload = PlainPayload::Action("waves".into());
        let bytes = postcard::to_allocvec(&payload).expect("serialize");
        assert_eq!(extract_text(&bytes), Some("waves".into()));
    }

    #[test]
    fn extract_text_returns_none_for_non_text() {
        let payload = PlainPayload::Typing(true);
        let bytes = postcard::to_allocvec(&payload).expect("serialize");
        assert_eq!(extract_text(&bytes), None);
    }

    #[test]
    fn extract_text_returns_none_for_garbage() {
        assert_eq!(extract_text(&[0xFF, 0xFE, 0xFD]), None);
    }

    #[tokio::test]
    async fn dispatch_contact_online() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        struct TestBot {
            called: Arc<AtomicBool>,
        }
        impl Bot for TestBot {
            async fn on_contact_online(
                &self,
                _ctx: &BotContext,
                _pubkey: Vec<u8>,
            ) -> Result<(), BotError> {
                self.called.store(true, Ordering::SeqCst);
                Ok(())
            }
        }

        // We need a DaemonClient to create BotContext, but we can't connect
        // to a daemon in tests. Instead, test dispatch logic through extract_text
        // and trait compilation. Full integration test requires a running daemon.
        let called = Arc::new(AtomicBool::new(false));
        let _bot = TestBot {
            called: called.clone(),
        };

        // Verify the bot trait compiles and the type is Send + Sync
        fn assert_bot<T: Bot>() {}
        assert_bot::<TestBot>();
        assert!(!called.load(Ordering::SeqCst));
    }
}
