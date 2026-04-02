//! Echo bot — replies to every message with "Echo: <text>".
//!
//! # Running
//!
//! 1. Start `aira-daemon` first.
//! 2. Run:
//!    ```bash
//!    cargo run --example echo -p aira-bot
//!    ```
//! 3. Send a message to this bot's address from another Aira client.

use aira_bot::{run_bot, Bot, BotContext, BotError, IncomingMessage};

struct EchoBot;

impl Bot for EchoBot {
    fn on_message(
        &self,
        ctx: &BotContext,
        msg: IncomingMessage,
    ) -> impl std::future::Future<Output = Result<(), BotError>> + Send {
        let reply_text = format!("Echo: {}", msg.text);
        let to = msg.from.clone();
        let ctx = ctx.clone();
        async move {
            tracing::info!("echoing message from {} bytes pubkey", to.len());
            ctx.reply(&to, &reply_text).await
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    println!("Echo bot starting... (Ctrl+C to stop)");
    run_bot(EchoBot).await?;
    Ok(())
}
