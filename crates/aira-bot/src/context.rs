//! `BotContext` — ergonomic wrapper over `DaemonClient` for bot operations.

use std::sync::Arc;

use aira_daemon::client::DaemonClient;
use aira_daemon::types::{DaemonRequest, DaemonResponse};
use aira_storage::{ContactInfo, StoredMessage};

use crate::BotError;

/// Context provided to [`Bot`](crate::Bot) event handlers.
///
/// Wraps a [`DaemonClient`] in an `Arc` so it can be cheaply cloned
/// and shared across spawned tasks.
///
/// # Example
///
/// ```no_run
/// # async fn example(ctx: &aira_bot::BotContext) -> Result<(), aira_bot::BotError> {
/// let addr = ctx.my_address().await?;
/// println!("Bot address: {} bytes", addr.len());
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct BotContext {
    client: Arc<DaemonClient>,
}

impl BotContext {
    /// Create a new `BotContext` wrapping the given `DaemonClient`.
    pub fn new(client: DaemonClient) -> Self {
        Self {
            client: Arc::new(client),
        }
    }

    /// Send a text message to a contact (reply).
    ///
    /// # Errors
    ///
    /// Returns `BotError::Ipc` on connection failure or
    /// `BotError::Daemon` if the daemon rejects the request.
    pub async fn reply(&self, to: &[u8], text: &str) -> Result<(), BotError> {
        let resp = self
            .client
            .request(&DaemonRequest::SendMessage {
                to: to.to_vec(),
                text: text.to_owned(),
            })
            .await?;
        match resp {
            DaemonResponse::Error(e) => Err(BotError::Daemon(e)),
            _ => Ok(()),
        }
    }

    /// Send a text message to a group.
    ///
    /// # Errors
    ///
    /// Returns `BotError::Ipc` on connection failure or
    /// `BotError::Daemon` if the daemon rejects the request.
    pub async fn send_group_message(&self, group_id: [u8; 32], text: &str) -> Result<(), BotError> {
        let resp = self
            .client
            .request(&DaemonRequest::SendGroupMessage {
                group_id,
                text: text.to_owned(),
            })
            .await?;
        match resp {
            DaemonResponse::Error(e) => Err(BotError::Daemon(e)),
            _ => Ok(()),
        }
    }

    /// Get this bot's own public key (ML-DSA identity address).
    ///
    /// # Errors
    ///
    /// Returns `BotError::Ipc` on connection failure or
    /// `BotError::Daemon` if the daemon returns an error.
    pub async fn my_address(&self) -> Result<Vec<u8>, BotError> {
        let resp = self.client.request(&DaemonRequest::GetMyAddress).await?;
        match resp {
            DaemonResponse::MyAddress(addr) => Ok(addr),
            DaemonResponse::Error(e) => Err(BotError::Daemon(e)),
            _ => Err(BotError::Daemon("unexpected response".into())),
        }
    }

    /// Get the contact list.
    ///
    /// # Errors
    ///
    /// Returns `BotError::Ipc` on connection failure or
    /// `BotError::Daemon` if the daemon returns an error.
    pub async fn contacts(&self) -> Result<Vec<ContactInfo>, BotError> {
        let resp = self.client.request(&DaemonRequest::GetContacts).await?;
        match resp {
            DaemonResponse::Contacts(list) => Ok(list),
            DaemonResponse::Error(e) => Err(BotError::Daemon(e)),
            _ => Err(BotError::Daemon("unexpected response".into())),
        }
    }

    /// Get message history for a contact.
    ///
    /// # Errors
    ///
    /// Returns `BotError::Ipc` on connection failure or
    /// `BotError::Daemon` if the daemon returns an error.
    pub async fn history(
        &self,
        contact: &[u8],
        limit: u32,
    ) -> Result<Vec<StoredMessage>, BotError> {
        let resp = self
            .client
            .request(&DaemonRequest::GetHistory {
                contact: contact.to_vec(),
                limit,
            })
            .await?;
        match resp {
            DaemonResponse::History(msgs) => Ok(msgs),
            DaemonResponse::Error(e) => Err(BotError::Daemon(e)),
            _ => Err(BotError::Daemon("unexpected response".into())),
        }
    }

    /// Send a file to a contact.
    ///
    /// # Errors
    ///
    /// Returns `BotError::Ipc` on connection failure or
    /// `BotError::Daemon` if the daemon rejects the request.
    pub async fn send_file(&self, to: &[u8], path: std::path::PathBuf) -> Result<(), BotError> {
        let resp = self
            .client
            .request(&DaemonRequest::SendFile {
                to: to.to_vec(),
                path,
            })
            .await?;
        match resp {
            DaemonResponse::Error(e) => Err(BotError::Daemon(e)),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bot_context_is_clone() {
        fn assert_clone<T: Clone>() {}
        assert_clone::<BotContext>();
    }
}
