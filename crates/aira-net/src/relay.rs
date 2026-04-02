//! Store-and-forward relay with pairwise mailboxes.
//!
//! Relay stores encrypted envelopes (≤64 KB each) for offline peers.
//! Relay NEVER stores file content — only message notifications.
//! `Mailbox ID = BLAKE3(shared_secret || "mailbox")` — pairwise, unlinkable.
//!
//! Quotas: 10 MB / 100 msgs per mailbox, TTL 7 days.
//! See SPEC.md §6.3b, §6.5, §11B.5.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aira_core::proto::EncryptedEnvelope;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::connection::{read_framed, write_framed};
use crate::NetError;

// ─── Constants ───────────────────────────────────────────────────────────────

/// KDF context for mailbox ID derivation.
const MAILBOX_KDF_CONTEXT: &str = "aira/relay/mailbox/v1";

// ─── Wire protocol ──────────────────────────────────────────────────────────

/// Client → Relay request.
#[derive(Debug, Serialize, Deserialize)]
pub enum RelayRequest {
    /// Deposit an encrypted envelope into a mailbox.
    Deposit {
        mailbox_id: [u8; 32],
        envelope: EncryptedEnvelope,
    },
    /// Retrieve all envelopes from a mailbox.
    Retrieve { mailbox_id: [u8; 32] },
    /// Acknowledge receipt of envelopes (by counter), allowing relay to delete them.
    Ack {
        mailbox_id: [u8; 32],
        counters: Vec<u64>,
    },
    /// Delete a mailbox entirely.
    DeleteMailbox { mailbox_id: [u8; 32] },
}

/// Relay → Client response.
#[derive(Debug, Serialize, Deserialize)]
pub enum RelayResponse {
    /// Envelope deposited successfully.
    DepositOk,
    /// Retrieved envelopes.
    Envelopes { envelopes: Vec<EncryptedEnvelope> },
    /// Acknowledgement processed.
    AckOk,
    /// Mailbox deleted.
    Deleted,
    /// Error response.
    Error {
        code: RelayErrorCode,
        message: String,
    },
}

/// Relay error codes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RelayErrorCode {
    MailboxFull,
    MailboxNotFound,
    EnvelopeTooLarge,
    RateLimited,
    Internal,
}

// ─── Mailbox ID derivation ──────────────────────────────────────────────────

/// Derive a deterministic mailbox ID from a shared secret.
///
/// Both peers compute the same ID: `BLAKE3-KDF("aira/relay/mailbox/v1", shared_secret)`.
#[must_use]
pub fn derive_mailbox_id(shared_secret: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(MAILBOX_KDF_CONTEXT, shared_secret)
}

// ─── Relay configuration ────────────────────────────────────────────────────

/// Configuration for the relay server.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Max envelopes per mailbox.
    pub max_envelopes: usize,
    /// Max total bytes per mailbox.
    pub max_bytes: usize,
    /// Max single envelope size.
    pub max_envelope_size: usize,
    /// Mailbox TTL before garbage collection.
    pub ttl: Duration,
    /// GC sweep interval.
    pub gc_interval: Duration,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_envelopes: 100,
            max_bytes: 10 * 1024 * 1024,             // 10 MB
            max_envelope_size: 64 * 1024,            // 64 KB
            ttl: Duration::from_secs(7 * 24 * 3600), // 7 days
            gc_interval: Duration::from_secs(60),
        }
    }
}

// ─── Server-side relay ──────────────────────────────────────────────────────

/// A stored envelope with timestamp for TTL tracking.
#[derive(Debug)]
struct StoredEnvelope {
    envelope: EncryptedEnvelope,
    #[allow(dead_code)]
    received_at: Instant,
    size: usize,
}

/// A pairwise mailbox.
#[derive(Debug)]
struct Mailbox {
    envelopes: VecDeque<StoredEnvelope>,
    total_bytes: usize,
    last_activity: Instant,
}

impl Mailbox {
    fn new() -> Self {
        Self {
            envelopes: VecDeque::new(),
            total_bytes: 0,
            last_activity: Instant::now(),
        }
    }
}

/// In-memory relay server implementing [`ProtocolHandler`] for `aira/1/relay`.
#[derive(Debug)]
pub struct RelayServer {
    mailboxes: Arc<RwLock<HashMap<[u8; 32], Mailbox>>>,
    config: RelayConfig,
}

impl RelayServer {
    /// Create a new relay server with the given configuration.
    #[must_use]
    pub fn new(config: RelayConfig) -> Self {
        Self {
            mailboxes: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Create a relay server with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(RelayConfig::default())
    }

    /// Spawn a background garbage collection task.
    ///
    /// Removes mailboxes that have been inactive for longer than `config.ttl`.
    /// Returns a handle that can be used to cancel the task.
    pub fn spawn_gc(&self, cancel: CancellationToken) {
        let mailboxes = Arc::clone(&self.mailboxes);
        let ttl = self.config.ttl;
        let interval = self.config.gc_interval;

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = cancel.cancelled() => break,
                    () = tokio::time::sleep(interval) => {
                        let mut mboxes = mailboxes.write().await;
                        let now = Instant::now();
                        let before = mboxes.len();
                        mboxes.retain(|_, mb| now.duration_since(mb.last_activity) < ttl);
                        let removed = before - mboxes.len();
                        if removed > 0 {
                            debug!(removed, "relay GC: removed expired mailboxes");
                        }
                    }
                }
            }
        });
    }

    /// Handle a single relay request.
    async fn handle_request(&self, req: RelayRequest) -> RelayResponse {
        match req {
            RelayRequest::Deposit {
                mailbox_id,
                envelope,
            } => self.handle_deposit(mailbox_id, envelope).await,
            RelayRequest::Retrieve { mailbox_id } => self.handle_retrieve(mailbox_id).await,
            RelayRequest::Ack {
                mailbox_id,
                counters,
            } => self.handle_ack(mailbox_id, &counters).await,
            RelayRequest::DeleteMailbox { mailbox_id } => self.handle_delete(mailbox_id).await,
        }
    }

    async fn handle_deposit(
        &self,
        mailbox_id: [u8; 32],
        envelope: EncryptedEnvelope,
    ) -> RelayResponse {
        let env_size = envelope.ciphertext.len() + 12 + 8; // nonce + counter + ciphertext
        if env_size > self.config.max_envelope_size {
            return RelayResponse::Error {
                code: RelayErrorCode::EnvelopeTooLarge,
                message: format!(
                    "envelope {} bytes exceeds max {}",
                    env_size, self.config.max_envelope_size
                ),
            };
        }

        let mut mailboxes = self.mailboxes.write().await;
        let mailbox = mailboxes.entry(mailbox_id).or_insert_with(Mailbox::new);

        if mailbox.envelopes.len() >= self.config.max_envelopes {
            return RelayResponse::Error {
                code: RelayErrorCode::MailboxFull,
                message: format!(
                    "mailbox has {}/{} envelopes",
                    mailbox.envelopes.len(),
                    self.config.max_envelopes
                ),
            };
        }

        if mailbox.total_bytes + env_size > self.config.max_bytes {
            return RelayResponse::Error {
                code: RelayErrorCode::MailboxFull,
                message: format!(
                    "mailbox would exceed byte limit: {} + {} > {}",
                    mailbox.total_bytes, env_size, self.config.max_bytes
                ),
            };
        }

        mailbox.total_bytes += env_size;
        mailbox.last_activity = Instant::now();
        mailbox.envelopes.push_back(StoredEnvelope {
            envelope,
            received_at: Instant::now(),
            size: env_size,
        });

        RelayResponse::DepositOk
    }

    async fn handle_retrieve(&self, mailbox_id: [u8; 32]) -> RelayResponse {
        let mailboxes = self.mailboxes.read().await;
        match mailboxes.get(&mailbox_id) {
            Some(mailbox) => RelayResponse::Envelopes {
                envelopes: mailbox
                    .envelopes
                    .iter()
                    .map(|s| s.envelope.clone())
                    .collect(),
            },
            None => RelayResponse::Envelopes {
                envelopes: Vec::new(),
            },
        }
    }

    async fn handle_ack(&self, mailbox_id: [u8; 32], counters: &[u64]) -> RelayResponse {
        let mut mailboxes = self.mailboxes.write().await;
        match mailboxes.get_mut(&mailbox_id) {
            Some(mailbox) => {
                mailbox.envelopes.retain(|stored| {
                    let keep = !counters.contains(&stored.envelope.counter);
                    if !keep {
                        mailbox.total_bytes = mailbox.total_bytes.saturating_sub(stored.size);
                    }
                    keep
                });
                mailbox.last_activity = Instant::now();
                RelayResponse::AckOk
            }
            None => RelayResponse::AckOk, // Idempotent — ack on missing mailbox is fine
        }
    }

    async fn handle_delete(&self, mailbox_id: [u8; 32]) -> RelayResponse {
        let mut mailboxes = self.mailboxes.write().await;
        mailboxes.remove(&mailbox_id);
        RelayResponse::Deleted
    }

    /// Number of active mailboxes (for testing/monitoring).
    pub async fn mailbox_count(&self) -> usize {
        self.mailboxes.read().await.len()
    }
}

impl ProtocolHandler for RelayServer {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(AcceptError::from_err)?;

        // Process relay requests until the stream closes
        loop {
            let req: RelayRequest = match read_framed(&mut recv).await {
                Ok(req) => req,
                Err(NetError::Stream(_)) => break, // Stream closed — normal
                Err(e) => {
                    warn!("relay: failed to read request: {e}");
                    break;
                }
            };

            let resp = self.handle_request(req).await;

            if let Err(e) = write_framed(&mut send, &resp).await {
                warn!("relay: failed to write response: {e}");
                break;
            }
        }

        Ok(())
    }
}

// ─── Client-side relay ──────────────────────────────────────────────────────

/// Client for interacting with a relay server.
#[derive(Debug, Clone)]
pub struct RelayClient {
    endpoint: crate::endpoint::AiraEndpoint,
    relay_addr: iroh::EndpointAddr,
}

impl RelayClient {
    /// Create a new relay client targeting a specific relay server.
    #[must_use]
    pub fn new(endpoint: crate::endpoint::AiraEndpoint, relay_addr: iroh::EndpointAddr) -> Self {
        Self {
            endpoint,
            relay_addr,
        }
    }

    /// Execute a single request-response exchange with the relay.
    async fn request(&self, req: &RelayRequest) -> Result<RelayResponse, NetError> {
        let conn = self
            .endpoint
            .connect(self.relay_addr.clone(), crate::alpn::RELAY)
            .await?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| NetError::Relay(e.to_string()))?;

        write_framed(&mut send, req).await?;

        // Read response before finishing the stream
        let resp: RelayResponse = read_framed(&mut recv).await?;

        // Now we can close
        send.finish().map_err(|e| NetError::Stream(e.to_string()))?;

        Ok(resp)
    }

    /// Deposit an encrypted envelope into a mailbox.
    pub async fn deposit(
        &self,
        mailbox_id: [u8; 32],
        envelope: EncryptedEnvelope,
    ) -> Result<(), NetError> {
        let resp = self
            .request(&RelayRequest::Deposit {
                mailbox_id,
                envelope,
            })
            .await?;

        match resp {
            RelayResponse::DepositOk => Ok(()),
            RelayResponse::Error { code, message } => match code {
                RelayErrorCode::MailboxFull => Err(NetError::MailboxFull { current: 0, max: 0 }),
                RelayErrorCode::EnvelopeTooLarge => {
                    Err(NetError::EnvelopeTooLarge { size: 0, max: 0 })
                }
                _ => Err(NetError::Relay(message)),
            },
            _ => Err(NetError::Relay("unexpected response".into())),
        }
    }

    /// Retrieve all envelopes from a mailbox.
    pub async fn retrieve(&self, mailbox_id: [u8; 32]) -> Result<Vec<EncryptedEnvelope>, NetError> {
        let resp = self.request(&RelayRequest::Retrieve { mailbox_id }).await?;

        match resp {
            RelayResponse::Envelopes { envelopes } => Ok(envelopes),
            RelayResponse::Error { message, .. } => Err(NetError::Relay(message)),
            _ => Err(NetError::Relay("unexpected response".into())),
        }
    }

    /// Acknowledge receipt of envelopes (by counter) so the relay can delete them.
    pub async fn ack(&self, mailbox_id: [u8; 32], counters: Vec<u64>) -> Result<(), NetError> {
        let resp = self
            .request(&RelayRequest::Ack {
                mailbox_id,
                counters,
            })
            .await?;

        match resp {
            RelayResponse::AckOk => Ok(()),
            RelayResponse::Error { message, .. } => Err(NetError::Relay(message)),
            _ => Err(NetError::Relay("unexpected response".into())),
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_mailbox_id_deterministic() {
        let secret = [42u8; 32];
        let id1 = derive_mailbox_id(&secret);
        let id2 = derive_mailbox_id(&secret);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_derive_mailbox_id_different_secrets() {
        let s1 = [1u8; 32];
        let s2 = [2u8; 32];
        assert_ne!(derive_mailbox_id(&s1), derive_mailbox_id(&s2));
    }

    fn make_envelope(counter: u64, size: usize) -> EncryptedEnvelope {
        EncryptedEnvelope {
            nonce: [0u8; 12],
            counter,
            ciphertext: vec![0u8; size],
        }
    }

    #[tokio::test]
    async fn test_relay_deposit_retrieve() {
        let server = RelayServer::with_defaults();
        let mailbox_id = [99u8; 32];

        let env = make_envelope(1, 100);
        let resp = server
            .handle_request(RelayRequest::Deposit {
                mailbox_id,
                envelope: env.clone(),
            })
            .await;
        assert!(matches!(resp, RelayResponse::DepositOk));

        let resp = server
            .handle_request(RelayRequest::Retrieve { mailbox_id })
            .await;
        match resp {
            RelayResponse::Envelopes { envelopes } => {
                assert_eq!(envelopes.len(), 1);
                assert_eq!(envelopes[0].counter, 1);
            }
            _ => panic!("expected Envelopes"),
        }
    }

    #[tokio::test]
    async fn test_relay_mailbox_quota_messages() {
        let config = RelayConfig {
            max_envelopes: 3,
            ..RelayConfig::default()
        };
        let server = RelayServer::new(config);
        let mailbox_id = [1u8; 32];

        for i in 0..3 {
            let resp = server
                .handle_request(RelayRequest::Deposit {
                    mailbox_id,
                    envelope: make_envelope(i, 10),
                })
                .await;
            assert!(matches!(resp, RelayResponse::DepositOk));
        }

        // 4th should fail
        let resp = server
            .handle_request(RelayRequest::Deposit {
                mailbox_id,
                envelope: make_envelope(3, 10),
            })
            .await;
        assert!(matches!(
            resp,
            RelayResponse::Error {
                code: RelayErrorCode::MailboxFull,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_relay_mailbox_quota_bytes() {
        let config = RelayConfig {
            max_bytes: 200,
            ..RelayConfig::default()
        };
        let server = RelayServer::new(config);
        let mailbox_id = [2u8; 32];

        // First envelope: ~120 bytes total (100 ciphertext + nonce + counter overhead)
        let resp = server
            .handle_request(RelayRequest::Deposit {
                mailbox_id,
                envelope: make_envelope(0, 100),
            })
            .await;
        assert!(matches!(resp, RelayResponse::DepositOk));

        // Second should exceed 200 byte limit
        let resp = server
            .handle_request(RelayRequest::Deposit {
                mailbox_id,
                envelope: make_envelope(1, 100),
            })
            .await;
        assert!(matches!(
            resp,
            RelayResponse::Error {
                code: RelayErrorCode::MailboxFull,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_relay_envelope_too_large() {
        let config = RelayConfig {
            max_envelope_size: 50,
            ..RelayConfig::default()
        };
        let server = RelayServer::new(config);
        let mailbox_id = [3u8; 32];

        let resp = server
            .handle_request(RelayRequest::Deposit {
                mailbox_id,
                envelope: make_envelope(0, 100),
            })
            .await;
        assert!(matches!(
            resp,
            RelayResponse::Error {
                code: RelayErrorCode::EnvelopeTooLarge,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_relay_ack_deletes() {
        let server = RelayServer::with_defaults();
        let mailbox_id = [4u8; 32];

        // Deposit 3 envelopes
        for i in 0..3 {
            server
                .handle_request(RelayRequest::Deposit {
                    mailbox_id,
                    envelope: make_envelope(i, 10),
                })
                .await;
        }

        // Ack counters 0 and 2
        let resp = server
            .handle_request(RelayRequest::Ack {
                mailbox_id,
                counters: vec![0, 2],
            })
            .await;
        assert!(matches!(resp, RelayResponse::AckOk));

        // Only counter=1 should remain
        let resp = server
            .handle_request(RelayRequest::Retrieve { mailbox_id })
            .await;
        match resp {
            RelayResponse::Envelopes { envelopes } => {
                assert_eq!(envelopes.len(), 1);
                assert_eq!(envelopes[0].counter, 1);
            }
            _ => panic!("expected Envelopes"),
        }
    }

    #[tokio::test]
    async fn test_relay_delete_mailbox() {
        let server = RelayServer::with_defaults();
        let mailbox_id = [5u8; 32];

        server
            .handle_request(RelayRequest::Deposit {
                mailbox_id,
                envelope: make_envelope(0, 10),
            })
            .await;

        assert_eq!(server.mailbox_count().await, 1);

        let resp = server
            .handle_request(RelayRequest::DeleteMailbox { mailbox_id })
            .await;
        assert!(matches!(resp, RelayResponse::Deleted));
        assert_eq!(server.mailbox_count().await, 0);
    }

    #[tokio::test]
    async fn test_relay_gc_ttl() {
        let config = RelayConfig {
            ttl: Duration::from_millis(50),
            gc_interval: Duration::from_millis(30),
            ..RelayConfig::default()
        };
        let server = RelayServer::new(config);
        let mailbox_id = [6u8; 32];

        server
            .handle_request(RelayRequest::Deposit {
                mailbox_id,
                envelope: make_envelope(0, 10),
            })
            .await;
        assert_eq!(server.mailbox_count().await, 1);

        let cancel = CancellationToken::new();
        server.spawn_gc(cancel.clone());

        // Wait for TTL to expire + GC to run
        tokio::time::sleep(Duration::from_millis(150)).await;

        assert_eq!(server.mailbox_count().await, 0);
        cancel.cancel();
    }
}
