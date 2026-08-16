//! The transport interface every backend implements.
//!
//! A transport is the dumb message relay the tunnel rides on. It only has to
//! connect, push inbound messages into a channel, and send one message at a
//! time. Everything else — framing, encryption, queueing, retry, pacing,
//! de-duplication, dispatch — lives in [`crate::tunnel`], so a backend stays
//! small and every platform behaves the same way.

use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::frame::payload_budget;

pub mod discord;
pub mod irc;
pub mod link;
pub mod tcp;
pub mod udp;
pub mod whatsapp;
pub mod ws;
pub mod xmpp;

/// One message received from the platform.
pub struct Inbound {
    pub text: String,
    /// Platform message ID, where there is one. Used to drop re-deliveries on
    /// at-least-once platforms; `None` means "no ID, can't de-duplicate".
    pub id: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// Will never succeed on retry — bad credentials, a closed messaging
    /// window, an unknown recipient.
    #[error("{0}")]
    Permanent(String),
    /// Worth another go: rate limited, server error, connection dropped.
    #[error("{0}")]
    Transient(String),
}

#[async_trait]
pub trait Transport: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    /// Hard character limit for one message on this platform. Everything about
    /// sizing derives from this.
    fn max_message_chars(&self) -> usize;

    /// Largest raw payload per frame.
    fn max_payload(&self) -> usize {
        payload_budget(self.max_message_chars())
    }

    /// How many sends may be in flight. Frames carry sequence numbers and both
    /// ends reassemble in order, so parallel sends are safe.
    fn concurrency(&self) -> usize {
        1
    }

    fn send_attempts(&self) -> u32 {
        1
    }

    fn retry_delay(&self) -> Duration {
        Duration::from_millis(500)
    }

    /// Minimum gap between sends, for platforms with flood protection.
    fn min_interval(&self) -> Duration {
        Duration::ZERO
    }

    /// Bring the backend up, and start feeding `inbound`. Must return once
    /// messages can be sent and received.
    ///
    /// Takes `Arc<Self>` because backends spawn long-lived read loops that
    /// outlive the call and need to hold onto themselves.
    async fn connect(
        self: std::sync::Arc<Self>,
        inbound: mpsc::UnboundedSender<Inbound>,
    ) -> anyhow::Result<()>;

    async fn send_message(&self, text: &str) -> Result<(), SendError>;

    async fn close(&self) {}
}
