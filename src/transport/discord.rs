//! Discord transport.
//!
//! Frames ride as ordinary messages in one channel. Outbound messages are sent
//! one at a time to stay friendly with Discord's per-channel rate limits, which
//! serenity's HTTP layer already backs off against — so no extra retry or
//! pacing is configured here.
//!
//! The client stamps frames `C` and the exit node stamps them `S`, and each
//! side ignores its own, so one bot token can drive both ends.
//!
//! The gateway connection is serenity's. The parts worth testing on their own —
//! which messages we accept, and how send failures are classified — are behind
//! [`ChannelSink`] and [`DiscordTransport::accept`], so they can be exercised
//! without a live token.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serenity::all::{ChannelId, GatewayIntents, Http};
use serenity::client::{Context, EventHandler};
use serenity::model::channel::Message;
use serenity::model::gateway::Ready;
use tokio::sync::{mpsc, Mutex, Notify};

use super::{Inbound, SendError, Transport};

/// Discord's hard per-message limit.
const MAX_MESSAGE_CHARS: usize = 2000;

pub struct DiscordConfig {
    pub token: String,
    pub channel_id: u64,
}

/// Where outbound messages actually go. Production uses Discord's REST API;
/// tests substitute their own so the whole tunnel can run without a token.
#[async_trait]
pub trait ChannelSink: Send + Sync + 'static {
    async fn send(&self, text: &str) -> Result<(), SendError>;
}

/// The real thing: POST to the channel over Discord's REST API.
pub struct RestSink {
    http: Arc<Http>,
    channel: ChannelId,
}

#[async_trait]
impl ChannelSink for RestSink {
    async fn send(&self, text: &str) -> Result<(), SendError> {
        self.channel
            .say(&self.http, text)
            .await
            .map(|_| ())
            // serenity already retries 429s internally, so anything surfacing
            // here is worth one more go from our side.
            .map_err(|e| SendError::Transient(e.to_string()))
    }
}

pub struct DiscordTransport {
    channel_id: u64,
    token: String,
    sink: Mutex<Option<Arc<dyn ChannelSink>>>,
    inbound: Arc<Mutex<Option<mpsc::UnboundedSender<Inbound>>>>,
    ready: Arc<Notify>,
}

impl DiscordTransport {
    pub fn new(cfg: DiscordConfig) -> Self {
        DiscordTransport {
            channel_id: cfg.channel_id,
            token: cfg.token,
            sink: Mutex::new(None),
            inbound: Arc::new(Mutex::new(None)),
            ready: Arc::new(Notify::new()),
        }
    }

    /// Build with a caller-supplied sink, bypassing the gateway. For tests.
    ///
    /// Sets the field directly rather than locking: `blocking_lock` would panic
    /// inside a tokio runtime, which is exactly where tests call this.
    #[doc(hidden)]
    pub fn with_sink(cfg: DiscordConfig, sink: Arc<dyn ChannelSink>) -> Self {
        let mut tp = DiscordTransport::new(cfg);
        tp.sink = Mutex::new(Some(sink));
        tp
    }

    /// Decide whether a channel message is one of ours to dispatch.
    ///
    /// A bot may sit in several channels; only the configured one counts.
    pub fn accept(&self, channel_id: u64, content: String, id: u64) -> Option<Inbound> {
        if channel_id != self.channel_id {
            return None;
        }
        Some(Inbound { text: content, id: Some(id.to_string()) })
    }

    /// Feed a message in as if the gateway had delivered it. For tests.
    #[doc(hidden)]
    pub async fn deliver_for_test(&self, channel_id: u64, content: String, id: u64) {
        if let Some(inbound) = self.accept(channel_id, content, id) {
            if let Some(tx) = self.inbound.lock().await.as_ref() {
                let _ = tx.send(inbound);
            }
        }
    }

    #[doc(hidden)]
    pub async fn set_inbound_for_test(&self, tx: mpsc::UnboundedSender<Inbound>) {
        *self.inbound.lock().await = Some(tx);
    }
}

struct Handler {
    channel_id: u64,
    inbound: Arc<Mutex<Option<mpsc::UnboundedSender<Inbound>>>>,
    ready: Arc<Notify>,
}

#[async_trait]
impl EventHandler for Handler {
    async fn message(&self, _ctx: Context, message: Message) {
        if message.channel_id.get() != self.channel_id {
            return;
        }
        if let Some(tx) = self.inbound.lock().await.as_ref() {
            let _ = tx.send(Inbound {
                text: message.content.clone(),
                id: Some(message.id.get().to_string()),
            });
        }
    }

    async fn ready(&self, _ctx: Context, ready: Ready) {
        println!("[discord] connected as {}", ready.user.name);
        self.ready.notify_waiters();
    }
}

#[async_trait]
impl Transport for DiscordTransport {
    fn name(&self) -> &'static str {
        "discord"
    }

    fn max_message_chars(&self) -> usize {
        MAX_MESSAGE_CHARS
    }

    fn concurrency(&self) -> usize {
        1 // serial: the per-channel rate limit is tight
    }

    async fn connect(self: Arc<Self>, inbound: mpsc::UnboundedSender<Inbound>) -> Result<()> {
        *self.inbound.lock().await = Some(inbound);

        // A sink may already be installed by a test, in which case there is no
        // gateway to bring up.
        if self.sink.lock().await.is_some() {
            return Ok(());
        }

        let http = Arc::new(Http::new(&self.token));
        *self.sink.lock().await = Some(Arc::new(RestSink {
            http: http.clone(),
            channel: ChannelId::new(self.channel_id),
        }));

        // MESSAGE_CONTENT is privileged and must be enabled in the dev portal;
        // without it every message body arrives empty.
        let intents = GatewayIntents::GUILD_MESSAGES
            | GatewayIntents::DIRECT_MESSAGES
            | GatewayIntents::MESSAGE_CONTENT;

        let handler = Handler {
            channel_id: self.channel_id,
            inbound: self.inbound.clone(),
            ready: self.ready.clone(),
        };
        let mut client = serenity::Client::builder(&self.token, intents)
            .event_handler(handler)
            .await
            .map_err(|e| anyhow!("building the Discord client: {e}"))?;

        tokio::spawn(async move {
            if let Err(err) = client.start().await {
                eprintln!("[discord] gateway stopped: {err}");
            }
        });

        self.ready.notified().await;
        println!("[discord] watching channel {}", self.channel_id);
        Ok(())
    }

    async fn send_message(&self, text: &str) -> Result<(), SendError> {
        let sink = self.sink.lock().await.clone();
        match sink {
            Some(sink) => sink.send(text).await,
            None => Err(SendError::Transient("not connected".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHANNEL: u64 = 123456789012345678;

    fn transport() -> DiscordTransport {
        DiscordTransport::new(DiscordConfig { token: "t".into(), channel_id: CHANNEL })
    }

    #[test]
    fn message_limit_matches_discord() {
        let tp = transport();
        assert_eq!(tp.max_message_chars(), 2000);
        assert_eq!(tp.max_payload(), 1429);
    }

    #[test]
    fn accepts_messages_from_the_configured_channel() {
        let tp = transport();
        let inbound = tp.accept(CHANNEL, "SP1|abc".into(), 42).unwrap();
        assert_eq!(inbound.text, "SP1|abc");
        assert_eq!(inbound.id.as_deref(), Some("42"));
    }

    #[test]
    fn ignores_other_channels() {
        // A bot in several channels must only listen to the configured one.
        assert!(transport().accept(999, "SP1|abc".into(), 42).is_none());
    }

    #[test]
    fn message_ids_are_carried_for_deduplication() {
        let tp = transport();
        let a = tp.accept(CHANNEL, "x".into(), 1).unwrap();
        let b = tp.accept(CHANNEL, "x".into(), 2).unwrap();
        assert_ne!(a.id, b.id);
    }
}
