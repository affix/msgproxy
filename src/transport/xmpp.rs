//! XMPP transport: frames ride as one-to-one chat messages between two JIDs.
//!
//! Each end logs in as an ordinary account and messages the other directly, so
//! this looks like two people chatting. Any server will do — a public one, or
//! one you run.
//!
//! Reconnection is the library's: `Client::new` uses StartTLS with automatic
//! reconnect, so a dropped stream comes back on its own and queued frames wait
//! for it rather than being discarded.
//!
//! Only chat messages from the configured peer JID are accepted; anything else
//! on the account is ignored. Comparison is on the *bare* JID, so the peer may
//! reconnect under a different resource without the tunnel noticing.

use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::time::timeout;
use tokio_xmpp::jid::{BareJid, Jid};
use tokio_xmpp::parsers::message::{Lang, Message as ChatMessage, MessageType};
use tokio_xmpp::{Client, ClientSender, Event};

use super::{Inbound, SendError, Transport};

/// Servers cap stanza size (ejabberd and Prosody default to 256 KB, but some
/// are far tighter). 16 KB is comfortably inside anything in the wild and still
/// leaves a ~12 KB payload per frame.
const MAX_MESSAGE_CHARS: usize = 16_384;

const ONLINE_TIMEOUT: Duration = Duration::from_secs(60);

pub struct XmppConfig {
    /// Our bare JID, e.g. `tunnel-client@example.org`.
    pub jid: String,
    pub password: String,
    /// The other end's bare JID.
    pub peer: String,
}

pub struct XmppTransport {
    peer: BareJid,
    jid: BareJid,
    password: String,
    sender: Mutex<Option<ClientSender>>,
    online: AtomicBool,
    online_notify: Notify,
    closing: AtomicBool,
    inbound: Mutex<Option<mpsc::UnboundedSender<Inbound>>>,
}

impl XmppTransport {
    pub fn new(cfg: XmppConfig) -> Result<Self> {
        let jid = BareJid::from_str(&cfg.jid).map_err(|e| anyhow!("our JID {:?}: {e}", cfg.jid))?;
        let peer =
            BareJid::from_str(&cfg.peer).map_err(|e| anyhow!("peer JID {:?}: {e}", cfg.peer))?;
        if jid == peer {
            return Err(anyhow!("the two ends must use different JIDs; both are {jid}"));
        }
        Ok(XmppTransport {
            peer,
            jid,
            password: cfg.password,
            sender: Mutex::new(None),
            online: AtomicBool::new(false),
            online_notify: Notify::new(),
            closing: AtomicBool::new(false),
            inbound: Mutex::new(None),
        })
    }

    /// rustls needs one process-wide crypto provider. Several dependencies can
    /// each enable one, so pick explicitly and ignore "already installed".
    pub fn install_crypto_provider() {
        let _ = tokio_xmpp::rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    fn set_online(&self, value: bool) {
        self.online.store(value, Ordering::SeqCst);
        if value {
            self.online_notify.notify_waiters();
        }
    }

    async fn wait_online(&self) {
        while !self.online.load(Ordering::SeqCst) && !self.closing.load(Ordering::SeqCst) {
            self.online_notify.notified().await;
        }
    }

    /// True if a stanza is a chat message from our peer; returns its body.
    ///
    /// Split out from the event loop so the filtering can be tested without a
    /// server: it is the part that decides what enters the tunnel.
    pub fn accept_message(&self, message: &ChatMessage) -> Option<String> {
        if message.type_ == MessageType::Error {
            return None;
        }
        let from = message.from.as_ref()?;
        if from.to_bare() != self.peer {
            return None; // someone else on this account's roster
        }
        message.bodies.get("").cloned()
    }
}

#[async_trait]
impl Transport for XmppTransport {
    fn name(&self) -> &'static str {
        "xmpp"
    }

    fn max_message_chars(&self) -> usize {
        MAX_MESSAGE_CHARS
    }

    fn send_attempts(&self) -> u32 {
        3 // survive a reconnect
    }

    async fn connect(self: Arc<Self>, inbound: mpsc::UnboundedSender<Inbound>) -> Result<()> {
        *self.inbound.lock().await = Some(inbound);
        Self::install_crypto_provider();

        let client = Client::new(self.jid.clone(), self.password.clone());
        let (sender, mut receiver) = client.split();
        *self.sender.lock().await = Some(sender);

        let me = self.clone();
        tokio::spawn(async move {
            while let Some(event) = receiver.next().await {
                match event {
                    Event::Online { bound_jid, .. } => {
                        println!("[xmpp] online as {bound_jid}; messaging {} directly", me.peer);
                        me.set_online(true);
                    }
                    Event::Disconnected(err) => {
                        me.set_online(false);
                        if !me.closing.load(Ordering::SeqCst) {
                            println!("[xmpp] disconnected ({err}); the client will reconnect");
                        }
                    }
                    Event::Stanza(stanza) => {
                        let Ok(message) = ChatMessage::try_from(stanza) else {
                            continue; // presence, iq, or something we don't handle
                        };
                        if let Some(body) = me.accept_message(&message) {
                            if let Some(tx) = me.inbound.lock().await.as_ref() {
                                let _ = tx.send(Inbound { text: body, id: None });
                            }
                        }
                    }
                }
            }
            me.set_online(false);
        });

        // Fail loudly on a bad JID or password rather than retrying silently
        // forever; later drops are the library's to recover from.
        timeout(ONLINE_TIMEOUT, self.wait_online())
            .await
            .map_err(|_| anyhow!("could not log in as {} within 60s", self.jid))?;
        Ok(())
    }

    async fn send_message(&self, text: &str) -> Result<(), SendError> {
        self.wait_online().await;
        if self.closing.load(Ordering::SeqCst) {
            return Ok(());
        }
        let mut message = ChatMessage::new(Some(Jid::from(self.peer.clone())));
        message.type_ = MessageType::Chat;
        message.bodies.insert(Lang::default(), text.to_string());

        // ClientSender isn't Clone, so send through the guard. It serializes
        // sends, which is what we want anyway.
        let guard = self.sender.lock().await;
        let sender = guard
            .as_ref()
            .ok_or_else(|| SendError::Transient("not connected".into()))?;
        match sender.send_stanza(message.into()).await {
            Ok(_) => Ok(()),
            Err(err) => {
                self.set_online(false);
                Err(SendError::Transient(err.to_string()))
            }
        }
    }

    async fn close(&self) {
        self.closing.store(true, Ordering::SeqCst);
        self.set_online(false);
        *self.sender.lock().await = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transport() -> XmppTransport {
        XmppTransport::new(XmppConfig {
            jid: "us@example.org".into(),
            password: "hunter2".into(),
            peer: "them@example.org".into(),
        })
        .unwrap()
    }

    /// `ChatMessage::new` takes the *recipient*, so set `from` explicitly —
    /// that is the field the filter actually reads.
    fn chat_from(from: &str, body: &str) -> ChatMessage {
        let mut message = ChatMessage::new(Some(Jid::from_str("us@example.org").unwrap()));
        message.from = Some(Jid::from_str(from).unwrap());
        message.type_ = MessageType::Chat;
        message.bodies.insert(Lang::default(), body.to_string());
        message
    }

    #[test]
    fn sizing_stays_inside_a_conservative_stanza_limit() {
        let tp = transport();
        assert_eq!(tp.max_message_chars(), 16_384);
        assert!(tp.max_payload() > 12_000, "got {}", tp.max_payload());
    }

    #[test]
    fn rejects_identical_jids() {
        match XmppTransport::new(XmppConfig {
            jid: "same@example.org".into(),
            password: "x".into(),
            peer: "same@example.org".into(),
        }) {
            Ok(_) => panic!("both ends on one JID was accepted"),
            Err(err) => assert!(err.to_string().contains("different JIDs"), "got: {err}"),
        }
    }

    #[test]
    fn rejects_a_malformed_jid() {
        assert!(XmppTransport::new(XmppConfig {
            jid: "not a jid".into(),
            password: "x".into(),
            peer: "them@example.org".into(),
        })
        .is_err());
    }

    #[test]
    fn accepts_a_chat_from_the_peer() {
        let tp = transport();
        let message = chat_from("them@example.org", "SP1|payload");
        assert_eq!(tp.accept_message(&message).as_deref(), Some("SP1|payload"));
    }

    #[test]
    fn accepts_the_peer_under_any_resource() {
        // The peer may reconnect as them@example.org/phone; the bare JID matches.
        let tp = transport();
        let message = chat_from("them@example.org/some-resource", "SP1|payload");
        assert_eq!(tp.accept_message(&message).as_deref(), Some("SP1|payload"));
    }

    #[test]
    fn ignores_messages_from_anyone_else() {
        let tp = transport();
        let message = chat_from("stranger@example.org", "SP1|payload");
        assert!(tp.accept_message(&message).is_none());
    }

    #[test]
    fn ignores_error_messages() {
        // A bounce carries our own text back; treating it as inbound would
        // feed our own frames into the reassembler.
        let tp = transport();
        let mut message = chat_from("them@example.org", "SP1|payload");
        message.type_ = MessageType::Error;
        assert!(tp.accept_message(&message).is_none());
    }

    #[test]
    fn ignores_messages_with_no_body() {
        let tp = transport();
        let mut message = chat_from("them@example.org", "");
        message.bodies.clear(); // e.g. a typing notification
        assert!(tp.accept_message(&message).is_none());
    }

    #[test]
    fn ignores_messages_with_no_sender() {
        let tp = transport();
        let mut message = ChatMessage::new(None);
        message.bodies.insert(Lang::default(), "SP1|payload".into());
        assert!(tp.accept_message(&message).is_none());
    }
}
