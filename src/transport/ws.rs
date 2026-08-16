//! Direct WebSocket transport: the two ends talk straight to each other.
//!
//! Same shape as the TCP transport, but each frame is one WebSocket **text**
//! message, so no delimiter is needed and the link survives anything that
//! insists on speaking HTTP — corporate proxies, CDNs, PaaS routers that only
//! forward 80/443.
//!
//! The listening end is a bare WebSocket server (no TLS of its own): terminate
//! TLS at a reverse proxy if you need `wss://`. Frame contents are already
//! encrypted under the shared passphrase either way.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, Notify};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_async, connect_async, MaybeTlsStream, WebSocketStream};

use super::link::{next_backoff, Role};
use super::{Inbound, SendError, Transport};

/// No platform limit; big messages mean fewer round trips.
const MAX_MESSAGE_CHARS: usize = 65_536;

type Outbound = futures_util::stream::SplitSink<WsStream, Message>;

/// Either side of the link, unified so one supervisor handles both roles.
enum WsStream {
    Server(WebSocketStream<TcpStream>),
    Client(WebSocketStream<MaybeTlsStream<TcpStream>>),
}

// Delegating Stream/Sink by hand keeps the two concrete socket types behind one
// name without boxing every message.
impl futures_util::Stream for WsStream {
    type Item = Result<Message, tokio_tungstenite::tungstenite::Error>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match self.get_mut() {
            WsStream::Server(s) => std::pin::Pin::new(s).poll_next(cx),
            WsStream::Client(s) => std::pin::Pin::new(s).poll_next(cx),
        }
    }
}

impl futures_util::Sink<Message> for WsStream {
    type Error = tokio_tungstenite::tungstenite::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match self.get_mut() {
            WsStream::Server(s) => std::pin::Pin::new(s).poll_ready(cx),
            WsStream::Client(s) => std::pin::Pin::new(s).poll_ready(cx),
        }
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        match self.get_mut() {
            WsStream::Server(s) => std::pin::Pin::new(s).start_send(item),
            WsStream::Client(s) => std::pin::Pin::new(s).start_send(item),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match self.get_mut() {
            WsStream::Server(s) => std::pin::Pin::new(s).poll_flush(cx),
            WsStream::Client(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match self.get_mut() {
            WsStream::Server(s) => std::pin::Pin::new(s).poll_close(cx),
            WsStream::Client(s) => std::pin::Pin::new(s).poll_close(cx),
        }
    }
}

pub struct WsTransport {
    role: Role,
    // Owned by the supervisor task, not shared: holding a mutex across
    // `accept().await` would block every other user of it indefinitely.
    sink: Mutex<Option<Outbound>>,
    online: AtomicBool,
    online_notify: Notify,
    closing: AtomicBool,
    inbound: Mutex<Option<mpsc::UnboundedSender<Inbound>>>,
    bound_port: Mutex<Option<u16>>,
}

impl WsTransport {
    pub fn new(role: Role) -> Self {
        WsTransport {
            role,
            sink: Mutex::new(None),
            online: AtomicBool::new(false),
            online_notify: Notify::new(),
            closing: AtomicBool::new(false),
            inbound: Mutex::new(None),
            bound_port: Mutex::new(None),
        }
    }

    pub async fn local_port(&self) -> Option<u16> {
        *self.bound_port.lock().await
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

    async fn supervise(self: Arc<Self>, listener: Option<TcpListener>) {
        let mut delay = Duration::from_secs(1);
        while !self.closing.load(Ordering::SeqCst) {
            match self.establish(listener.as_ref()).await {
                Ok(stream) => {
                    delay = Duration::from_secs(1);
                    let (sink, mut stream) = stream.split();
                    *self.sink.lock().await = Some(sink);
                    self.set_online(true);
                    println!("[ws] link up");

                    while let Some(Ok(message)) = stream.next().await {
                        // Text is what we send; ping/pong/close are tungstenite's
                        // business and binary is not ours.
                        if let Message::Text(text) = message {
                            if let Some(tx) = self.inbound.lock().await.as_ref() {
                                let _ = tx.send(Inbound { text: text.to_string(), id: None });
                            }
                        }
                    }

                    self.set_online(false);
                    *self.sink.lock().await = None;
                    if !self.closing.load(Ordering::SeqCst) {
                        println!("[ws] link down; re-establishing");
                    }
                }
                Err(err) => {
                    if self.closing.load(Ordering::SeqCst) {
                        break;
                    }
                    eprintln!("[ws] {err}; retrying in {delay:?}");
                    tokio::time::sleep(delay).await;
                    delay = next_backoff(delay);
                }
            }
        }
    }

    async fn establish(&self, listener: Option<&TcpListener>) -> Result<WsStream> {
        match &self.role {
            Role::Listen(_) => {
                let listener = listener.ok_or_else(|| anyhow!("listener was not bound"))?;
                let (stream, peer) = listener.accept().await?;
                let ws = accept_async(stream)
                    .await
                    .map_err(|e| anyhow!("websocket handshake with {peer}: {e}"))?;
                println!("[ws] accepted {peer}");
                Ok(WsStream::Server(ws))
            }
            Role::Connect(url) => {
                let (ws, _) = connect_async(url)
                    .await
                    .map_err(|e| anyhow!("connecting to {url}: {e}"))?;
                println!("[ws] connected to {url}");
                Ok(WsStream::Client(ws))
            }
        }
    }
}

#[async_trait]
impl Transport for WsTransport {
    fn name(&self) -> &'static str {
        "ws"
    }

    fn max_message_chars(&self) -> usize {
        MAX_MESSAGE_CHARS
    }

    fn send_attempts(&self) -> u32 {
        3
    }

    async fn connect(self: Arc<Self>, inbound: mpsc::UnboundedSender<Inbound>) -> Result<()> {
        *self.inbound.lock().await = Some(inbound);

        let listener = match &self.role {
            Role::Listen(addr) => {
                let listener = TcpListener::bind(addr)
                    .await
                    .map_err(|e| anyhow!("binding {addr}: {e}"))?;
                let port = listener.local_addr()?.port();
                *self.bound_port.lock().await = Some(port);
                println!("[ws] listening on {addr} (port {port})");
                Some(listener)
            }
            Role::Connect(_) => None,
        };

        tokio::spawn(self.clone().supervise(listener));
        Ok(())
    }

    async fn send_message(&self, text: &str) -> Result<(), SendError> {
        self.wait_online().await;
        if self.closing.load(Ordering::SeqCst) {
            return Ok(());
        }
        let mut guard = self.sink.lock().await;
        let sink = guard
            .as_mut()
            .ok_or_else(|| SendError::Transient("link is down".into()))?;
        match sink.send(Message::text(text.to_string())).await {
            Ok(()) => Ok(()),
            Err(err) => {
                drop(guard);
                self.set_online(false);
                Err(SendError::Transient(err.to_string()))
            }
        }
    }

    async fn close(&self) {
        self.closing.store(true, Ordering::SeqCst);
        self.set_online(false);
        if let Some(mut sink) = self.sink.lock().await.take() {
            let _ = sink.close().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizing_leaves_a_large_payload() {
        let tp = WsTransport::new(Role::Connect("ws://127.0.0.1:1".into()));
        assert_eq!(tp.max_message_chars(), 65_536);
        assert!(tp.max_payload() > 40_000, "got {}", tp.max_payload());
    }

    #[tokio::test]
    async fn a_listener_reports_its_bound_port() {
        let tp = Arc::new(WsTransport::new(Role::Listen("127.0.0.1:0".into())));
        let (tx, _rx) = mpsc::unbounded_channel();
        tp.clone().connect(tx).await.unwrap();
        assert!(tp.local_port().await.unwrap() > 0);
        tp.close().await;
    }
}
