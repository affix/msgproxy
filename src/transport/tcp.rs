//! Direct TCP transport: the two ends talk straight to each other.
//!
//! No platform in the middle, so there is no rate limit and no message-size cap
//! beyond what we choose. Messages are newline-delimited, which is safe because
//! an encoded frame is base64 plus a marker prefix — never a newline.
//!
//! Useful when you can reach the exit node directly and just want the framing,
//! and as the fastest way to exercise the tunnel end to end.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, Notify};

use super::link::{next_backoff, Role};
use super::{Inbound, SendError, Transport};

/// Generous: there is no platform limit here, and bigger messages mean fewer
/// round trips. Leaves a ~48 KB payload per frame.
const MAX_MESSAGE_CHARS: usize = 65_536;

pub struct TcpTransport {
    role: Role,
    // The listener is owned by the supervisor task, not shared: holding a mutex
    // across `accept().await` would block every other user of it indefinitely.
    writer: Mutex<Option<OwnedWriteHalf>>,
    online: AtomicBool,
    online_notify: Notify,
    closing: AtomicBool,
    inbound: Mutex<Option<mpsc::UnboundedSender<Inbound>>>,
    bound_port: Mutex<Option<u16>>,
}

impl TcpTransport {
    pub fn new(role: Role) -> Self {
        TcpTransport {
            role,
            writer: Mutex::new(None),
            online: AtomicBool::new(false),
            online_notify: Notify::new(),
            closing: AtomicBool::new(false),
            inbound: Mutex::new(None),
            bound_port: Mutex::new(None),
        }
    }

    /// The port actually bound, when listening. Tests pass :0 and read it back.
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

    /// Keep the link up: accept or dial, pump until it drops, repeat.
    async fn supervise(self: Arc<Self>, listener: Option<TcpListener>) {
        let mut delay = Duration::from_secs(1);
        while !self.closing.load(Ordering::SeqCst) {
            match self.establish(listener.as_ref()).await {
                Ok(stream) => {
                    delay = Duration::from_secs(1);
                    let (reader, writer) = stream.into_split();
                    *self.writer.lock().await = Some(writer);
                    self.set_online(true);
                    println!("[tcp] link up");

                    let mut lines = BufReader::new(reader).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        if line.is_empty() {
                            continue;
                        }
                        if let Some(tx) = self.inbound.lock().await.as_ref() {
                            let _ = tx.send(Inbound { text: line, id: None });
                        }
                    }

                    self.set_online(false);
                    *self.writer.lock().await = None;
                    if !self.closing.load(Ordering::SeqCst) {
                        println!("[tcp] link down; re-establishing");
                    }
                }
                Err(err) => {
                    if self.closing.load(Ordering::SeqCst) {
                        break;
                    }
                    eprintln!("[tcp] {err}; retrying in {delay:?}");
                    tokio::time::sleep(delay).await;
                    delay = next_backoff(delay);
                }
            }
        }
    }

    async fn establish(&self, listener: Option<&TcpListener>) -> Result<TcpStream> {
        match &self.role {
            Role::Listen(_) => {
                let listener = listener.ok_or_else(|| anyhow!("listener was not bound"))?;
                let (stream, peer) = listener.accept().await?;
                println!("[tcp] accepted {peer}");
                Ok(stream)
            }
            Role::Connect(addr) => {
                let stream = TcpStream::connect(addr)
                    .await
                    .map_err(|e| anyhow!("connecting to {addr}: {e}"))?;
                println!("[tcp] connected to {addr}");
                Ok(stream)
            }
        }
    }
}

#[async_trait]
impl Transport for TcpTransport {
    fn name(&self) -> &'static str {
        "tcp"
    }

    fn max_message_chars(&self) -> usize {
        MAX_MESSAGE_CHARS
    }

    fn send_attempts(&self) -> u32 {
        3 // survive a reconnect
    }

    async fn connect(self: Arc<Self>, inbound: mpsc::UnboundedSender<Inbound>) -> Result<()> {
        *self.inbound.lock().await = Some(inbound);

        // Bind up front so the port is known before anyone dials us, and so a
        // bad address fails now rather than inside the supervisor loop.
        let listener = match &self.role {
            Role::Listen(addr) => {
                let listener = TcpListener::bind(addr)
                    .await
                    .map_err(|e| anyhow!("binding {addr}: {e}"))?;
                let port = listener.local_addr()?.port();
                *self.bound_port.lock().await = Some(port);
                println!("[tcp] listening on {addr} (port {port})");
                Some(listener)
            }
            Role::Connect(_) => None,
        };

        // Returns immediately: sends wait for the link, so the exit node can
        // come up before the client exists.
        tokio::spawn(self.clone().supervise(listener));
        Ok(())
    }

    async fn send_message(&self, text: &str) -> Result<(), SendError> {
        self.wait_online().await;
        if self.closing.load(Ordering::SeqCst) {
            return Ok(());
        }
        let mut guard = self.writer.lock().await;
        let writer = guard
            .as_mut()
            .ok_or_else(|| SendError::Transient("link is down".into()))?;
        let mut line = text.as_bytes().to_vec();
        line.push(b'\n');
        match writer.write_all(&line).await {
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
        if let Some(mut writer) = self.writer.lock().await.take() {
            let _ = writer.shutdown().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizing_leaves_a_large_payload() {
        let tp = TcpTransport::new(Role::Connect("127.0.0.1:1".into()));
        assert_eq!(tp.max_message_chars(), 65_536);
        assert!(tp.max_payload() > 40_000, "got {}", tp.max_payload());
    }

    #[tokio::test]
    async fn binding_a_bad_address_fails_at_connect() {
        let tp = Arc::new(TcpTransport::new(Role::Listen("256.256.256.256:9".into())));
        let (tx, _rx) = mpsc::unbounded_channel();
        assert!(tp.connect(tx).await.is_err());
    }

    #[tokio::test]
    async fn a_listener_reports_its_bound_port() {
        let tp = Arc::new(TcpTransport::new(Role::Listen("127.0.0.1:0".into())));
        let (tx, _rx) = mpsc::unbounded_channel();
        tp.clone().connect(tx).await.unwrap();
        assert!(tp.local_port().await.unwrap() > 0);
        tp.close().await;
    }
}
