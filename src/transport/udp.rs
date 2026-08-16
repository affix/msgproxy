//! Direct UDP transport, with just enough reliability to be usable.
//!
//! The tunnel's reassembler waits for a missing sequence number forever, so a
//! single lost datagram would stall that stream permanently. Raw UDP is
//! therefore not good enough; this transport adds a small acknowledge-and-
//! retransmit layer of its own.
//!
//! Datagram layout:
//!
//! ```text
//! kind : 1 byte   - 0 = DATA, 1 = ACK
//! seq  : 8 bytes  - per-sender, monotonic
//! body : DATA only, the encoded message
//! ```
//!
//! Every DATA is retransmitted on a timer until the peer acknowledges it or we
//! give up, and each side acknowledges immediately on receipt. Duplicates are
//! expected and harmless: the tunnel de-duplicates on the sequence number.
//!
//! This is not a congestion-controlled protocol. It fixes "one lost packet
//! stalls a stream forever"; it does not make UDP a good idea over a congested
//! path. Prefer the TCP or WebSocket transport where you can.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::time::Instant;

use super::link::Role;
use super::{Inbound, SendError, Transport};

const KIND_DATA: u8 = 0;
const KIND_ACK: u8 = 1;
const HEADER: usize = 9;

/// Keeps the datagram inside a common MTU, leaving ~741 bytes of payload.
const MAX_MESSAGE_CHARS: usize = 1100;

const RETRANSMIT_TICK: Duration = Duration::from_millis(100);
const INITIAL_RTO: Duration = Duration::from_millis(400);
const MAX_RTO: Duration = Duration::from_secs(8);
const MAX_ATTEMPTS: u32 = 10;

struct Pending {
    datagram: Vec<u8>,
    attempts: u32,
    sent_at: Instant,
    rto: Duration,
}

pub struct UdpTransport {
    role: Role,
    socket: Mutex<Option<Arc<UdpSocket>>>,
    /// Where to send. Known up front when dialling; learned from the first
    /// datagram when listening.
    peer: Mutex<Option<SocketAddr>>,
    next_seq: AtomicU64,
    unacked: Mutex<HashMap<u64, Pending>>,
    online: AtomicBool,
    online_notify: Notify,
    closing: AtomicBool,
    inbound: Mutex<Option<mpsc::UnboundedSender<Inbound>>>,
    bound_port: Mutex<Option<u16>>,
}

impl UdpTransport {
    pub fn new(role: Role) -> Self {
        UdpTransport {
            role,
            socket: Mutex::new(None),
            peer: Mutex::new(None),
            next_seq: AtomicU64::new(1),
            unacked: Mutex::new(HashMap::new()),
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

    /// How many datagrams are still waiting to be acknowledged.
    pub async fn unacked_count(&self) -> usize {
        self.unacked.lock().await.len()
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

    pub fn encode_datagram(kind: u8, seq: u64, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER + body.len());
        out.push(kind);
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    pub fn decode_datagram(raw: &[u8]) -> Option<(u8, u64, &[u8])> {
        if raw.len() < HEADER {
            return None;
        }
        let seq = u64::from_be_bytes(raw[1..HEADER].try_into().ok()?);
        Some((raw[0], seq, &raw[HEADER..]))
    }

    async fn receive_loop(self: Arc<Self>, socket: Arc<UdpSocket>) {
        let mut buf = vec![0u8; 2048];
        while !self.closing.load(Ordering::SeqCst) {
            let (len, from) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(err) => {
                    if self.closing.load(Ordering::SeqCst) {
                        break;
                    }
                    eprintln!("[udp] receive error: {err}");
                    continue;
                }
            };
            let Some((kind, seq, body)) = Self::decode_datagram(&buf[..len]) else {
                continue; // too short to be ours
            };

            // Listening end learns (and follows) the peer's address.
            {
                let mut peer = self.peer.lock().await;
                if *peer != Some(from) {
                    if peer.is_some() {
                        println!("[udp] peer moved to {from}");
                    } else {
                        println!("[udp] peer is {from}");
                    }
                    *peer = Some(from);
                }
            }
            self.set_online(true);

            match kind {
                KIND_ACK => {
                    self.unacked.lock().await.remove(&seq);
                }
                KIND_DATA => {
                    // Acknowledge first: the sender is retransmitting until we do.
                    let ack = Self::encode_datagram(KIND_ACK, seq, &[]);
                    let _ = socket.send_to(&ack, from).await;

                    if let Ok(text) = std::str::from_utf8(body) {
                        if let Some(tx) = self.inbound.lock().await.as_ref() {
                            // The sequence number doubles as the de-duplication
                            // key, so retransmits are dropped upstream.
                            let _ = tx.send(Inbound {
                                text: text.to_string(),
                                id: Some(seq.to_string()),
                            });
                        }
                    }
                }
                _ => {}
            }
        }
    }

    async fn retransmit_loop(self: Arc<Self>, socket: Arc<UdpSocket>) {
        let mut ticker = tokio::time::interval(RETRANSMIT_TICK);
        while !self.closing.load(Ordering::SeqCst) {
            ticker.tick().await;
            let Some(peer) = *self.peer.lock().await else {
                continue;
            };

            let mut give_up = Vec::new();
            let mut resend = Vec::new();
            {
                let mut unacked = self.unacked.lock().await;
                for (seq, pending) in unacked.iter_mut() {
                    if pending.sent_at.elapsed() < pending.rto {
                        continue;
                    }
                    if pending.attempts >= MAX_ATTEMPTS {
                        give_up.push(*seq);
                        continue;
                    }
                    pending.attempts += 1;
                    pending.sent_at = Instant::now();
                    pending.rto = (pending.rto * 2).min(MAX_RTO); // back off per datagram
                    resend.push(pending.datagram.clone());
                }
                for seq in &give_up {
                    unacked.remove(seq);
                }
            }

            for datagram in resend {
                let _ = socket.send_to(&datagram, peer).await;
            }
            if !give_up.is_empty() {
                eprintln!(
                    "[udp] gave up on {} datagram(s) after {MAX_ATTEMPTS} attempts; \
                     the affected streams will stall",
                    give_up.len()
                );
            }
        }
    }
}

#[async_trait]
impl Transport for UdpTransport {
    fn name(&self) -> &'static str {
        "udp"
    }

    fn max_message_chars(&self) -> usize {
        MAX_MESSAGE_CHARS
    }

    fn concurrency(&self) -> usize {
        4 // sends are fire-and-forget; retransmission is what provides delivery
    }

    async fn connect(self: Arc<Self>, inbound: mpsc::UnboundedSender<Inbound>) -> Result<()> {
        *self.inbound.lock().await = Some(inbound);

        let bind = match &self.role {
            Role::Listen(addr) => addr.clone(),
            // Dialling still needs a local socket; let the OS choose the port.
            Role::Connect(_) => "0.0.0.0:0".to_string(),
        };
        let socket = Arc::new(
            UdpSocket::bind(&bind)
                .await
                .map_err(|e| anyhow!("binding {bind}: {e}"))?,
        );
        let port = socket.local_addr()?.port();
        *self.bound_port.lock().await = Some(port);

        if let Role::Connect(addr) = &self.role {
            let peer = tokio::net::lookup_host(addr)
                .await
                .map_err(|e| anyhow!("resolving {addr}: {e}"))?
                .next()
                .ok_or_else(|| anyhow!("{addr} resolved to nothing"))?;
            *self.peer.lock().await = Some(peer);
            self.set_online(true); // we can transmit; retransmits cover the rest
            println!("[udp] sending to {peer} from port {port}");
        } else {
            println!("[udp] listening on {bind} (port {port})");
        }

        *self.socket.lock().await = Some(socket.clone());
        tokio::spawn(self.clone().receive_loop(socket.clone()));
        tokio::spawn(self.clone().retransmit_loop(socket));
        Ok(())
    }

    async fn send_message(&self, text: &str) -> Result<(), SendError> {
        self.wait_online().await;
        if self.closing.load(Ordering::SeqCst) {
            return Ok(());
        }
        let (socket, peer) = {
            let socket = self.socket.lock().await.clone();
            let peer = *self.peer.lock().await;
            match (socket, peer) {
                (Some(s), Some(p)) => (s, p),
                _ => return Err(SendError::Transient("no peer yet".into())),
            }
        };

        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let datagram = Self::encode_datagram(KIND_DATA, seq, text.as_bytes());

        // Register before sending, so an ack that arrives immediately still
        // finds the entry to clear.
        self.unacked.lock().await.insert(
            seq,
            Pending {
                datagram: datagram.clone(),
                attempts: 0,
                sent_at: Instant::now(),
                rto: INITIAL_RTO,
            },
        );

        match socket.send_to(&datagram, peer).await {
            Ok(_) => Ok(()),
            Err(err) => {
                self.unacked.lock().await.remove(&seq);
                Err(SendError::Transient(err.to_string()))
            }
        }
    }

    async fn close(&self) {
        self.closing.store(true, Ordering::SeqCst);
        self.set_online(false);
        self.unacked.lock().await.clear();
        *self.socket.lock().await = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizing_fits_inside_a_common_mtu() {
        let tp = UdpTransport::new(Role::Connect("127.0.0.1:1".into()));
        assert_eq!(tp.max_message_chars(), 1100);
        // header + the encoded message must stay well under a 1500-byte MTU.
        assert!(HEADER + tp.max_message_chars() < 1400);
        assert!(tp.max_payload() > 700, "got {}", tp.max_payload());
    }

    #[test]
    fn datagram_round_trip() {
        let raw = UdpTransport::encode_datagram(KIND_DATA, 7, b"hello");
        let (kind, seq, body) = UdpTransport::decode_datagram(&raw).unwrap();
        assert_eq!((kind, seq, body), (KIND_DATA, 7, b"hello".as_ref()));
    }

    #[test]
    fn an_ack_carries_no_body() {
        let raw = UdpTransport::encode_datagram(KIND_ACK, u64::MAX, &[]);
        let (kind, seq, body) = UdpTransport::decode_datagram(&raw).unwrap();
        assert_eq!((kind, seq), (KIND_ACK, u64::MAX));
        assert!(body.is_empty());
    }

    #[test]
    fn short_datagrams_are_rejected() {
        for len in 0..HEADER {
            assert!(UdpTransport::decode_datagram(&vec![0u8; len]).is_none());
        }
    }

    #[tokio::test]
    async fn a_listener_reports_its_bound_port() {
        let tp = Arc::new(UdpTransport::new(Role::Listen("127.0.0.1:0".into())));
        let (tx, _rx) = mpsc::unbounded_channel();
        tp.clone().connect(tx).await.unwrap();
        assert!(tp.local_port().await.unwrap() > 0);
        tp.close().await;
    }
}
