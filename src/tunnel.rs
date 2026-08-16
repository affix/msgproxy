//! The shared machinery above a transport: queueing, retry, pacing,
//! de-duplication and frame dispatch.
//!
//! This is the Rust counterpart of the Python `BaseTransport`. Backends stay
//! free of it, so all three platforms behave identically.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, Instant};

use crate::frame::{Codec, Frame, FrameType};
use crate::transport::{Inbound, SendError, Transport};

/// Bounded memory of inbound message IDs, for platforms that deliver
/// at-least-once. A replayed frame whose seq we already consumed would
/// otherwise sit in a reassembly buffer forever.
const SEEN_CAPACITY: usize = 4096;

pub struct Tunnel {
    out_tx: mpsc::UnboundedSender<Frame>,
    side: u8,
    max_payload: usize,
    transport: Arc<dyn Transport>,
}

impl Tunnel {
    /// Connect the transport and start the pumps.
    ///
    /// Returns the tunnel plus the stream of inbound frames from the other side.
    pub async fn start(
        transport: Arc<dyn Transport>,
        codec: Arc<Codec>,
        side: u8,
    ) -> anyhow::Result<(Arc<Tunnel>, mpsc::UnboundedReceiver<Frame>)> {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Inbound>();
        transport.clone().connect(inbound_tx).await?;

        let (out_tx, out_rx) = mpsc::unbounded_channel::<Frame>();
        let (frames_tx, frames_rx) = mpsc::unbounded_channel::<Frame>();

        let tunnel = Arc::new(Tunnel {
            out_tx,
            side,
            max_payload: transport.max_payload(),
            transport: transport.clone(),
        });

        tokio::spawn(dispatch(inbound_rx, frames_tx, codec.clone(), side, transport.name()));

        let out_rx = Arc::new(Mutex::new(out_rx));
        let last_send = Arc::new(Mutex::new(None::<Instant>));
        for _ in 0..transport.concurrency().max(1) {
            tokio::spawn(sender(
                out_rx.clone(),
                transport.clone(),
                codec.clone(),
                last_send.clone(),
            ));
        }

        Ok((tunnel, frames_rx))
    }

    /// Largest raw payload that fits one message on this platform.
    pub fn max_payload(&self) -> usize {
        self.max_payload
    }

    pub fn transport_name(&self) -> &'static str {
        self.transport.name()
    }

    /// Queue a frame stamped with our side. Non-blocking.
    pub fn send(&self, ftype: FrameType, stream_id: u32, seq: u32, payload: Vec<u8>) {
        let _ = self.out_tx.send(Frame::new(self.side, ftype, stream_id, seq, payload));
    }

    pub async fn close(&self) {
        self.transport.close().await;
    }
}

/// Inbound messages -> decoded frames from the *other* side.
async fn dispatch(
    mut inbound: mpsc::UnboundedReceiver<Inbound>,
    frames: mpsc::UnboundedSender<Frame>,
    codec: Arc<Codec>,
    my_side: u8,
    name: &'static str,
) {
    let mut seen_order: VecDeque<String> = VecDeque::with_capacity(SEEN_CAPACITY);
    let mut seen: HashSet<String> = HashSet::with_capacity(SEEN_CAPACITY);

    while let Some(msg) = inbound.recv().await {
        // Not ours, or failed to authenticate under our key.
        let Some(frame) = codec.from_message(&msg.text) else {
            continue;
        };
        if let Some(id) = msg.id {
            if !seen.insert(id.clone()) {
                continue; // already handled this delivery
            }
            if seen_order.len() == SEEN_CAPACITY {
                if let Some(old) = seen_order.pop_front() {
                    seen.remove(&old);
                }
            }
            seen_order.push_back(id);
        }
        if frame.side == my_side {
            continue; // our own frame echoed back
        }
        if frames.send(frame).is_err() {
            break; // nobody is listening any more
        }
    }
    eprintln!("[{name}] inbound stream ended");
}

/// Queued frames -> one message at a time, with pacing and retry.
async fn sender(
    out_rx: Arc<Mutex<mpsc::UnboundedReceiver<Frame>>>,
    transport: Arc<dyn Transport>,
    codec: Arc<Codec>,
    last_send: Arc<Mutex<Option<Instant>>>,
) {
    loop {
        let frame = {
            let mut rx = out_rx.lock().await;
            match rx.recv().await {
                Some(f) => f,
                None => break,
            }
        };

        let text = codec.to_message(&frame);
        if text.len() > transport.max_message_chars() {
            eprintln!(
                "[{}] frame too large for one message ({} > {} chars); dropped",
                transport.name(),
                text.len(),
                transport.max_message_chars()
            );
            continue;
        }

        let mut delay = transport.retry_delay();
        for attempt in 0..transport.send_attempts().max(1) {
            throttle(&last_send, transport.min_interval()).await;
            match transport.send_message(&text).await {
                Ok(()) => break,
                Err(SendError::Permanent(msg)) => {
                    eprintln!("[{}] send failed permanently: {msg}", transport.name());
                    break;
                }
                Err(SendError::Transient(msg)) => {
                    if attempt + 1 >= transport.send_attempts().max(1) {
                        eprintln!("[{}] send failed: {msg}", transport.name());
                        break;
                    }
                    sleep(delay).await;
                    delay *= 2;
                }
            }
        }
    }
}

/// Hold the floor between sends, for platforms with flood protection.
async fn throttle(last_send: &Arc<Mutex<Option<Instant>>>, min_interval: Duration) {
    if min_interval.is_zero() {
        return;
    }
    let mut last = last_send.lock().await;
    if let Some(prev) = *last {
        let elapsed = prev.elapsed();
        if elapsed < min_interval {
            sleep(min_interval - elapsed).await;
        }
    }
    *last = Some(Instant::now());
}
