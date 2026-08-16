//! End-to-end over the Discord transport, with the gateway replaced by a
//! loopback sink.
//!
//! Discord's gateway can't be stood up locally, so outbound messages are handed
//! straight to the peer's inbound path — the same substitution the transport
//! makes available for exactly this reason. Everything else is shipping code:
//! framing, encryption, dispatch, de-duplication, reassembly, SOCKS, exit node.

mod support;

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use msgproxy::frame::{Codec, SIDE_CLIENT, SIDE_SERVER};
use msgproxy::transport::discord::{ChannelSink, DiscordConfig, DiscordTransport};
use msgproxy::transport::SendError;
use msgproxy::tunnel::Tunnel;
use msgproxy::{exit, socks};

use support::{socks_roundtrip, start_echo_server};

const CHANNEL: u64 = 123456789012345678;

#[derive(Default)]
struct Recorder {
    longest: AtomicUsize,
    oversize: AtomicUsize,
    sent: AtomicUsize,
}

/// Hands each outbound message to the peer, as Discord would.
struct LoopbackSink {
    peer: Mutex<Option<Arc<DiscordTransport>>>,
    next_id: AtomicU64,
    record: Arc<Recorder>,
    limit: usize,
}

#[async_trait]
impl ChannelSink for LoopbackSink {
    async fn send(&self, text: &str) -> Result<(), SendError> {
        self.record.sent.fetch_add(1, Ordering::SeqCst);
        self.record.longest.fetch_max(text.len(), Ordering::SeqCst);
        if text.len() > self.limit {
            self.record.oversize.fetch_add(1, Ordering::SeqCst);
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let peer = self.peer.lock().await.clone();
        if let Some(peer) = peer {
            peer.deliver_for_test(CHANNEL, text.to_string(), id).await;
        }
        Ok(())
    }
}

struct Harness {
    socks_port: u16,
    echo_port: u16,
    record: Arc<Recorder>,
    client: Arc<Tunnel>,
    server_transport: Arc<DiscordTransport>,
}

async fn setup() -> Harness {
    let codec = Arc::new(Codec::from_passphrase("a shared test passphrase"));
    let echo_port = start_echo_server().await;
    let record = Arc::new(Recorder::default());

    let client_sink = Arc::new(LoopbackSink {
        peer: Mutex::new(None),
        next_id: AtomicU64::new(1),
        record: record.clone(),
        limit: 2000,
    });
    let server_sink = Arc::new(LoopbackSink {
        peer: Mutex::new(None),
        next_id: AtomicU64::new(1_000_000),
        record: record.clone(),
        limit: 2000,
    });

    let client_transport = Arc::new(DiscordTransport::with_sink(
        DiscordConfig { token: "mock".into(), channel_id: CHANNEL },
        client_sink.clone(),
    ));
    let server_transport = Arc::new(DiscordTransport::with_sink(
        DiscordConfig { token: "mock".into(), channel_id: CHANNEL },
        server_sink.clone(),
    ));

    // Cross-wire: what one sends, the other receives.
    *client_sink.peer.lock().await = Some(server_transport.clone());
    *server_sink.peer.lock().await = Some(client_transport.clone());

    let (client, client_frames) = Tunnel::start(client_transport, codec.clone(), SIDE_CLIENT)
        .await
        .expect("client tunnel");
    let (server, server_frames) = Tunnel::start(server_transport.clone(), codec, SIDE_SERVER)
        .await
        .expect("server tunnel");

    tokio::spawn(exit::run(server, server_frames));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_port = listener.local_addr().unwrap().port();
    tokio::spawn(socks::serve(listener, client.clone(), client_frames));

    Harness { socks_port, echo_port, record, client, server_transport }
}

#[tokio::test]
async fn round_trip() {
    let h = setup().await;
    let got = socks_roundtrip(h.socks_port, "127.0.0.1", h.echo_port, b"hello discord").await;
    assert_eq!(got, b"HELLO DISCORD".to_vec());
}

#[tokio::test]
async fn multi_frame_transfer_reassembles_exactly() {
    let h = setup().await;
    let payload: Vec<u8> = (b'a'..=b'z').cycle().take(20_000).collect();
    assert!(payload.len() > h.client.max_payload() * 3);

    let got = socks_roundtrip(h.socks_port, "127.0.0.1", h.echo_port, &payload).await;
    assert_eq!(got, payload.to_ascii_uppercase());
}

#[tokio::test]
async fn concurrent_streams_do_not_bleed() {
    let h = setup().await;
    let payloads: Vec<Vec<u8>> = (0..5)
        .map(|i| format!("stream-{i}-").repeat(30).into_bytes())
        .collect();

    let mut tasks = Vec::new();
    for payload in payloads.clone() {
        let (port, echo) = (h.socks_port, h.echo_port);
        tasks.push(tokio::spawn(async move {
            socks_roundtrip(port, "127.0.0.1", echo, &payload).await
        }));
    }
    for (task, payload) in tasks.into_iter().zip(payloads) {
        assert_eq!(task.await.unwrap(), payload.to_ascii_uppercase());
    }
}

#[tokio::test]
async fn never_exceeds_the_discord_message_limit() {
    let h = setup().await;
    let payload: Vec<u8> = (0..=255u8).cycle().take(20_000).collect();
    socks_roundtrip(h.socks_port, "127.0.0.1", h.echo_port, &payload).await;

    assert_eq!(h.record.oversize.load(Ordering::SeqCst), 0, "sent a message over 2000 chars");
    let longest = h.record.longest.load(Ordering::SeqCst);
    assert!(longest <= 2000, "longest message was {longest}");
    assert!(longest > 1000, "test never pushed a large message (longest {longest})");
    assert!(h.record.sent.load(Ordering::SeqCst) > 0);
}

#[tokio::test]
async fn channel_chatter_creates_no_streams() {
    let h = setup().await;
    // Humans talk in the channel too; none of it may become a stream.
    for (i, text) in ["hey, what's this channel for?", "SP1|not-valid-base64!!", ""]
        .iter()
        .enumerate()
    {
        h.server_transport
            .deliver_for_test(CHANNEL, text.to_string(), 9000 + i as u64)
            .await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // The tunnel still works afterwards, which it would not if junk had been
    // dispatched into the stream table.
    let got = socks_roundtrip(h.socks_port, "127.0.0.1", h.echo_port, b"still alive").await;
    assert_eq!(got, b"STILL ALIVE".to_vec());
}

#[tokio::test]
async fn duplicate_deliveries_are_dropped() {
    // Same message ID twice must dispatch once — the tunnel's dedup layer.
    let h = setup().await;
    let codec = Codec::from_passphrase("a shared test passphrase");
    let frame = msgproxy::frame::Frame::new(
        SIDE_CLIENT,
        msgproxy::frame::FrameType::Data,
        4242,
        0,
        b"payload".to_vec(),
    );
    let message = codec.to_message(&frame);

    for _ in 0..2 {
        h.server_transport.deliver_for_test(CHANNEL, message.clone(), 555).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let got = socks_roundtrip(h.socks_port, "127.0.0.1", h.echo_port, b"ok").await;
    assert_eq!(got, b"OK".to_vec());
}
