//! End-to-end over the direct transports (TCP, WebSocket, UDP).
//!
//! Nothing is mocked here at all: these transports have no third party, so both
//! ends are the real thing talking over a real loopback socket. The exit node
//! listens on an ephemeral port and the SOCKS client dials it, which is the
//! deployment shape in miniature.

mod support;

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use msgproxy::frame::{Codec, SIDE_CLIENT, SIDE_SERVER};
use msgproxy::transport::link::Role;
use msgproxy::transport::tcp::TcpTransport;
use msgproxy::transport::udp::UdpTransport;
use msgproxy::transport::ws::WsTransport;
use msgproxy::transport::Transport;
use msgproxy::tunnel::Tunnel;
use msgproxy::{exit, socks};

use support::{socks_roundtrip, start_echo_server};

#[derive(Copy, Clone, Debug)]
enum Kind {
    Tcp,
    Ws,
    Udp,
}

struct Harness {
    socks_port: u16,
    echo_port: u16,
    client: Arc<Tunnel>,
    /// Kept so UDP tests can inspect the outstanding-acknowledgement table.
    udp_client: Option<Arc<UdpTransport>>,
}

/// Bring up the listening end first so its port is known, then dial it.
async fn setup(kind: Kind) -> Harness {
    let codec = Arc::new(Codec::from_passphrase("a shared test passphrase"));
    let echo_port = start_echo_server().await;

    // A transport binds inside `connect`, which `Tunnel::start` calls — so the
    // listening end must be started *first*, its port read back, and only then
    // the client built against it. Calling `connect` twice to peek at the port
    // would bind twice and leave the client dialling a dead address.
    let (server, server_frames, server_port) = match kind {
        Kind::Tcp => {
            let t = Arc::new(TcpTransport::new(Role::Listen("127.0.0.1:0".into())));
            let (tunnel, frames) = Tunnel::start(t.clone(), codec.clone(), SIDE_SERVER)
                .await
                .expect("server tunnel");
            let port = t.local_port().await.expect("bound port");
            (tunnel, frames, port)
        }
        Kind::Ws => {
            let t = Arc::new(WsTransport::new(Role::Listen("127.0.0.1:0".into())));
            let (tunnel, frames) = Tunnel::start(t.clone(), codec.clone(), SIDE_SERVER)
                .await
                .expect("server tunnel");
            let port = t.local_port().await.expect("bound port");
            (tunnel, frames, port)
        }
        Kind::Udp => {
            let t = Arc::new(UdpTransport::new(Role::Listen("127.0.0.1:0".into())));
            let (tunnel, frames) = Tunnel::start(t.clone(), codec.clone(), SIDE_SERVER)
                .await
                .expect("server tunnel");
            let port = t.local_port().await.expect("bound port");
            (tunnel, frames, port)
        }
    };

    let (client_transport, udp_client): (Arc<dyn Transport>, Option<Arc<UdpTransport>>) = match kind
    {
        Kind::Tcp => (
            Arc::new(TcpTransport::new(Role::Connect(format!("127.0.0.1:{server_port}")))),
            None,
        ),
        Kind::Ws => (
            Arc::new(WsTransport::new(Role::Connect(format!("ws://127.0.0.1:{server_port}")))),
            None,
        ),
        Kind::Udp => {
            let t = Arc::new(UdpTransport::new(Role::Connect(format!(
                "127.0.0.1:{server_port}"
            ))));
            (t.clone(), Some(t))
        }
    };

    let (client, client_frames) = Tunnel::start(client_transport, codec, SIDE_CLIENT)
        .await
        .expect("client tunnel");

    tokio::spawn(exit::run(server, server_frames));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_port = listener.local_addr().unwrap().port();
    tokio::spawn(socks::serve(listener, client.clone(), client_frames));

    // Give the link a moment to come up before the first byte.
    tokio::time::sleep(Duration::from_millis(300)).await;

    Harness { socks_port, echo_port, client, udp_client }
}

async fn round_trip(kind: Kind) {
    let h = setup(kind).await;
    let got = socks_roundtrip(h.socks_port, "127.0.0.1", h.echo_port, b"hello direct").await;
    assert_eq!(got, b"HELLO DIRECT".to_vec(), "{kind:?}");
}

async fn multi_frame(kind: Kind) {
    let h = setup(kind).await;
    // Sized off the transport: TCP and WebSocket carry ~48 KB per frame, UDP
    // only ~740, so a fixed length would be a single frame for two of them.
    let size = h.client.max_payload() * 3 + 500;
    let payload: Vec<u8> = (b'a'..=b'z').cycle().take(size).collect();
    assert!(payload.len() > h.client.max_payload(), "{kind:?} needs more than one frame");

    let got = socks_roundtrip(h.socks_port, "127.0.0.1", h.echo_port, &payload).await;
    assert_eq!(got, payload.to_ascii_uppercase(), "{kind:?}");
}

async fn concurrent_streams(kind: Kind) {
    let h = setup(kind).await;
    let payloads: Vec<Vec<u8>> = (0..4)
        .map(|i| format!("stream-{i}-").repeat(20).into_bytes())
        .collect();

    let mut tasks = Vec::new();
    for payload in payloads.clone() {
        let (port, echo) = (h.socks_port, h.echo_port);
        tasks.push(tokio::spawn(async move {
            socks_roundtrip(port, "127.0.0.1", echo, &payload).await
        }));
    }
    for (task, payload) in tasks.into_iter().zip(payloads) {
        assert_eq!(task.await.unwrap(), payload.to_ascii_uppercase(), "{kind:?}");
    }
}

#[tokio::test]
async fn tcp_round_trip() {
    round_trip(Kind::Tcp).await;
}

#[tokio::test]
async fn tcp_multi_frame() {
    multi_frame(Kind::Tcp).await;
}

#[tokio::test]
async fn tcp_concurrent_streams() {
    concurrent_streams(Kind::Tcp).await;
}

#[tokio::test]
async fn ws_round_trip() {
    round_trip(Kind::Ws).await;
}

#[tokio::test]
async fn ws_multi_frame() {
    multi_frame(Kind::Ws).await;
}

#[tokio::test]
async fn ws_concurrent_streams() {
    concurrent_streams(Kind::Ws).await;
}

#[tokio::test]
async fn udp_round_trip() {
    round_trip(Kind::Udp).await;
}

#[tokio::test]
async fn udp_multi_frame() {
    multi_frame(Kind::Udp).await;
}

#[tokio::test]
async fn udp_concurrent_streams() {
    concurrent_streams(Kind::Udp).await;
}

#[tokio::test]
async fn udp_acknowledges_everything_it_sends() {
    // If acks were not arriving, the retransmit table would keep growing and
    // never drain — the failure mode that makes raw UDP unusable here.
    let h = setup(Kind::Udp).await;
    let payload: Vec<u8> = (b'a'..=b'z').cycle().take(8_000).collect();
    socks_roundtrip(h.socks_port, "127.0.0.1", h.echo_port, &payload).await;

    let udp = h.udp_client.expect("udp client transport");
    let mut drained = false;
    for _ in 0..100 {
        if udp.unacked_count().await == 0 {
            drained = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(drained, "{} datagrams never acknowledged", udp.unacked_count().await);
}
