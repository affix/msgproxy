//! End-to-end: real SOCKS traffic through the real framing, encryption and
//! stream multiplexing, over the real IRC transport, against a mock ircd.
//!
//! Only the ircd is mocked. Everything above the socket is shipping code.

mod support;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::mpsc;

use msgproxy::frame::{Codec, Frame, SIDE_CLIENT, SIDE_SERVER};
use msgproxy::transport::irc::{IrcConfig, IrcTransport};
use msgproxy::transport::Transport;
use msgproxy::tunnel::Tunnel;
use msgproxy::{exit, socks};

use support::{socks_roundtrip, start_echo_server, MockIrcd, LINE_LIMIT};

struct Harness {
    ircd: Arc<MockIrcd>,
    socks_port: u16,
    echo_port: u16,
    client: Arc<Tunnel>,
}

fn config(port: u16, nick: &str, peer: &str) -> IrcConfig {
    IrcConfig {
        host: "127.0.0.1".into(),
        port,
        peer: peer.into(),
        nick: nick.into(),
        user: None,
        realname: None,
        password: None,
        nickserv_password: None,
        tls: false,
        tls_verify: false,
        rate: 0.0, // no pacing; the mock has no flood protection
    }
}

async fn setup() -> Harness {
    let codec = Arc::new(Codec::from_passphrase("a shared test passphrase"));
    let ircd = MockIrcd::new();
    let irc_port = ircd.start().await;
    let echo_port = start_echo_server().await;

    let client_transport = Arc::new(IrcTransport::new(config(irc_port, "mpclient", "mpserver")).unwrap());
    let server_transport = Arc::new(IrcTransport::new(config(irc_port, "mpserver", "mpclient")).unwrap());

    let (client, client_frames) = Tunnel::start(client_transport, codec.clone(), SIDE_CLIENT)
        .await
        .expect("client tunnel");
    let (server, server_frames) = Tunnel::start(server_transport, codec, SIDE_SERVER)
        .await
        .expect("server tunnel");

    tokio::spawn(exit::run(server, server_frames));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_port = listener.local_addr().unwrap().port();
    tokio::spawn(socks::serve(listener, client.clone(), client_frames));

    Harness { ircd, socks_port, echo_port, client }
}

#[tokio::test]
async fn round_trip() {
    let h = setup().await;
    let got = socks_roundtrip(h.socks_port, "127.0.0.1", h.echo_port, b"hello irc").await;
    assert_eq!(got, b"HELLO IRC".to_vec());
}

#[tokio::test]
async fn multi_frame_transfer_reassembles_exactly() {
    let h = setup().await;
    // Many times the per-frame limit, so this only passes if ordering and
    // reassembly are right.
    let payload: Vec<u8> = (b'a'..=b'z').cycle().take(6000).collect();
    assert!(payload.len() > h.client.max_payload() * 3);

    let got = socks_roundtrip(h.socks_port, "127.0.0.1", h.echo_port, &payload).await;
    assert_eq!(got, payload.to_ascii_uppercase());
}

#[tokio::test]
async fn concurrent_streams_do_not_bleed() {
    let h = setup().await;
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
        assert_eq!(task.await.unwrap(), payload.to_ascii_uppercase());
    }
}

#[tokio::test]
async fn never_exceeds_the_irc_line_limit() {
    let h = setup().await;
    let payload: Vec<u8> = (0..=255u8).cycle().take(8000).collect();
    socks_roundtrip(h.socks_port, "127.0.0.1", h.echo_port, &payload).await;

    assert_eq!(h.ircd.oversize_lines.load(Ordering::SeqCst), 0, "relayed a line over 512 bytes");
    let longest = h.ircd.longest_line.load(Ordering::SeqCst);
    assert!(longest <= LINE_LIMIT, "longest line was {longest}");
    assert!(longest > 300, "test never pushed a large line (longest {longest})");
}

#[tokio::test]
async fn joins_no_channel() {
    let h = setup().await;
    socks_roundtrip(h.socks_port, "127.0.0.1", h.echo_port, b"hi").await;
    assert_eq!(h.ircd.joins.load(Ordering::SeqCst), 0, "direct mode must not JOIN");
    assert!(h.ircd.is_online("mpclient").await);
    assert!(h.ircd.is_online("mpserver").await);
}

#[tokio::test]
async fn a_refused_upstream_connect_surfaces_as_eof() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let h = setup().await;
    // Bind and immediately drop, so nothing is listening on this port.
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };

    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", h.socks_port)).await.unwrap();
    socket.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0u8; 2];
    socket.read_exact(&mut greeting).await.unwrap();

    let host = "127.0.0.1";
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&dead.to_be_bytes());
    socket.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    socket.read_exact(&mut reply).await.unwrap();

    // The optimistic reply already arrived; the RST shows up as EOF.
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(30), socket.read(&mut buf))
        .await
        .expect("timed out waiting for the reset")
        .unwrap();
    assert_eq!(n, 0, "expected EOF, got {n} bytes");
}

#[tokio::test]
async fn reconnects_after_the_server_drops_the_link() {
    let h = setup().await;
    assert_eq!(
        socks_roundtrip(h.socks_port, "127.0.0.1", h.echo_port, b"before").await,
        b"BEFORE".to_vec()
    );

    h.ircd.drop_all().await;

    // Both ends should re-register on their own.
    let mut back = false;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if h.ircd.is_online("mpclient").await && h.ircd.is_online("mpserver").await {
            back = true;
            break;
        }
    }
    assert!(back, "the transports never reconnected");

    assert_eq!(
        socks_roundtrip(h.socks_port, "127.0.0.1", h.echo_port, b"after").await,
        b"AFTER".to_vec()
    );
}

#[tokio::test]
async fn frames_from_strangers_and_other_targets_are_ignored() {
    // Drive the codec directly: a stranger's PRIVMSG must never become a frame.
    let codec = Codec::from_passphrase("a shared test passphrase");
    let frame = Frame::new(SIDE_CLIENT, msgproxy::frame::FrameType::Data, 1, 0, b"x".to_vec());
    let message = codec.to_message(&frame);

    let ircd = MockIrcd::new();
    let port = ircd.start().await;
    let transport = Arc::new(IrcTransport::new(config(port, "mpserver", "mpclient")).unwrap());
    let (tx, mut rx) = mpsc::unbounded_channel();
    transport.clone().connect(tx).await.unwrap();

    // From the wrong nick, and to the wrong target: both must be dropped.
    transport.handle_line_for_test(&format!(":stranger!u@h PRIVMSG mpserver :{message}")).await;
    transport.handle_line_for_test(&format!(":mpclient!u@h PRIVMSG #chan :{message}")).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(rx.try_recv().is_err(), "a foreign message was accepted");

    // The real peer, addressed to us, does get through.
    transport.handle_line_for_test(&format!(":mpclient!u@h PRIVMSG mpserver :{message}")).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(rx.try_recv().is_ok(), "the peer's message was dropped");
}
