//! End-to-end over the WhatsApp transport.
//!
//! Only Meta is mocked, and only at the edge: a stand-in Graph API receives the
//! real `POST /{version}/{phone_id}/messages` and turns it into a genuine,
//! HMAC-signed webhook delivery to the peer's real webhook server. So the
//! reqwest client, the axum webhook, signature verification, JSON shape
//! handling and de-duplication are all exercised for real.

mod support;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use msgproxy::frame::{Codec, SIDE_CLIENT, SIDE_SERVER};
use msgproxy::transport::whatsapp::{WhatsAppConfig, WhatsAppTransport};
use msgproxy::tunnel::Tunnel;
use msgproxy::{exit, socks};

use support::{socks_roundtrip, start_echo_server};

const APP_SECRET: &str = "test-app-secret";
const CLIENT_NUMBER: &str = "+15550000001";
const SERVER_NUMBER: &str = "+15550000002";

/// Where each phone ID's messages should be delivered, and who they're from.
#[derive(Clone)]
struct Route {
    peer_webhook_port: u16,
    from_number: String,
}

#[derive(Default)]
struct GraphState {
    routes: Mutex<HashMap<String, Route>>,
    delivered: AtomicUsize,
    longest: AtomicUsize,
    oversize: AtomicUsize,
}

fn sign(body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(APP_SECRET.as_bytes()).unwrap();
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// Stand-in for `graph.facebook.com`.
async fn graph_messages(
    State(state): State<Arc<GraphState>>,
    Path((_version, phone_id)): Path<(String, String)>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let text = body["text"]["body"].as_str().unwrap_or_default().to_string();
    state.longest.fetch_max(text.len(), Ordering::SeqCst);
    if text.len() > 4096 {
        state.oversize.fetch_add(1, Ordering::SeqCst);
    }
    let n = state.delivered.fetch_add(1, Ordering::SeqCst);

    let route = state.routes.lock().await.get(&phone_id).cloned();
    if let Some(route) = route {
        let envelope = serde_json::json!({
            "object": "whatsapp_business_account",
            "entry": [{"id": "WABA", "changes": [{"field": "messages", "value": {
                "messaging_product": "whatsapp",
                "metadata": {"display_phone_number": route.from_number, "phone_number_id": phone_id},
                "messages": [{
                    "from": route.from_number.trim_start_matches('+'),
                    "id": format!("wamid.{phone_id}.{n}"),
                    "timestamp": "0",
                    "type": "text",
                    "text": {"body": text},
                }],
            }}]}],
        });
        let raw = serde_json::to_vec(&envelope).unwrap();
        let url = format!("http://127.0.0.1:{}/webhook", route.peer_webhook_port);
        let client = reqwest::Client::new();
        // Meta delivers at least once; every third message goes twice, so the
        // tunnel's de-duplication is exercised for real.
        let times = if n % 3 == 0 { 2 } else { 1 };
        for _ in 0..times {
            let response = client
                .post(&url)
                .header("Content-Type", "application/json")
                .header("X-Hub-Signature-256", sign(&raw))
                .body(raw.clone())
                .send()
                .await
                .expect("webhook delivery");
            assert_eq!(response.status(), 200, "webhook rejected a signed delivery");
        }
    }
    (StatusCode::OK, Json(serde_json::json!({"messages": [{"id": "wamid.ok"}]})))
}

struct Harness {
    socks_port: u16,
    echo_port: u16,
    graph: Arc<GraphState>,
    client: Arc<Tunnel>,
    client_webhook: u16,
}

async fn setup() -> Harness {
    let codec = Arc::new(Codec::from_passphrase("a shared test passphrase"));
    let echo_port = start_echo_server().await;

    let graph = Arc::new(GraphState::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let graph_port = listener.local_addr().unwrap().port();
    let app = Router::new()
        .route("/{version}/{phone_id}/messages", post(graph_messages))
        .with_state(graph.clone());
    tokio::spawn(async move { axum::serve(listener, app).await });
    let api_base = format!("http://127.0.0.1:{graph_port}");

    let config = |phone_id: &str, peer: &str| WhatsAppConfig {
        token: "t".into(),
        phone_id: phone_id.into(),
        peer: peer.into(),
        verify_token: "vt".into(),
        app_secret: Some(APP_SECRET.into()),
        host: "127.0.0.1".into(),
        port: 0, // ephemeral; read back with webhook_port()
        path: "/webhook".into(),
        api_version: "v22.0".into(),
        api_base: api_base.clone(),
        concurrency: 4,
    };

    let client_transport = Arc::new(WhatsAppTransport::new(config("PID_C", SERVER_NUMBER)).unwrap());
    let server_transport = Arc::new(WhatsAppTransport::new(config("PID_S", CLIENT_NUMBER)).unwrap());

    let (client, client_frames) = Tunnel::start(client_transport.clone(), codec.clone(), SIDE_CLIENT)
        .await
        .expect("client tunnel");
    let (server, server_frames) = Tunnel::start(server_transport.clone(), codec, SIDE_SERVER)
        .await
        .expect("server tunnel");

    // Now the webhooks are bound, tell the mock Graph API where to deliver.
    let client_webhook = client_transport.webhook_port().await.unwrap();
    let server_webhook = server_transport.webhook_port().await.unwrap();
    {
        let mut routes = graph.routes.lock().await;
        // What the client sends arrives at the server's webhook, from the client.
        routes.insert(
            "PID_C".into(),
            Route { peer_webhook_port: server_webhook, from_number: CLIENT_NUMBER.into() },
        );
        routes.insert(
            "PID_S".into(),
            Route { peer_webhook_port: client_webhook, from_number: SERVER_NUMBER.into() },
        );
    }

    tokio::spawn(exit::run(server, server_frames));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_port = listener.local_addr().unwrap().port();
    tokio::spawn(socks::serve(listener, client.clone(), client_frames));

    Harness { socks_port, echo_port, graph, client, client_webhook }
}

#[tokio::test]
async fn round_trip() {
    let h = setup().await;
    let got = socks_roundtrip(h.socks_port, "127.0.0.1", h.echo_port, b"hello whatsapp").await;
    assert_eq!(got, b"HELLO WHATSAPP".to_vec());
}

#[tokio::test]
async fn multi_frame_transfer_reassembles_exactly() {
    let h = setup().await;
    let payload: Vec<u8> = (b'a'..=b'z').cycle().take(30_000).collect();
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
async fn never_exceeds_the_whatsapp_message_limit() {
    let h = setup().await;
    let payload: Vec<u8> = (0..=255u8).cycle().take(30_000).collect();
    socks_roundtrip(h.socks_port, "127.0.0.1", h.echo_port, &payload).await;

    assert_eq!(h.graph.oversize.load(Ordering::SeqCst), 0, "sent a message over 4096 chars");
    let longest = h.graph.longest.load(Ordering::SeqCst);
    assert!(longest <= 4096, "longest message was {longest}");
    assert!(longest > 2000, "test never pushed a large message (longest {longest})");
}

#[tokio::test]
async fn webhook_verification_handshake() {
    let h = setup().await;
    let url = format!("http://127.0.0.1:{}/webhook", h.client_webhook);
    let client = reqwest::Client::new();

    let ok = client
        .get(&url)
        .query(&[
            ("hub.mode", "subscribe"),
            ("hub.verify_token", "vt"),
            ("hub.challenge", "CHALLENGE"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    assert_eq!(ok.text().await.unwrap(), "CHALLENGE");

    let wrong = client
        .get(&url)
        .query(&[
            ("hub.mode", "subscribe"),
            ("hub.verify_token", "not-the-token"),
            ("hub.challenge", "CHALLENGE"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 403, "a wrong verify token was accepted");
}

#[tokio::test]
async fn unsigned_and_missigned_deliveries_are_rejected() {
    let h = setup().await;
    let url = format!("http://127.0.0.1:{}/webhook", h.client_webhook);
    let client = reqwest::Client::new();

    let bad = client
        .post(&url)
        .header("X-Hub-Signature-256", "sha256=deadbeef")
        .body("{\"entry\":[]}")
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 403, "a bad signature was accepted");

    let missing = client.post(&url).body("{\"entry\":[]}").send().await.unwrap();
    assert_eq!(missing.status(), 403, "an unsigned delivery was accepted");
}

#[tokio::test]
async fn authentic_junk_still_returns_200() {
    // Meta retries non-2xx, so a junk frame must not trigger a retry storm.
    let h = setup().await;
    let envelope = serde_json::json!({
        "entry": [{"changes": [{"value": {"messages": [
            {"type": "text", "id": "wamid.junk", "from": CLIENT_NUMBER.trim_start_matches('+'),
             "text": {"body": "not one of ours at all"}}
        ]}}]}]
    });
    let raw = serde_json::to_vec(&envelope).unwrap();
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/webhook", h.client_webhook))
        .header("X-Hub-Signature-256", sign(&raw))
        .body(raw)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn messages_from_other_numbers_are_ignored() {
    let h = setup().await;
    let codec = Codec::from_passphrase("a shared test passphrase");
    let frame = msgproxy::frame::Frame::new(
        SIDE_SERVER,
        msgproxy::frame::FrameType::Data,
        7777,
        0,
        b"payload".to_vec(),
    );
    let envelope = serde_json::json!({
        "entry": [{"changes": [{"value": {"messages": [
            {"type": "text", "id": "wamid.stranger", "from": "19999999999",
             "text": {"body": codec.to_message(&frame)}}
        ]}}]}]
    });
    let raw = serde_json::to_vec(&envelope).unwrap();
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/webhook", h.client_webhook))
        .header("X-Hub-Signature-256", sign(&raw))
        .body(raw)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    // Accepted at the HTTP layer, but dropped before dispatch — the tunnel
    // still works.
    let got = socks_roundtrip(h.socks_port, "127.0.0.1", h.echo_port, b"still alive").await;
    assert_eq!(got, b"STILL ALIVE".to_vec());
}
