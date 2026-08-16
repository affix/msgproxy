//! WhatsApp transport, on top of the WhatsApp Business Cloud API.
//!
//! Frames go out as ordinary text messages via
//! `POST /{version}/{phone_number_id}/messages` and come back in on a webhook
//! that Meta calls. That means this end needs a **publicly reachable HTTPS URL**
//! pointed at the little server started here (put it behind nginx/Caddy, a
//! tunnel like cloudflared, or any HTTPS reverse proxy) — the Cloud API has no
//! polling equivalent of a gateway connection.
//!
//! Both ends are WhatsApp Business numbers messaging each other. Note Meta's
//! 24-hour customer-service window: a business may only send freeform text
//! within 24h of the last inbound message from that number. Steady tunnel
//! traffic keeps the window open in both directions; see the README for kicking
//! it off.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use axum::Router;
// hmac 0.13 moved `new_from_slice` onto KeyInit, which must be in scope.
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::Sha256;
use tokio::sync::{mpsc, Mutex};

use super::{Inbound, SendError, Transport};

/// WhatsApp text bodies cap at 4096 characters.
const MAX_MESSAGE_CHARS: usize = 4096;

pub const DEFAULT_API_BASE: &str = "https://graph.facebook.com";

pub struct WhatsAppConfig {
    pub token: String,
    pub phone_id: String,
    pub peer: String,
    pub verify_token: String,
    pub app_secret: Option<String>,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub api_version: String,
    pub api_base: String,
    pub concurrency: usize,
}

impl WhatsAppConfig {
    fn normalised_path(&self) -> String {
        if self.path.starts_with('/') {
            self.path.clone()
        } else {
            format!("/{}", self.path)
        }
    }
}

/// Normalise a phone number for comparison ("+44 7700 900123" -> "447700900123").
pub fn digits(number: &str) -> String {
    number.chars().filter(|c| c.is_ascii_digit()).collect()
}

pub struct WhatsAppTransport {
    cfg: WhatsAppConfig,
    url: String,
    peer_digits: String,
    client: reqwest::Client,
    /// Set once the webhook is up, so handlers can publish inbound messages.
    inbound: Arc<Mutex<Option<mpsc::UnboundedSender<Inbound>>>>,
    bound_port: Arc<Mutex<Option<u16>>>,
}

#[derive(Clone)]
struct WebhookState {
    verify_token: String,
    app_secret: Option<String>,
    peer_digits: String,
    inbound: Arc<Mutex<Option<mpsc::UnboundedSender<Inbound>>>>,
}

impl WhatsAppTransport {
    pub fn new(cfg: WhatsAppConfig) -> Result<Self> {
        if cfg.phone_id.is_empty() || cfg.peer.is_empty() {
            return Err(anyhow!("whatsapp needs a phone id and a peer number"));
        }
        let url = format!(
            "{}/{}/{}/messages",
            cfg.api_base.trim_end_matches('/'),
            cfg.api_version,
            cfg.phone_id
        );
        Ok(WhatsAppTransport {
            peer_digits: digits(&cfg.peer),
            url,
            cfg,
            client: reqwest::Client::new(),
            inbound: Arc::new(Mutex::new(None)),
            bound_port: Arc::new(Mutex::new(None)),
        })
    }

    /// The port the webhook actually bound to. Tests pass port 0 and read this.
    pub async fn webhook_port(&self) -> Option<u16> {
        *self.bound_port.lock().await
    }
}

/// Meta's one-off webhook verification handshake.
#[derive(Deserialize)]
struct VerifyQuery {
    #[serde(rename = "hub.mode")]
    mode: Option<String>,
    #[serde(rename = "hub.verify_token")]
    verify_token: Option<String>,
    #[serde(rename = "hub.challenge")]
    challenge: Option<String>,
}

async fn handle_verify(
    State(state): State<WebhookState>,
    Query(query): Query<VerifyQuery>,
) -> (StatusCode, String) {
    if query.mode.as_deref() == Some("subscribe")
        && query.verify_token.as_deref() == Some(state.verify_token.as_str())
    {
        (StatusCode::OK, query.challenge.unwrap_or_default())
    } else {
        (StatusCode::FORBIDDEN, "verification failed".into())
    }
}

/// True if the delivery carries a valid `X-Hub-Signature-256` for our secret.
pub fn signature_ok(app_secret: Option<&str>, body: &[u8], header: Option<&str>) -> bool {
    let Some(secret) = app_secret else {
        return true; // no secret configured; nothing to check against
    };
    let Some(header) = header.and_then(|h| h.strip_prefix("sha256=")) else {
        return false;
    };
    let Ok(expected) = hex::decode(header) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

/// Pull every text message out of a webhook body, tolerating odd shapes.
pub fn text_messages(payload: &serde_json::Value) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let Some(entries) = payload.get("entry").and_then(|v| v.as_array()) else {
        return out;
    };
    for entry in entries {
        let Some(changes) = entry.get("changes").and_then(|v| v.as_array()) else {
            continue;
        };
        for change in changes {
            let Some(messages) = change
                .get("value")
                .and_then(|v| v.get("messages"))
                .and_then(|v| v.as_array())
            else {
                continue;
            };
            for message in messages {
                if message.get("type").and_then(|v| v.as_str()) != Some("text") {
                    continue;
                }
                let from = message.get("from").and_then(|v| v.as_str()).unwrap_or("");
                let id = message.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let body = message
                    .get("text")
                    .and_then(|v| v.get("body"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                out.push((from.to_string(), id.to_string(), body.to_string()));
            }
        }
    }
    out
}

async fn handle_webhook(
    State(state): State<WebhookState>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, &'static str) {
    let header = headers
        .get("X-Hub-Signature-256")
        .and_then(|v| v.to_str().ok());
    if !signature_ok(state.app_secret.as_deref(), &body, header) {
        eprintln!("[whatsapp] rejected webhook delivery: bad signature");
        return (StatusCode::FORBIDDEN, "bad signature");
    }

    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad json");
    };

    // Always 200 once the delivery is authentic, even if a frame inside is
    // junk — otherwise Meta retries the whole batch and we re-process it.
    if let Some(tx) = state.inbound.lock().await.as_ref() {
        for (from, id, text) in text_messages(&payload) {
            if !state.peer_digits.is_empty() && digits(&from) != state.peer_digits {
                continue; // chatter from some other number
            }
            let _ = tx.send(Inbound { text, id: Some(id) });
        }
    }
    (StatusCode::OK, "ok")
}

#[async_trait]
impl Transport for WhatsAppTransport {
    fn name(&self) -> &'static str {
        "whatsapp"
    }

    fn max_message_chars(&self) -> usize {
        MAX_MESSAGE_CHARS
    }

    fn concurrency(&self) -> usize {
        self.cfg.concurrency.max(1)
    }

    fn send_attempts(&self) -> u32 {
        4 // a dropped frame stalls its stream
    }

    async fn connect(self: Arc<Self>, inbound: mpsc::UnboundedSender<Inbound>) -> Result<()> {
        *self.inbound.lock().await = Some(inbound);

        let state = WebhookState {
            verify_token: self.cfg.verify_token.clone(),
            app_secret: self.cfg.app_secret.clone(),
            peer_digits: self.peer_digits.clone(),
            inbound: self.inbound.clone(),
        };
        let path = self.cfg.normalised_path();
        let app = Router::new()
            .route(&path, get(handle_verify).post(handle_webhook))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind((self.cfg.host.as_str(), self.cfg.port))
            .await
            .map_err(|e| anyhow!("binding the webhook on port {}: {e}", self.cfg.port))?;
        let port = listener.local_addr()?.port();
        *self.bound_port.lock().await = Some(port);

        tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, app).await {
                eprintln!("[whatsapp] webhook server stopped: {err}");
            }
        });

        println!("[whatsapp] webhook listening on {}:{port}{path}", self.cfg.host);
        println!(
            "[whatsapp] sending as phone ID {} to peer {}",
            self.cfg.phone_id, self.cfg.peer
        );
        if self.cfg.app_secret.is_none() {
            println!("[whatsapp] warning: no app secret set; webhook signatures unverified");
        }
        Ok(())
    }

    async fn send_message(&self, text: &str) -> Result<(), SendError> {
        let body = serde_json::json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": self.cfg.peer,
            "type": "text",
            "text": { "preview_url": false, "body": text },
        });

        let response = self
            .client
            .post(&self.url)
            .bearer_auth(&self.cfg.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| SendError::Transient(e.to_string()))?;

        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let detail: String = response
            .text()
            .await
            .unwrap_or_default()
            .chars()
            .take(300)
            .collect();
        // 429 and 5xx are worth another go; any other 4xx is our fault (bad
        // token, closed 24h window, wrong number) and won't heal on retry.
        if status.as_u16() != 429 && status.is_client_error() {
            Err(SendError::Permanent(format!("HTTP {status}: {detail}")))
        } else {
            Err(SendError::Transient(format!("HTTP {status}: {detail}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> WhatsAppConfig {
        WhatsAppConfig {
            token: "t".into(),
            phone_id: "PID".into(),
            peer: "+15550000001".into(),
            verify_token: "vt".into(),
            app_secret: Some("secret".into()),
            host: "127.0.0.1".into(),
            port: 0,
            path: "/webhook".into(),
            api_version: "v22.0".into(),
            api_base: DEFAULT_API_BASE.into(),
            concurrency: 4,
        }
    }

    #[test]
    fn message_limit_matches_whatsapp() {
        let tp = WhatsAppTransport::new(config()).unwrap();
        assert_eq!(tp.max_message_chars(), 4096);
        assert_eq!(tp.max_payload(), 2997);
    }

    #[test]
    fn builds_the_graph_api_url() {
        let tp = WhatsAppTransport::new(config()).unwrap();
        assert_eq!(tp.url, "https://graph.facebook.com/v22.0/PID/messages");
    }

    #[test]
    fn webhook_path_is_normalised() {
        let mut cfg = config();
        cfg.path = "hook".into();
        assert_eq!(cfg.normalised_path(), "/hook");
    }

    #[test]
    fn phone_numbers_normalise() {
        assert_eq!(digits("+44 7700 900123"), "447700900123");
        assert_eq!(digits("447700900123"), "447700900123");
        assert_eq!(digits("+1 (555) 000-0001"), "15550000001");
        assert_eq!(digits(""), "");
    }

    #[test]
    fn signature_check_accepts_a_correct_digest() {
        let body = b"{\"entry\":[]}";
        let mut mac = Hmac::<Sha256>::new_from_slice(b"secret").unwrap();
        mac.update(body);
        let sig = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        assert!(signature_ok(Some("secret"), body, Some(&sig)));
    }

    #[test]
    fn signature_check_rejects_bad_and_missing_digests() {
        let body = b"{\"entry\":[]}";
        assert!(!signature_ok(Some("secret"), body, Some("sha256=deadbeef")));
        assert!(!signature_ok(Some("secret"), body, None));
        assert!(!signature_ok(Some("secret"), body, Some("not-even-prefixed")));
        // A digest for a *different* body must not pass.
        let mut mac = Hmac::<Sha256>::new_from_slice(b"secret").unwrap();
        mac.update(b"something else");
        let sig = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        assert!(!signature_ok(Some("secret"), body, Some(&sig)));
    }

    #[test]
    fn without_a_secret_anything_is_accepted() {
        assert!(signature_ok(None, b"whatever", None));
    }

    #[test]
    fn extracts_text_messages() {
        let payload = serde_json::json!({
            "entry": [{"changes": [{"value": {"messages": [
                {"type": "image", "id": "1", "from": "15550000001"},
                {"type": "text", "id": "2", "from": "15550000001", "text": {"body": "hi"}},
            ]}}]}]
        });
        let found = text_messages(&payload);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], ("15550000001".into(), "2".into(), "hi".into()));
    }

    #[test]
    fn odd_webhook_shapes_do_not_panic() {
        for payload in [
            serde_json::json!({}),
            serde_json::json!({"entry": null}),
            serde_json::json!({"entry": [{}]}),
            serde_json::json!({"entry": [{"changes": null}]}),
            serde_json::json!({"entry": [{"changes": [{"value": {}}]}]}),
            serde_json::json!({"entry": [{"changes": [{"value": {"messages": null}}]}]}),
        ] {
            assert!(text_messages(&payload).is_empty());
        }
    }
}
