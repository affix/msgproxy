//! IRC transport: frames ride as PRIVMSG straight between two nicks.
//!
//! The two ends message each other directly — no channel is joined, so nothing
//! is relayed through a room where third parties can read the ciphertext, flood
//! it, or kick you out of it. Each end needs the other's nick and nothing else.
//!
//! Only a small slice of RFC 1459/2812 is needed — PASS/NICK/USER to register,
//! PING/PONG to stay alive, and PRIVMSG both ways — so this speaks the protocol
//! directly rather than pulling in a client library.
//!
//! Three things to know:
//!
//!   * **512 bytes per line, total.** That budget includes the
//!     `:nick!user@host` prefix the server prepends when relaying to the peer,
//!     so the usable payload is small and depends on the peer's nick length.
//!   * **Flood protection.** Most networks kill a client that sustains more
//!     than roughly one message every two seconds; `rate` sets the floor.
//!   * **Nicks are the address.** If ours is taken we fall back to `nick_`, but
//!     the peer expects the original and will ignore us until it is free. That
//!     is logged loudly rather than failing silently.
//!
//! Connections drop, so this reconnects with backoff automatically; queued
//! frames wait for the link rather than being discarded.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::time::timeout;

use super::{Inbound, SendError, Transport};

/// RFC 2812: a line, including the trailing CRLF, may not exceed 512 bytes.
pub const LINE_LIMIT: usize = 512;

/// The server prepends ":nick!user@host " when it relays our PRIVMSG onward,
/// and that counts against the same 512. We can't know the final hostmask
/// (cloaks, long hostnames, nick changes), so reserve a generous fixed slice.
const HOSTMASK_RESERVE: usize = 110;

const WELCOME_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Split one IRC line into (sender_nick, command, params).
pub fn parse_line(line: &str) -> (String, String, Vec<String>) {
    let mut rest = line;
    if rest.starts_with('@') {
        // IRCv3 message tags; we don't use them.
        rest = rest.split_once(' ').map(|(_, r)| r).unwrap_or("");
    }
    let mut prefix = "";
    if let Some(stripped) = rest.strip_prefix(':') {
        match stripped.split_once(' ') {
            Some((p, r)) => {
                prefix = p;
                rest = r;
            }
            None => {
                prefix = stripped;
                rest = "";
            }
        }
    }
    let (command, mut rest) = match rest.split_once(' ') {
        Some((c, r)) => (c, r),
        None => (rest, ""),
    };
    let mut params = Vec::new();
    loop {
        if rest.is_empty() {
            break;
        }
        if let Some(trailing) = rest.strip_prefix(':') {
            // Trailing param: the rest of the line, verbatim.
            params.push(trailing.to_string());
            break;
        }
        match rest.split_once(' ') {
            Some((part, remainder)) => {
                if !part.is_empty() {
                    params.push(part.to_string());
                }
                rest = remainder;
            }
            None => {
                if !rest.is_empty() {
                    params.push(rest.to_string());
                }
                break;
            }
        }
    }
    let nick = prefix.split('!').next().unwrap_or("").to_string();
    (nick, command.to_uppercase(), params)
}

pub struct IrcConfig {
    pub host: String,
    pub port: u16,
    pub peer: String,
    pub nick: String,
    pub user: Option<String>,
    pub realname: Option<String>,
    pub password: Option<String>,
    pub nickserv_password: Option<String>,
    pub tls: bool,
    pub tls_verify: bool,
    pub rate: f64,
}

struct Connection {
    writer: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
}

pub struct IrcTransport {
    cfg: IrcConfig,
    max_message_chars: usize,
    /// Current nick — may gain underscores if ours was taken.
    nick: Arc<Mutex<String>>,
    conn: Arc<Mutex<Option<Connection>>>,
    online: Arc<AtomicBool>,
    online_notify: Arc<Notify>,
    welcome: Arc<Notify>,
    closing: Arc<AtomicBool>,
    inbound: Arc<Mutex<Option<mpsc::UnboundedSender<Inbound>>>>,
}

impl IrcTransport {
    pub fn new(cfg: IrcConfig) -> Result<Self> {
        if cfg.peer.starts_with('#') || cfg.peer.starts_with('&') {
            return Err(anyhow!(
                "peer {:?} looks like a channel; this transport messages a nick",
                cfg.peer
            ));
        }
        // 512 minus the relayed hostmask, "PRIVMSG ", the peer's nick, " :" and CRLF.
        let overhead = HOSTMASK_RESERVE + "PRIVMSG ".len() + cfg.peer.len() + " :\r\n".len();
        let max_message_chars = LINE_LIMIT.saturating_sub(overhead);
        if crate::frame::payload_budget(max_message_chars) == 0 {
            return Err(anyhow!(
                "peer nick {:?} leaves no room for a payload in 512 bytes",
                cfg.peer
            ));
        }
        let nick = cfg.nick.clone();
        Ok(IrcTransport {
            cfg,
            max_message_chars,
            nick: Arc::new(Mutex::new(nick)),
            conn: Arc::new(Mutex::new(None)),
            online: Arc::new(AtomicBool::new(false)),
            online_notify: Arc::new(Notify::new()),
            welcome: Arc::new(Notify::new()),
            closing: Arc::new(AtomicBool::new(false)),
            inbound: Arc::new(Mutex::new(None)),
        })
    }

    async fn write_line(&self, line: &str) -> Result<()> {
        let mut guard = self.conn.lock().await;
        let conn = guard.as_mut().ok_or_else(|| anyhow!("not connected"))?;
        let mut bytes = line.as_bytes().to_vec();
        bytes.truncate(LINE_LIMIT - 2);
        bytes.extend_from_slice(b"\r\n");
        conn.writer.write_all(&bytes).await?;
        conn.writer.flush().await?;
        Ok(())
    }

    async fn wait_online(&self) {
        while !self.online.load(Ordering::SeqCst) && !self.closing.load(Ordering::SeqCst) {
            self.online_notify.notified().await;
        }
    }

    fn set_online(&self, value: bool) {
        self.online.store(value, Ordering::SeqCst);
        if value {
            self.online_notify.notify_waiters();
        }
    }

    /// Connect and register.
    ///
    /// Returns a boxed future because this recurses: `open` spawns the read
    /// loop, which on disconnect calls `reconnect`, which calls `open` again.
    /// A plain `async fn` would make that an infinite opaque type.
    fn open(self: Arc<Self>) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        Box::pin(async move {
        let addr = format!("{}:{}", self.cfg.host, self.cfg.port);
        let tcp = TcpStream::connect(&addr)
            .await
            .with_context(|| format!("connecting to {addr}"))?;

        let (reader, writer): (
            Box<dyn tokio::io::AsyncRead + Send + Unpin>,
            Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
        ) = if self.cfg.tls {
            let stream = crate::transport::irc::tls::connect(tcp, &self.cfg).await?;
            let (r, w) = tokio::io::split(stream);
            (Box::new(r), Box::new(w))
        } else {
            let (r, w) = tokio::io::split(tcp);
            (Box::new(r), Box::new(w))
        };
        println!(
            "[irc] connected to {addr}{}",
            if self.cfg.tls { " (tls)" } else { "" }
        );

        *self.conn.lock().await = Some(Connection { writer });
        *self.nick.lock().await = self.cfg.nick.clone();

        let me = self.clone();
        tokio::spawn(async move { me.read_loop(reader).await });

        if let Some(password) = &self.cfg.password {
            self.write_line(&format!("PASS :{password}")).await?;
        }
        let nick = self.cfg.nick.clone();
        let user = self.cfg.user.clone().unwrap_or_else(|| nick.clone());
        let realname = self.cfg.realname.clone().unwrap_or_else(|| nick.clone());
        self.write_line(&format!("NICK {nick}")).await?;
        self.write_line(&format!("USER {user} 0 * :{realname}")).await?;

        timeout(WELCOME_TIMEOUT, self.welcome.notified())
            .await
            .map_err(|_| anyhow!("no welcome from the server within 60s"))?;

        if let Some(pw) = &self.cfg.nickserv_password {
            self.write_line(&format!("PRIVMSG NickServ :IDENTIFY {pw}")).await?;
        }

        self.set_online(true);
        println!(
            "[irc] registered as {}; messaging {} directly",
            self.nick.lock().await,
            self.cfg.peer
        );
        Ok(())
        })
    }

    async fn read_loop(self: Arc<Self>, reader: Box<dyn tokio::io::AsyncRead + Send + Unpin>) {
        let mut lines = BufReader::new(reader).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if let Err(err) = self.handle_line(&line).await {
                        eprintln!("[irc] error handling line: {err}");
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    eprintln!("[irc] read error: {err}");
                    break;
                }
            }
        }
        if !self.closing.load(Ordering::SeqCst) {
            self.set_online(false);
            println!("[irc] disconnected");
            let me = self.clone();
            tokio::spawn(async move { me.reconnect().await });
        }
    }

    /// Feed one raw IRC line in, as if the server had sent it.
    ///
    /// Exposed so tests can drive protocol handling — nick collisions, offline
    /// peers, messages from strangers — without staging them on a real server.
    #[doc(hidden)]
    pub async fn handle_line_for_test(&self, line: &str) {
        if let Err(err) = self.handle_line(line).await {
            eprintln!("[irc] test line failed: {err}");
        }
    }

    async fn handle_line(&self, line: &str) -> Result<()> {
        if line.is_empty() {
            return Ok(());
        }
        let (sender, command, params) = parse_line(line);

        match command.as_str() {
            "PING" => {
                let token = params.last().cloned().unwrap_or_default();
                self.write_line(&format!("PONG :{token}")).await?;
            }
            "001" => {
                // RPL_WELCOME: the server's idea of our nick wins.
                if let Some(nick) = params.first() {
                    *self.nick.lock().await = nick.clone();
                }
                self.welcome.notify_waiters();
            }
            "433" | "436" => {
                let mut nick = self.nick.lock().await;
                let taken = nick.clone();
                nick.push('_');
                let next = nick.clone();
                drop(nick);
                println!(
                    "[irc] nick {taken} is taken, trying {next} — but the peer expects {} \
                     and will ignore us until that nick is free (register it with NickServ \
                     to avoid this)",
                    self.cfg.nick
                );
                self.write_line(&format!("NICK {next}")).await?;
            }
            "401" => {
                println!(
                    "[irc] {} is not online; frames sent now are lost",
                    self.cfg.peer
                );
            }
            "404" | "531" | "716" => {
                println!(
                    "[irc] cannot message {}: {} (the peer may have +R set, requiring \
                     you to identify first)",
                    self.cfg.peer,
                    params.get(1..).map(|p| p.join(" ")).unwrap_or_default()
                );
            }
            "ERROR" => println!("[irc] server error: {}", params.join(" ")),
            "PRIVMSG" => {
                if params.len() < 2 {
                    return Ok(());
                }
                let dest = &params[0];
                // Direct messages only: addressed to us, and from the peer.
                if !dest.eq_ignore_ascii_case(&self.nick.lock().await) {
                    return Ok(());
                }
                if !sender.eq_ignore_ascii_case(&self.cfg.peer) {
                    return Ok(());
                }
                if let Some(tx) = self.inbound.lock().await.as_ref() {
                    let _ = tx.send(Inbound { text: params[1].clone(), id: None });
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn reconnect(self: Arc<Self>) {
        let mut delay = Duration::from_secs(1);
        while !self.closing.load(Ordering::SeqCst) {
            match self.clone().open().await {
                Ok(()) => return,
                Err(err) => {
                    eprintln!("[irc] reconnect failed ({err}); retrying in {delay:?}");
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(MAX_BACKOFF);
                }
            }
        }
    }
}

/// TLS setup, split out to keep the connect path readable.
mod tls {
    use std::sync::Arc;

    use anyhow::{anyhow, Result};
    use tokio::net::TcpStream;
    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
    use tokio_rustls::{client::TlsStream, TlsConnector};

    use super::IrcConfig;

    /// Accepts any certificate — only used behind an explicit opt-out flag, for
    /// private ircds with self-signed certs.
    #[derive(Debug)]
    struct NoVerification;

    impl ServerCertVerifier for NoVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
            ]
        }
    }

    pub async fn connect(tcp: TcpStream, cfg: &IrcConfig) -> Result<TlsStream<TcpStream>> {
        let config = if cfg.tls_verify {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        } else {
            eprintln!("[irc] warning: TLS certificate verification is disabled");
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerification))
                .with_no_client_auth()
        };

        let server_name = ServerName::try_from(cfg.host.clone())
            .map_err(|_| anyhow!("invalid TLS server name {:?}", cfg.host))?;
        Ok(TlsConnector::from(Arc::new(config))
            .connect(server_name, tcp)
            .await?)
    }
}

#[async_trait]
impl Transport for IrcTransport {
    fn name(&self) -> &'static str {
        "irc"
    }

    fn max_message_chars(&self) -> usize {
        self.max_message_chars
    }

    fn concurrency(&self) -> usize {
        1 // one line at a time; flood protection is the binding limit
    }

    fn send_attempts(&self) -> u32 {
        3 // resend across a reconnect before giving up
    }

    fn min_interval(&self) -> Duration {
        Duration::from_secs_f64(self.cfg.rate.max(0.0))
    }

    async fn connect(self: Arc<Self>, inbound: mpsc::UnboundedSender<Inbound>) -> Result<()> {
        *self.inbound.lock().await = Some(inbound);
        self.clone().open().await
    }

    async fn send_message(&self, text: &str) -> Result<(), SendError> {
        self.wait_online().await; // a reconnect in progress just makes us wait
        if self.closing.load(Ordering::SeqCst) {
            return Ok(());
        }
        let line = format!("PRIVMSG {} :{}", self.cfg.peer, text);
        match self.write_line(&line).await {
            Ok(()) => Ok(()),
            Err(err) => {
                self.set_online(false); // provoke a wait until the link is back
                Err(SendError::Transient(err.to_string()))
            }
        }
    }

    async fn close(&self) {
        self.closing.store(true, Ordering::SeqCst);
        self.set_online(false);
        let _ = self.write_line("QUIT :bye").await;
        *self.conn.lock().await = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(peer: &str) -> IrcConfig {
        IrcConfig {
            host: "127.0.0.1".into(),
            port: 6667,
            peer: peer.into(),
            nick: "mp".into(),
            user: None,
            realname: None,
            password: None,
            nickserv_password: None,
            tls: false,
            tls_verify: true,
            rate: 0.0,
        }
    }

    #[test]
    fn parses_a_privmsg() {
        let (nick, cmd, params) = parse_line(":nick!user@host PRIVMSG #chan :hello world");
        assert_eq!(nick, "nick");
        assert_eq!(cmd, "PRIVMSG");
        assert_eq!(params, vec!["#chan", "hello world"]);
    }

    #[test]
    fn parses_a_ping() {
        let (nick, cmd, params) = parse_line("PING :server1");
        assert_eq!((nick.as_str(), cmd.as_str()), ("", "PING"));
        assert_eq!(params, vec!["server1"]);
    }

    #[test]
    fn parses_a_numeric() {
        let (_, cmd, params) = parse_line(":irc.example 001 mynick :Welcome");
        assert_eq!(cmd, "001");
        assert_eq!(params, vec!["mynick", "Welcome"]);
    }

    #[test]
    fn strips_ircv3_tags() {
        let (nick, cmd, params) = parse_line("@tag=1;x=y :n!u@h PRIVMSG me :hi");
        assert_eq!((nick.as_str(), cmd.as_str()), ("n", "PRIVMSG"));
        assert_eq!(params, vec!["me", "hi"]);
    }

    #[test]
    fn keeps_colons_and_spaces_in_the_trailing_param() {
        // Our base64 payload must survive verbatim.
        let (_, _, params) = parse_line(":n!u@h PRIVMSG #c :SP1|abc:def ghi: jkl");
        assert_eq!(params[1], "SP1|abc:def ghi: jkl");
    }

    #[test]
    fn handles_an_empty_trailing_param() {
        let (_, _, params) = parse_line(":n!u@h PRIVMSG #c :");
        assert_eq!(params, vec!["#c", ""]);
    }

    #[test]
    fn handles_a_command_with_no_trailing_param() {
        let (_, cmd, params) = parse_line(":n!u@h JOIN #chan");
        assert_eq!(cmd, "JOIN");
        assert_eq!(params, vec!["#chan"]);
    }

    #[test]
    fn uppercases_the_command() {
        let (_, cmd, _) = parse_line("privmsg #c :lowercase");
        assert_eq!(cmd, "PRIVMSG");
    }

    #[test]
    fn budget_leaves_room_for_the_relayed_hostmask() {
        let tp = IrcTransport::new(cfg("mpserver")).unwrap();
        let worst_prefix = format!(":{}!{}@{} ", "n".repeat(30), "u".repeat(10), "h".repeat(63));
        let line = format!(
            "{worst_prefix}PRIVMSG mpserver :{}\r\n",
            "x".repeat(tp.max_message_chars())
        );
        assert!(line.len() <= LINE_LIMIT, "worst-case line was {} bytes", line.len());
    }

    #[test]
    fn longer_peer_nicks_shrink_the_payload() {
        let short = IrcTransport::new(cfg("ab")).unwrap().max_payload();
        let long = IrcTransport::new(cfg("a-very-long-nickname-indeed")).unwrap().max_payload();
        assert!(short >= long);
    }

    #[test]
    fn a_channel_as_peer_is_rejected() {
        for peer in ["#msgproxy", "&local"] {
            match IrcTransport::new(cfg(peer)) {
                Ok(_) => panic!("channel {peer} was accepted as a peer nick"),
                Err(err) => assert!(err.to_string().contains("channel"), "got: {err}"),
            }
        }
    }

    #[test]
    fn an_impossible_peer_is_rejected() {
        assert!(IrcTransport::new(cfg(&"x".repeat(400))).is_err());
    }

    #[test]
    fn payload_matches_the_shared_budget_helper() {
        let tp = IrcTransport::new(cfg("mpserver")).unwrap();
        assert_eq!(tp.max_payload(), crate::frame::payload_budget(tp.max_message_chars()));
        assert_eq!(tp.max_payload(), 213, "an 8-char peer nick should leave 213 bytes");
    }
}
