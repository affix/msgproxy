//! A mock ircd and helpers, so the IRC transport can be exercised end to end
//! without an account or a network.
//!
//! This module is compiled into every integration-test binary, so the ones that
//! don't touch IRC see the ircd as dead code.
#![allow(dead_code)]
//!
//! The mock speaks just enough RFC 1459 to be honest about the thing that
//! constrains this transport: it relays PRIVMSG with the `:nick!user@host`
//! prefix prepended, which is what eats the 512-byte line budget. It records
//! the longest line it ever relayed so tests can assert we stay inside it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::task::AbortHandle;

use msgproxy::transport::irc::parse_line;

pub const LINE_LIMIT: usize = 512;

#[derive(Default)]
pub struct MockIrcd {
    clients: Mutex<HashMap<String, mpsc::UnboundedSender<String>>>,
    connections: Mutex<Vec<AbortHandle>>,
    pub longest_line: AtomicUsize,
    pub oversize_lines: AtomicUsize,
    pub joins: AtomicUsize,
    hostname: &'static str,
}

impl MockIrcd {
    pub fn new() -> Arc<Self> {
        Arc::new(MockIrcd { hostname: "irc.test", ..Default::default() })
    }

    /// Bind an ephemeral port and start serving. Returns the port.
    pub async fn start(self: &Arc<Self>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else { break };
                let me = me.clone();
                let session = me.clone();
                let handle = tokio::spawn(async move { session.session(socket).await });
                me.connections.lock().await.push(handle.abort_handle());
            }
        });
        port
    }

    pub async fn is_online(&self, nick: &str) -> bool {
        self.clients.lock().await.contains_key(nick)
    }

    /// Yank every connection, to force the transports to reconnect.
    pub async fn drop_all(&self) {
        for handle in self.connections.lock().await.drain(..) {
            handle.abort();
        }
        self.clients.lock().await.clear();
    }

    async fn session(self: Arc<Self>, socket: TcpStream) {
        let (reader, mut writer) = socket.into_split();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            while let Some(line) = out_rx.recv().await {
                if writer.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
            }
        });

        let mut lines = BufReader::new(reader).lines();
        let (mut nick, mut user, mut registered) = (None::<String>, None::<String>, false);

        while let Ok(Some(line)) = lines.next_line().await {
            let (_, command, params) = parse_line(&line);
            match command.as_str() {
                "NICK" => {
                    let wanted = params[0].clone();
                    if self.clients.lock().await.contains_key(&wanted) {
                        let _ = out_tx.send(format!(
                            ":{} 433 * {wanted} :Nickname is already in use\r\n",
                            self.hostname
                        ));
                        continue;
                    }
                    nick = Some(wanted);
                }
                "USER" => user = Some(params[0].clone()),
                "JOIN" => {
                    self.joins.fetch_add(1, Ordering::SeqCst);
                }
                "PRIVMSG" => {
                    if let (Some(n), Some(u)) = (&nick, &user) {
                        self.relay(n, u, &params[0], &params[1]).await;
                    }
                }
                "QUIT" => break,
                _ => {}
            }

            if let (Some(n), Some(_), false) = (&nick, &user, registered) {
                registered = true;
                self.clients.lock().await.insert(n.clone(), out_tx.clone());
                let _ = out_tx.send(format!(":{} 001 {n} :Welcome\r\n", self.hostname));
                let _ = out_tx.send("PING :keepalive\r\n".to_string()); // exercise PONG
            }
        }

        if let Some(n) = nick {
            self.clients.lock().await.remove(&n);
        }
    }

    async fn relay(&self, from: &str, user: &str, dest: &str, text: &str) {
        let line = format!(":{from}!{user}@{} PRIVMSG {dest} :{text}\r\n", self.hostname);
        self.longest_line.fetch_max(line.len(), Ordering::SeqCst);
        if line.len() > LINE_LIMIT {
            self.oversize_lines.fetch_add(1, Ordering::SeqCst);
        }
        if let Some(target) = self.clients.lock().await.get(dest) {
            let _ = target.send(line);
        }
    }
}

/// Stand in for "the internet": echo back whatever arrives, uppercased, so a
/// passing test proves the bytes made the full round trip.
pub async fn start_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    use tokio::io::AsyncReadExt;
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let upper: Vec<u8> = buf[..n].to_ascii_uppercase();
                            if socket.write_all(&upper).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

/// Do the SOCKS5 greeting + CONNECT, send a payload, read the same number of
/// bytes back.
pub async fn socks_roundtrip(socks_port: u16, host: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    use tokio::io::AsyncReadExt;

    let mut socket = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
    socket.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0u8; 2];
    socket.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0], "bad SOCKS greeting");

    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    socket.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    socket.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..2], &[5, 0], "SOCKS connect refused");

    socket.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    socket.read_exact(&mut got).await.unwrap();
    got
}
