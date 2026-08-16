//! Exit node.
//!
//! Listens on the transport for frames from the client. On SYN it opens a real
//! TCP connection to the requested host:port and relays bytes both ways. This
//! process must run somewhere with the outbound network access you want to
//! proxy through.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::frame::{Frame, FrameType};
use crate::stream::{Delivery, Reassembler};
use crate::tunnel::Tunnel;

type Chunk = Option<Vec<u8>>;

enum Ctl {
    /// The upstream socket is up; deliver buffered and future bytes here.
    Connected { sid: u32, out: mpsc::UnboundedSender<Chunk> },
    Close { sid: u32 },
}

pub async fn run(tunnel: Arc<Tunnel>, mut frames: mpsc::UnboundedReceiver<Frame>) {
    println!("[server] exit node ready; waiting for streams");

    struct Entry {
        reassembler: Reassembler,
        /// Bytes that arrived before the upstream socket finished connecting.
        buffered: Vec<Chunk>,
        out: Option<mpsc::UnboundedSender<Chunk>>,
    }
    let mut streams: HashMap<u32, Entry> = HashMap::new();
    let (ctl_tx, mut ctl_rx) = mpsc::unbounded_channel::<Ctl>();

    loop {
        tokio::select! {
            Some(message) = ctl_rx.recv() => match message {
                Ctl::Connected { sid, out } => {
                    if let Some(entry) = streams.get_mut(&sid) {
                        // Drain anything that arrived while we were connecting.
                        for chunk in entry.buffered.drain(..) {
                            if out.send(chunk).is_err() {
                                break;
                            }
                        }
                        entry.out = Some(out);
                    }
                }
                Ctl::Close { sid } => { streams.remove(&sid); }
            },
            Some(frame) = frames.recv() => {
                let sid = frame.stream_id;
                match frame.ftype {
                    FrameType::Syn => {
                        if streams.contains_key(&sid) {
                            continue;
                        }
                        let Some((host, port)) = parse_syn(&frame.payload) else {
                            eprintln!("[server] stream {sid}: malformed SYN, ignoring");
                            continue;
                        };
                        // The client's SYN was seq 0, so its data starts at 1.
                        streams.insert(sid, Entry {
                            reassembler: Reassembler::new(1),
                            buffered: Vec::new(),
                            out: None,
                        });
                        // Connect in the background so we keep processing frames
                        // meanwhile; data arriving first is buffered above.
                        tokio::spawn(connect(sid, host, port, tunnel.clone(), ctl_tx.clone()));
                    }
                    FrameType::Rst => {
                        if let Some(entry) = streams.remove(&sid) {
                            if let Some(out) = entry.out {
                                let _ = out.send(None);
                            }
                        }
                    }
                    ftype => {
                        let Some(entry) = streams.get_mut(&sid) else { continue };
                        for delivery in entry.reassembler.accept(frame.seq, ftype, frame.payload) {
                            let chunk = match delivery {
                                Delivery::Data(bytes) => Some(bytes),
                                Delivery::Eof => None,
                            };
                            match &entry.out {
                                Some(out) => { let _ = out.send(chunk); }
                                None => entry.buffered.push(chunk),
                            }
                        }
                    }
                }
            },
            else => break,
        }
    }
}

fn parse_syn(payload: &[u8]) -> Option<(String, u16)> {
    if payload.len() < 3 {
        return None;
    }
    let port = u16::from_be_bytes([payload[0], payload[1]]);
    let host = String::from_utf8(payload[2..].to_vec()).ok()?;
    Some((host, port))
}

async fn connect(
    sid: u32,
    host: String,
    port: u16,
    tunnel: Arc<Tunnel>,
    ctl: mpsc::UnboundedSender<Ctl>,
) {
    let socket = match TcpStream::connect((host.as_str(), port)).await {
        Ok(socket) => socket,
        Err(err) => {
            println!("[server] connect {host}:{port} failed: {err}");
            tunnel.send(FrameType::Rst, sid, 0, Vec::new());
            let _ = ctl.send(Ctl::Close { sid });
            return;
        }
    };
    println!("[server] stream {sid} -> {host}:{port}");

    let (out_tx, out_rx) = mpsc::unbounded_channel::<Chunk>();
    let _ = ctl.send(Ctl::Connected { sid, out: out_tx });

    let (mut reader, writer) = socket.into_split();
    tokio::spawn(pump_to_remote(writer, out_rx));

    // Remote server bytes -> DATA frames back to the client.
    let mut send_seq: u32 = 0;
    let mut buf = vec![0u8; tunnel.max_payload()];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                tunnel.send(FrameType::Data, sid, send_seq, buf[..n].to_vec());
                send_seq = send_seq.wrapping_add(1);
            }
        }
    }
    tunnel.send(FrameType::Fin, sid, send_seq, Vec::new());
    let _ = ctl.send(Ctl::Close { sid });
}

/// Ordered client bytes -> the upstream socket.
async fn pump_to_remote(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut out: mpsc::UnboundedReceiver<Chunk>,
) {
    while let Some(Some(chunk)) = out.recv().await {
        if writer.write_all(&chunk).await.is_err() {
            break;
        }
    }
    let _ = writer.shutdown().await;
}
