//! SOCKS5 front-end.
//!
//! Runs a local SOCKS5 server. Each accepted connection becomes a stream that
//! is carried, both ways, over the transport to the exit node.
//!
//! Only CONNECT is supported (no BIND/UDP-ASSOCIATE), and no auth.

use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::frame::{Frame, FrameType};
use crate::stream::{Delivery, Reassembler};
use crate::tunnel::Tunnel;

/// Bytes handed to a stream's socket-writer task; `None` means EOF.
type Chunk = Option<Vec<u8>>;

/// Control messages from connection handlers to the stream table.
enum Ctl {
    Open { sid: u32, out: mpsc::UnboundedSender<Chunk> },
    Close { sid: u32 },
}

pub async fn run(
    listen: &str,
    port: u16,
    tunnel: Arc<Tunnel>,
    frames: mpsc::UnboundedReceiver<Frame>,
) -> Result<()> {
    let listener = TcpListener::bind((listen, port)).await?;
    println!("[client] SOCKS5 listening on {listen}:{port}");
    serve(listener, tunnel, frames).await
}

/// Serve SOCKS on an already-bound listener. Tests use this to take an
/// ephemeral port and still learn which one they got.
pub async fn serve(
    listener: TcpListener,
    tunnel: Arc<Tunnel>,
    frames: mpsc::UnboundedReceiver<Frame>,
) -> Result<()> {
    let (ctl_tx, ctl_rx) = mpsc::unbounded_channel::<Ctl>();
    tokio::spawn(stream_table(frames, ctl_rx));

    let next_sid = Arc::new(AtomicU32::new(1));
    loop {
        let (socket, _) = listener.accept().await?;
        let tunnel = tunnel.clone();
        let ctl_tx = ctl_tx.clone();
        let next_sid = next_sid.clone();
        tokio::spawn(async move {
            if let Err(err) = handle(socket, tunnel, ctl_tx, next_sid).await {
                eprintln!("[client] socks error: {err}");
            }
        });
    }
}

/// Owns the stream table, so no locking is needed: frames and control messages
/// are funnelled into this one task.
async fn stream_table(
    mut frames: mpsc::UnboundedReceiver<Frame>,
    mut ctl: mpsc::UnboundedReceiver<Ctl>,
) {
    struct Entry {
        out: mpsc::UnboundedSender<Chunk>,
        reassembler: Reassembler,
    }
    let mut streams: HashMap<u32, Entry> = HashMap::new();

    loop {
        tokio::select! {
            Some(message) = ctl.recv() => match message {
                Ctl::Open { sid, out } => {
                    // Server->client frames start at seq 0 (we never receive a SYN).
                    streams.insert(sid, Entry { out, reassembler: Reassembler::new(0) });
                }
                Ctl::Close { sid } => { streams.remove(&sid); }
            },
            Some(frame) = frames.recv() => {
                let Some(entry) = streams.get_mut(&frame.stream_id) else { continue };
                if frame.ftype == FrameType::Rst {
                    let _ = entry.out.send(None);
                    streams.remove(&frame.stream_id);
                    continue;
                }
                for delivery in entry.reassembler.accept(frame.seq, frame.ftype, frame.payload) {
                    let chunk = match delivery {
                        Delivery::Data(bytes) => Some(bytes),
                        Delivery::Eof => None,
                    };
                    let closed = chunk.is_none();
                    if entry.out.send(chunk).is_err() || closed {
                        break;
                    }
                }
            },
            else => break,
        }
    }
}

async fn handle(
    mut socket: TcpStream,
    tunnel: Arc<Tunnel>,
    ctl: mpsc::UnboundedSender<Ctl>,
    next_sid: Arc<AtomicU32>,
) -> Result<()> {
    // Greeting: version, nmethods, methods. We answer "no auth".
    let mut head = [0u8; 2];
    socket.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Ok(());
    }
    let mut methods = vec![0u8; head[1] as usize];
    socket.read_exact(&mut methods).await?;
    socket.write_all(&[5, 0]).await?;

    let (host, port) = match read_target(&mut socket).await {
        Ok(target) => target,
        Err(_) => {
            // Command or address type not supported.
            socket.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            return Ok(());
        }
    };

    let sid = next_sid.fetch_add(1, Ordering::SeqCst);
    let (out_tx, out_rx) = mpsc::unbounded_channel::<Chunk>();
    let _ = ctl.send(Ctl::Open { sid, out: out_tx });

    // Open the stream. SYN is always seq 0.
    let mut payload = port.to_be_bytes().to_vec();
    payload.extend_from_slice(host.as_bytes());
    tunnel.send(FrameType::Syn, sid, 0, payload);
    let mut send_seq: u32 = 1;

    // Optimistic success reply (BND.ADDR 0.0.0.0:0). If the remote connect
    // fails the exit node sends RST and the app sees a reset — one fewer round
    // trip than waiting for a real confirmation.
    socket.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;

    let (mut reader, writer) = socket.into_split();
    tokio::spawn(pump_to_socket(writer, out_rx));

    let max_payload = tunnel.max_payload();
    let mut buf = vec![0u8; max_payload];
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
    Ok(())
}

/// Ordered server->client bytes -> the local SOCKS socket.
async fn pump_to_socket(
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

/// Parse a SOCKS5 CONNECT request; return (host, port).
async fn read_target(socket: &mut TcpStream) -> Result<(String, u16)> {
    let mut head = [0u8; 4];
    socket.read_exact(&mut head).await?;
    let (version, command, atyp) = (head[0], head[1], head[3]);
    if version != 5 || command != 1 {
        return Err(anyhow!("only CONNECT is supported"));
    }
    let host = match atyp {
        1 => {
            let mut addr = [0u8; 4];
            socket.read_exact(&mut addr).await?;
            std::net::Ipv4Addr::from(addr).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            socket.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            socket.read_exact(&mut name).await?;
            String::from_utf8(name)?
        }
        4 => {
            let mut addr = [0u8; 16];
            socket.read_exact(&mut addr).await?;
            Ipv6Addr::from(addr).to_string()
        }
        other => return Err(anyhow!("unsupported address type {other}")),
    };
    let mut port = [0u8; 2];
    socket.read_exact(&mut port).await?;
    Ok((host, u16::from_be_bytes(port)))
}
