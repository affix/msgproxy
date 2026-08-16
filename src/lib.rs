//! msgproxy — a SOCKS5 proxy tunnelled through a chat platform.
//!
//! Layout:
//!
//! * [`frame`] — the wire format: framing, encryption, message sizing.
//! * [`stream`] — per-stream reassembly, shared by both ends.
//! * [`tunnel`] — queueing, retry, pacing, de-duplication, dispatch.
//! * [`transport`] — the backend trait and its implementations.
//! * [`socks`] / [`exit`] — the SOCKS5 front-end and the exit node.

pub mod exit;
pub mod frame;
pub mod socks;
pub mod stream;
pub mod transport;
pub mod tunnel;
