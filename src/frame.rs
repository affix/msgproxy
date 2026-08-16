//! Framing and encryption — the wire format, shared by every transport.
//!
//! A single TCP connection accepted by the SOCKS client is a *stream*. Streams
//! are multiplexed over one message channel. Each frame is a small binary header
//! plus a payload, base64-encoded and posted as an ordinary chat message with a
//! marker prefix so unrelated chatter is ignored.
//!
//! Header (network byte order):
//! ```text
//! side       : 1 byte  - b'C' (client) or b'S' (server); the receiver drops
//!                        frames stamped with its own side.
//! type       : 1 byte  - SYN / DATA / FIN / RST
//! stream_id  : 4 bytes - allocated by the client, per connection
//! seq        : 4 bytes - per-direction, per-stream, used to reassemble in order
//! ```
//!
//! Sequence numbering (both ends must agree):
//!   * the client's SYN is seq 0, its first DATA is seq 1;
//!   * so the server starts reassembling client->server frames at seq 1;
//!   * server->client frames start at seq 0 (the client never receives a SYN).

use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use base64::Engine as _;
use sha2::Sha256;

/// Message marker. Anything in the channel not starting with this is ignored.
pub const PREFIX: &str = "SP1|";

pub const HEADER_LEN: usize = 10;

/// Fixed salt: acceptable because security rests entirely on the shared
/// passphrase, and both ends must derive the identical key without coordination.
const KDF_SALT: &[u8] = b"msgproxy-discord-socks-v1";
const KDF_ITERATIONS: u32 = 200_000;

/// Conservative default payload cap, sized for the tightest transport.
/// Transports override this via their own message-character limit.
pub const DEFAULT_MAX_PAYLOAD: usize = 1200;

pub const SIDE_CLIENT: u8 = b'C';
pub const SIDE_SERVER: u8 = b'S';

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// Open a stream; payload is <2-byte port><host bytes>.
    Syn,
    /// Raw TCP bytes.
    Data,
    /// Half-close: no more data this direction.
    Fin,
    /// Abort the stream (e.g. the exit-node connect failed).
    Rst,
}

impl FrameType {
    fn to_byte(self) -> u8 {
        match self {
            FrameType::Syn => 0,
            FrameType::Data => 1,
            FrameType::Fin => 2,
            FrameType::Rst => 3,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0 => FrameType::Syn,
            1 => FrameType::Data,
            2 => FrameType::Fin,
            3 => FrameType::Rst,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub side: u8,
    pub ftype: FrameType,
    pub stream_id: u32,
    pub seq: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(side: u8, ftype: FrameType, stream_id: u32, seq: u32, payload: Vec<u8>) -> Self {
        Frame { side, ftype, stream_id, seq, payload }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.push(self.side);
        out.push(self.ftype.to_byte());
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(raw: &[u8]) -> Option<Frame> {
        if raw.len() < HEADER_LEN {
            return None;
        }
        Some(Frame {
            side: raw[0],
            ftype: FrameType::from_byte(raw[1])?,
            stream_id: u32::from_be_bytes(raw[2..6].try_into().ok()?),
            seq: u32::from_be_bytes(raw[6..10].try_into().ok()?),
            payload: raw[HEADER_LEN..].to_vec(),
        })
    }
}

/// Turns frames into chat messages and back.
///
/// With a passphrase, every frame — header and payload — is encrypted and
/// authenticated with Fernet before it touches the platform, so the channel
/// reveals neither the tunnelled bytes nor the stream metadata. Both ends must
/// use the same passphrase. Without one, frames are only base64 (no privacy).
pub struct Codec {
    fernet: Option<fernet::Fernet>,
}

impl Codec {
    /// No encryption: frames are base64-encoded only.
    pub fn plaintext() -> Self {
        Codec { fernet: None }
    }

    /// Derive the Fernet key from a shared passphrase (PBKDF2-SHA256, 200k).
    pub fn from_passphrase(passphrase: &str) -> Self {
        if passphrase.is_empty() {
            return Codec::plaintext();
        }
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), KDF_SALT, KDF_ITERATIONS, &mut key);
        // Python does Fernet(urlsafe_b64encode(key)); the fernet crate takes the
        // same url-safe base64 string, so the two ends interoperate.
        let encoded = URL_SAFE.encode(key);
        Codec {
            fernet: fernet::Fernet::new(&encoded),
        }
    }

    pub fn is_encrypted(&self) -> bool {
        self.fernet.is_some()
    }

    pub fn to_message(&self, frame: &Frame) -> String {
        let raw = frame.encode();
        match &self.fernet {
            Some(f) => format!("{}{}", PREFIX, f.encrypt(&raw)),
            None => format!("{}{}", PREFIX, STANDARD.encode(&raw)),
        }
    }

    /// Recover a frame from one channel message, or None if it isn't ours.
    ///
    /// Returns None on anything that fails to authenticate — including frames
    /// encrypted under a different key — so a wrong passphrase simply yields no
    /// usable traffic rather than corrupt data.
    ///
    /// Two details matter, because anyone can post anything in the channel:
    /// base64 is decoded strictly (the Rust decoder rejects out-of-alphabet
    /// characters, so a Fernet token is not silently mangled into a plausible
    /// frame), and anything too short to hold a header is rejected here.
    pub fn from_message(&self, content: &str) -> Option<Frame> {
        let body = content.strip_prefix(PREFIX)?;
        let raw = match &self.fernet {
            Some(f) => f.decrypt(body).ok()?,
            None => STANDARD.decode(body).ok()?,
        };
        if raw.len() < HEADER_LEN {
            return None;
        }
        Frame::decode(&raw)
    }
}

/// Largest raw payload whose encoded message fits in `max_chars` characters.
///
/// Sized for the encrypted case, which is always the larger of the two: a frame
/// becomes a Fernet token (57 bytes of version/timestamp/IV/HMAC around
/// PKCS7-padded AES-CBC ciphertext) and is then base64'd, 4 chars per 3 bytes.
/// Used by transports whose limit is tight enough that guessing wastes real
/// throughput — notably IRC, where it also varies with the peer's nick.
pub fn payload_budget(max_chars: usize) -> usize {
    let body = match max_chars.checked_sub(PREFIX.len()) {
        Some(n) if n > 0 => n,
        _ => return 0,
    };
    let token_bytes = (body / 4) * 3; // invert base64 (padded to 4-char groups)
    let ciphertext = match token_bytes.checked_sub(57) {
        Some(n) if n >= 32 => n, // strip Fernet's fixed overhead
        _ => return 0,
    };
    // PKCS7 pads up to the next multiple of 16, adding a whole block when the
    // plaintext is already aligned — so the largest safe frame is one under.
    let frame = (ciphertext / 16) * 16 - 1;
    frame.saturating_sub(HEADER_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(payload: Vec<u8>) -> Frame {
        Frame::new(SIDE_CLIENT, FrameType::Data, 42, 7, payload)
    }

    #[test]
    fn frame_round_trip() {
        for payload in [vec![], vec![b'x'], vec![0u8; 1200], (0..=255u8).collect()] {
            let f = frame(payload);
            assert_eq!(Frame::decode(&f.encode()).unwrap(), f);
        }
    }

    #[test]
    fn frame_fields_survive_extremes() {
        let f = Frame::new(SIDE_CLIENT, FrameType::Syn, u32::MAX, u32::MAX, b"hi".to_vec());
        let back = Frame::decode(&f.encode()).unwrap();
        assert_eq!((back.stream_id, back.seq, back.payload), (u32::MAX, u32::MAX, b"hi".to_vec()));
    }

    #[test]
    fn rejects_unknown_frame_type() {
        let mut raw = frame(vec![]).encode();
        raw[1] = 99;
        assert!(Frame::decode(&raw).is_none());
    }

    #[test]
    fn rejects_truncated_frames() {
        // A stranger posting "SP1|AAAA" must not reach the header parser.
        for len in 0..HEADER_LEN {
            assert!(Frame::decode(&vec![0u8; len]).is_none(), "accepted {len} bytes");
        }
    }

    #[test]
    fn message_round_trip_encrypted() {
        let codec = Codec::from_passphrase("a shared passphrase");
        assert!(codec.is_encrypted());
        let f = frame(b"secret payload".to_vec());
        let msg = codec.to_message(&f);
        assert!(msg.starts_with(PREFIX));
        assert!(!msg.contains("secret"), "plaintext leaked into the message");
        assert_eq!(codec.from_message(&msg).unwrap(), f);
    }

    #[test]
    fn message_round_trip_plaintext() {
        let codec = Codec::plaintext();
        let f = frame(b"payload".to_vec());
        assert_eq!(codec.from_message(&codec.to_message(&f)).unwrap(), f);
    }

    #[test]
    fn wrong_passphrase_yields_nothing() {
        let a = Codec::from_passphrase("passphrase one");
        let b = Codec::from_passphrase("passphrase two");
        let msg = a.to_message(&frame(b"payload".to_vec()));
        assert!(b.from_message(&msg).is_none());
    }

    #[test]
    fn plaintext_reader_rejects_encrypted_message() {
        let enc = Codec::from_passphrase("a passphrase");
        let msg = enc.to_message(&frame(b"payload".to_vec()));
        assert!(Codec::plaintext().from_message(&msg).is_none());
    }

    #[test]
    fn encrypted_reader_rejects_plaintext_message() {
        let msg = Codec::plaintext().to_message(&frame(b"payload".to_vec()));
        assert!(Codec::from_passphrase("a passphrase").from_message(&msg).is_none());
    }

    #[test]
    fn foreign_messages_ignored() {
        let codec = Codec::from_passphrase("a passphrase");
        for content in ["just people chatting", "", "SP1", "SP1|not valid base64 !!!", "SP1|"] {
            assert!(codec.from_message(content).is_none(), "accepted {content:?}");
        }
    }

    #[test]
    fn short_messages_are_rejected() {
        let codec = Codec::plaintext();
        for body in ["AAAA", "AA==", "", "AAAAAAAA", "AAAAAAAAAAAA"] {
            assert!(codec.from_message(&format!("{PREFIX}{body}")).is_none());
        }
    }

    #[test]
    fn payload_budget_always_fits() {
        let codec = Codec::from_passphrase("a passphrase");
        for limit in (80..4300).step_by(7) {
            let budget = payload_budget(limit);
            if budget == 0 {
                continue;
            }
            let msg = codec.to_message(&frame(vec![0u8; budget]));
            assert!(msg.len() <= limit, "budget {budget} for limit {limit} gave {}", msg.len());
        }
    }

    #[test]
    fn payload_budget_is_tight() {
        let codec = Codec::from_passphrase("a passphrase");
        for limit in [512usize, 2000, 4096] {
            let budget = payload_budget(limit);
            let msg = codec.to_message(&frame(vec![0u8; budget + 1]));
            assert!(msg.len() > limit, "one more byte still fit at limit {limit}");
        }
    }

    #[test]
    fn payload_budget_refuses_impossible_limits() {
        assert_eq!(payload_budget(0), 0);
        assert_eq!(payload_budget(10), 0);
        assert_eq!(payload_budget(80), 0);
    }

    #[test]
    fn budget_is_safe_without_encryption() {
        let budget = payload_budget(2000);
        let msg = Codec::plaintext().to_message(&frame(vec![0u8; budget]));
        assert!(msg.len() <= 2000);
    }

    /// Known-answer test for the key derivation.
    ///
    /// Round-trip tests can't catch a change here, because both ends would
    /// change together and still agree with each other while silently losing
    /// compatibility with every already-deployed peer. This pins the actual
    /// bytes, so a dependency upgrade that alters PBKDF2 or the key encoding
    /// fails loudly instead.
    #[test]
    fn key_derivation_is_stable() {
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(
            b"known answer passphrase",
            KDF_SALT,
            KDF_ITERATIONS,
            &mut key,
        );
        assert_eq!(
            hex::encode(key),
            "c31aaf391f37ac05d3c8a0b4baef3bec5d2b12764a6a6811212533c0a2ce9333"
        );
    }

    /// Known-answer test for the whole wire format.
    ///
    /// This token was produced by an earlier build. If it still decrypts to the
    /// same frame, the salt, iteration count, key encoding, Fernet framing and
    /// header layout are all unchanged, and a new build can still talk to an
    /// old peer.
    #[test]
    fn a_previously_encrypted_message_still_decodes() {
        const TOKEN: &str = "SP1|gAAAAABqgXWpIv-jg-EvJU9I17li51pliILiXlR6GiAkrqA_KVJKkIrC_6SyUX8bkLLv4me6zwkyFwfZCm9dYPN34bbWYMRkfXT_gzhQcMAGso3IGHzIjRA=";
        let codec = Codec::from_passphrase("known answer passphrase");
        let frame = codec.from_message(TOKEN).expect("an old message must still decode");
        assert_eq!(frame.side, SIDE_CLIENT);
        assert_eq!(frame.ftype, FrameType::Data);
        assert_eq!((frame.stream_id, frame.seq), (7, 3));
        assert_eq!(frame.payload, b"known answer payload".to_vec());
    }

    #[test]
    fn budget_matches_the_python_implementation() {
        // Values the Python suite pins, so a mixed pair frames identically.
        assert_eq!(payload_budget(2000), 1429); // Discord
        assert_eq!(payload_budget(4096), 2997); // WhatsApp
        assert_eq!(payload_budget(382), 213); // IRC with an 8-char peer nick
    }
}
