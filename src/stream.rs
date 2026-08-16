//! Per-stream reassembly, shared by the SOCKS client and the exit node.
//!
//! Messages can arrive out of order — platforms reorder, and we may have several
//! sends in flight — so each direction of each stream carries a monotonic
//! sequence number and is buffered here until it can be delivered contiguously.

use std::collections::HashMap;

use crate::frame::FrameType;

#[derive(Debug, PartialEq, Eq)]
pub enum Delivery {
    Data(Vec<u8>),
    /// Half-close: no more data in this direction.
    Eof,
}

pub struct Reassembler {
    recv_next: u32,
    pending: HashMap<u32, (FrameType, Vec<u8>)>,
}

impl Reassembler {
    /// `start` is the first sequence number expected in this direction: 1 at the
    /// exit node (the client's SYN was seq 0), 0 at the client.
    pub fn new(start: u32) -> Self {
        Reassembler { recv_next: start, pending: HashMap::new() }
    }

    /// Buffer one frame and return whatever is now contiguous, in order.
    pub fn accept(&mut self, seq: u32, ftype: FrameType, payload: Vec<u8>) -> Vec<Delivery> {
        self.pending.insert(seq, (ftype, payload));
        let mut ready = Vec::new();
        while let Some((ftype, payload)) = self.pending.remove(&self.recv_next) {
            self.recv_next = self.recv_next.wrapping_add(1);
            match ftype {
                FrameType::Data => ready.push(Delivery::Data(payload)),
                FrameType::Fin => ready.push(Delivery::Eof),
                _ => {}
            }
        }
        ready
    }

    #[cfg(test)]
    pub fn buffered(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(b: &[u8]) -> Delivery {
        Delivery::Data(b.to_vec())
    }

    #[test]
    fn delivers_in_order_arrivals_immediately() {
        let mut r = Reassembler::new(0);
        assert_eq!(r.accept(0, FrameType::Data, b"one".to_vec()), vec![data(b"one")]);
        assert_eq!(r.accept(1, FrameType::Data, b"two".to_vec()), vec![data(b"two")]);
    }

    #[test]
    fn holds_back_out_of_order_arrivals() {
        let mut r = Reassembler::new(0);
        assert_eq!(r.accept(2, FrameType::Data, b"three".to_vec()), vec![]);
        assert_eq!(r.accept(1, FrameType::Data, b"two".to_vec()), vec![]);
        assert_eq!(r.buffered(), 2);
        // Seq 0 unblocks the whole run at once, in order.
        assert_eq!(
            r.accept(0, FrameType::Data, b"one".to_vec()),
            vec![data(b"one"), data(b"two"), data(b"three")]
        );
        assert_eq!(r.buffered(), 0);
    }

    #[test]
    fn exit_node_starts_at_seq_one() {
        // The client's SYN was seq 0, so the first DATA is seq 1.
        let mut r = Reassembler::new(1);
        assert_eq!(r.accept(1, FrameType::Data, b"first".to_vec()), vec![data(b"first")]);
    }

    #[test]
    fn fin_becomes_eof_in_sequence() {
        let mut r = Reassembler::new(0);
        assert_eq!(r.accept(1, FrameType::Fin, vec![]), vec![]);
        assert_eq!(
            r.accept(0, FrameType::Data, b"last".to_vec()),
            vec![data(b"last"), Delivery::Eof]
        );
    }

    #[test]
    fn syn_and_rst_are_not_delivered_as_bytes() {
        let mut r = Reassembler::new(0);
        assert_eq!(r.accept(0, FrameType::Syn, b"ignored".to_vec()), vec![]);
        assert_eq!(r.accept(1, FrameType::Rst, vec![]), vec![]);
    }

    #[test]
    fn a_duplicate_of_a_consumed_seq_is_dropped() {
        let mut r = Reassembler::new(0);
        r.accept(0, FrameType::Data, b"one".to_vec());
        // Re-delivery of seq 0 must not be replayed, and must not accumulate.
        assert_eq!(r.accept(0, FrameType::Data, b"one".to_vec()), vec![]);
        assert_eq!(r.buffered(), 1, "a stale duplicate is buffered but never delivered");
    }
}
