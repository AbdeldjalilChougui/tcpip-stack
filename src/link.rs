//! The link layer is a trait so the stack never touches a real NIC in tests.
//!
//! [`MemWire`] connects two [`MemLink`] endpoints in memory and can drop, delay, reorder
//! and duplicate frames with a seeded RNG, so lossy runs are reproducible. It can also
//! record every frame it carries to a pcap file.

use crate::pcap::{PcapWriter, LINKTYPE_ETHERNET};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, BufWriter};
use std::path::Path;
use std::rc::Rc;

/// Something that moves whole Ethernet frames. Time is in milliseconds, supplied by the caller.
pub trait Link {
    fn send(&mut self, now_ms: u64, frame: &[u8]);
    fn recv(&mut self, now_ms: u64) -> Option<Vec<u8>>;
}

/// Small deterministic PRNG (xorshift64*), good enough for fault injection.
#[derive(Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    /// Uniform in [0, 1).
    pub fn chance(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }
}

#[derive(Clone, Debug)]
pub struct WireConfig {
    /// One-way delay for every frame.
    pub latency_ms: u64,
    /// Probability that a frame is dropped.
    pub loss: f64,
    /// Probability that a frame gets an extra random delay of up to `reorder_ms`, letting
    /// later frames overtake it.
    pub reorder: f64,
    pub reorder_ms: u64,
    /// Probability that a frame is delivered twice.
    pub duplicate: f64,
    pub seed: u64,
}

impl Default for WireConfig {
    fn default() -> Self {
        WireConfig { latency_ms: 1, loss: 0.0, reorder: 0.0, reorder_ms: 0, duplicate: 0.0, seed: 1 }
    }
}

impl WireConfig {
    pub fn lossy(loss: f64, reorder: f64, seed: u64) -> Self {
        WireConfig { latency_ms: 2, loss, reorder, reorder_ms: 15, duplicate: 0.02, seed }
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct WireStats {
    pub sent: usize,
    pub dropped: usize,
    pub reordered: usize,
    pub duplicated: usize,
}

struct WireState {
    cfg: WireConfig,
    rng: Rng,
    /// queues[side] holds frames travelling *towards* `side`: (deliver_at, seq, frame).
    queues: [VecDeque<(u64, u64, Vec<u8>)>; 2],
    seq: u64,
    pcap: Option<PcapWriter<BufWriter<File>>>,
    stats: WireStats,
}

/// A simulated cable between two endpoints.
#[derive(Clone)]
pub struct MemWire(Rc<RefCell<WireState>>);

impl MemWire {
    pub fn new(cfg: WireConfig) -> Self {
        let rng = Rng::new(cfg.seed);
        MemWire(Rc::new(RefCell::new(WireState {
            cfg,
            rng,
            queues: [VecDeque::new(), VecDeque::new()],
            seq: 0,
            pcap: None,
            stats: WireStats::default(),
        })))
    }

    /// Record every frame put on the wire (including ones that will be dropped, like a tap
    /// on the sender's side would see them).
    pub fn capture(&self, path: impl AsRef<Path>) -> io::Result<()> {
        if let Some(dir) = path.as_ref().parent() {
            std::fs::create_dir_all(dir)?;
        }
        let w = PcapWriter::new(BufWriter::new(File::create(path)?), LINKTYPE_ETHERNET)?;
        self.0.borrow_mut().pcap = Some(w);
        Ok(())
    }

    pub fn flush_capture(&self) -> io::Result<()> {
        match self.0.borrow_mut().pcap.as_mut() {
            Some(p) => p.flush(),
            None => Ok(()),
        }
    }

    pub fn stats(&self) -> WireStats {
        self.0.borrow().stats
    }

    /// The two ends: frames sent on `a` arrive on `b` and vice versa.
    pub fn endpoints(&self) -> (MemLink, MemLink) {
        (MemLink { wire: self.clone(), side: 0 }, MemLink { wire: self.clone(), side: 1 })
    }

    pub fn in_flight(&self) -> usize {
        let s = self.0.borrow();
        s.queues[0].len() + s.queues[1].len()
    }
}

pub struct MemLink {
    wire: MemWire,
    side: usize,
}

impl Link for MemLink {
    fn send(&mut self, now_ms: u64, frame: &[u8]) {
        let mut guard = self.wire.0.borrow_mut();
        let s = &mut *guard;
        s.stats.sent += 1;
        if let Some(p) = s.pcap.as_mut() {
            let _ = p.write(now_ms * 1000, frame);
        }
        if s.rng.chance() < s.cfg.loss {
            s.stats.dropped += 1;
            return;
        }
        let copies = if s.rng.chance() < s.cfg.duplicate {
            s.stats.duplicated += 1;
            2
        } else {
            1
        };
        for _ in 0..copies {
            let mut at = now_ms + s.cfg.latency_ms;
            if s.rng.chance() < s.cfg.reorder {
                s.stats.reordered += 1;
                at += 1 + s.rng.below(s.cfg.reorder_ms.max(1));
            }
            s.seq += 1;
            let seq = s.seq;
            s.queues[1 - self.side].push_back((at, seq, frame.to_vec()));
        }
    }

    fn recv(&mut self, now_ms: u64) -> Option<Vec<u8>> {
        let mut s = self.wire.0.borrow_mut();
        let q = &mut s.queues[self.side];
        // Earliest due frame first; ties broken by send order.
        let (i, _) = q
            .iter()
            .enumerate()
            .filter(|(_, (at, _, _))| *at <= now_ms)
            .min_by_key(|(_, (at, seq, _))| (*at, *seq))?;
        q.remove(i).map(|(_, _, f)| f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perfect_wire_delivers_in_order_after_latency() {
        let w = MemWire::new(WireConfig { latency_ms: 5, ..Default::default() });
        let (mut a, mut b) = w.endpoints();
        a.send(0, b"one");
        a.send(1, b"two");
        assert_eq!(b.recv(4), None);
        assert_eq!(b.recv(6).as_deref(), Some(&b"one"[..]));
        assert_eq!(b.recv(6).as_deref(), Some(&b"two"[..]));
        assert_eq!(a.recv(100), None);
    }

    #[test]
    fn lossy_wire_is_deterministic_per_seed() {
        let run = |seed| {
            let w = MemWire::new(WireConfig { loss: 0.3, seed, ..Default::default() });
            let (mut a, mut b) = w.endpoints();
            for i in 0..100u8 {
                a.send(0, &[i]);
            }
            let mut got = Vec::new();
            while let Some(f) = b.recv(10) {
                got.push(f[0]);
            }
            got
        };
        assert_eq!(run(7), run(7));
        let n = run(7).len();
        assert!((50..90).contains(&n), "{n}");
    }
}
