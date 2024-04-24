//! Two stacks on one simulated wire, stepped one millisecond at a time.

use crate::link::{MemLink, MemWire, WireConfig};
use crate::stack::{Config, Stack};
use crate::wire::MacAddr;
use std::net::Ipv4Addr;

pub const IP_A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
pub const IP_B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
pub const MAC_A: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x0a]);
pub const MAC_B: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x0b]);

pub struct Pair {
    pub a: Stack,
    pub b: Stack,
    pub wire: MemWire,
    la: MemLink,
    lb: MemLink,
    pub now: u64,
}

impl Pair {
    pub fn new(cfg: WireConfig) -> Self {
        let wire = MemWire::new(cfg.clone());
        let (la, lb) = wire.endpoints();
        Pair {
            a: Stack::new(Config { mac: MAC_A, ip: IP_A, seed: cfg.seed ^ 0xa }),
            b: Stack::new(Config { mac: MAC_B, ip: IP_B, seed: cfg.seed ^ 0xb }),
            wire,
            la,
            lb,
            now: 0,
        }
    }

    /// Advance one millisecond: both stacks receive what arrived and transmit.
    pub fn step(&mut self) {
        self.a.run(&mut self.la, self.now);
        self.b.run(&mut self.lb, self.now);
        self.now += 1;
    }

    /// Step until `done` holds or `max_ms` passes. Returns whether `done` held.
    pub fn run_until(&mut self, max_ms: u64, mut done: impl FnMut(&mut Pair) -> bool) -> bool {
        let end = self.now + max_ms;
        while self.now < end {
            if done(self) {
                return true;
            }
            self.step();
        }
        done(self)
    }
}
