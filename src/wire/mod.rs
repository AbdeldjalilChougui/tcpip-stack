//! Packet formats: parse from bytes and build into bytes. No state lives here.

pub mod arp;
pub mod ethernet;
pub mod icmp;
pub mod ipv4;
pub mod tcp;
pub mod udp;

use std::fmt;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    Truncated,
    BadChecksum,
    Malformed(&'static str),
    Unsupported(&'static str),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Truncated => f.write_str("truncated packet"),
            WireError::BadChecksum => f.write_str("bad checksum"),
            WireError::Malformed(w) => write!(f, "malformed: {w}"),
            WireError::Unsupported(w) => write!(f, "unsupported: {w}"),
        }
    }
}

impl std::error::Error for WireError {}

pub type Result<T> = std::result::Result<T, WireError>;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);
    pub const ZERO: MacAddr = MacAddr([0; 6]);
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = self.0;
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// RFC 1071 Internet checksum, fed incrementally.
#[derive(Default)]
pub struct Checksum {
    sum: u32,
    odd: Option<u8>,
}

impl Checksum {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, mut data: &[u8]) -> &mut Self {
        if let (Some(hi), Some((&lo, rest))) = (self.odd, data.split_first()) {
            self.sum += u32::from(u16::from_be_bytes([hi, lo]));
            self.odd = None;
            data = rest;
        }
        let mut chunks = data.chunks_exact(2);
        for c in &mut chunks {
            self.sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
        }
        if let [b] = chunks.remainder() {
            self.odd = Some(*b);
        }
        self
    }

    /// TCP/UDP pseudo-header.
    pub fn pseudo(&mut self, src: Ipv4Addr, dst: Ipv4Addr, proto: u8, len: usize) -> &mut Self {
        self.add(&src.octets()).add(&dst.octets()).add(&[0, proto]).add(&(len as u16).to_be_bytes())
    }

    pub fn finish(&self) -> u16 {
        let mut s = self.sum;
        if let Some(hi) = self.odd {
            s += u32::from(hi) << 8;
        }
        while s >> 16 != 0 {
            s = (s & 0xffff) + (s >> 16);
        }
        !(s as u16)
    }
}

pub fn checksum(data: &[u8]) -> u16 {
    Checksum::new().add(data).finish()
}

pub(crate) fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

pub(crate) fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1071_example() {
        // Example from RFC 1071 section 3: sum of 0001 f203 f4f5 f6f7 = ddf2, checksum = 220d
        assert_eq!(checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]), 0x220d);
    }

    #[test]
    fn incremental_equals_one_shot_with_odd_splits() {
        let data: Vec<u8> = (0..101u32).map(|i| (i * 7 + 3) as u8).collect();
        let whole = checksum(&data);
        for split in 0..data.len() {
            let mut c = Checksum::new();
            c.add(&data[..split]).add(&data[split..]);
            assert_eq!(c.finish(), whole, "split at {split}");
        }
    }

    #[test]
    fn checksum_of_data_with_checksum_is_zero() {
        let mut d = vec![0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x40, 0x00, 0x40, 0x01, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
        let c = checksum(&d);
        d[10..12].copy_from_slice(&c.to_be_bytes());
        assert_eq!(checksum(&d), 0);
    }
}
