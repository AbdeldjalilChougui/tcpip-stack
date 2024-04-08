//! ARP for IPv4 over Ethernet (RFC 826).

use super::{be16, MacAddr, Result, WireError};
use std::net::Ipv4Addr;

pub const OP_REQUEST: u16 = 1;
pub const OP_REPLY: u16 = 2;
pub const LEN: usize = 28;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet {
    pub op: u16,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

pub fn parse(b: &[u8]) -> Result<Packet> {
    if b.len() < LEN {
        return Err(WireError::Truncated);
    }
    if be16(b, 0) != 1 || be16(b, 2) != 0x0800 || b[4] != 6 || b[5] != 4 {
        return Err(WireError::Unsupported("ARP hardware/protocol type"));
    }
    let mac = |at: usize| MacAddr(b[at..at + 6].try_into().unwrap());
    let ip = |at: usize| Ipv4Addr::new(b[at], b[at + 1], b[at + 2], b[at + 3]);
    Ok(Packet { op: be16(b, 6), sender_mac: mac(8), sender_ip: ip(14), target_mac: mac(18), target_ip: ip(24) })
}

pub fn build(p: &Packet) -> Vec<u8> {
    let mut v = Vec::with_capacity(LEN);
    v.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4]);
    v.extend_from_slice(&p.op.to_be_bytes());
    v.extend_from_slice(&p.sender_mac.0);
    v.extend_from_slice(&p.sender_ip.octets());
    v.extend_from_slice(&p.target_mac.0);
    v.extend_from_slice(&p.target_ip.octets());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let p = Packet {
            op: OP_REQUEST,
            sender_mac: MacAddr([2, 0, 0, 0, 0, 1]),
            sender_ip: Ipv4Addr::new(10, 0, 0, 1),
            target_mac: MacAddr::ZERO,
            target_ip: Ipv4Addr::new(10, 0, 0, 2),
        };
        assert_eq!(parse(&build(&p)).unwrap(), p);
    }
}
