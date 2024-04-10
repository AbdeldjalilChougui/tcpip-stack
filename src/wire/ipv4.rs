//! IPv4 header (RFC 791). Options are skipped on input and never sent. Fragments are
//! recognised and reported so the stack can drop them (no reassembly).

use super::{be16, checksum, Result, WireError};
use std::net::Ipv4Addr;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const HEADER_LEN: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    pub ttl: u8,
    pub ident: u16,
    pub dont_fragment: bool,
    /// True if this is any piece of a fragmented datagram (MF set or offset > 0).
    pub is_fragment: bool,
    pub payload: &'a [u8],
}

pub fn parse(b: &[u8]) -> Result<Packet<'_>> {
    if b.len() < HEADER_LEN {
        return Err(WireError::Truncated);
    }
    if b[0] >> 4 != 4 {
        return Err(WireError::Unsupported("IP version"));
    }
    let ihl = usize::from(b[0] & 0x0f) * 4;
    if ihl < HEADER_LEN || b.len() < ihl {
        return Err(WireError::Malformed("IHL"));
    }
    let total = usize::from(be16(b, 2));
    if total < ihl || total > b.len() {
        return Err(WireError::Malformed("total length"));
    }
    if checksum(&b[..ihl]) != 0 {
        return Err(WireError::BadChecksum);
    }
    let flags_frag = be16(b, 6);
    Ok(Packet {
        src: Ipv4Addr::new(b[12], b[13], b[14], b[15]),
        dst: Ipv4Addr::new(b[16], b[17], b[18], b[19]),
        protocol: b[9],
        ttl: b[8],
        ident: be16(b, 4),
        dont_fragment: flags_frag & 0x4000 != 0,
        is_fragment: flags_frag & 0x2000 != 0 || flags_frag & 0x1fff != 0,
        // `total` may be shorter than `b` because of Ethernet padding.
        payload: &b[ihl..total],
    })
}

pub fn build(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, ident: u16, ttl: u8, payload: &[u8]) -> Vec<u8> {
    let total = (HEADER_LEN + payload.len()) as u16;
    let mut v = Vec::with_capacity(total as usize);
    v.extend_from_slice(&[0x45, 0]);
    v.extend_from_slice(&total.to_be_bytes());
    v.extend_from_slice(&ident.to_be_bytes());
    v.extend_from_slice(&0x4000u16.to_be_bytes()); // DF, offset 0
    v.extend_from_slice(&[ttl, protocol, 0, 0]);
    v.extend_from_slice(&src.octets());
    v.extend_from_slice(&dst.octets());
    let c = checksum(&v);
    v[10..12].copy_from_slice(&c.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_checksum() {
        let (a, b) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
        let mut p = build(a, b, PROTO_UDP, 7, 64, b"hi");
        let mut padded = p.clone();
        padded.extend_from_slice(&[0; 10]);
        let q = parse(&padded).unwrap();
        assert_eq!((q.src, q.dst, q.protocol, q.ident, q.ttl), (a, b, PROTO_UDP, 7, 64));
        assert_eq!(q.payload, b"hi");
        assert!(q.dont_fragment && !q.is_fragment);
        p[8] = 63; // change TTL without fixing the checksum
        assert_eq!(parse(&p), Err(WireError::BadChecksum));
    }

    #[test]
    fn detects_fragments() {
        let mut p = build(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, PROTO_UDP, 1, 64, b"x");
        p[6] = 0x20; // MF
        p[10] = 0;
        p[11] = 0;
        let c = checksum(&p[..20]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        assert!(parse(&p).unwrap().is_fragment);
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse(&[0x45; 10]), Err(WireError::Truncated));
        let mut p = build(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, PROTO_UDP, 1, 64, b"x");
        p[0] = 0x65;
        assert_eq!(parse(&p), Err(WireError::Unsupported("IP version")));
    }
}
