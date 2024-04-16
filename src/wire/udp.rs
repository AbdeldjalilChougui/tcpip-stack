//! UDP (RFC 768) with the IPv4 pseudo-header checksum.

use super::{be16, ipv4::PROTO_UDP, Checksum, Result, WireError};
use std::net::Ipv4Addr;

pub const HEADER_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

pub fn parse<'a>(src: Ipv4Addr, dst: Ipv4Addr, b: &'a [u8]) -> Result<Datagram<'a>> {
    if b.len() < HEADER_LEN {
        return Err(WireError::Truncated);
    }
    let len = usize::from(be16(b, 4));
    if len < HEADER_LEN || len > b.len() {
        return Err(WireError::Malformed("UDP length"));
    }
    // A zero checksum means "not computed" for UDP over IPv4.
    if be16(b, 6) != 0 && Checksum::new().pseudo(src, dst, PROTO_UDP, len).add(&b[..len]).finish() != 0 {
        return Err(WireError::BadChecksum);
    }
    Ok(Datagram { src_port: be16(b, 0), dst_port: be16(b, 2), payload: &b[HEADER_LEN..len] })
}

pub fn build(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let len = HEADER_LEN + payload.len();
    let mut v = Vec::with_capacity(len);
    v.extend_from_slice(&src_port.to_be_bytes());
    v.extend_from_slice(&dst_port.to_be_bytes());
    v.extend_from_slice(&(len as u16).to_be_bytes());
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(payload);
    let mut c = Checksum::new().pseudo(src, dst, PROTO_UDP, len).add(&v).finish();
    if c == 0 {
        c = 0xffff; // 0 is reserved for "no checksum"
    }
    v[6..8].copy_from_slice(&c.to_be_bytes());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_pseudo_header_matters() {
        let (a, b) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
        let d = build(a, b, 5000, 53, b"query");
        let p = parse(a, b, &d).unwrap();
        assert_eq!((p.src_port, p.dst_port, p.payload), (5000, 53, &b"query"[..]));
        // Same bytes "received" with a different source address must fail.
        assert_eq!(parse(Ipv4Addr::new(10, 0, 0, 3), b, &d), Err(WireError::BadChecksum));
    }
}
