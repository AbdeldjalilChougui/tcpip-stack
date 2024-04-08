//! Ethernet II frames (no 802.1Q tags, no FCS: the link layer strips it).

use super::{be16, MacAddr, Result, WireError};

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const HEADER_LEN: usize = 14;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame<'a> {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

pub fn parse(b: &[u8]) -> Result<Frame<'_>> {
    if b.len() < HEADER_LEN {
        return Err(WireError::Truncated);
    }
    let mac = |at: usize| MacAddr(b[at..at + 6].try_into().unwrap());
    Ok(Frame { dst: mac(0), src: mac(6), ethertype: be16(b, 12), payload: &b[HEADER_LEN..] })
}

pub fn build(dst: MacAddr, src: MacAddr, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(HEADER_LEN + payload.len().max(46));
    v.extend_from_slice(&dst.0);
    v.extend_from_slice(&src.0);
    v.extend_from_slice(&ethertype.to_be_bytes());
    v.extend_from_slice(payload);
    // Minimum frame size is 60 bytes without FCS; pad with zeros like a NIC would.
    if v.len() < 60 {
        v.resize(60, 0);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_padding() {
        let a = MacAddr([2, 0, 0, 0, 0, 1]);
        let f = build(MacAddr::BROADCAST, a, ETHERTYPE_ARP, &[1, 2, 3]);
        assert_eq!(f.len(), 60);
        let p = parse(&f).unwrap();
        assert_eq!((p.dst, p.src, p.ethertype), (MacAddr::BROADCAST, a, ETHERTYPE_ARP));
        assert_eq!(&p.payload[..3], &[1, 2, 3]);
        assert_eq!(parse(&f[..10]), Err(WireError::Truncated));
    }
}
