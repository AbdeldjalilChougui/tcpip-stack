//! TCP segment format (RFC 793 / 9293). Only the MSS option is understood.

use super::{be16, be32, ipv4::PROTO_TCP, Checksum, Result, WireError};
use std::fmt;
use std::net::Ipv4Addr;

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
pub const HEADER_LEN: usize = 20;

#[derive(Clone, PartialEq, Eq, Default)]
pub struct Segment {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
    pub payload: Vec<u8>,
}

impl Segment {
    pub fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }

    /// Sequence space consumed: payload plus one for SYN and one for FIN.
    pub fn seq_len(&self) -> u32 {
        self.payload.len() as u32 + u32::from(self.has(SYN)) + u32::from(self.has(FIN))
    }
}

impl fmt::Debug for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut fl = String::new();
        for (bit, c) in [(SYN, 'S'), (ACK, '.'), (FIN, 'F'), (RST, 'R'), (PSH, 'P')] {
            if self.has(bit) {
                fl.push(c);
            }
        }
        write!(
            f,
            "{}->{} [{fl}] seq={} ack={} win={} len={}",
            self.src_port,
            self.dst_port,
            self.seq,
            self.ack,
            self.window,
            self.payload.len()
        )
    }
}

pub fn parse(src: Ipv4Addr, dst: Ipv4Addr, b: &[u8]) -> Result<Segment> {
    if b.len() < HEADER_LEN {
        return Err(WireError::Truncated);
    }
    let off = usize::from(b[12] >> 4) * 4;
    if off < HEADER_LEN || off > b.len() {
        return Err(WireError::Malformed("data offset"));
    }
    if Checksum::new().pseudo(src, dst, PROTO_TCP, b.len()).add(b).finish() != 0 {
        return Err(WireError::BadChecksum);
    }
    let mut mss = None;
    let mut opts = &b[HEADER_LEN..off];
    while let Some(&kind) = opts.first() {
        match kind {
            0 => break,
            1 => opts = &opts[1..],
            _ => {
                let len = usize::from(*opts.get(1).ok_or(WireError::Malformed("option"))?);
                if len < 2 || len > opts.len() {
                    return Err(WireError::Malformed("option length"));
                }
                if kind == 2 && len == 4 {
                    mss = Some(be16(opts, 2));
                }
                opts = &opts[len..];
            }
        }
    }
    Ok(Segment {
        src_port: be16(b, 0),
        dst_port: be16(b, 2),
        seq: be32(b, 4),
        ack: be32(b, 8),
        flags: b[13],
        window: be16(b, 14),
        mss,
        payload: b[off..].to_vec(),
    })
}

pub fn build(src: Ipv4Addr, dst: Ipv4Addr, s: &Segment) -> Vec<u8> {
    let opt_len = if s.mss.is_some() { 4 } else { 0 };
    let off = HEADER_LEN + opt_len;
    let mut v = Vec::with_capacity(off + s.payload.len());
    v.extend_from_slice(&s.src_port.to_be_bytes());
    v.extend_from_slice(&s.dst_port.to_be_bytes());
    v.extend_from_slice(&s.seq.to_be_bytes());
    v.extend_from_slice(&s.ack.to_be_bytes());
    v.push(((off / 4) as u8) << 4);
    v.push(s.flags);
    v.extend_from_slice(&s.window.to_be_bytes());
    v.extend_from_slice(&[0, 0, 0, 0]); // checksum, urgent pointer
    if let Some(m) = s.mss {
        v.extend_from_slice(&[2, 4]);
        v.extend_from_slice(&m.to_be_bytes());
    }
    v.extend_from_slice(&s.payload);
    let c = Checksum::new().pseudo(src, dst, PROTO_TCP, v.len()).add(&v).finish();
    v[16..18].copy_from_slice(&c.to_be_bytes());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_mss() {
        let (a, b) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
        let s = Segment {
            src_port: 40000,
            dst_port: 80,
            seq: 0xfffffff0,
            ack: 5,
            flags: SYN | ACK,
            window: 4096,
            mss: Some(1460),
            payload: b"odd".to_vec(),
        };
        let bytes = build(a, b, &s);
        assert_eq!(parse(a, b, &bytes).unwrap(), s);
        assert_eq!(s.seq_len(), 4);
        let mut bad = bytes.clone();
        bad[25] ^= 0x40;
        assert_eq!(parse(a, b, &bad), Err(WireError::BadChecksum));
    }
}
