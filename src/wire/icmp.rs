//! ICMP (RFC 792): echo request/reply and destination unreachable.

use super::{be16, checksum, Result, WireError};

pub const ECHO_REPLY: u8 = 0;
pub const DEST_UNREACHABLE: u8 = 3;
pub const ECHO_REQUEST: u8 = 8;
pub const CODE_PORT_UNREACHABLE: u8 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    pub kind: u8,
    pub code: u8,
    /// Bytes 4..8: identifier + sequence for echo, unused for unreachable.
    pub rest: [u8; 4],
    pub data: &'a [u8],
}

impl Message<'_> {
    pub fn ident(&self) -> u16 {
        be16(&self.rest, 0)
    }

    pub fn seq(&self) -> u16 {
        be16(&self.rest, 2)
    }
}

pub fn parse(b: &[u8]) -> Result<Message<'_>> {
    if b.len() < 8 {
        return Err(WireError::Truncated);
    }
    if checksum(b) != 0 {
        return Err(WireError::BadChecksum);
    }
    Ok(Message { kind: b[0], code: b[1], rest: b[4..8].try_into().unwrap(), data: &b[8..] })
}

pub fn build(kind: u8, code: u8, rest: [u8; 4], data: &[u8]) -> Vec<u8> {
    let mut v = vec![kind, code, 0, 0];
    v.extend_from_slice(&rest);
    v.extend_from_slice(data);
    let c = checksum(&v);
    v[2..4].copy_from_slice(&c.to_be_bytes());
    v
}

pub fn echo(kind: u8, ident: u16, seq: u16, data: &[u8]) -> Vec<u8> {
    let mut rest = [0; 4];
    rest[..2].copy_from_slice(&ident.to_be_bytes());
    rest[2..].copy_from_slice(&seq.to_be_bytes());
    build(kind, 0, rest, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_roundtrip() {
        let m = echo(ECHO_REQUEST, 0x1234, 9, b"abcdefg");
        let p = parse(&m).unwrap();
        assert_eq!((p.kind, p.ident(), p.seq(), p.data), (ECHO_REQUEST, 0x1234, 9, &b"abcdefg"[..]));
        let mut bad = m.clone();
        bad[9] ^= 1;
        assert_eq!(parse(&bad), Err(WireError::BadChecksum));
    }
}
