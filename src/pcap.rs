//! Minimal classic pcap writer/reader (the format Wireshark and tcpdump open).

use std::io::{self, Write};

pub const LINKTYPE_ETHERNET: u32 = 1;

pub struct PcapWriter<W: Write> {
    out: W,
    pub frames: usize,
}

impl<W: Write> PcapWriter<W> {
    pub fn new(mut out: W, linktype: u32) -> io::Result<Self> {
        out.write_all(&0xa1b2c3d4u32.to_le_bytes())?; // magic, microsecond timestamps
        out.write_all(&2u16.to_le_bytes())?;
        out.write_all(&4u16.to_le_bytes())?;
        out.write_all(&0i32.to_le_bytes())?; // thiszone
        out.write_all(&0u32.to_le_bytes())?; // sigfigs
        out.write_all(&65535u32.to_le_bytes())?; // snaplen
        out.write_all(&linktype.to_le_bytes())?;
        Ok(PcapWriter { out, frames: 0 })
    }

    /// `ts_us`: timestamp in microseconds (simulated time is fine).
    pub fn write(&mut self, ts_us: u64, frame: &[u8]) -> io::Result<()> {
        self.out.write_all(&((ts_us / 1_000_000) as u32).to_le_bytes())?;
        self.out.write_all(&((ts_us % 1_000_000) as u32).to_le_bytes())?;
        self.out.write_all(&(frame.len() as u32).to_le_bytes())?;
        self.out.write_all(&(frame.len() as u32).to_le_bytes())?;
        self.out.write_all(frame)?;
        self.frames += 1;
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    pub fn into_inner(self) -> W {
        self.out
    }
}

/// One captured frame: (timestamp in µs, bytes).
pub type Record = (u64, Vec<u8>);

/// Parse a pcap file written by `PcapWriter` back into (linktype, records).
pub fn read(b: &[u8]) -> Option<(u32, Vec<Record>)> {
    if b.len() < 24 || b[..4] != 0xa1b2c3d4u32.to_le_bytes() {
        return None;
    }
    let linktype = u32::from_le_bytes(b[20..24].try_into().ok()?);
    let mut recs = Vec::new();
    let mut at = 24;
    while at + 16 <= b.len() {
        let w = |o: usize| u32::from_le_bytes(b[at + o..at + o + 4].try_into().unwrap());
        let ts = u64::from(w(0)) * 1_000_000 + u64::from(w(4));
        let len = w(8) as usize;
        let data = b.get(at + 16..at + 16 + len)?.to_vec();
        recs.push((ts, data));
        at += 16 + len;
    }
    Some((linktype, recs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read() {
        let mut w = PcapWriter::new(Vec::new(), LINKTYPE_ETHERNET).unwrap();
        w.write(1_500_000, &[1, 2, 3]).unwrap();
        w.write(2_000_001, &[4; 70]).unwrap();
        let bytes = w.into_inner();
        let (lt, recs) = read(&bytes).unwrap();
        assert_eq!(lt, LINKTYPE_ETHERNET);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0], (1_500_000, vec![1, 2, 3]));
        assert_eq!(recs[1].0, 2_000_001);
    }
}
