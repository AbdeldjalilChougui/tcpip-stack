//! TCP connection state machine (one transmission control block per connection).
//!
//! Sans-I/O: [`Tcb::on_segment`] consumes a parsed segment, [`Tcb::poll`] returns the
//! segments to transmit now. Time is a plain millisecond counter passed in by the caller.
//!
//! What is implemented: three-way handshake (active and passive), sequence/ack tracking with
//! wrapping arithmetic, a sliding window bounded by the peer's advertised window, an
//! out-of-order receive queue, go-back-N retransmission on a single RTO timer with
//! exponential backoff, zero-window probing, FIN teardown through every closing state
//! including TIME-WAIT, and RST handling. Not implemented: congestion control, fast
//! retransmit, SACK, window scaling, timestamps, RTT estimation, delayed ACKs, urgent data.

use crate::wire::tcp::{Segment, ACK, FIN, PSH, RST, SYN};
use std::collections::{BTreeMap, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// Orderly FIN exchange finished.
    Normal,
    /// Peer sent RST.
    Reset,
    /// RST in answer to our SYN: nobody listening.
    Refused,
    /// Too many retransmissions.
    Timeout,
    /// We called `abort`.
    Aborted,
}

pub const OUR_MSS: u16 = 1460;
pub const DEFAULT_PEER_MSS: u16 = 536;
pub const INITIAL_RTO_MS: u64 = 200;
pub const MAX_RTO_MS: u64 = 6_400;
pub const MAX_RETRIES: u32 = 12;
/// 2*MSL, shortened from minutes to keep simulations short.
pub const TIME_WAIT_MS: u64 = 2_000;
pub const BUF_CAP: usize = 65_535;

pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
pub fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}
pub fn seq_gt(a: u32, b: u32) -> bool {
    seq_lt(b, a)
}
pub fn seq_ge(a: u32, b: u32) -> bool {
    seq_le(b, a)
}

#[derive(Debug, Default, Clone, Copy)]
pub struct TcbStats {
    pub segs_in: u64,
    pub segs_out: u64,
    pub retransmit_timeouts: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub out_of_order_queued: u64,
    pub dup_or_old: u64,
}

#[derive(Debug)]
pub struct Tcb {
    pub state: State,
    pub local_port: u16,
    pub remote_port: u16,
    pub close_reason: Option<CloseReason>,
    pub stats: TcbStats,

    // send side
    iss: u32,
    snd_una: u32,
    snd_nxt: u32,
    snd_wnd: u32,
    /// Bytes from `buf_seq` on: sent-but-unacked followed by not-yet-sent.
    send_buf: VecDeque<u8>,
    buf_seq: u32,
    fin_queued: bool,
    fin_seq: Option<u32>,
    peer_mss: u16,

    // receive side
    irs: u32,
    rcv_nxt: u32,
    recv_buf: VecDeque<u8>,
    /// Out-of-order data keyed by offset from `irs` (fine below 4 GiB per connection).
    ooo: BTreeMap<u32, Vec<u8>>,
    peer_fin: bool,

    // timers
    rto: u64,
    timer: Option<u64>,
    retries: u32,
    force_probe: bool,
    time_wait_until: Option<u64>,

    ack_pending: bool,
    rst_out: Option<(u32, u32, u8)>,
}

impl Tcb {
    fn blank(local_port: u16, remote_port: u16, iss: u32, state: State) -> Self {
        Tcb {
            state,
            local_port,
            remote_port,
            close_reason: None,
            stats: TcbStats::default(),
            iss,
            snd_una: iss,
            snd_nxt: iss,
            snd_wnd: 0,
            send_buf: VecDeque::new(),
            buf_seq: iss.wrapping_add(1),
            fin_queued: false,
            fin_seq: None,
            peer_mss: DEFAULT_PEER_MSS,
            irs: 0,
            rcv_nxt: 0,
            recv_buf: VecDeque::new(),
            ooo: BTreeMap::new(),
            peer_fin: false,
            rto: INITIAL_RTO_MS,
            timer: None,
            retries: 0,
            force_probe: false,
            time_wait_until: None,
            ack_pending: false,
            rst_out: None,
        }
    }

    /// Active open: the first `poll` sends the SYN.
    pub fn connect(local_port: u16, remote_port: u16, iss: u32) -> Self {
        Tcb::blank(local_port, remote_port, iss, State::SynSent)
    }

    /// Passive open, from a SYN that hit a listening port. The first `poll` sends SYN-ACK.
    pub fn accept(local_port: u16, syn: &Segment, iss: u32) -> Self {
        let mut t = Tcb::blank(local_port, syn.src_port, iss, State::SynReceived);
        t.irs = syn.seq;
        t.rcv_nxt = syn.seq.wrapping_add(1);
        t.snd_wnd = u32::from(syn.window);
        t.peer_mss = syn.mss.unwrap_or(DEFAULT_PEER_MSS);
        t
    }

    // ----- application side -----

    /// Queue bytes for sending; returns how many fit in the send buffer.
    pub fn send(&mut self, data: &[u8]) -> usize {
        if self.fin_queued || !matches!(self.state, State::SynSent | State::SynReceived | State::Established | State::CloseWait) {
            return 0;
        }
        let n = data.len().min(BUF_CAP - self.send_buf.len());
        self.send_buf.extend(&data[..n]);
        n
    }

    /// Read received in-order bytes.
    pub fn recv(&mut self, buf: &mut [u8]) -> usize {
        let was_closed = self.rcv_wnd() == 0;
        let n = buf.len().min(self.recv_buf.len());
        for (dst, src) in buf.iter_mut().zip(self.recv_buf.drain(..n)) {
            *dst = src;
        }
        if was_closed && n > 0 {
            self.ack_pending = true; // window update
        }
        n
    }

    pub fn recv_available(&self) -> usize {
        self.recv_buf.len()
    }

    /// Bytes queued but not yet acknowledged by the peer.
    pub fn send_pending(&self) -> usize {
        self.send_buf.len()
    }

    /// The peer has closed its side and every byte was read.
    pub fn is_eof(&self) -> bool {
        self.peer_fin && self.recv_buf.is_empty()
    }

    /// Orderly close: FIN goes out after the queued data.
    pub fn close(&mut self) {
        match self.state {
            // Nothing to deliver yet: just forget the connection.
            State::SynSent if self.send_buf.is_empty() => self.finish(CloseReason::Normal),
            // Queued data still has to go out: FIN once the handshake completes.
            State::SynSent | State::SynReceived => self.fin_queued = true,
            State::Established => {
                self.fin_queued = true;
                self.state = State::FinWait1;
            }
            State::CloseWait => {
                self.fin_queued = true;
                self.state = State::LastAck;
            }
            _ => {}
        }
    }

    pub fn abort(&mut self) {
        if !matches!(self.state, State::Closed | State::SynSent | State::TimeWait) {
            self.rst_out = Some((self.snd_nxt, 0, RST));
        }
        self.finish(CloseReason::Aborted);
    }

    fn finish(&mut self, why: CloseReason) {
        self.state = State::Closed;
        self.close_reason.get_or_insert(why);
        self.timer = None;
        self.time_wait_until = None;
    }

    fn enter_time_wait(&mut self, now: u64) {
        self.state = State::TimeWait;
        self.timer = None;
        self.time_wait_until = Some(now + TIME_WAIT_MS);
    }

    fn rcv_wnd(&self) -> u32 {
        (BUF_CAP - self.recv_buf.len().min(BUF_CAP)) as u32
    }

    fn mss(&self) -> usize {
        usize::from(self.peer_mss.min(OUR_MSS))
    }

    fn arm(&mut self, now: u64) {
        if self.timer.is_none() {
            self.timer = Some(now + self.rto);
        }
    }

    /// Earliest time `poll` has something to do, for drivers that sleep.
    pub fn next_deadline(&self) -> Option<u64> {
        match (self.timer, self.time_wait_until) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    // ----- network side -----

    pub fn on_segment(&mut self, seg: &Segment, now: u64) {
        self.stats.segs_in += 1;
        match self.state {
            State::Closed => return,
            State::SynSent => return self.on_segment_syn_sent(seg),
            _ => {}
        }

        // Acceptability test (RFC 9293 3.10.7.4).
        let seg_len = seg.seq_len();
        let wnd = self.rcv_wnd();
        let in_wnd = |x: u32| seq_le(self.rcv_nxt, x) && seq_lt(x, self.rcv_nxt.wrapping_add(wnd));
        let acceptable = match (seg_len, wnd) {
            (0, 0) => seg.seq == self.rcv_nxt,
            (0, _) => in_wnd(seg.seq),
            (_, 0) => false,
            _ => in_wnd(seg.seq) || in_wnd(seg.seq.wrapping_add(seg_len - 1)),
        };
        if !acceptable {
            if !seg.has(RST) {
                self.stats.dup_or_old += 1;
                self.ack_pending = true;
                if self.state == State::SynReceived && seg.has(SYN) {
                    self.snd_nxt = self.iss; // our SYN-ACK was probably lost: resend it
                }
            }
            return;
        }
        if seg.has(RST) {
            // RFC 1337: a RST must not cut TIME-WAIT short (it is often the peer answering
            // our re-ACK of a duplicate FIN after it already closed).
            if self.state != State::TimeWait {
                self.finish(CloseReason::Reset);
            }
            return;
        }
        if seg.has(SYN) {
            // SYN inside the window of a synchronized connection is an error.
            self.rst_out = Some((self.snd_nxt, 0, RST));
            return self.finish(CloseReason::Reset);
        }
        if !seg.has(ACK) {
            return;
        }

        if self.state == State::SynReceived {
            if seq_lt(self.snd_una, seg.ack) && seq_le(seg.ack, self.snd_nxt) {
                self.state = if self.fin_queued { State::FinWait1 } else { State::Established };
            } else {
                self.rst_out = Some((seg.ack, 0, RST));
                return;
            }
        }

        if seq_lt(self.snd_una, seg.ack) && seq_le(seg.ack, self.snd_nxt) {
            if seq_gt(seg.ack, self.buf_seq) {
                let n = (seg.ack.wrapping_sub(self.buf_seq) as usize).min(self.send_buf.len());
                self.send_buf.drain(..n);
                self.buf_seq = self.buf_seq.wrapping_add(n as u32);
                self.stats.bytes_sent += n as u64;
            }
            self.snd_una = seg.ack;
            self.retries = 0;
            self.rto = INITIAL_RTO_MS;
            self.timer = (self.snd_una != self.snd_nxt).then_some(now + self.rto);
        } else if seq_gt(seg.ack, self.snd_nxt) {
            self.ack_pending = true; // acks data we never sent
            return;
        }
        if seq_ge(seg.ack, self.snd_una) {
            self.snd_wnd = u32::from(seg.window);
        }

        let mut fin_acked = false;
        if let Some(fs) = self.fin_seq {
            if seq_gt(self.snd_una, fs) {
                fin_acked = true;
                match self.state {
                    State::FinWait1 => self.state = State::FinWait2,
                    State::Closing => return self.enter_time_wait(now),
                    State::LastAck => return self.finish(CloseReason::Normal),
                    _ => {}
                }
            }
        }

        if !seg.payload.is_empty() && matches!(self.state, State::Established | State::FinWait1 | State::FinWait2) {
            self.accept_data(seg.seq, &seg.payload);
        }

        if seg.has(FIN) {
            self.ack_pending = true;
            let fin_at = seg.seq.wrapping_add(seg.payload.len() as u32);
            if fin_at == self.rcv_nxt && !self.peer_fin {
                self.peer_fin = true;
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                match self.state {
                    State::Established => self.state = State::CloseWait,
                    State::FinWait1 if fin_acked => self.enter_time_wait(now),
                    State::FinWait1 => self.state = State::Closing,
                    State::FinWait2 => self.enter_time_wait(now),
                    _ => {}
                }
            }
            // An out-of-order FIN is dropped; the peer retransmits it.
        }
    }

    fn on_segment_syn_sent(&mut self, seg: &Segment) {
        let ack_ok = seg.ack == self.iss.wrapping_add(1);
        if seg.has(ACK) && !ack_ok {
            if !seg.has(RST) {
                self.rst_out = Some((seg.ack, 0, RST));
            }
            return;
        }
        if seg.has(RST) {
            if seg.has(ACK) {
                self.finish(CloseReason::Refused);
            }
            return;
        }
        if !seg.has(SYN) {
            return;
        }
        self.irs = seg.seq;
        self.rcv_nxt = seg.seq.wrapping_add(1);
        self.peer_mss = seg.mss.unwrap_or(DEFAULT_PEER_MSS);
        self.snd_wnd = u32::from(seg.window);
        self.ack_pending = true;
        if seg.has(ACK) {
            self.snd_una = seg.ack;
            self.state = if self.fin_queued { State::FinWait1 } else { State::Established };
            self.timer = None;
            self.retries = 0;
            self.rto = INITIAL_RTO_MS;
        } else {
            // Simultaneous open: answer with SYN-ACK.
            self.state = State::SynReceived;
            self.snd_nxt = self.iss;
        }
    }

    fn accept_data(&mut self, mut seq: u32, payload: &[u8]) {
        let mut data = payload;
        if seq_lt(seq, self.rcv_nxt) {
            let skip = self.rcv_nxt.wrapping_sub(seq) as usize;
            if skip >= data.len() {
                self.stats.dup_or_old += 1;
                self.ack_pending = true;
                return;
            }
            data = &data[skip..];
            seq = self.rcv_nxt;
        }
        let ahead = seq.wrapping_sub(self.rcv_nxt) as usize;
        let room = (self.rcv_wnd() as usize).saturating_sub(ahead);
        data = &data[..data.len().min(room)];
        self.ack_pending = true;
        if data.is_empty() {
            return;
        }
        if ahead > 0 {
            self.stats.out_of_order_queued += 1;
            let key = seq.wrapping_sub(self.irs);
            let e = self.ooo.entry(key).or_default();
            if data.len() > e.len() {
                *e = data.to_vec();
            }
            return;
        }
        self.push_in_order(data);
        // Pull now-contiguous segments out of the reorder queue.
        while let Some((&key, _)) = self.ooo.first_key_value() {
            let s = self.irs.wrapping_add(key);
            if seq_gt(s, self.rcv_nxt) {
                break;
            }
            let d = self.ooo.remove(&key).unwrap();
            let skip = self.rcv_nxt.wrapping_sub(s) as usize;
            if skip < d.len() {
                let room = self.rcv_wnd() as usize;
                let end = d.len().min(skip + room);
                self.push_in_order(&d[skip..end]);
            }
        }
    }

    fn push_in_order(&mut self, d: &[u8]) {
        self.recv_buf.extend(d);
        self.rcv_nxt = self.rcv_nxt.wrapping_add(d.len() as u32);
        self.stats.bytes_received += d.len() as u64;
    }

    fn seg(&self, seq: u32, flags: u8, payload: Vec<u8>) -> Segment {
        Segment {
            src_port: self.local_port,
            dst_port: self.remote_port,
            seq,
            ack: if flags & ACK != 0 { self.rcv_nxt } else { 0 },
            flags,
            window: self.rcv_wnd().min(u32::from(u16::MAX)) as u16,
            mss: (flags & SYN != 0).then_some(OUR_MSS),
            payload,
        }
    }

    fn on_timers(&mut self, now: u64) {
        if self.time_wait_until.is_some_and(|t| now >= t) {
            return self.finish(CloseReason::Normal);
        }
        let Some(deadline) = self.timer else { return };
        if now < deadline {
            return;
        }
        self.retries += 1;
        if self.retries > MAX_RETRIES {
            self.rst_out = Some((self.snd_nxt, 0, RST));
            return self.finish(CloseReason::Timeout);
        }
        self.stats.retransmit_timeouts += 1;
        self.rto = (self.rto * 2).min(MAX_RTO_MS);
        self.timer = Some(now + self.rto);
        // Go-back-N: resend everything from the oldest unacknowledged byte.
        self.snd_nxt = self.snd_una;
        if let Some(fs) = self.fin_seq {
            if seq_le(self.snd_una, fs) {
                self.fin_seq = None;
            }
        }
        self.force_probe = true;
    }

    /// Run timers and return the segments to send now.
    pub fn poll(&mut self, now: u64) -> Vec<Segment> {
        self.on_timers(now);
        let mut out = Vec::new();
        if let Some((seq, ack, flags)) = self.rst_out.take() {
            let mut s = self.seg(seq, flags, Vec::new());
            s.ack = ack;
            s.window = 0;
            out.push(s);
        }
        match self.state {
            State::Closed => {}
            State::TimeWait => {
                if self.ack_pending {
                    out.push(self.seg(self.snd_nxt, ACK, Vec::new()));
                }
            }
            State::SynSent | State::SynReceived => {
                if self.snd_nxt == self.iss {
                    let flags = if self.state == State::SynSent { SYN } else { SYN | ACK };
                    out.push(self.seg(self.iss, flags, Vec::new()));
                    self.snd_nxt = self.iss.wrapping_add(1);
                    self.arm(now);
                } else if self.ack_pending && self.state == State::SynReceived {
                    out.push(self.seg(self.snd_nxt, ACK, Vec::new()));
                }
            }
            _ => self.poll_data(now, &mut out),
        }
        self.ack_pending = false;
        self.stats.segs_out += out.len() as u64;
        out
    }

    fn poll_data(&mut self, now: u64, out: &mut Vec<Segment>) {
        let mss = self.mss();
        loop {
            let off = self.snd_nxt.wrapping_sub(self.buf_seq) as usize;
            if self.fin_seq.is_some() || off >= self.send_buf.len() {
                break;
            }
            let in_flight = self.snd_nxt.wrapping_sub(self.snd_una);
            let mut wnd = self.snd_wnd;
            if self.force_probe && in_flight == 0 {
                wnd = wnd.max(1); // zero-window probe / retransmit at least one byte
            }
            let n = mss.min(self.send_buf.len() - off).min(wnd.saturating_sub(in_flight) as usize);
            if n == 0 {
                break;
            }
            let payload: Vec<u8> = self.send_buf.range(off..off + n).copied().collect();
            out.push(self.seg(self.snd_nxt, ACK | PSH, payload));
            self.snd_nxt = self.snd_nxt.wrapping_add(n as u32);
            self.ack_pending = false;
            self.force_probe = false;
            self.arm(now);
        }
        let all_sent = self.snd_nxt.wrapping_sub(self.buf_seq) as usize == self.send_buf.len();
        if self.fin_queued && self.fin_seq.is_none() && all_sent {
            out.push(self.seg(self.snd_nxt, FIN | ACK, Vec::new()));
            self.fin_seq = Some(self.snd_nxt);
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            self.ack_pending = false;
            self.arm(now);
        }
        if !all_sent && self.fin_seq.is_none() {
            self.arm(now); // persist timer while the peer's window is closed
        }
        if self.ack_pending {
            out.push(self.seg(self.snd_nxt, ACK, Vec::new()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shuttle segments between two TCBs directly (no IP), returning how many moved.
    fn exchange(a: &mut Tcb, b: &mut Tcb, now: u64) -> usize {
        let mut moved = 0;
        for s in a.poll(now) {
            b.on_segment(&s, now);
            moved += 1;
        }
        for s in b.poll(now) {
            a.on_segment(&s, now);
            moved += 1;
        }
        moved
    }

    fn handshake() -> (Tcb, Tcb) {
        let mut c = Tcb::connect(40000, 80, 0xffff_fff0); // ISS near wrap on purpose
        let syn = c.poll(0).remove(0);
        assert!(syn.has(SYN) && !syn.has(ACK) && syn.mss == Some(OUR_MSS));
        let mut s = Tcb::accept(80, &syn, 1000);
        let synack = s.poll(0).remove(0);
        assert!(synack.has(SYN) && synack.has(ACK) && synack.ack == 0xffff_fff1);
        c.on_segment(&synack, 0);
        assert_eq!(c.state, State::Established);
        let ack = c.poll(0).remove(0);
        s.on_segment(&ack, 0);
        assert_eq!(s.state, State::Established);
        (c, s)
    }

    #[test]
    fn seq_arithmetic_wraps() {
        assert!(seq_lt(0xffff_fff0, 5));
        assert!(seq_gt(5, 0xffff_fff0));
        assert!(seq_le(7, 7) && seq_ge(7, 7));
    }

    #[test]
    fn handshake_data_across_seq_wrap_and_teardown() {
        let (mut c, mut s) = handshake();
        let data: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        assert_eq!(c.send(&data), data.len());
        for t in 0..20 {
            exchange(&mut c, &mut s, t);
        }
        let mut got = vec![0; 6000];
        let n = s.recv(&mut got);
        assert_eq!(&got[..n], &data[..]);
        assert_eq!(c.send_pending(), 0);

        c.close();
        assert_eq!(c.state, State::FinWait1);
        exchange(&mut c, &mut s, 30);
        assert_eq!(s.state, State::CloseWait);
        assert!(s.is_eof());
        assert_eq!(c.state, State::FinWait2);
        s.close();
        exchange(&mut s, &mut c, 31);
        assert_eq!(s.state, State::Closed);
        assert_eq!(s.close_reason, Some(CloseReason::Normal));
        assert_eq!(c.state, State::TimeWait);
        c.poll(31 + TIME_WAIT_MS);
        assert_eq!(c.state, State::Closed);
    }

    #[test]
    fn out_of_order_segments_are_reassembled() {
        let (mut c, mut s) = handshake();
        c.send(&[1u8; 3 * 1460]);
        let segs = c.poll(1);
        assert_eq!(segs.len(), 3);
        s.on_segment(&segs[2], 1);
        s.on_segment(&segs[1], 1);
        assert_eq!(s.recv_available(), 0);
        s.on_segment(&segs[0], 1);
        assert_eq!(s.recv_available(), 3 * 1460);
        assert_eq!(s.stats.out_of_order_queued, 2);
    }

    #[test]
    fn lost_segment_is_retransmitted_after_rto() {
        let (mut c, mut s) = handshake();
        c.send(b"hello");
        let lost = c.poll(0);
        assert_eq!(lost.len(), 1);
        assert!(c.poll(INITIAL_RTO_MS - 1).is_empty());
        let again = c.poll(INITIAL_RTO_MS);
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].payload, b"hello");
        assert_eq!(again[0].seq, lost[0].seq);
        s.on_segment(&again[0], INITIAL_RTO_MS);
        for a in s.poll(INITIAL_RTO_MS) {
            c.on_segment(&a, INITIAL_RTO_MS);
        }
        assert_eq!(c.send_pending(), 0);
        assert_eq!(c.next_deadline(), None);
    }

    #[test]
    fn window_limits_bytes_in_flight_and_zero_window_is_probed() {
        let (mut c, mut s) = handshake();
        c.send(&vec![7u8; BUF_CAP]);
        // Peer never reads: after one buffer's worth the window closes.
        let mut now = 1;
        for _ in 0..200 {
            exchange(&mut c, &mut s, now);
            now += 1;
        }
        assert_eq!(s.recv_available(), BUF_CAP);
        c.send(b"more");
        exchange(&mut c, &mut s, now);
        assert_eq!(s.recv_available(), BUF_CAP); // nothing accepted beyond the window
        // A probe goes out once the persist timer fires, even with snd_wnd == 0.
        let probes = c.poll(now + MAX_RTO_MS);
        assert!(probes.iter().any(|p| !p.payload.is_empty()));
        // Reading opens the window; the sender finishes.
        let mut sink = vec![0; BUF_CAP];
        s.recv(&mut sink);
        for _ in 0..50 {
            now += MAX_RTO_MS;
            exchange(&mut c, &mut s, now);
        }
        assert_eq!(s.recv_available(), 4);
    }

    #[test]
    fn close_during_handshake_still_delivers_queued_data() {
        let mut c = Tcb::connect(40000, 80, 1);
        assert_eq!(c.send(b"early"), 5);
        c.close();
        assert_eq!(c.state, State::SynSent);
        let syn = c.poll(0).remove(0);
        let mut s = Tcb::accept(80, &syn, 9);
        for t in 0..10 {
            exchange(&mut c, &mut s, t);
        }
        let mut b = [0; 16];
        assert_eq!(s.recv(&mut b), 5);
        assert_eq!(&b[..5], b"early");
        assert!(s.is_eof());
        assert_eq!(c.state, State::FinWait2);
    }

    #[test]
    fn rst_to_syn_means_refused() {
        let mut c = Tcb::connect(40000, 81, 10);
        let syn = c.poll(0).remove(0);
        let rst = Segment { src_port: 81, dst_port: 40000, ack: syn.seq + 1, flags: RST | ACK, ..Default::default() };
        c.on_segment(&rst, 0);
        assert_eq!((c.state, c.close_reason), (State::Closed, Some(CloseReason::Refused)));
    }

    #[test]
    fn gives_up_after_max_retries() {
        let mut c = Tcb::connect(40000, 80, 10);
        let mut now = 0;
        while c.state != State::Closed {
            c.poll(now);
            now += 100;
            assert!(now < 1_000_000);
        }
        assert_eq!(c.close_reason, Some(CloseReason::Timeout));
    }

    #[test]
    fn simultaneous_close_goes_through_closing() {
        let (mut c, mut s) = handshake();
        c.close();
        s.close();
        let fc = c.poll(1);
        let fs = s.poll(1);
        for x in &fs {
            c.on_segment(x, 1);
        }
        for x in &fc {
            s.on_segment(x, 1);
        }
        assert_eq!((c.state, s.state), (State::Closing, State::Closing));
        exchange(&mut c, &mut s, 2);
        assert_eq!((c.state, s.state), (State::TimeWait, State::TimeWait));
    }
}
