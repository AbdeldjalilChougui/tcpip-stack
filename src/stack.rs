//! The interface: ARP cache, IPv4 demux, ICMP echo, UDP and TCP sockets.
//!
//! Sans-I/O like the TCB: feed frames to [`Stack::receive`], collect frames to transmit
//! from [`Stack::poll`]. [`Stack::run`] does both against a [`Link`].

use crate::link::{Link, Rng};
use crate::tcp::{State, Tcb};
use crate::wire::tcp::{Segment, ACK, RST, SYN};
use crate::wire::{arp, ethernet, icmp, ipv4, tcp as tcpw, udp, MacAddr, WireError};
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;

pub type Handle = usize;

#[derive(Debug, Clone)]
pub struct Config {
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
    /// Seeds initial sequence numbers and ephemeral ports.
    pub seed: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct StackStats {
    pub frames_in: u64,
    pub frames_out: u64,
    pub parse_errors: u64,
    pub bad_checksums: u64,
    pub not_for_us: u64,
    pub fragments_dropped: u64,
    pub arp_requests_sent: u64,
    pub rst_sent: u64,
    pub icmp_unreachable_sent: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingReply {
    pub from: Ipv4Addr,
    pub ident: u16,
    pub seq: u16,
    pub rtt_ms: u64,
    pub data: Vec<u8>,
}

enum Socket {
    Listener { port: u16, backlog: VecDeque<Handle> },
    Tcp { tcb: Box<Tcb>, remote_ip: Ipv4Addr, parent: Option<Handle>, announced: bool },
    Udp { port: u16, rx: VecDeque<(Ipv4Addr, u16, Vec<u8>)> },
}

const ARP_RETRY_MS: u64 = 1_000;
const ARP_QUEUE_MAX: usize = 256;

pub struct Stack {
    cfg: Config,
    sockets: Vec<Option<Socket>>,
    arp_cache: HashMap<Ipv4Addr, MacAddr>,
    arp_requested: HashMap<Ipv4Addr, u64>,
    arp_waiting: Vec<(Ipv4Addr, Vec<u8>)>,
    tx: VecDeque<Vec<u8>>,
    ip_ident: u16,
    rng: Rng,
    next_port: u16,
    pings_out: HashMap<(u16, u16), u64>,
    ping_replies: Vec<PingReply>,
    pub stats: StackStats,
}

impl Stack {
    pub fn new(cfg: Config) -> Self {
        let mut rng = Rng::new(cfg.seed);
        let next_port = 49152 + rng.below(1000) as u16;
        Stack {
            cfg,
            sockets: Vec::new(),
            arp_cache: HashMap::new(),
            arp_requested: HashMap::new(),
            arp_waiting: Vec::new(),
            tx: VecDeque::new(),
            ip_ident: 1,
            rng,
            next_port,
            pings_out: HashMap::new(),
            ping_replies: Vec::new(),
            stats: StackStats::default(),
        }
    }

    pub fn ip(&self) -> Ipv4Addr {
        self.cfg.ip
    }

    pub fn mac(&self) -> MacAddr {
        self.cfg.mac
    }

    pub fn arp_lookup(&self, ip: Ipv4Addr) -> Option<MacAddr> {
        self.arp_cache.get(&ip).copied()
    }

    fn add(&mut self, s: Socket) -> Handle {
        if let Some(i) = self.sockets.iter().position(Option::is_none) {
            self.sockets[i] = Some(s);
            i
        } else {
            self.sockets.push(Some(s));
            self.sockets.len() - 1
        }
    }

    /// Forget a socket (its handle may be reused).
    pub fn release(&mut self, h: Handle) {
        if let Some(slot) = self.sockets.get_mut(h) {
            *slot = None;
        }
    }

    fn ephemeral_port(&mut self) -> u16 {
        let p = self.next_port;
        self.next_port = if p >= 65000 { 49152 } else { p + 1 };
        p
    }

    // ----- TCP API -----

    pub fn tcp_listen(&mut self, port: u16) -> Handle {
        self.add(Socket::Listener { port, backlog: VecDeque::new() })
    }

    /// Next established connection from a listener's backlog.
    pub fn tcp_accept(&mut self, listener: Handle) -> Option<Handle> {
        match self.sockets.get_mut(listener)? {
            Some(Socket::Listener { backlog, .. }) => backlog.pop_front(),
            _ => None,
        }
    }

    pub fn tcp_connect(&mut self, ip: Ipv4Addr, port: u16) -> Handle {
        let local = self.ephemeral_port();
        let iss = self.rng.next_u64() as u32;
        self.add(Socket::Tcp { tcb: Box::new(Tcb::connect(local, port, iss)), remote_ip: ip, parent: None, announced: true })
    }

    /// The connection's control block (state, stats, close reason, buffers).
    pub fn tcp(&self, h: Handle) -> &Tcb {
        match self.sockets.get(h) {
            Some(Some(Socket::Tcp { tcb, .. })) => tcb,
            _ => panic!("handle {h} is not a TCP connection"),
        }
    }

    pub fn tcp_mut(&mut self, h: Handle) -> &mut Tcb {
        match self.sockets.get_mut(h) {
            Some(Some(Socket::Tcp { tcb, .. })) => tcb,
            _ => panic!("handle {h} is not a TCP connection"),
        }
    }

    pub fn tcp_state(&self, h: Handle) -> State {
        self.tcp(h).state
    }

    pub fn tcp_send(&mut self, h: Handle, data: &[u8]) -> usize {
        self.tcp_mut(h).send(data)
    }

    pub fn tcp_recv(&mut self, h: Handle, buf: &mut [u8]) -> usize {
        self.tcp_mut(h).recv(buf)
    }

    pub fn tcp_close(&mut self, h: Handle) {
        self.tcp_mut(h).close()
    }

    // ----- UDP API -----

    pub fn udp_bind(&mut self, port: u16) -> Handle {
        self.add(Socket::Udp { port, rx: VecDeque::new() })
    }

    pub fn udp_send_to(&mut self, h: Handle, dst: Ipv4Addr, dst_port: u16, data: &[u8], now: u64) {
        let port = match self.sockets.get(h) {
            Some(Some(Socket::Udp { port, .. })) => *port,
            _ => panic!("handle {h} is not a UDP socket"),
        };
        let d = udp::build(self.cfg.ip, dst, port, dst_port, data);
        self.send_ip(dst, ipv4::PROTO_UDP, &d, now);
    }

    pub fn udp_recv_from(&mut self, h: Handle) -> Option<(Ipv4Addr, u16, Vec<u8>)> {
        match self.sockets.get_mut(h)? {
            Some(Socket::Udp { rx, .. }) => rx.pop_front(),
            _ => None,
        }
    }

    // ----- ICMP API -----

    pub fn ping(&mut self, dst: Ipv4Addr, ident: u16, seq: u16, data: &[u8], now: u64) {
        self.pings_out.insert((ident, seq), now);
        let m = icmp::echo(icmp::ECHO_REQUEST, ident, seq, data);
        self.send_ip(dst, ipv4::PROTO_ICMP, &m, now);
    }

    pub fn take_ping_replies(&mut self) -> Vec<PingReply> {
        std::mem::take(&mut self.ping_replies)
    }

    // ----- output path -----

    fn send_ip(&mut self, dst: Ipv4Addr, proto: u8, payload: &[u8], now: u64) {
        let pkt = ipv4::build(self.cfg.ip, dst, proto, self.ip_ident, 64, payload);
        self.ip_ident = self.ip_ident.wrapping_add(1);
        if dst == Ipv4Addr::BROADCAST {
            return self.send_frame(MacAddr::BROADCAST, ethernet::ETHERTYPE_IPV4, &pkt);
        }
        match self.arp_cache.get(&dst) {
            Some(&mac) => self.send_frame(mac, ethernet::ETHERTYPE_IPV4, &pkt),
            None => {
                if self.arp_waiting.len() < ARP_QUEUE_MAX {
                    self.arp_waiting.push((dst, pkt));
                }
                self.arp_request(dst, now);
            }
        }
    }

    fn arp_request(&mut self, ip: Ipv4Addr, now: u64) {
        if self.arp_requested.get(&ip).is_some_and(|&t| now < t + ARP_RETRY_MS) {
            return;
        }
        self.arp_requested.insert(ip, now);
        self.stats.arp_requests_sent += 1;
        let p = arp::Packet {
            op: arp::OP_REQUEST,
            sender_mac: self.cfg.mac,
            sender_ip: self.cfg.ip,
            target_mac: MacAddr::ZERO,
            target_ip: ip,
        };
        self.send_frame(MacAddr::BROADCAST, ethernet::ETHERTYPE_ARP, &arp::build(&p));
    }

    fn send_frame(&mut self, dst: MacAddr, ethertype: u16, payload: &[u8]) {
        self.stats.frames_out += 1;
        self.tx.push_back(ethernet::build(dst, self.cfg.mac, ethertype, payload));
    }

    fn send_tcp(&mut self, dst: Ipv4Addr, seg: &Segment, now: u64) {
        let b = tcpw::build(self.cfg.ip, dst, seg);
        self.send_ip(dst, ipv4::PROTO_TCP, &b, now);
    }

    /// Run TCP timers/output and return every frame waiting to be transmitted.
    pub fn poll(&mut self, now: u64) -> Vec<Vec<u8>> {
        // Retry ARP for packets still waiting.
        let waiting: Vec<Ipv4Addr> = self.arp_waiting.iter().map(|(ip, _)| *ip).collect();
        for ip in waiting {
            self.arp_request(ip, now);
        }
        let mut out = Vec::new();
        for s in self.sockets.iter_mut().flatten() {
            if let Socket::Tcp { tcb, remote_ip, .. } = s {
                for seg in tcb.poll(now) {
                    out.push((*remote_ip, seg));
                }
            }
        }
        for (ip, seg) in out {
            self.send_tcp(ip, &seg, now);
        }
        self.tx.drain(..).collect()
    }

    /// Drain the link's receive side, then transmit what the stack produced.
    pub fn run(&mut self, link: &mut dyn Link, now: u64) {
        while let Some(f) = link.recv(now) {
            self.receive(&f, now);
        }
        for f in self.poll(now) {
            link.send(now, &f);
        }
    }

    // ----- input path -----

    fn count_err(&mut self, e: WireError) {
        match e {
            WireError::BadChecksum => self.stats.bad_checksums += 1,
            _ => self.stats.parse_errors += 1,
        }
    }

    pub fn receive(&mut self, frame: &[u8], now: u64) {
        self.stats.frames_in += 1;
        let f = match ethernet::parse(frame) {
            Ok(f) => f,
            Err(e) => return self.count_err(e),
        };
        if f.dst != self.cfg.mac && f.dst != MacAddr::BROADCAST {
            self.stats.not_for_us += 1;
            return;
        }
        match f.ethertype {
            ethernet::ETHERTYPE_ARP => match arp::parse(f.payload) {
                Ok(p) => self.on_arp(p, now),
                Err(e) => self.count_err(e),
            },
            ethernet::ETHERTYPE_IPV4 => self.on_ipv4(f.payload, now),
            _ => self.stats.parse_errors += 1,
        }
    }

    fn on_arp(&mut self, p: arp::Packet, now: u64) {
        let known = self.arp_cache.contains_key(&p.sender_ip);
        if known || p.target_ip == self.cfg.ip {
            self.arp_cache.insert(p.sender_ip, p.sender_mac);
            self.arp_requested.remove(&p.sender_ip);
            // Flush packets that were waiting for this address.
            let (ready, rest): (Vec<_>, Vec<_>) =
                std::mem::take(&mut self.arp_waiting).into_iter().partition(|(ip, _)| *ip == p.sender_ip);
            self.arp_waiting = rest;
            for (_, pkt) in ready {
                self.send_frame(p.sender_mac, ethernet::ETHERTYPE_IPV4, &pkt);
            }
        }
        if p.op == arp::OP_REQUEST && p.target_ip == self.cfg.ip {
            let reply = arp::Packet {
                op: arp::OP_REPLY,
                sender_mac: self.cfg.mac,
                sender_ip: self.cfg.ip,
                target_mac: p.sender_mac,
                target_ip: p.sender_ip,
            };
            self.send_frame(p.sender_mac, ethernet::ETHERTYPE_ARP, &arp::build(&reply));
        }
        let _ = now;
    }

    fn on_ipv4(&mut self, b: &[u8], now: u64) {
        let p = match ipv4::parse(b) {
            Ok(p) => p,
            Err(e) => return self.count_err(e),
        };
        if p.dst != self.cfg.ip && p.dst != Ipv4Addr::BROADCAST {
            self.stats.not_for_us += 1;
            return;
        }
        if p.is_fragment {
            self.stats.fragments_dropped += 1;
            return;
        }
        let header_and_8 = &b[..(b.len().min(ipv4::HEADER_LEN + 8))];
        match p.protocol {
            ipv4::PROTO_ICMP => self.on_icmp(p.src, p.payload, now),
            ipv4::PROTO_UDP => self.on_udp(p.src, p.dst, p.payload, header_and_8, now),
            ipv4::PROTO_TCP => self.on_tcp(p.src, p.dst, p.payload, now),
            _ => self.stats.parse_errors += 1,
        }
    }

    fn on_icmp(&mut self, src: Ipv4Addr, b: &[u8], now: u64) {
        let m = match icmp::parse(b) {
            Ok(m) => m,
            Err(e) => return self.count_err(e),
        };
        match m.kind {
            icmp::ECHO_REQUEST => {
                let r = icmp::echo(icmp::ECHO_REPLY, m.ident(), m.seq(), m.data);
                self.send_ip(src, ipv4::PROTO_ICMP, &r, now);
            }
            icmp::ECHO_REPLY => {
                if let Some(sent) = self.pings_out.remove(&(m.ident(), m.seq())) {
                    self.ping_replies.push(PingReply {
                        from: src,
                        ident: m.ident(),
                        seq: m.seq(),
                        rtt_ms: now - sent,
                        data: m.data.to_vec(),
                    });
                }
            }
            _ => {}
        }
    }

    fn on_udp(&mut self, src: Ipv4Addr, dst: Ipv4Addr, b: &[u8], orig: &[u8], now: u64) {
        let d = match udp::parse(src, dst, b) {
            Ok(d) => d,
            Err(e) => return self.count_err(e),
        };
        for s in self.sockets.iter_mut().flatten() {
            if let Socket::Udp { port, rx } = s {
                if *port == d.dst_port {
                    rx.push_back((src, d.src_port, d.payload.to_vec()));
                    return;
                }
            }
        }
        if dst != Ipv4Addr::BROADCAST {
            self.stats.icmp_unreachable_sent += 1;
            let m = icmp::build(icmp::DEST_UNREACHABLE, icmp::CODE_PORT_UNREACHABLE, [0; 4], orig);
            self.send_ip(src, ipv4::PROTO_ICMP, &m, now);
        }
    }

    fn on_tcp(&mut self, src: Ipv4Addr, dst: Ipv4Addr, b: &[u8], now: u64) {
        let seg = match tcpw::parse(src, dst, b) {
            Ok(s) => s,
            Err(e) => return self.count_err(e),
        };
        // 1. An existing connection for this 4-tuple.
        let conn = self.sockets.iter().position(|s| {
            matches!(s, Some(Socket::Tcp { tcb, remote_ip, .. })
                if tcb.local_port == seg.dst_port && tcb.remote_port == seg.src_port
                    && *remote_ip == src && tcb.state != State::Closed)
        });
        if let Some(h) = conn {
            let mut announce = None;
            if let Some(Socket::Tcp { tcb, parent, announced, .. }) = &mut self.sockets[h] {
                tcb.on_segment(&seg, now);
                if !*announced && tcb.state != State::SynReceived && tcb.state != State::Closed {
                    *announced = true;
                    announce = *parent;
                }
            }
            if let Some(Some(Socket::Listener { backlog, .. })) = announce.and_then(|p| self.sockets.get_mut(p)) {
                backlog.push_back(h);
            }
            return;
        }
        // 2. A listener, for a fresh SYN.
        let listener = self
            .sockets
            .iter()
            .position(|s| matches!(s, Some(Socket::Listener { port, .. }) if *port == seg.dst_port));
        if let Some(l) = listener {
            if seg.has(SYN) && !seg.has(ACK) && !seg.has(RST) {
                let iss = self.rng.next_u64() as u32;
                let tcb = Box::new(Tcb::accept(seg.dst_port, &seg, iss));
                self.add(Socket::Tcp { tcb, remote_ip: src, parent: Some(l), announced: false });
                return;
            }
        }
        // 3. Nobody: answer with RST (never to a RST).
        if seg.has(RST) {
            return;
        }
        self.stats.rst_sent += 1;
        let rst = if seg.has(ACK) {
            Segment { src_port: seg.dst_port, dst_port: seg.src_port, seq: seg.ack, flags: RST, ..Default::default() }
        } else {
            Segment {
                src_port: seg.dst_port,
                dst_port: seg.src_port,
                seq: 0,
                ack: seg.seq.wrapping_add(seg.seq_len()),
                flags: RST | ACK,
                ..Default::default()
            }
        };
        self.send_tcp(src, &rst, now);
    }
}
