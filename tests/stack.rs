//! Two full stacks talking over the in-memory wire. Every test writes a pcap under
//! `pcap/` (git-ignored) so the exchange can be opened in Wireshark.

use std::net::Ipv4Addr;
use tcpip_stack::link::WireConfig;
use tcpip_stack::pcap;
use tcpip_stack::sim::{Pair, IP_A, IP_B, MAC_A, MAC_B};
use tcpip_stack::tcp::{CloseReason, State};
use tcpip_stack::wire::{ethernet, ipv4, udp};

fn capture(p: &Pair, name: &str) -> String {
    let path = format!("{}/pcap/{name}.pcap", env!("CARGO_MANIFEST_DIR"));
    p.wire.capture(&path).unwrap();
    path
}

fn frames(path: &str) -> Vec<Vec<u8>> {
    let (lt, recs) = pcap::read(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(lt, pcap::LINKTYPE_ETHERNET);
    recs.into_iter().map(|(_, f)| f).collect()
}

#[test]
fn arp_then_ping() {
    let mut p = Pair::new(WireConfig::default());
    let path = capture(&p, "ping");
    for seq in 0..3 {
        let now = p.now;
        p.a.ping(IP_B, 0x77, seq, b"hello from a", now);
    }
    let mut replies = Vec::new();
    assert!(p.run_until(100, |p| {
        replies.extend(p.a.take_ping_replies());
        replies.len() == 3
    }));
    assert!(replies.iter().all(|r| r.from == IP_B && r.data == b"hello from a" && r.ident == 0x77));
    assert_eq!(p.a.arp_lookup(IP_B), Some(MAC_B));
    assert_eq!(p.b.arp_lookup(IP_A), Some(MAC_A));
    assert_eq!(p.a.stats.arp_requests_sent, 1); // three pings waited on one ARP request
    p.wire.flush_capture().unwrap();
    let f = frames(&path);
    // ARP request, ARP reply, 3 echo requests, 3 echo replies.
    assert_eq!(f.len(), 8);
    let types: Vec<u16> = f.iter().map(|x| ethernet::parse(x).unwrap().ethertype).collect();
    assert_eq!(&types[..2], &[ethernet::ETHERTYPE_ARP, ethernet::ETHERTYPE_ARP]);
}

#[test]
fn udp_roundtrip_and_port_unreachable() {
    let mut p = Pair::new(WireConfig::default());
    capture(&p, "udp");
    let ua = p.a.udp_bind(5000);
    let ub = p.b.udp_bind(53);
    let now = p.now;
    p.a.udp_send_to(ua, IP_B, 53, b"question?", now);
    let mut got = None;
    assert!(p.run_until(50, |p| {
        got = p.b.udp_recv_from(ub);
        got.is_some()
    }));
    assert_eq!(got, Some((IP_A, 5000, b"question?".to_vec())));
    let now = p.now;
    p.b.udp_send_to(ub, IP_A, 5000, b"answer", now);
    assert!(p.run_until(50, |p| p.a.udp_recv_from(ua) == Some((IP_B, 53, b"answer".to_vec()))));
    // Nothing on port 9: B answers with ICMP port unreachable.
    let now = p.now;
    p.a.udp_send_to(ua, IP_B, 9, b"anyone?", now);
    p.run_until(20, |_| false);
    assert_eq!(p.b.stats.icmp_unreachable_sent, 1);
    p.wire.flush_capture().unwrap();
}

#[test]
fn corrupted_and_fragmented_packets_are_dropped() {
    let mut p = Pair::new(WireConfig::default());
    let ub = p.b.udp_bind(53);
    let mk = |payload: &[u8]| {
        let d = udp::build(IP_A, IP_B, 1, 53, payload);
        ipv4::build(IP_A, IP_B, ipv4::PROTO_UDP, 9, 64, &d)
    };
    let mut bad = mk(b"x");
    let last = bad.len() - 1;
    bad[last] ^= 0xff; // breaks the UDP checksum only
    p.b.receive(&ethernet::build(MAC_B, MAC_A, ethernet::ETHERTYPE_IPV4, &bad), 0);
    let mut frag = mk(b"y");
    frag[6] |= 0x20; // MF flag
    frag[10] = 0;
    frag[11] = 0;
    let c = tcpip_stack::wire::checksum(&frag[..20]);
    frag[10..12].copy_from_slice(&c.to_be_bytes());
    p.b.receive(&ethernet::build(MAC_B, MAC_A, ethernet::ETHERTYPE_IPV4, &frag), 0);
    // Addressed to another MAC.
    p.b.receive(&ethernet::build(MAC_A, MAC_A, ethernet::ETHERTYPE_IPV4, &mk(b"z")), 0);
    assert_eq!(p.b.udp_recv_from(ub), None);
    assert_eq!(p.b.stats.bad_checksums, 1);
    assert_eq!(p.b.stats.fragments_dropped, 1);
    assert_eq!(p.b.stats.not_for_us, 1);
    p.b.receive(&ethernet::build(MAC_B, MAC_A, ethernet::ETHERTYPE_IPV4, &mk(b"ok")), 0);
    assert_eq!(p.b.udp_recv_from(ub).map(|x| x.2), Some(b"ok".to_vec()));
}

#[test]
fn connect_to_closed_port_is_refused() {
    let mut p = Pair::new(WireConfig::default());
    capture(&p, "refused");
    let c = p.a.tcp_connect(IP_B, 81);
    assert!(p.run_until(100, |p| p.a.tcp_state(c) == State::Closed));
    assert_eq!(p.a.tcp(c).close_reason, Some(CloseReason::Refused));
    assert_eq!(p.b.stats.rst_sent, 1);
    p.wire.flush_capture().unwrap();
}

/// Client on A sends `size` bytes, server on B echoes them, then both close.
/// Returns the simulated milliseconds it took.
fn echo_transfer(p: &mut Pair, size: usize, max_ms: u64) -> u64 {
    let listener = p.b.tcp_listen(7);
    let c = p.a.tcp_connect(IP_B, 7);
    let data: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
    let (mut sent, mut back, mut srv, mut pending) = (0usize, Vec::new(), None, Vec::new());
    let mut client_closed = false;
    let start = p.now;
    let ok = p.run_until(max_ms, |p| {
        if sent < size {
            sent += p.a.tcp_send(c, &data[sent..]);
        }
        let mut buf = vec![0u8; 8192];
        let n = p.a.tcp_recv(c, &mut buf);
        back.extend_from_slice(&buf[..n]);
        if back.len() == size && !client_closed {
            p.a.tcp_close(c);
            client_closed = true;
        }
        if srv.is_none() {
            srv = p.b.tcp_accept(listener);
        }
        if let Some(s) = srv {
            let n = p.b.tcp_recv(s, &mut buf);
            pending.extend_from_slice(&buf[..n]);
            let m = p.b.tcp_send(s, &pending);
            pending.drain(..m);
            if p.b.tcp(s).is_eof() && pending.is_empty() && p.b.tcp_state(s) == State::CloseWait {
                p.b.tcp_close(s);
            }
        }
        let a_done = matches!(p.a.tcp_state(c), State::TimeWait | State::Closed);
        a_done && srv.is_some_and(|s| p.b.tcp_state(s) == State::Closed)
    });
    assert!(ok, "transfer did not finish: client {:?}, got back {}/{size}", p.a.tcp_state(c), back.len());
    assert_eq!(back, data, "echoed bytes differ");
    assert_eq!(p.b.tcp(srv.unwrap()).close_reason, Some(CloseReason::Normal));
    // TIME-WAIT expires.
    assert!(p.run_until(5_000, |p| p.a.tcp_state(c) == State::Closed));
    assert_eq!(p.a.tcp(c).close_reason, Some(CloseReason::Normal));
    p.now - start
}

#[test]
fn tcp_echo_on_a_perfect_wire() {
    let mut p = Pair::new(WireConfig::default());
    capture(&p, "tcp-clean");
    echo_transfer(&mut p, 200_000, 10_000);
    let s = p.wire.stats();
    assert_eq!(s.dropped, 0);
    p.wire.flush_capture().unwrap();
}

#[test]
fn tcp_echo_survives_loss_reordering_and_duplicates() {
    for seed in 1..=8 {
        let mut p = Pair::new(WireConfig::lossy(0.10, 0.20, seed));
        if seed == 1 {
            capture(&p, "tcp-lossy");
        }
        let ms = echo_transfer(&mut p, 60_000, 300_000);
        let s = p.wire.stats();
        assert!(s.dropped > 0 && s.reordered > 0, "seed {seed}: fault injection inactive {s:?}");
        eprintln!("seed {seed}: {ms} ms simulated, wire {s:?}");
        p.wire.flush_capture().unwrap();
    }
}

#[test]
fn tcp_heavy_loss_still_completes() {
    let mut p = Pair::new(WireConfig::lossy(0.30, 0.30, 99));
    echo_transfer(&mut p, 20_000, 1_200_000);
}

#[test]
fn several_connections_at_once_over_a_lossy_wire() {
    let mut p = Pair::new(WireConfig::lossy(0.05, 0.10, 4));
    capture(&p, "tcp-multi");
    let l = p.b.tcp_listen(80);
    let clients: Vec<_> = (0..4).map(|_| p.a.tcp_connect(IP_B, 80)).collect();
    let msgs: Vec<Vec<u8>> = (0..4).map(|i| format!("request from client {i} ").repeat(500).into_bytes()).collect();
    let mut sent = [0usize; 4];
    let mut servers = Vec::new();
    let mut received: std::collections::HashMap<usize, Vec<u8>> = Default::default();
    let ok = p.run_until(200_000, |p| {
        for i in 0..4 {
            if sent[i] < msgs[i].len() {
                sent[i] += p.a.tcp_send(clients[i], &msgs[i][sent[i]..]);
            }
        }
        while let Some(s) = p.b.tcp_accept(l) {
            servers.push(s);
        }
        let mut buf = vec![0; 4096];
        for &s in &servers {
            let n = p.b.tcp_recv(s, &mut buf);
            received.entry(s).or_default().extend_from_slice(&buf[..n]);
        }
        received.len() == 4 && received.values().all(|v| msgs.contains(v))
    });
    assert!(ok);
    // Each server connection got exactly one client's stream, and all four differ.
    let mut got: Vec<_> = received.into_values().collect();
    got.sort();
    got.dedup();
    assert_eq!(got.len(), 4);
    let ports: std::collections::HashSet<u16> = clients.iter().map(|&c| p.a.tcp(c).local_port).collect();
    assert_eq!(ports.len(), 4);
    p.wire.flush_capture().unwrap();
}

#[test]
fn peer_reset_is_reported() {
    let mut p = Pair::new(WireConfig::default());
    let l = p.b.tcp_listen(80);
    let c = p.a.tcp_connect(IP_B, 80);
    let mut srv = None;
    assert!(p.run_until(100, |p| {
        srv = srv.or_else(|| p.b.tcp_accept(l));
        srv.is_some() && p.a.tcp_state(c) == State::Established
    }));
    p.b.tcp_mut(srv.unwrap()).abort();
    assert!(p.run_until(100, |p| p.a.tcp_state(c) == State::Closed));
    assert_eq!(p.a.tcp(c).close_reason, Some(CloseReason::Reset));
}

#[test]
fn unreachable_host_times_out() {
    // B never answers ARP for 10.0.0.99; the SYN is retried and the connection gives up.
    let mut p = Pair::new(WireConfig::default());
    let c = p.a.tcp_connect(Ipv4Addr::new(10, 0, 0, 99), 80);
    assert!(p.run_until(200_000, |p| p.a.tcp_state(c) == State::Closed));
    assert_eq!(p.a.tcp(c).close_reason, Some(CloseReason::Timeout));
    assert!(p.a.stats.arp_requests_sent > 10);
}
