//! Send a message over a lossy, reordering in-memory wire and save the capture.
//! `cargo run --example lossy_demo -- [out.pcap] [loss] [reorder] [seed]`
//! Open the result in Wireshark: retransmissions, out-of-order segments and dup ACKs are
//! all visible.

use tcpip_stack::link::WireConfig;
use tcpip_stack::sim::{Pair, IP_B};
use tcpip_stack::tcp::State;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = args.first().cloned().unwrap_or_else(|| "lossy_demo.pcap".into());
    let loss = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.15);
    let reorder = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0.25);
    let seed = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3);

    let mut p = Pair::new(WireConfig::lossy(loss, reorder, seed));
    p.wire.capture(&out).expect("create pcap");
    let l = p.b.tcp_listen(80);
    let c = p.a.tcp_connect(IP_B, 80);
    let msg: Vec<u8> = b"The quick brown fox jumps over the lazy dog. ".repeat(100);
    let (mut sent, mut srv, mut got) = (0, None, Vec::new());
    let done = p.run_until(120_000, |p| {
        if sent < msg.len() {
            sent += p.a.tcp_send(c, &msg[sent..]);
            if sent == msg.len() {
                p.a.tcp_close(c);
            }
        }
        srv = srv.or_else(|| p.b.tcp_accept(l));
        if let Some(s) = srv {
            let mut buf = [0u8; 4096];
            let n = p.b.tcp_recv(s, &mut buf);
            got.extend_from_slice(&buf[..n]);
            if p.b.tcp(s).is_eof() && p.b.tcp_state(s) == State::CloseWait {
                p.b.tcp_close(s);
            }
            return p.b.tcp_state(s) == State::Closed;
        }
        false
    });
    p.wire.flush_capture().unwrap();
    assert!(done && got == msg, "transfer failed");
    let t = p.a.tcp(c).stats;
    println!("delivered {} bytes in {} simulated ms", got.len(), p.now);
    println!("wire: {:?}", p.wire.stats());
    println!("client: {} segments out, {} retransmission timeouts", t.segs_out, t.retransmit_timeouts);
    println!("server: {} segments queued out of order", p.b.tcp(srv.unwrap()).stats.out_of_order_queued);
    println!("capture written to {out}");
}
