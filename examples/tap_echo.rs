//! Run the stack on a real TAP device: answers ping and echoes TCP and UDP on port 7.
//!
//! One-time setup (needs CAP_NET_ADMIN, i.e. root, once):
//!   sudo ip tuntap add dev tap0 mode tap user $USER
//!   sudo ip addr add 10.0.0.1/24 dev tap0 && sudo ip link set tap0 up
//! Then, as your user:
//!   cargo run --features tun --example tap_echo -- tap0
//!   ping 10.0.0.2 ; nc 10.0.0.2 7 ; nc -u 10.0.0.2 7

use std::time::Instant;
use tcpip_stack::link::Link;
use tcpip_stack::pcap::{PcapWriter, LINKTYPE_ETHERNET};
use tcpip_stack::tap::TapLink;
use tcpip_stack::tcp::State;
use tcpip_stack::wire::MacAddr;
use tcpip_stack::{Config, Stack};

/// Wraps a link and records both directions to a pcap file.
struct Recording<L> {
    inner: L,
    pcap: PcapWriter<std::io::BufWriter<std::fs::File>>,
}

impl<L: Link> Link for Recording<L> {
    fn send(&mut self, now: u64, f: &[u8]) {
        let _ = self.pcap.write(now * 1000, f);
        self.inner.send(now, f)
    }
    fn recv(&mut self, now: u64) -> Option<Vec<u8>> {
        let f = self.inner.recv(now)?;
        let _ = self.pcap.write(now * 1000, &f);
        Some(f)
    }
}

fn main() -> std::io::Result<()> {
    let name = std::env::args().nth(1).unwrap_or_else(|| "tap0".into());
    let tap = TapLink::open(&name)?;
    let file = std::io::BufWriter::new(std::fs::File::create("tap_echo.pcap")?);
    let mut link = Recording { inner: tap, pcap: PcapWriter::new(file, LINKTYPE_ETHERNET)? };
    let ip = "10.0.0.2".parse().unwrap();
    let mut stack = Stack::new(Config { mac: MacAddr([0x02, 0, 0, 0, 0, 0x02]), ip, seed: 42 });
    let listener = stack.tcp_listen(7);
    let udp = stack.udp_bind(7);
    let mut conns = Vec::new();
    let start = Instant::now();
    println!("stack up on {name} as {ip}; writing tap_echo.pcap; Ctrl-C to stop");
    loop {
        link.inner.wait(10)?;
        let now = start.elapsed().as_millis() as u64;
        stack.run(&mut link, now);
        while let Some(c) = stack.tcp_accept(listener) {
            println!("tcp connection {c}");
            conns.push(c);
        }
        while let Some((src, port, data)) = stack.udp_recv_from(udp) {
            stack.udp_send_to(udp, src, port, &data, now);
        }
        let mut buf = [0u8; 4096];
        for &c in &conns {
            let n = stack.tcp_recv(c, &mut buf);
            if n > 0 {
                stack.tcp_send(c, &buf[..n]);
            }
            if stack.tcp(c).is_eof() && stack.tcp_state(c) == State::CloseWait {
                stack.tcp_close(c);
            }
        }
        conns.retain(|&c| stack.tcp_state(c) != State::Closed);
        let _ = link.pcap.flush();
    }
}
