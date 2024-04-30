# tcpip-stack

A userspace TCP/IP stack in Rust: Ethernet, ARP, IPv4, ICMP echo, UDP and a minimal TCP.
The link layer is a trait, so the whole stack is tested **without root**: two stacks talk
over an in-memory wire that drops, delays, reorders and duplicates frames, and every test
writes a pcap you can open in Wireshark. A TAP backend (feature `tun`) runs it on a real
interface.

## What it teaches

- How the layers fit: frame → ARP or IPv4 → ICMP / UDP / TCP demux, and the reverse path
  with ARP resolution and a queue of packets waiting for an answer.
- The Internet checksum and the TCP/UDP pseudo-header.
- TCP as a state machine: handshake, sequence numbers with wrap-around, ACKs, the
  receiver's window, out-of-order reassembly, retransmission with exponential backoff,
  zero-window probes, FIN/TIME-WAIT, RST, and the bugs you hit when packets are lost or
  arrive late (two of them are described under "Status").
- Sans-I/O design: the stack never reads a socket or a clock. You pass it frames and a
  millisecond counter, it hands back frames. That makes lossy runs deterministic.

## Quick start

```sh
cargo test                                   # unit + two-stack tests, writes pcap/*.pcap
cargo run --example lossy_demo -- out.pcap 0.15 0.25 3   # loss, reorder, seed
wireshark out.pcap                           # or open samples/*.pcap
```

```rust
use tcpip_stack::{link::WireConfig, sim::{Pair, IP_B}};

let mut p = Pair::new(WireConfig::lossy(0.10, 0.20, 7)); // 10% loss, 20% reordered
p.wire.capture("trace.pcap")?;
let l = p.b.tcp_listen(80);
let c = p.a.tcp_connect(IP_B, 80);
p.a.tcp_send(c, b"hello over a bad cable");
p.run_until(10_000, |p| p.b.tcp_accept(l).is_some());
```

### On a real interface (TAP, needs CAP_NET_ADMIN once)

Creating a TAP device needs `CAP_NET_ADMIN`. Do it once as root and hand the device to
your user; after that the stack opens it unprivileged:

```sh
sudo ip tuntap add dev tap0 mode tap user $USER
sudo ip addr add 10.0.0.1/24 dev tap0 && sudo ip link set tap0 up
cargo run --features tun --example tap_echo -- tap0     # stack is 10.0.0.2
ping 10.0.0.2          # ICMP echo
nc 10.0.0.2 7          # TCP echo
nc -u 10.0.0.2 7       # UDP echo
```

The example also writes `tap_echo.pcap`. (Alternatively grant the binary the capability
with `setcap cap_net_admin+ep`.) The TAP path was compiled and checked to fail cleanly with
`EPERM` here, but not run against a live device, because that needs the root setup above.

## How it works

| file | role |
|---|---|
| `wire/*.rs` | parse/build for Ethernet II, ARP, IPv4, ICMP, UDP, TCP (MSS option); incremental RFC 1071 checksum |
| `link.rs` | `Link` trait; `MemWire` with seeded loss / reorder / duplicate / latency and pcap capture |
| `pcap.rs` | classic pcap writer (and a reader used by tests) |
| `stack.rs` | the interface: ARP cache and pending queue, IPv4 checks, ICMP echo + port unreachable, UDP sockets, TCP demux by 4-tuple, listeners and backlogs, RST for closed ports |
| `tcp.rs` | the TCB: `on_segment` (RFC 9293 acceptability test, ACK processing, reassembly, FIN) and `poll` (timers, data within the peer's window, FIN, pure ACKs) |
| `sim.rs` | `Pair`: two stacks on one wire, stepped 1 ms at a time |
| `tap.rs` | Linux TAP device via `/dev/net/tun` (feature `tun`) |

TCP details: one RTO timer per connection, starting at 200 ms and doubling up to 6.4 s;
on expiry it goes back to `snd_una` and resends (go-back-N). After 12 timeouts the
connection resets. Segments beyond `rcv_nxt` go into a reorder queue and are released when
the gap fills. The advertised window is the free space in a 64 KiB receive buffer; when
the peer's window is zero the timer acts as a persist timer and sends a 1-byte probe.
TIME-WAIT is 2 s (simulated) instead of 2 MSL minutes.

## Tests

`cargo test` runs 23 unit tests (checksums, every header round-trip, sequence arithmetic,
the TCB driven directly: handshake across a sequence-number wrap, reassembly, RTO,
zero-window probing, refused connect, give-up after max retries, simultaneous close,
close during the handshake) and 10 two-stack tests in `tests/stack.rs`:

- ARP + three pings sharing one ARP request; UDP both ways and ICMP port unreachable;
  corrupted checksum, fragment and wrong-MAC frames dropped and counted.
- TCP connect to a closed port → RST → `Refused`; peer `abort` → `Reset`; unreachable host
  → SYN retries → `Timeout`.
- 200 KB echoed on a clean wire; 60 KB echoed over **10% loss, 20% reordering, 2%
  duplication** for 8 seeds; 20 KB over 30% loss; four simultaneous connections over a
  lossy wire. Each checks byte-exact data and a clean FIN close on both sides.

The pcaps land in `pcap/` (git-ignored). Two small ones are committed in `samples/`. The
generated captures were also checked with scapy, which recomputed every IP, ICMP, UDP and
TCP checksum with zero mismatches.

## Status / limitations

Learning project. Missing on purpose: IP fragmentation/reassembly (fragments are dropped),
IP options, routing (single subnet, no gateway), IPv6, ICMP errors other than port
unreachable, and on the TCP side congestion control, fast retransmit, SACK, window
scaling, timestamps, RTT estimation (fixed initial RTO), delayed ACKs, Nagle and urgent
data. A FIN that arrives out of order is dropped and waits for retransmission.

Two bugs the lossy tests caught along the way: a `close()` during the handshake used to
throw away data already queued, and a RST arriving in TIME-WAIT (the peer answering our
re-ACK of a duplicated FIN) killed the connection instead of being ignored (RFC 1337).

## License

MIT, see [LICENSE](LICENSE).
