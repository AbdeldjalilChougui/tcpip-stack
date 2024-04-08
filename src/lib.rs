//! A userspace TCP/IP stack for learning: Ethernet, ARP, IPv4, ICMP echo, UDP and a
//! minimal TCP. Everything is sans-I/O; a [`link::Link`] moves frames. Tests run two stacks
//! over an in-memory wire with loss and reordering, and can write pcap files.

pub mod link;
pub mod pcap;
pub mod sim;
pub mod stack;
pub mod tcp;
#[cfg(feature = "tun")]
pub mod tap;
pub mod wire;

pub use stack::{Config, Handle, Stack};
