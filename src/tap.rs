//! Linux TAP backend (feature `tun`). A TAP device is the Ethernet flavour of TUN/TAP, so
//! the stack runs unchanged, ARP included.
//!
//! Opening `/dev/net/tun` and attaching to a device needs `CAP_NET_ADMIN`, unless the
//! device was created persistent and owned by your user beforehand:
//!
//! ```sh
//! sudo ip tuntap add dev tap0 mode tap user $USER
//! sudo ip addr add 10.0.0.1/24 dev tap0 && sudo ip link set tap0 up
//! ```

use crate::link::Link;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;

#[repr(C)]
struct IfReq {
    name: [u8; libc::IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

pub struct TapLink {
    file: File,
    pub name: String,
}

impl TapLink {
    pub fn open(name: &str) -> io::Result<Self> {
        if name.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "interface name too long"));
        }
        let file = OpenOptions::new().read(true).write(true).custom_flags(libc::O_NONBLOCK).open("/dev/net/tun")?;
        let mut req = IfReq { name: [0; libc::IFNAMSIZ], flags: IFF_TAP | IFF_NO_PI, _pad: [0; 22] };
        req.name[..name.len()].copy_from_slice(name.as_bytes());
        // SAFETY: TUNSETIFF reads/writes a `struct ifreq`, which `IfReq` matches in layout
        // and size (40 bytes) on Linux.
        let r = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF as _, &mut req as *mut IfReq) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        let end = req.name.iter().position(|&b| b == 0).unwrap_or(req.name.len());
        Ok(TapLink { file, name: String::from_utf8_lossy(&req.name[..end]).into_owned() })
    }

    /// Block up to `ms` milliseconds until a frame can be read.
    pub fn wait(&self, ms: i32) -> io::Result<bool> {
        let mut p = libc::pollfd { fd: self.file.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        // SAFETY: one valid pollfd for the duration of the call.
        let r = unsafe { libc::poll(&mut p, 1, ms) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(r > 0)
    }
}

impl Link for TapLink {
    fn send(&mut self, _now_ms: u64, frame: &[u8]) {
        if let Err(e) = self.file.write_all(frame) {
            eprintln!("tap write: {e}");
        }
    }

    fn recv(&mut self, _now_ms: u64) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 2048];
        match self.file.read(&mut buf) {
            Ok(n) => {
                buf.truncate(n);
                Some(buf)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => None,
            Err(e) => {
                eprintln!("tap read: {e}");
                None
            }
        }
    }
}
