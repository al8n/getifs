//! Android interface-enumeration fallback.
//!
//! Android 11+ denies `RTM_GETLINK` to untrusted apps: it requires the
//! SELinux `nlmsg_readpriv` permission, neverallowed for apps targeting
//! API >= 30 (on top of the `bind` denial, b/155595000). The netlink
//! interface dump used on every other Linux target therefore fails with
//! `PermissionDenied`. `RTM_GETADDR` stays permitted, as do the `SIOCGIF*`
//! ioctls on a datagram socket — the same combination bionic's `getifaddrs`
//! and Go's `net` package fall back to.
//!
//! We take the interface indices from the address dump, then fill
//! name / MTU / flags via ioctl. MAC addresses are privacy-restricted on
//! Android (apps read all-zero), so `mac_addr` is left `None`.
//!
//! Limitation: because the index list comes from the address dump,
//! enumerating *all* interfaces (`interface_table(0)`, i.e. `interfaces()`)
//! on this denied path omits any interface that currently has no address
//! (e.g. a down or freshly-created tunnel interface). There is no permitted
//! alternative for an untrusted app — `/sys/class/net` and `if_nameindex`
//! (which itself uses `RTM_GETLINK`) are equally restricted, and `getifaddrs`
//! is deliberately not used. Looking an interface up by a known index or name
//! (`interface_table(idx)`) goes straight to the ioctl path, so
//! `interface_by_index` / `interface_by_name` are unaffected.
//!
//! Reached only as a fallback from [`super::interface_table`] when the
//! netlink path is denied; Android versions / app domains that still allow
//! `RTM_GETLINK` keep the richer netlink result (including the MAC address).
//!
//! Permission note: the `SIOCGIF*` ioctls are issued on an `AF_INET` datagram
//! socket, and Android gates inet-socket creation on
//! `android.permission.INTERNET`, so this path requires that permission. The
//! device ioctls themselves work on any socket, but moving to a non-INET
//! family would trade the INTERNET requirement for less certain netlink /
//! SELinux-`ioctl` behaviour that can't be verified off-device; any app
//! enumerating interfaces realistically already holds INTERNET, so the
//! `AF_INET` handle is kept and the requirement documented.

use std::{collections::BTreeSet, io};

use rustix::{
  fd::{AsFd, BorrowedFd},
  ioctl::{self, Opcode, Updater},
  net::{
    netdevice::{index_to_name_inlined, name_to_index},
    socket, AddressFamily, SocketType,
  },
};
use smallvec_wrapper::TinyVec;
use smol_str::SmolStr;

use super::{netlink::netlink_addr, Flags};
use crate::{IfNet, Interface};

const IF_NAMESIZE: usize = 16;

// Stable Linux UAPI opcodes (include/uapi/linux/sockios.h). The SIOC* numbers
// are raw opcodes (not `_IOC`-encoded), so they are used as the ioctl opcode
// directly; `Updater` selects the read-write direction.
const SIOCGIFFLAGS: Opcode = 0x8913;
const SIOCGIFMTU: Opcode = 0x8921;

/// `struct ifreq`: a 16-byte interface name followed by a union large enough
/// for any member (`struct ifmap` / `sockaddr`). We read the result out of
/// the raw `ifr_ifru` bytes rather than naming a union field, keeping the
/// layout explicit and self-contained.
#[repr(C)]
struct Ifreq {
  ifr_name: [u8; IF_NAMESIZE],
  ifr_ifru: [u8; 24],
}

impl Ifreq {
  fn for_name(name: &str) -> Self {
    let mut ifr = Ifreq {
      ifr_name: [0; IF_NAMESIZE],
      ifr_ifru: [0; 24],
    };
    let bytes = name.as_bytes();
    let n = bytes.len().min(IF_NAMESIZE - 1);
    ifr.ifr_name[..n].copy_from_slice(&bytes[..n]);
    ifr
  }
}

pub(super) fn interface_table(index: u32) -> io::Result<TinyVec<Interface>> {
  // Datagram socket used purely as an ioctl handle; SIOCGIF* on it is
  // permitted for untrusted_app (unlike RTM_GETLINK). AF_INET creation
  // requires android.permission.INTERNET — see the module-level permission
  // note.
  let sock = socket(AddressFamily::INET, SocketType::DGRAM, None)?;

  let mut out = TinyVec::new();

  if index != 0 {
    if let Some(ifi) = build_interface(sock.as_fd(), index)? {
      out.push(ifi);
    }
    return Ok(out);
  }

  // `RTM_GETADDR` is permitted even when `RTM_GETLINK` is not; use it to
  // discover the interface indices that currently have an address.
  let addrs = netlink_addr::<IfNet, _>(AddressFamily::UNSPEC, 0, |_| true)?;
  let mut seen = BTreeSet::new();
  for net in &addrs {
    let idx = net.index();
    if idx != 0 && seen.insert(idx) {
      if let Some(ifi) = build_interface(sock.as_fd(), idx)? {
        out.push(ifi);
      }
    }
  }
  Ok(out)
}

/// Build one [`Interface`] from its index via `SIOCGIFNAME` + `SIOCGIFMTU` +
/// `SIOCGIFFLAGS`.
///
/// Returns `Ok(None)` *only* when the interface vanished between the address
/// dump and these calls (`ENODEV`/`ENXIO`). Any other ioctl failure — a
/// permission denial, a bad opcode, an unsupported call, a transient kernel
/// error — is propagated rather than masked as a zeroed or missing
/// interface, so a real problem can't pass as a successful-but-wrong result.
fn build_interface(sock: BorrowedFd<'_>, index: u32) -> io::Result<Option<Interface>> {
  // `index_to_name_inlined` issues SIOCGIFNAME, permitted for untrusted_app.
  let name = match index_to_name_inlined(sock, index) {
    Ok(n) => SmolStr::new(n.as_str()),
    Err(e) if vanished(e) => return Ok(None),
    Err(e) => return Err(e.into()),
  };

  let mut ifr = Ifreq::for_name(&name);

  // SIOCGIFMTU writes the MTU (an int) into the front of the ifru union.
  let mtu = match unsafe { ioctl::ioctl(sock, Updater::<SIOCGIFMTU, Ifreq>::new(&mut ifr)) } {
    Ok(()) => i32::from_ne_bytes(ifr.ifr_ifru[..4].try_into().unwrap()) as u32,
    Err(e) if vanished(e) => return Ok(None),
    Err(e) => return Err(e.into()),
  };

  // SIOCGIFFLAGS writes the flags (a short) into the front of the union.
  let flags = match unsafe { ioctl::ioctl(sock, Updater::<SIOCGIFFLAGS, Ifreq>::new(&mut ifr)) } {
    Ok(()) => {
      let raw = i16::from_ne_bytes(ifr.ifr_ifru[..2].try_into().unwrap()) as u16;
      Flags::from_bits_truncate(raw as u32)
    }
    Err(e) if vanished(e) => return Ok(None),
    Err(e) => return Err(e.into()),
  };

  // Guard against a name being reassigned between the index->name resolution
  // and the by-name SIOCGIF* ioctls (TOCTOU): the ioctls operate by name, so
  // if `index` was deleted and another interface took its name, the MTU/flags
  // just read would belong to that other device. Re-resolve the name and
  // require it still maps to the requested index; on mismatch (or a vanished
  // name) treat this index as gone.
  match name_to_index(sock, name.as_str()) {
    Ok(i) if i == index => {}
    Ok(_) => return Ok(None),
    Err(e) if vanished(e) => return Ok(None),
    Err(e) => return Err(e.into()),
  }

  Ok(Some(Interface {
    index,
    mtu,
    name,
    // MAC is privacy-restricted on Android (apps read all-zero), so we do
    // not attempt SIOCGIFHWADDR.
    mac_addr: None,
    flags,
  }))
}

/// An interface can disappear between the address dump and these per-index
/// lookups (DHCP renewal, VPN connect/disconnect). The kernel reports that
/// as `ENODEV` / `ENXIO`; only those are treated as "skip this index". Every
/// other errno is a real failure that must propagate.
fn vanished(e: rustix::io::Errno) -> bool {
  e == rustix::io::Errno::NODEV || e == rustix::io::Errno::NXIO
}
