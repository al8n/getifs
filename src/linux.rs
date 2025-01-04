use std::{io, net::IpAddr};

use libc::AF_UNSPEC;
use smallvec_wrapper::{OneOrMore, SmallVec};
use smol_str::SmolStr;

use super::{Interface, IpNet, MacAddr};

#[path = "linux/netlink.rs"]
mod netlink;

use netlink::{netlink_addr, netlink_interface};

impl Interface {
  #[inline]
  fn new(index: u32, flags: Flags) -> Self {
    Self {
      index,
      mtu: 0,
      addrs: SmallVec::new(),
      name: SmolStr::default(),
      mac_addr: None,
      flags,
    }
  }
}

bitflags::bitflags! {
  /// Flags represents the interface flags.
  #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
  pub struct Flags: u32 {
    /// Interface is administratively up
    const UP = 0x1;
    /// Interface supports broadcast access capability
    const BROADCAST = 0x2;
    /// Turn on debugging
    const DEBUG = 0x4;
    /// Interface is a loopback net
    const LOOPBACK = 0x8;
    /// Interface is point-to-point link
    const POINTOPOINT = 0x10;
    /// Obsolete: avoid use of trailers
    const NOTRAILERS = 0x20;
    /// Resources allocated
    const RUNNING = 0x40;
    /// No address resolution protocol
    const NOARP = 0x80;
    /// Receive all packets
    const PROMISC = 0x100;
    /// Receive all multicast packets
    const ALLMULTI = 0x200;
    /// Transmission is in progress
    const MASTER = 0x400;
    /// Can't hear own transmissions
    const SLAVE = 0x800;
    /// Per link layer defined bit
    const MULTICAST = 0x1000;
    /// Per link layer defined bit
    const PORTSEL = 0x2000;
    /// Per link layer defined bit
    const AUTOMEDIA = 0x4000;
    /// Supports multicast access capability
    const DYNAMIC = 0x8000;
  }
}

pub(super) fn interface_table(index: u32) -> io::Result<OneOrMore<Interface>> {
  let mut ift = netlink_interface(AF_UNSPEC, index)?;
  if index == 0 {
    for i in ift.iter_mut() {
      let addrs = netlink_addr(AF_UNSPEC, i.index)?;
      i.addrs = addrs;
    }

    Ok(ift)
  } else {
    if let Some(ifi) = ift.iter_mut().find(|i| i.index == index) {
      ifi.addrs = netlink_addr(AF_UNSPEC, ifi.index)?;
    }

    Ok(ift)
  }
}

pub(super) fn interface_addr_table(ifi: u32) -> io::Result<SmallVec<IpNet>> {
  netlink_addr(AF_UNSPEC, ifi)
}

pub(super) fn interface_multiaddr_table(
  ifi: Option<&Interface>,
) -> std::io::Result<SmallVec<IpAddr>> {
  let mut addrs = SmallVec::new();

  // Parse IPv4 multicast addrs
  let ifmat4 = parse_proc_net_igmp("/proc/net/igmp", ifi)?;
  addrs.extend(ifmat4);

  // Parse IPv6 multicast addrs
  let ifmat6 = parse_proc_net_igmp6("/proc/net/igmp6", ifi)?;
  addrs.extend(ifmat6);

  Ok(addrs)
}

fn parse_proc_net_igmp(path: &str, ifi: Option<&Interface>) -> std::io::Result<Vec<IpAddr>> {
  use std::io::BufRead;

  let file = std::fs::File::open(path)?;
  let reader = std::io::BufReader::new(file);
  let mut ifmat = Vec::new();
  let mut name = SmolStr::default();
  let mut lines = reader.lines();

  // Skip first line
  lines.next();

  for line in lines {
    let line = line?;
    let fields: smallvec_wrapper::MediumVec<&str> = line
      .split([' ', ':', '\r', '\t', '\n'])
      .filter(|s| !s.is_empty())
      .collect();

    if fields.len() < 4 {
      continue;
    }

    match () {
      () if !line.starts_with(' ') && !line.starts_with('\t') => {
        // New interface line
        name = SmolStr::from(fields[1]);
      }
      () if fields[0].len() == 8 => {
        match ifi {
          Some(ifi) if ifi.name != name => continue,
          _ => {
            // The Linux kernel puts the IP
            // address in /proc/net/igmp in native
            // endianness.
            let src = fields[0];
            let mut b = [0u8; 4];
            for i in (0..src.len()).step_by(2) {
              b[i / 2] = xtoi2(&src[i..i + 2], 0).unwrap_or(0);
            }

            b.reverse();
            ifmat.push(IpAddr::V4(b.into()));
          }
        }
      }
      _ => {}
    }
  }

  Ok(ifmat)
}

fn parse_proc_net_igmp6(path: &str, ifi: Option<&Interface>) -> std::io::Result<Vec<IpAddr>> {
  use std::io::BufRead;

  let file = std::fs::File::open(path)?;
  let reader = std::io::BufReader::new(file);
  let mut ifmat = Vec::new();

  for line in reader.lines() {
    let line = line?;
    let fields: smallvec_wrapper::MediumVec<&str> = line
      .split([' ', '\r', '\t', '\n'])
      .filter(|s| !s.is_empty())
      .collect();

    if fields.len() < 6 {
      continue;
    }

    match ifi {
      Some(ifi) if ifi.name != fields[1] => {}
      _ => {
        let mut i = 0;
        let src = fields[2];
        let mut data = [0u8; 16];
        while i + 1 < src.len() {
          data[i / 2] = xtoi2(&src[i..i + 2], 0).unwrap_or(0);
          i += 2;
        }

        ifmat.push(IpAddr::V6(data.into()));
      }
    }
  }

  Ok(ifmat)
}

/// Maximum value to prevent overflow
const BIG: i32 = 0x7fffffff;

/// Converts a hexadecimal string to an integer.
/// Returns a tuple containing:
/// - The parsed number
/// - Number of characters consumed
#[inline]
fn xtoi(s: &str) -> Option<(i32, usize)> {
  let mut n: i32 = 0;
  let mut i: usize = 0;

  for &c in s.as_bytes() {
    match c {
      b'0'..=b'9' => {
        n *= 16;
        n += (c - b'0') as i32;
      }
      b'a'..=b'f' => {
        n *= 16;
        n += (c - b'a') as i32 + 10;
      }
      b'A'..=b'F' => {
        n *= 16;
        n += (c - b'A') as i32 + 10;
      }
      _ => break,
    }

    if n == BIG {
      return None;
    }

    i += 1;
  }

  if i == 0 {
    return None;
  }

  Some((n, i))
}

/// Converts the next two hex digits of s into a byte.
/// If s is longer than 2 bytes then the third byte must match e.
#[inline]
fn xtoi2(s: &str, e: u8) -> Option<u8> {
  // Check if string is longer than 2 chars and third char matches e
  if s.len() > 2 && s.as_bytes()[2] != e {
    return None;
  }

  // Take first two characters and parse them
  let slice = if s.len() >= 2 { &s[..2] } else { s };
  xtoi(slice).and_then(|(n, ei)| if ei == 2 { Some(n as u8) } else { None })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_xtoi() {
    assert_eq!(xtoi(""), None);
    assert_eq!(xtoi("0"), Some((0, 1)));
    assert_eq!(xtoi("12"), Some((0x12, 2)));
    assert_eq!(xtoi("1a"), Some((0x1a, 2)));
    assert_eq!(xtoi("1A"), Some((0x1a, 2)));
    assert_eq!(xtoi("12x"), Some((0x12, 2)));
    assert_eq!(xtoi("x12"), None);
  }

  #[test]
  fn test_xtoi2() {
    assert_eq!(xtoi2("12", b'\0'), Some(0x12));
    assert_eq!(xtoi2("12x", b'x'), Some(0x12));
    assert_eq!(xtoi2("12y", b'x'), None);
    assert_eq!(xtoi2("1", b'\0'), None);
    assert_eq!(xtoi2("xy", b'\0'), None);
  }
}

#[test]
fn test_interfaces() {
  let interfaces = interface_addr_table(1).unwrap();
  for interface in interfaces {
    println!("{:?}", interface);
  }

  // let interfaces = interface_table(2).unwrap();
  // for interface in interfaces {
  //   println!("{:?}", interface);
  // }
}
