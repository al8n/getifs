#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]
#![deny(missing_docs)]

use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use either::Either;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use smallvec_wrapper::{OneOrMore, SmallVec};

pub use ifaddr::*;
pub use ipnet;
pub use os::*;
pub use smol_str::SmolStr;

// #[cfg(feature = "serde")]
// mod serde_impl;
mod ifaddr;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod os;

#[cfg(any(
  target_os = "macos",
  target_os = "tvos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "visionos",
  target_os = "dragonfly",
  target_os = "freebsd",
  target_os = "netbsd",
  target_os = "openbsd",
))]
#[path = "bsd_like.rs"]
mod os;

#[cfg(windows)]
#[path = "windows.rs"]
mod os;

#[cfg(all(test, not(windows)))]
mod tests;

pub use hardware_address::{MacAddr, ParseMacAddrError};

const MAC_ADDRESS_SIZE: usize = 6;

/// The inferface struct
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Interface {
  index: u32,
  mtu: u32,
  name: SmolStr,
  mac_addr: Option<MacAddr>,
  flags: Flags,
}

impl Interface {
  /// Returns the interface index.
  #[inline]
  pub const fn index(&self) -> u32 {
    self.index
  }

  /// Returns the interface name.
  #[inline]
  pub const fn name(&self) -> &SmolStr {
    &self.name
  }

  /// Returns the interface MTU.
  #[inline]
  pub const fn mtu(&self) -> u32 {
    self.mtu
  }

  /// Returns the hardware address of the interface.
  #[inline]
  pub const fn mac_addr(&self) -> Option<MacAddr> {
    self.mac_addr
  }

  /// Returns the flags of the interface.
  #[inline]
  pub const fn flags(&self) -> Flags {
    self.flags
  }

  /// Returns a list of unicast interface addrs for a specific
  /// interface.
  #[inline]
  pub fn addrs(&self) -> io::Result<SmallVec<IfAddr>> {
    interface_addresses(self.index)
  }

  /// Returns a list of unicast, IPv4 interface addrs for a specific
  /// interface.
  #[inline]
  pub fn ipv4_addrs(&self) -> io::Result<SmallVec<Ifv4Addr>> {
    interface_ipv4_addresses(self.index)
  }

  /// Returns a list of unicast, IPv6 interface addrs for a specific
  /// interface.
  #[inline]
  pub fn ipv6_addrs(&self) -> io::Result<SmallVec<Ifv6Addr>> {
    interface_ipv6_addresses(self.index)
  }

  /// Returns a list of multicast, joined group addrs
  /// for a specific interface.
  #[cfg(any(
    target_os = "macos",
    target_os = "tvos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "visionos",
    target_os = "freebsd",
    target_os = "linux",
    windows
  ))]
  #[cfg_attr(
    docsrs,
    doc(cfg(any(
      target_os = "macos",
      target_os = "tvos",
      target_os = "ios",
      target_os = "watchos",
      target_os = "visionos",
      target_os = "freebsd",
      target_os = "linux",
      windows
    )))
  )]
  pub fn multicast_addrs(&self) -> io::Result<SmallVec<IpAddr>> {
    interface_multiaddr_table(Some(self))
  }
}

/// Returns a list of the system's network interfaces.
pub fn interfaces() -> io::Result<OneOrMore<Interface>> {
  interface_table(0)
}

/// Returns the interface specified by index.
pub fn interface_by_index(index: u32) -> io::Result<Option<Interface>> {
  interface_table(index).map(|v| v.into_iter().find(|ifi| ifi.index == index))
}

/// Returns the interface specified by name.
pub fn interface_by_name(name: &str) -> io::Result<Option<Interface>> {
  interface_table(0).map(|v| v.into_iter().find(|ifi| ifi.name == name))
}

/// Returns a list of the system's unicast interface
/// addrs.
///
/// The returned list does not identify the associated interface; use
/// [`interfaces`] and [`Interface::addrs`] for more detail.
pub fn interface_addrs() -> io::Result<SmallVec<IfAddr>> {
  interface_addresses(0)
}

/// Returns the IPv4 gateway address of the system.
pub fn gateway_ipv4() -> io::Result<Option<Ipv4Addr>> {
  os::gateway_ipv4()
}

/// Returns the IPv6 gateway address of the system.
pub fn gateway_ipv6() -> io::Result<Option<Ipv6Addr>> {
  os::gateway_ipv6()
}

trait Address: Sized {
  fn try_from(index: u32, addr: IpAddr, prefix: u8) -> Option<Self>;

  fn try_from_with_filter<F>(index: u32, addr: IpAddr, prefix: u8, f: F) -> Option<Self>
  where
    F: FnMut(&IpAddr) -> bool;

  fn addr(&self) -> IpAddr;

  fn index(&self) -> u32;
}

impl Address for IfAddr {
  #[inline]
  fn try_from(index: u32, addr: IpAddr, prefix: u8) -> Option<Self> {
    Some(IfAddr::with_prefix_len_assert(index, addr, prefix))
  }

  fn try_from_with_filter<F>(index: u32, addr: IpAddr, prefix: u8, f: F) -> Option<Self>
  where
    F: FnOnce(&IpAddr) -> bool,
  {
    if !f(&addr) {
      return None;
    }

    <Self as Address>::try_from(index, addr, prefix)
  }

  #[inline]
  fn addr(&self) -> IpAddr {
    self.addr()
  }

  #[inline]
  fn index(&self) -> u32 {
    self.index()
  }
}

impl Address for Ifv4Addr {
  #[inline]
  fn try_from(index: u32, addr: IpAddr, prefix: u8) -> Option<Self> {
    match addr {
      IpAddr::V4(ip) => Some(Ifv4Addr::with_prefix_len_assert(index, ip, prefix)),
      _ => None,
    }
  }

  #[inline]
  fn try_from_with_filter<F>(index: u32, addr: IpAddr, prefix: u8, f: F) -> Option<Self>
  where
    F: FnOnce(&IpAddr) -> bool,
  {
    if !f(&addr) {
      return None;
    }

    <Self as Address>::try_from(index, addr, prefix)
  }

  #[inline]
  fn addr(&self) -> IpAddr {
    self.addr().into()
  }

  #[inline]
  fn index(&self) -> u32 {
    self.index()
  }
}

impl Address for Ifv6Addr {
  #[inline]
  fn try_from(index: u32, addr: IpAddr, prefix: u8) -> Option<Self> {
    match addr {
      IpAddr::V6(ip) => Some(Ifv6Addr::with_prefix_len_assert(index, ip, prefix)),
      _ => None,
    }
  }

  #[inline]
  fn try_from_with_filter<F>(index: u32, addr: IpAddr, prefix: u8, f: F) -> Option<Self>
  where
    F: FnOnce(&IpAddr) -> bool,
  {
    if !f(&addr) {
      return None;
    }

    <Self as Address>::try_from(index, addr, prefix)
  }

  #[inline]
  fn addr(&self) -> IpAddr {
    self.addr().into()
  }

  #[inline]
  fn index(&self) -> u32 {
    self.index()
  }
}

trait Ipv6AddrExt {
  fn is_unicast_link_local(&self) -> bool;

  fn is_unique_local(&self) -> bool;
}

impl Ipv6AddrExt for Ipv6Addr {
  #[inline]
  fn is_unicast_link_local(&self) -> bool {
    (self.segments()[0] & 0xffc0) == 0xfe80
  }

  #[inline]
  fn is_unique_local(&self) -> bool {
    (self.segments()[0] & 0xfe00) == 0xfc00
  }
}

#[test]
fn test_local_ip() {
  // let ip = local_ip(true).unwrap();
  // println!("local_ip: {:?}", ip);

  // let ip = local_ip(false).unwrap();
  // println!("local_ip: {:?}", ip);
  let addrs = interface_addrs().unwrap();
  for addr in addrs {
    if !addr.addr().is_loopback() {
      println!("{}", addr);
    }
  }
  println!("local {}", local_ip_address::local_ip().unwrap());
  println!("local v6 {}", local_ip_address::local_ipv6().unwrap());
  // println!("local broadcast {}", local_ip_address::local_broadcast_ip().unwrap())
}
