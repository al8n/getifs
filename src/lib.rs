// #![doc = include_str!("../README.md")]
//! a
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]
#![deny(missing_docs)]

use std::{io, net::IpAddr};

pub use os::*;

pub use ipnet::{IpNet, Ipv4Net, Ipv6Net};
pub use smol_str::SmolStr;

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

mod probe;
pub use probe::*;

/// Represents a physical hardware address (MAC address).
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
  /// Returns the hardware address as a byte array.
  #[inline]
  pub const fn as_bytes(&self) -> &[u8] {
    &self.0
  }
}

impl AsRef<[u8]> for MacAddr {
  #[inline]
  fn as_ref(&self) -> &[u8] {
    self.as_bytes()
  }
}

impl core::fmt::Debug for MacAddr {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    core::fmt::Display::fmt(self, f)
  }
}

impl core::fmt::Display for MacAddr {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "{:<02x}:{:<02x}:{:<02x}:{:<02x}:{:<02x}:{:<02x}",
      self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
    )
  }
}

/// The inferface struct
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Interface {
  index: u32,
  mtu: u32,
  name: SmolStr,
  mac_addr: Option<MacAddr>,
  flags: Flags,
}

impl core::fmt::Debug for Interface {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    let mut f = f.debug_struct("Interface");

    f.field("index", &self.index).field("name", &self.name);

    f.field("mtu", &self.mtu);

    f.field("mac_addr", &self.mac_addr);

    f.field("flags", &self.flags);

    f.finish()
  }
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

  /// Returns a list of unicast interface addresses for a specific
  /// interface.
  pub fn addresses(&self) -> io::Result<Vec<IpNet>> {
    interface_addr_table(self.index)
  }

  /// Returns a list of multicast, joined group addresses
  /// for a specific interface.
  #[cfg(any(
    target_os = "macos",
    target_os = "tvos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "visionos",
    target_os = "freebsd",
    target_os = "linux",
  ))]
  pub fn multicast_addresses(&self) -> io::Result<Vec<IpAddr>> {
    interface_multiaddr_table(Some(self))
  }
}

/// Returns a list of the system's network interfaces.
pub fn interfaces() -> io::Result<Vec<Interface>> {
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
/// addresses.
///
/// The returned list does not identify the associated interface; use
/// Interfaces and Interface.Addrs for more detail.
pub fn interface_addrs() -> io::Result<Vec<IpNet>> {
  interface_addr_table(0)
}

#[test]
fn t() {
  interfaces().unwrap();
}