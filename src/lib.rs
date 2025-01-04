#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]
#![deny(missing_docs)]

use std::{io, net::IpAddr};

pub use os::*;

pub use ipnet;
use smallvec_wrapper::{OneOrMore, SmallVec};
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Interface {
  index: u32,
  mtu: u32,
  name: SmolStr,
  mac_addr: Option<MacAddr>,
  addrs: SmallVec<IpNet>,
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
  pub fn addrs(&self) -> &[IpNet] {
    &self.addrs
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
  ))]
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
pub fn interface_addrs() -> io::Result<SmallVec<IpNet>> {
  interface_addr_table(0)
}

/// An IP network address, either IPv4 or IPv6.
///
/// A wrapper over [`ipnet::IpNet`], with an additional field `index`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IpNet {
  net: ipnet::IpNet,
  index: u32,
}

impl From<IpNet> for ipnet::IpNet {
  fn from(ipnet: IpNet) -> Self {
    ipnet.net
  }
}

impl core::ops::Deref for IpNet {
  type Target = ipnet::IpNet;

  fn deref(&self) -> &Self::Target {
    &self.net
  }
}

impl core::convert::AsRef<ipnet::IpNet> for IpNet {
  fn as_ref(&self) -> &ipnet::IpNet {
    &self.net
  }
}

impl core::ops::DerefMut for IpNet {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.net
  }
}

impl core::convert::AsMut<ipnet::IpNet> for IpNet {
  fn as_mut(&mut self) -> &mut ipnet::IpNet {
    &mut self.net
  }
}

impl core::borrow::Borrow<ipnet::IpNet> for IpNet {
  fn borrow(&self) -> &ipnet::IpNet {
    &self.net
  }
}

impl IpNet {
  /// See [`ipnet::IpNet::new`](ipnet::IpNet::new).
  #[inline]
  pub fn new(index: u32, addr: IpAddr, prefix_len: u8) -> Result<Self, ipnet::PrefixLenError> {
    ipnet::IpNet::new(addr, prefix_len).map(|net| Self { net, index })
  }

  /// See [`ipnet::IpNet::new_assert`](ipnet::IpNet::new_assert).
  #[inline]
  pub fn new_assert(index: u32, addr: IpAddr, prefix_len: u8) -> Self {
    Self {
      net: ipnet::IpNet::new_assert(addr, prefix_len),
      index,
    }
  }

  /// Returns the interface index.
  #[inline]
  pub const fn index(&self) -> u32 {
    self.index
  }
}
