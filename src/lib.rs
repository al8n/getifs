#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]
#![deny(missing_docs)]

use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub use os::*;

pub use ipnet;
use smallvec_wrapper::{OneOrMore, SmallVec};
pub use smol_str::SmolStr;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod os;

#[cfg(feature = "serde")]
mod serde_impl;

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

pub use hardware_address::{MacAddr, ParseMacAddrError};
#[cfg(test)]
mod tests;

const MAC_ADDRESS_SIZE: usize = 6;

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

/// Returns the local IPv4 address of the system.
///
/// `allow_private` specifies whether to return a private address.
pub fn local_ip_v4(allow_private: bool) -> io::Result<Option<Ipv4Addr>> {
  interfaces().map(|ifs| {
    ifs.into_iter().find_map(|ifi| {
      if ifi.flags.contains(Flags::LOOPBACK) {
        return None;
      }

      for addr in ifi.addrs {
        if let IpAddr::V4(addr) = addr.addr() {
          if addr.is_broadcast()
            || addr.is_multicast()
            || addr.is_link_local()
            || addr.is_loopback()
          {
            return None;
          }

          if !allow_private && addr.is_private() {
            return None;
          }

          return Some(addr);
        }
      }

      None
    })
  })
}

/// Returns the local IPv6 address of the system.
///
/// `allow_private` specifies whether to return a private address.
pub fn local_ip_v6(allow_private: bool) -> io::Result<Option<Ipv6Addr>> {
  interfaces().map(|ifs| {
    ifs.into_iter().find_map(|ifi| {
      if ifi.flags.contains(Flags::LOOPBACK) {
        return None;
      }

      for addr in ifi.addrs {
        if let IpAddr::V6(addr) = addr.addr() {
          if addr.is_multicast() || addr.is_unicast_link_local() || addr.is_loopback() {
            return None;
          }

          if !allow_private && addr.is_unique_local() {
            return None;
          }

          return Some(addr);
        }
      }

      None
    })
  })
}

#[test]
fn test_local_ip_v4() {
  let ip = local_ip_v4(true).unwrap();
  println!("local_ip_v4: {:?}", ip);
}

#[test]
fn test_local_ip_v6() {
  let ip = local_ip_v6(true).unwrap();
  println!("local_ip_v6: {:?}", ip);
}
