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
pub use os::*;

pub use ipnet;
use smallvec_wrapper::{OneOrMore, SmallVec};
pub use smol_str::SmolStr;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod os;

// #[cfg(feature = "serde")]
// mod serde_impl;
mod ifaddr;


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
    interface_addr_table(self.index)
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
  interface_addr_table(0)
}

/// An IP network address, either IPv4 or IPv6.
///
/// A wrapper over [`ipnet::IpNet`], with an additional field `index`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IfAddr {
  net: Either<ipnet::IpNet, IpAddr>,
  index: u32,
}

impl core::fmt::Display for IfAddr {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self.net {
      Either::Left(net) => write!(f, "{} ({})", net, self.index),
      Either::Right(addr) => write!(f, "{} ({})", addr, self.index),
    }
  }
}

impl IfAddr {
  /// Creates a new `IfAddr` with the given IP network address.
  #[inline]
  pub const fn new(index: u32, net: IpAddr) -> Self {
    Self {
      net: Either::Right(net),
      index,
    }
  }

  /// Creates a new `IfAddr` with the given IP network
  #[inline]
  pub const fn with_net(index: u32, net: ipnet::IpNet) -> Self {
    Self {
      net: Either::Left(net),
      index,
    }
  }

  /// See [`ipnet::IpNet::new`](ipnet::IpNet::new).
  #[inline]
  pub const fn with_prefix_len(
    index: u32,
    addr: IpAddr,
    prefix_len: u8,
  ) -> Result<Self, ipnet::PrefixLenError> {
    match addr {
      IpAddr::V4(addr) => {
        match Ipv4Net::new(addr, prefix_len) {
          Ok(net) => Ok(Self {
            net: Either::Left(IpNet::V4(net)),
            index,
          }),
          Err(e) => Err(e),
        }
      }
      IpAddr::V6(addr) => {
        match Ipv6Net::new(addr, prefix_len) {
          Ok(net) => Ok(Self {
            net: Either::Left(IpNet::V6(net)),
            index,
          }),
          Err(e) => Err(e),
        }
      }
    }
  }

  /// See [`ipnet::IpNet::new_assert`](ipnet::IpNet::new_assert).
  #[inline]
  pub const fn with_prefix_len_assert(index: u32, addr: IpAddr, prefix_len: u8) -> Self {
    Self {
      net: Either::Left(ipnet::IpNet::new_assert(addr, prefix_len)),
      index,
    }
  }

  /// Returns the interface index.
  #[inline]
  pub const fn index(&self) -> u32 {
    self.index
  }

  /// Returns the IP network address.
  #[inline]
  pub fn addr(&self) -> IpAddr {
    match self.net {
      Either::Left(ref net) => net.addr(),
      Either::Right(addr) => addr,
    }
  }

  /// Returns the prefix length of the IP network address.
  #[inline]
  pub fn prefix_len(&self) -> Option<u8> {
    match self.net {
      Either::Left(ref net) => Some(net.prefix_len()),
      Either::Right(_) => None,
    }
  }

  /// Returns the maximum prefix length of the IP network address.
  #[inline]
  pub fn max_prefix_len(&self) -> Option<u8> {
    match self.net {
      Either::Left(ref net) => Some(net.max_prefix_len()),
      Either::Right(_) => None,
    }
  }

  /// Returns the IP network address as an `IpNet`.
  #[inline]
  pub fn as_net(&self) -> Option<&ipnet::IpNet> {
    match self.net {
      Either::Left(ref net) => Some(net),
      Either::Right(_) => None,
    }
  }
}

/// a
pub enum AddressFilter {

}

/// Returns the local IP address of the system.
/// 
/// `allow_private` specifies whether to return a private address.
pub fn local_ip(allow_private: bool) -> io::Result<Option<IpAddr>> {
  std::process::id();
  // interfaces().map(|ifs| {
  //   ifs.into_iter().find_map(|ifi| {
  //     if ifi.flags.contains(Flags::LOOPBACK) {
  //       return None;
  //     }

  //     for addr in ifi.addrs()? {
  //       match addr.addr() {
  //         IpAddr::V4(addr) => {
  //           if addr.is_broadcast()
  //             || addr.is_multicast()
  //             || addr.is_link_local()
  //             || addr.is_loopback()
  //           {
  //             continue;
  //           }

  //           if !allow_private && addr.is_private() {
  //             continue;
  //           }

  //           return Some(IpAddr::V4(addr));
  //         }
  //         IpAddr::V6(addr) => {
  //           if addr.is_multicast() || Ipv6AddrExt::is_unicast_link_local(&addr) || addr.is_loopback()
  //           {
  //             continue;
  //           }

  //           if !allow_private && Ipv6AddrExt::is_unique_local(&addr) {
  //             continue;
  //           }

  //           return Some(IpAddr::V6(addr));
  //         }
  //       }
  //     }

  //     None
  //   })
  // })
  todo!()
}

/// Returns the local IPv4 address of the system.
///
/// `allow_private` specifies whether to return a private address.
pub fn local_ipv4(allow_private: bool) -> io::Result<Option<Ipv4Addr>> {
  // interfaces().map(|ifs| {
  //   ifs.into_iter().find_map(|ifi| {
  //     if ifi.flags.contains(Flags::LOOPBACK) {
  //       return None;
  //     }

  //     for addr in ifi.addrs {
  //       if let IpAddr::V4(addr) = addr.addr() {
  //         if addr.is_broadcast()
  //           || addr.is_multicast()
  //           || addr.is_link_local()
  //           || addr.is_loopback()
  //         {
  //           return None;
  //         }

  //         if !allow_private && addr.is_private() {
  //           return None;
  //         }

  //         return Some(addr);
  //       }
  //     }

  //     None
  //   })
  // })
  todo!()
}

/// Returns the local IPv6 address of the system.
///
/// `allow_private` specifies whether to return a private address.
pub fn local_ipv6(allow_private: bool) -> io::Result<Option<Ipv6Addr>> {
  // interfaces().map(|ifs| {
  //   ifs.into_iter().find_map(|ifi| {
  //     if ifi.flags.contains(Flags::LOOPBACK) {
  //       return None;
  //     }

  //     for addr in ifi.addrs {
  //       if let IpAddr::V6(addr) = addr.addr() {
  //         if addr.is_multicast() || Ipv6AddrExt::is_unicast_link_local(&addr) || addr.is_loopback()
  //         {
  //           return None;
  //         }

  //         if !allow_private && Ipv6AddrExt::is_unique_local(&addr) {
  //           return None;
  //         }

  //         return Some(addr);
  //       }
  //     }

  //     None
  //   })
  // })
  todo!()
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
fn test_local_ip_v4() {
  let ip = local_ipv4(true).unwrap();
  println!("local_ip_v4: {:?}", ip);

  let ip = local_ipv4(false).unwrap();
  println!("local_ip_v4: {:?}", ip);
}

#[test]
fn test_local_ipv6() {
  let ip = local_ipv6(true).unwrap();
  println!("local_ip_v6: {:?}", ip);

  let ip = local_ipv6(false).unwrap();
  println!("local_ip_v6: {:?}", ip);

  let lip_ip = local_ip_address::local_ipv6().unwrap();
  println!("lip_ipv6: {:?}", lip_ip);
}

#[test]
fn test_local_ip() {
  // let ip = local_ip(true).unwrap();
  // println!("local_ip: {:?}", ip);

  // let ip = local_ip(false).unwrap();
  // println!("local_ip: {:?}", ip);
  let addrs = interface_addrs().unwrap();
  for addr in addrs {
    println!("{}", addr);
  }
}