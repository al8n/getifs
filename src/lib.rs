#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]
#![deny(missing_docs)]

#[macro_use]
mod macros;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub use gateway::*;
pub use hardware_address::{MacAddr, ParseMacAddrError};
pub use idx_to_name::ifindex_to_name;
pub use ifaddr::*;
pub use ifnet::*;
pub use interfaces::*;
pub use ipnet;
/// Known RFCs for IP addresses
#[doc(inline)]
pub use iprfc as rfc;
/// IP protocol probing
#[doc(inline)]
pub use iprobe as probe;
pub use local_addrs::*;
pub use name_to_idx::ifname_to_index;
pub use os::Flags;
pub use private_ip_addrs::*;
pub use public_ip_addrs::*;
pub use smol_str::SmolStr;

// #[cfg(feature = "serde")]
// mod serde_impl;
mod gateway;
mod idx_to_name;
mod ifaddr;
mod ifnet;
mod interfaces;
mod local_addrs;
mod name_to_idx;
mod private_ip_addrs;
mod public_ip_addrs;
mod utils;

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

const MAC_ADDRESS_SIZE: usize = 6;

#[allow(dead_code)]
trait Address: Sized {
  fn try_from(index: u32, addr: IpAddr) -> Option<Self>;

  fn try_from_with_filter<F>(index: u32, addr: IpAddr, mut f: F) -> Option<Self>
  where
    F: FnMut(&IpAddr) -> bool,
  {
    if !f(&addr) {
      return None;
    }

    <Self as Address>::try_from(index, addr)
  }

  fn addr(&self) -> IpAddr;

  fn index(&self) -> u32;
}

impl Address for IfAddr {
  #[inline]
  fn try_from(index: u32, addr: IpAddr) -> Option<Self> {
    Some(IfAddr::new(index, addr))
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
  fn try_from(index: u32, addr: IpAddr) -> Option<Self> {
    match addr {
      IpAddr::V4(ip) => Some(Ifv4Addr::new(index, ip)),
      _ => None,
    }
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
  fn try_from(index: u32, addr: IpAddr) -> Option<Self> {
    match addr {
      IpAddr::V6(ip) => Some(Ifv6Addr::new(index, ip)),
      _ => None,
    }
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

#[allow(dead_code)]
trait Net: Sized {
  fn try_from(index: u32, addr: IpAddr, prefix: u8) -> Option<Self>;

  fn try_from_with_filter<F>(index: u32, addr: IpAddr, prefix: u8, mut f: F) -> Option<Self>
  where
    F: FnMut(&IpAddr) -> bool,
  {
    if !f(&addr) {
      return None;
    }

    <Self as Net>::try_from(index, addr, prefix)
  }

  fn addr(&self) -> IpAddr;

  fn index(&self) -> u32;
}

impl Net for IfNet {
  #[inline]
  fn try_from(index: u32, addr: IpAddr, prefix: u8) -> Option<Self> {
    Some(IfNet::with_prefix_len_assert(index, addr, prefix))
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

impl Net for Ifv4Net {
  #[inline]
  fn try_from(index: u32, addr: IpAddr, prefix: u8) -> Option<Self> {
    match addr {
      IpAddr::V4(ip) => Some(Ifv4Net::with_prefix_len_assert(index, ip, prefix)),
      _ => None,
    }
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

impl Net for Ifv6Net {
  #[inline]
  fn try_from(index: u32, addr: IpAddr, prefix: u8) -> Option<Self> {
    match addr {
      IpAddr::V6(ip) => Some(Ifv6Net::with_prefix_len_assert(index, ip, prefix)),
      _ => None,
    }
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

#[allow(dead_code)]
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

#[inline]
fn ipv4_filter_to_ip_filter<F>(mut f: F) -> impl FnMut(&IpAddr) -> bool
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  move |addr: &IpAddr| match addr {
    IpAddr::V4(ip) => f(ip),
    _ => false,
  }
}

#[inline]
fn ipv6_filter_to_ip_filter<F>(mut f: F) -> impl FnMut(&IpAddr) -> bool
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  move |addr: &IpAddr| match addr {
    IpAddr::V6(ip) => f(ip),
    _ => false,
  }
}

#[inline]
fn local_ip_filter(addr: &IpAddr) -> bool {
  match addr {
    IpAddr::V4(addr) => !(addr.is_loopback() || addr.is_link_local()),
    IpAddr::V6(addr) => !(addr.is_loopback() || Ipv6AddrExt::is_unicast_link_local(addr)),
  }
}

#[allow(dead_code)]
#[inline]
fn is_ipv6_unspecified(addr: [u8; 16]) -> bool {
  u128::from_be_bytes(addr) == u128::from_be_bytes(Ipv6Addr::UNSPECIFIED.octets())
}
