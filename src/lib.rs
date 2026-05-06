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
pub use mtu::*;
pub use name_to_idx::ifname_to_index;
pub use name_to_iface::{ifname_to_iface, ifname_to_v4_iface, ifname_to_v6_iface};
pub use os::Flags;
pub use private_ip_addrs::*;
pub use public_ip_addrs::*;
pub use route::*;
pub use smol_str::SmolStr;

// #[cfg(feature = "serde")]
// mod serde_impl;
mod gateway;
mod idx_to_name;
mod ifaddr;
mod ifnet;
mod interfaces;
mod local_addrs;
mod mtu;
mod name_to_idx;
mod name_to_iface;
mod private_ip_addrs;
mod public_ip_addrs;
mod route;
mod utils;

#[cfg(linux_like)]
#[path = "linux.rs"]
mod os;

#[cfg(bsd_like)]
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

// Coverage tests for the `Address` / `Net` trait impls. The wrong-
// family arms of `try_from`, the simple `addr()` / `index()`
// delegations, and the filter / unspecified-address helpers all live
// in this file but are only ever invoked through deeply layered
// platform code paths, so live tarpaulin runs miss them. These
// trivial unit tests give us a direct hit on each arm without
// requiring a particular host network configuration.
#[cfg(test)]
mod address_trait_tests {
  use super::*;
  use ipnet::{Ipv4Net, Ipv6Net};

  fn v4(addr: [u8; 4]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(addr))
  }
  fn v6(addr: [u8; 16]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(addr))
  }

  #[test]
  fn ifaddr_address_trait() {
    let a = IfAddr::new(7, v4([10, 0, 0, 1]));
    assert_eq!(<IfAddr as Address>::index(&a), 7);
    assert_eq!(<IfAddr as Address>::addr(&a), v4([10, 0, 0, 1]));
    assert!(<IfAddr as Address>::try_from(7, v4([10, 0, 0, 1])).is_some());
    assert!(<IfAddr as Address>::try_from(7, v6([0; 16])).is_some());
  }

  #[test]
  fn ifv4addr_address_trait() {
    let a = Ifv4Addr::new(3, Ipv4Addr::LOCALHOST);
    assert_eq!(<Ifv4Addr as Address>::index(&a), 3);
    assert_eq!(<Ifv4Addr as Address>::addr(&a), v4([127, 0, 0, 1]));
    let made = <Ifv4Addr as Address>::try_from(3, v4([10, 0, 0, 1]));
    assert!(made.is_some());
    // Wrong-family input → None (this is the `_ => None` arm at
    // src/lib.rs:109).
    let wrong = <Ifv4Addr as Address>::try_from(3, v6([0u8; 16]));
    assert!(wrong.is_none());
  }

  #[test]
  fn ifv6addr_address_trait() {
    let a = Ifv6Addr::new(5, Ipv6Addr::LOCALHOST);
    assert_eq!(<Ifv6Addr as Address>::index(&a), 5);
    assert!(matches!(<Ifv6Addr as Address>::addr(&a), IpAddr::V6(_)));
    let made = <Ifv6Addr as Address>::try_from(5, v6([0u8; 16]));
    assert!(made.is_some());
    // Wrong-family input → None (the `_ => None` arm).
    let wrong = <Ifv6Addr as Address>::try_from(5, v4([10, 0, 0, 1]));
    assert!(wrong.is_none());
  }

  #[test]
  fn ifnet_net_trait() {
    let n = IfNet::with_prefix_len_assert(7, v4([10, 0, 0, 0]), 24);
    assert_eq!(<IfNet as Net>::index(&n), 7);
    assert_eq!(<IfNet as Net>::addr(&n), v4([10, 0, 0, 0]));
    let made = <IfNet as Net>::try_from(7, v4([10, 0, 0, 0]), 24);
    assert!(made.is_some());
  }

  #[test]
  fn ifv4net_net_trait() {
    let net = Ipv4Net::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap();
    let n = Ifv4Net::new(1, net);
    assert_eq!(<Ifv4Net as Net>::index(&n), 1);
    assert_eq!(<Ifv4Net as Net>::addr(&n), v4([192, 168, 0, 0]));
    let made = <Ifv4Net as Net>::try_from(1, v4([192, 168, 0, 0]), 16);
    assert!(made.is_some());
    // Wrong-family input → None.
    let wrong = <Ifv4Net as Net>::try_from(1, v6([0u8; 16]), 64);
    assert!(wrong.is_none());
  }

  #[test]
  fn ifv6net_net_trait() {
    let net = Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).unwrap();
    let n = Ifv6Net::new(2, net);
    assert_eq!(<Ifv6Net as Net>::index(&n), 2);
    assert!(matches!(<Ifv6Net as Net>::addr(&n), IpAddr::V6(_)));
    let made = <Ifv6Net as Net>::try_from(2, v6([0u8; 16]), 0);
    assert!(made.is_some());
    // Wrong-family input → None.
    let wrong = <Ifv6Net as Net>::try_from(2, v4([10, 0, 0, 0]), 8);
    assert!(wrong.is_none());
  }

  #[test]
  fn ipv6addr_ext_classification() {
    // Link-local fe80::/10 — `is_unicast_link_local` arm.
    assert!(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).is_unicast_link_local());
    // fc00::/7 — `is_unique_local` arm.
    assert!(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1).is_unique_local());
    // Counter-cases.
    assert!(!Ipv6Addr::LOCALHOST.is_unicast_link_local());
    assert!(!Ipv6Addr::LOCALHOST.is_unique_local());
  }

  #[test]
  fn ipvx_filter_to_ip_filter_wrong_family() {
    let mut v4_only = ipv4_filter_to_ip_filter(|_: &Ipv4Addr| true);
    assert!(v4_only(&v4([1, 2, 3, 4])));
    // Wrong family → false (the `_ => false` arm).
    assert!(!v4_only(&v6([0u8; 16])));

    let mut v6_only = ipv6_filter_to_ip_filter(|_: &Ipv6Addr| true);
    assert!(v6_only(&v6([0u8; 16])));
    assert!(!v6_only(&v4([1, 2, 3, 4])));
  }

  #[test]
  fn local_filter_classifies_addresses() {
    // Loopback / link-local are excluded from `local` (the filter is
    // for "interface-local-non-loopback / non-link-local"
    // addresses).
    assert!(!local_ip_filter(&v4([127, 0, 0, 1])));
    assert!(!local_ip_filter(&v6(Ipv6Addr::LOCALHOST.octets())));
    assert!(!local_ip_filter(&v4([169, 254, 1, 1])));
    let mut ll = [0u8; 16];
    ll[0] = 0xfe;
    ll[1] = 0x80;
    assert!(!local_ip_filter(&v6(ll)));
    // Ordinary unicast → kept.
    assert!(local_ip_filter(&v4([10, 0, 0, 1])));
    let mut ula = [0u8; 16];
    ula[0] = 0xfd;
    assert!(local_ip_filter(&v6(ula)));
  }

  #[test]
  fn is_ipv6_unspecified_helper() {
    assert!(is_ipv6_unspecified([0u8; 16]));
    let mut not_unspec = [0u8; 16];
    not_unspec[15] = 1;
    assert!(!is_ipv6_unspecified(not_unspec));
  }
}
