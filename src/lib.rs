#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]
#![deny(missing_docs)]

#[allow(unused_macros)]
macro_rules! cfg_apple {
  ($($item:item)*) => {
    $(
      #[cfg(any(
        target_os = "macos",
        target_os = "tvos",
        target_os = "ios",
        target_os = "watchos",
        target_os = "visionos",
      ))]
      #[cfg_attr(docsrs, doc(cfg(any(
        target_os = "macos",
        target_os = "tvos",
        target_os = "ios",
        target_os = "watchos",
        target_os = "visionos",
      ))))]
      $item
    )*
  }
}

#[allow(unused_macros)]
macro_rules! cfg_bsd_multicast {
  ($($item:item)*) => {
    $(
      #[cfg(any(
        target_os = "macos",
        target_os = "tvos",
        target_os = "ios",
        target_os = "watchos",
        target_os = "visionos",
        target_os = "freebsd",
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
        )))
      )]
      $item
    )*
  };
}

macro_rules! cfg_multicast {
  ($($item:item)*) => {
    $(
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
      $item
    )*
  }
}

use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use smallvec_wrapper::{OneOrMore, SmallVec};

pub use hardware_address::{MacAddr, ParseMacAddrError};
pub use idx_to_name::ifindex_to_name;
pub use ifaddr::*;
pub use ifnet::*;
pub use ipnet;
pub use name_to_idx::ifname_to_index;
pub use os::Flags;
pub use rt_host::*;
pub use rt_net::*;
pub use smol_str::SmolStr;

// #[cfg(feature = "serde")]
// mod serde_impl;
mod idx_to_name;
mod ifaddr;
mod ifnet;
mod name_to_idx;
mod rt_host;
mod rt_net;
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
  pub fn addrs(&self) -> io::Result<SmallVec<IfNet>> {
    os::interface_addresses(self.index, |_| true)
  }

  /// Returns a list of unicast interface addrs for a specific
  /// interface. The filter is used to
  /// determine which multicast addresses to include.
  #[inline]
  pub fn addrs_by_filter<F>(&self, f: F) -> io::Result<SmallVec<Ifv4Net>>
  where
    F: FnMut(&IpAddr) -> bool,
  {
    os::interface_ipv4_addresses(self.index, f)
  }

  /// Returns a list of unicast, IPv4 interface addrs for a specific
  /// interface.
  #[inline]
  pub fn ipv4_addrs(&self) -> io::Result<SmallVec<Ifv4Net>> {
    os::interface_ipv4_addresses(self.index, |_| true)
  }

  /// Returns a list of unicast, IPv4 interface addrs for a specific
  /// interface. The filter is used to
  /// determine which multicast addresses to include.
  #[inline]
  pub fn ipv4_addrs_by_filter<F>(&self, f: F) -> io::Result<SmallVec<Ifv4Net>>
  where
    F: FnMut(&Ipv4Addr) -> bool,
  {
    os::interface_ipv4_addresses(self.index, ipv4_filter_to_ip_filter(f))
  }

  /// Returns a list of unicast, IPv6 interface addrs for a specific
  /// interface.
  #[inline]
  pub fn ipv6_addrs(&self) -> io::Result<SmallVec<Ifv6Net>> {
    os::interface_ipv6_addresses(self.index, |_| true)
  }

  /// Returns a list of unicast, IPv6 interface addrs for a specific
  /// interface. The filter is used to
  /// determine which multicast addresses to include.
  #[inline]
  pub fn ipv6_addrs_by_filter<F>(&self, f: F) -> io::Result<SmallVec<Ifv6Net>>
  where
    F: FnMut(&Ipv6Addr) -> bool,
  {
    os::interface_ipv6_addresses(self.index, ipv6_filter_to_ip_filter(f))
  }

  cfg_multicast!(
    /// Returns a list of multicast, joined group addrs
    /// for a specific interface.
    pub fn multicast_addrs(&self) -> io::Result<SmallVec<IfAddr>> {
      os::interface_multicast_ip_addresses(self.index, |_| true)
    }

    /// Returns a list of multicast, joined group addrs
    /// for a specific interface. The filter is used to
    /// determine which multicast addresses to include.
    pub fn multicast_addrs_by_filter<F>(&self, f: F) -> io::Result<SmallVec<IfAddr>>
    where
      F: FnMut(&IpAddr) -> bool,
    {
      os::interface_multicast_ip_addresses(self.index, f)
    }

    /// Returns a list of multicast, joined group IPv4 addrs
    /// for a specific interface.
    pub fn ipv4_multicast_addrs(&self) -> io::Result<SmallVec<Ifv4Addr>> {
      os::interface_multicast_ipv4_addresses(self.index, |_| true)
    }

    /// Returns a list of multicast, joined group IPv4 addrs
    /// for a specific interface. The filter is used to
    /// determine which multicast addresses to include.
    pub fn ipv4_multicast_addrs_by_filter<F>(&self, f: F) -> io::Result<SmallVec<Ifv4Addr>>
    where
      F: FnMut(&Ipv4Addr) -> bool,
    {
      os::interface_multicast_ipv4_addresses(self.index, f)
    }

    /// Returns a list of multicast, joined group IPv6 addrs
    /// for a specific interface.
    pub fn ipv6_multicast_addrs(&self) -> io::Result<SmallVec<Ifv6Addr>> {
      os::interface_multicast_ipv6_addresses(self.index, |_| true)
    }

    /// Returns a list of multicast, joined group IPv6 addrs
    /// for a specific interface. The filter is used to
    /// determine which multicast addresses to include.
    pub fn ipv6_multicast_addrs_by_filter<F>(&self, f: F) -> io::Result<SmallVec<Ifv6Addr>>
    where
      F: FnMut(&Ipv6Addr) -> bool,
    {
      os::interface_multicast_ipv6_addresses(self.index, f)
    }
  );
}

/// Returns a list of the system's network interfaces.
///
/// ## Example
///
/// ```rust
/// use getifs::interfaces;
///
/// let interfaces = interfaces().unwrap();
///
/// for interface in interfaces {
///   println!("Interface: {:?}", interface);
/// }
/// ```
pub fn interfaces() -> io::Result<OneOrMore<Interface>> {
  os::interface_table(0)
}

/// Returns the interface specified by index.
///
/// ## Example
///
/// ```rust
/// use getifs::{interface_by_index, ifname_to_index};
///
/// let lo0 = ifname_to_index("lo0").unwrap();
/// let interface = interface_by_index(lo0).unwrap();
///
/// println!("lo0: {:?}", interface);
/// ```
pub fn interface_by_index(index: u32) -> io::Result<Option<Interface>> {
  os::interface_table(index).map(|v| v.into_iter().find(|ifi| ifi.index == index))
}

/// Returns the interface specified by name.
///
/// ## Example
///
/// ```rust
/// use getifs::interface_by_name;
///
/// let interface = interface_by_name("lo0").unwrap();
/// println!("lo0: {:?}", interface);
/// ```
pub fn interface_by_name(name: &str) -> io::Result<Option<Interface>> {
  let idx = ifname_to_index(name)?;
  os::interface_table(idx).map(|v| v.into_iter().find(|ifi| ifi.name == name))
}

/// Returns a list of the system's unicast interface
/// addrs.
///
/// The returned list does not identify the associated interface; use
/// [`interfaces`] and [`Interface::addrs`] for more detail.
///
/// ## Example
///
/// ```rust
/// use getifs::interface_addrs;
///
/// let addrs = interface_addrs().unwrap();
///
/// for addr in addrs {
///   println!("Addr: {:?}", addr);
/// }
/// ```
pub fn interface_addrs() -> io::Result<SmallVec<IfNet>> {
  os::interface_addresses(0, |_| true)
}

/// Returns a list of the system's unicast, IPv4 interface
/// addrs.
///
/// The returned list does not identify the associated interface; use
/// [`interfaces`] and [`Interface::ipv4_addrs`] for more detail.
///
/// ## Example
///
/// ```rust
/// use getifs::interface_ipv4_addrs;
///
/// let addrs = interface_ipv4_addrs().unwrap();
///
/// for addr in addrs {
///   println!("IPv4 Addr: {:?}", addr);
/// }
/// ```
pub fn interface_ipv4_addrs() -> io::Result<SmallVec<Ifv4Net>> {
  os::interface_ipv4_addresses(0, |_| true)
}

/// Returns a list of the system's unicast, IPv6 interface
/// addrs.
///
/// The returned list does not identify the associated interface; use
/// [`interfaces`] and [`Interface::ipv6_addrs`] for more detail.
///
/// ## Example
///
/// ```rust
/// use getifs::interface_ipv6_addrs;
///
/// let addrs = interface_ipv6_addrs().unwrap();
///
/// for addr in addrs {
///   println!("IPv6 Addr: {:?}", addr);
/// }
/// ```
pub fn interface_ipv6_addrs() -> io::Result<SmallVec<Ifv6Net>> {
  os::interface_ipv6_addresses(0, |_| true)
}

/// Returns all gateway IP addresses (both IPv4 and IPv6) configured on the system.
/// Only returns addresses from interfaces that have valid routes and
/// excludes any addresses that are not configured as gateways.
///
/// ## Example
///
/// ```rust
/// use getifs::gateway_ip_addrs;
///
/// let gateways = gateway_ip_addrs().unwrap();
/// for gw in gateways {
///   println!("Gateway: {}", gw);
/// }
/// ```
pub fn gateway_ip_addrs() -> io::Result<SmallVec<IfAddr>> {
  os::gateway_ip_addrs()
}

/// Returns all IPv4 gateway addresses configured on the system.
/// Only returns addresses from interfaces that have valid routes and
/// excludes any addresses that are not configured as gateways.
///
/// ## Example
///
/// ```rust
/// use getifs::gateway_ipv4_addrs;
///
/// let gateways = gateway_ipv4_addrs().unwrap();
/// for gw in gateways {
///   println!("IPv4 Gateway: {}", gw);
/// }
/// ```
pub fn gateway_ipv4_addrs() -> io::Result<SmallVec<Ifv4Addr>> {
  os::gateway_ipv4_addrs()
}

/// Returns all IPv6 gateway addresses configured on the system.
/// Only returns addresses from interfaces that have valid routes and
/// excludes any addresses that are not configured as gateways.
///
/// ## Example
///
/// ```rust
/// use getifs::gateway_ipv6_addrs;
///
/// let gateways = gateway_ipv6_addrs().unwrap();
/// for gw in gateways {
///   println!("IPv6 Gateway: {}", gw);
/// }
/// ```
pub fn gateway_ipv6_addrs() -> io::Result<SmallVec<Ifv6Addr>> {
  os::gateway_ipv6_addrs()
}

/// Returns all IPv4 addresses from interfaces that have valid routes (excluding loopback).
/// This ensures we only return addresses that can be used for communication.
///
/// See also [`best_local_ipv4_addrs`] and [`local_ipv4_addrs_by_filter`].
///
/// ## Example
///
/// ```rust
/// use getifs::local_ipv4_addrs;
///
/// let ipv4_addrs = local_ipv4_addrs()?;
/// for addr in ipv4_addrs {
///   println!("IPv4: {}", addr);
/// }
/// ```
pub fn local_ipv4_addrs() -> io::Result<SmallVec<Ifv4Net>> {
  os::local_ipv4_addrs()
}

/// Returns all IPv6 addresses from interfaces that have valid routes (excluding loopback).
/// This ensures we only return addresses that can be used for communication.
///
/// See also [`best_local_ipv6_addrs`] and [`local_ipv6_addrs_by_filter`].
///
/// ## Example
///
/// ```rust
/// use getifs::local_ipv6_addrs;
///
/// let ipv6_addrs = local_ipv6_addrs()?;
/// for addr in ipv6_addrs {
///   println!("IPv6: {}", addr);
/// }
/// ```
pub fn local_ipv6_addrs() -> io::Result<SmallVec<Ifv6Net>> {
  os::local_ipv6_addrs()
}

/// Returns all IP addresses (both IPv4 and IPv6) from interfaces that have valid routes (excluding loopback).
/// This ensures we only return addresses that can be used for communication.
///
/// See also [`best_local_ip_addrs`] and [`local_ip_addrs_by_filter`].
///
/// ## Example
///
/// ```rust
/// use getifs::local_ip_addrs;
///
/// let all_addrs = local_ip_addrs()?;
/// for addr in all_addrs {
///     println!("IP: {}", addr);
/// }
/// ```
pub fn local_ip_addrs() -> io::Result<SmallVec<IfNet>> {
  os::local_ip_addrs()
}

/// Returns all IPv4 addresses from interfaces that have valid routes.
///
/// Use the provided filter to further refine the results.
///
/// ## Example
///
/// ```rust
/// use getifs::local_ipv4_addrs_by_filter;
///
/// let addrs = local_ipv4_addrs_by_filter(|addr| !addr.is_loopback())?;
/// for addr in addrs {
///   println!("IPv4: {}", addr);
/// }
/// ```
pub fn local_ipv4_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv4Net>>
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  os::local_ipv4_addrs_by_filter(f)
}

/// Returns all IPv6 addresses from interfaces that have valid routes.
///
/// Use the provided filter to further refine the results.
///
/// ## Example
///
/// ```rust
/// use getifs::local_ipv6_addrs_by_filter;
///
/// let addrs = local_ipv6_addrs_by_filter(|addr| !addr.is_loopback())?;
/// for addr in addrs {
///   println!("IPv6: {}", addr);
/// }
/// ```
pub fn local_ipv6_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv6Net>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  os::local_ipv6_addrs_by_filter(f)
}

/// Returns all IP addresses (both IPv4 and IPv6) from interfaces that have valid routes.
///
/// Use the provided filter to further refine the results.
///
/// ## Example
///
/// ```rust
/// use getifs::local_ip_addrs_by_filter;
///
///
/// let addrs = local_ip_addrs_by_filter(|addr| !addr.is_loopback())?;
/// for addr in addrs {
///   println!("IP: {}", addr);
/// }
/// ```
pub fn local_ip_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<IfNet>>
where
  F: FnMut(&IpAddr) -> bool,
{
  os::local_ip_addrs_by_filter(f)
}

/// Returns the IPv4 addresses from the interface with the best default route.
/// The "best" interface is determined by the routing metrics of default routes (`0.0.0.0`).
///
/// See also [`local_ipv4_addrs`].
///
/// ## Example
///
/// ```rust
/// use getifs::best_local_ipv4_addrs;
///
/// let ipv4_addrs = best_local_ipv4_addrs()?;
/// for addr in ipv4_addrs {
///   println!("IPv4: {} on interface {}", addr.addr, addr.ifindex);
/// }
/// ```
pub fn best_local_ipv4_addrs() -> io::Result<SmallVec<Ifv4Net>> {
  os::best_local_ipv4_addrs()
}

#[test]
fn t() {
  let addrs = best_local_ip_addrs().unwrap();
  for addr in addrs {
    println!("{addr}");
  }
}

/// Returns the IPv6 addresses from the interface with the best default route.
/// The "best" interface is determined by the routing metrics of default routes (`::`).
///
/// See also [`local_ipv6_addrs`].
///
/// ## Example
///
/// ```rust
/// use getifs::best_local_ipv6_addrs;
///
/// let ipv6_addrs = best_local_ipv6_addrs()?;
/// // Will only contain addresses from the interface with best default route
/// for addr in ipv6_addrs {
///   println!("IPv6: {} on interface {}", addr.addr, addr.ifindex);
/// }
/// ```
pub fn best_local_ipv6_addrs() -> io::Result<SmallVec<Ifv6Net>> {
  os::best_local_ipv6_addrs()
}

/// Returns both IPv4 and IPv6 addresses from the interfaces with the best default routes.
/// The "best" interfaces are determined by the routing metrics of default routes.
///
/// See also [`local_ip_addrs`].
///
/// ## Example
///
/// ```rust
/// use getifs::best_local_ip_addrs;
///
/// let all_addrs = best_local_ip_addrs()?;
/// // Will only contain addresses from interfaces with best default routes
/// for addr in all_addrs {
///   println!("IP: {} on interface {}", addr.addr, addr.ifindex);
/// }
/// ```
pub fn best_local_ip_addrs() -> io::Result<SmallVec<IfNet>> {
  os::best_local_ip_addrs()
}

cfg_multicast!(
  /// Returns a list of the system's multicast interface
  /// addrs.
  ///
  /// The returned list does not identify the associated interface; use
  /// [`interfaces`] and [`Interface::multicast_addrs`] for more detail.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use getifs::interface_multicast_addrs;
  ///
  /// let addrs = interface_multicast_addrs().unwrap();
  ///
  /// for addr in addrs {
  ///   println!("Multicast Addr: {:?}", addr);
  /// }
  /// ```
  pub fn interface_multicast_addrs() -> io::Result<SmallVec<IfAddr>> {
    os::interface_multicast_ip_addresses(0, |_| true)
  }

  /// Returns a list of the system's multicast interface
  /// addrs. The filter is used to determine which multicast
  /// addresses to include.
  ///
  /// The returned list does not identify the associated interface; use
  /// [`interfaces`] and [`Interface::multicast_addrs_by_filter`] for more detail.
  pub fn interface_multicast_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<IfAddr>>
  where
    F: FnMut(&IpAddr) -> bool,
  {
    os::interface_multicast_ip_addresses(0, f)
  }

  /// Returns a list of the system's multicast, IPv4 interface
  /// addrs.
  ///
  /// The returned list does not identify the associated interface; use
  /// [`interfaces`] and [`Interface::ipv4_multicast_addrs`] for more detail.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use getifs::interface_ipv4_multicast_addrs;
  ///
  /// let addrs = interface_ipv4_multicast_addrs().unwrap();
  ///
  /// for addr in addrs {
  ///  println!("Multicast IPv4 Addr: {:?}", addr);
  /// }
  /// ```
  pub fn interface_ipv4_multicast_addrs() -> io::Result<SmallVec<Ifv4Addr>> {
    os::interface_multicast_ipv4_addresses(0, |_| true)
  }

  /// Returns a list of the system's multicast, IPv4 interface
  /// addrs. The filter is used to determine which multicast
  /// addresses to include.
  ///
  /// The returned list does not identify the associated interface; use
  /// [`interfaces`] and [`Interface::ipv4_multicast_addrs_by_filter`] for more detail.
  pub fn interface_ipv4_multicast_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv4Addr>>
  where
    F: FnMut(&Ipv4Addr) -> bool,
  {
    os::interface_multicast_ipv4_addresses(0, f)
  }

  /// Returns a list of the system's multicast, IPv6 interface
  /// addrs.
  ///
  /// The returned list does not identify the associated interface; use
  /// [`interfaces`] and [`Interface::ipv6_multicast_addrs`] for more detail.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use getifs::interface_ipv6_multicast_addrs;
  ///
  /// let addrs = interface_ipv6_multicast_addrs().unwrap();
  ///
  /// for addr in addrs {
  ///   println!("Multicast IPv6 Addr: {:?}", addr);
  /// }
  /// ```
  pub fn interface_ipv6_multicast_addrs() -> io::Result<SmallVec<Ifv6Addr>> {
    os::interface_multicast_ipv6_addresses(0, |_| true)
  }

  /// Returns a list of the system's multicast, IPv6 interface
  /// addrs. The filter is used to determine which multicast
  /// addresses to include.
  ///
  /// The returned list does not identify the associated interface; use
  /// [`interfaces`] and [`Interface::ipv6_multicast_addrs_by_filter`] for more detail.
  pub fn interface_ipv6_multicast_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv6Addr>>
  where
    F: FnMut(&Ipv6Addr) -> bool,
  {
    os::interface_multicast_ipv6_addresses(0, f)
  }
);

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

#[test]
fn test_local_ip() {
  // let ip = local_ip(true).unwrap();
  // println!("local_ip: {:?}", ip);

  // let ip = local_ip(false).unwrap();
  // println!("local_ip: {:?}", ip);
  let addrs = interface_addrs().unwrap();
  for addr in addrs {
    // if !addr.addr().is_loopback() {
    println!("{}", addr);
    // }
  }
  // println!("local {}", local_ip_address::local_ip().unwrap());
  // println!("local v6 {}", local_ip_address::local_ipv6().unwrap());
  // println!("local broadcast {}", local_ip_address::local_broadcast_ip().unwrap())
}
