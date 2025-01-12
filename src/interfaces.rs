use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use hardware_address::MacAddr;
use smallvec_wrapper::{SmallVec, TinyVec};
use smol_str::SmolStr;

use super::{
  ifname_to_index, ipv4_filter_to_ip_filter, ipv6_filter_to_ip_filter, os, Flags, IfAddr, IfNet,
  Ifv4Addr, Ifv4Net, Ifv6Addr, Ifv6Net,
};

/// The inferface struct
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Interface {
  pub(super) index: u32,
  pub(super) mtu: u32,
  pub(super) name: SmolStr,
  pub(super) mac_addr: Option<MacAddr>,
  pub(super) flags: Flags,
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
  ///
  /// ## Example
  ///
  /// ```rust
  /// use getifs::interfaces;
  ///
  /// let interface = interfaces().unwrap().into_iter().next().unwrap();
  /// let addrs = interface.addrs_by_filter(|addr| { addr.is_loopback() }).unwrap();
  ///
  /// for addr in addrs {
  ///   println!("Addr: {}", addr);
  /// }
  /// ```
  #[inline]
  pub fn addrs_by_filter<F>(&self, f: F) -> io::Result<SmallVec<Ifv4Net>>
  where
    F: FnMut(&IpAddr) -> bool,
  {
    os::interface_ipv4_addresses(self.index, f)
  }

  /// Returns a list of unicast, IPv4 interface addrs for a specific
  /// interface.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use getifs::interfaces;
  ///
  /// let interface = interfaces().unwrap().into_iter().next().unwrap();
  ///
  /// let addrs = interface.ipv4_addrs().unwrap();
  ///
  /// for addr in addrs {
  ///   println!("IPv4 Addr: {}", addr);
  /// }
  /// ```
  #[inline]
  pub fn ipv4_addrs(&self) -> io::Result<SmallVec<Ifv4Net>> {
    os::interface_ipv4_addresses(self.index, |_| true)
  }

  /// Returns a list of unicast, IPv4 interface addrs for a specific
  /// interface. The filter is used to
  /// determine which multicast addresses to include.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use getifs::interfaces;
  ///
  /// let interface = interfaces().unwrap().into_iter().next().unwrap();
  ///
  /// let addrs = interface.ipv4_addrs_by_filter(|addr| {
  ///   !addr.is_loopback()
  /// }).unwrap();
  ///
  /// for addr in addrs {
  ///   println!("IPv4 Addr: {}", addr);
  /// }
  /// ```
  #[inline]
  pub fn ipv4_addrs_by_filter<F>(&self, f: F) -> io::Result<SmallVec<Ifv4Net>>
  where
    F: FnMut(&Ipv4Addr) -> bool,
  {
    os::interface_ipv4_addresses(self.index, ipv4_filter_to_ip_filter(f))
  }

  /// Returns a list of unicast, IPv6 interface addrs for a specific
  /// interface.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use getifs::interfaces;
  ///
  /// let interface = interfaces().unwrap().into_iter().next().unwrap();
  ///
  /// let addrs = interface.ipv6_addrs().unwrap();
  ///
  /// for addr in addrs {
  ///   println!("IPv6 Addr: {}", addr);
  /// }
  /// ```
  #[inline]
  pub fn ipv6_addrs(&self) -> io::Result<SmallVec<Ifv6Net>> {
    os::interface_ipv6_addresses(self.index, |_| true)
  }

  /// Returns a list of unicast, IPv6 interface addrs for a specific
  /// interface. The filter is used to
  /// determine which multicast addresses to include.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use getifs::interfaces;
  ///
  /// let interface = interfaces().unwrap().into_iter().next().unwrap();
  ///
  /// let addrs = interface.ipv6_addrs_by_filter(|addr| {
  ///   !addr.is_loopback()
  /// }).unwrap();
  ///
  /// for addr in addrs {
  ///   println!("IPv6 Addr: {}", addr);
  /// }
  /// ```
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
    ///
    /// ## Example
    ///
    /// ```rust
    /// use getifs::interfaces;
    ///
    /// let interface = interfaces().unwrap().into_iter().next().unwrap();
    ///
    /// let addrs = interface.multicast_addrs().unwrap();
    ///
    /// for addr in addrs {
    ///   println!("Multicast Addr: {}", addr);
    /// }
    /// ```
    pub fn multicast_addrs(&self) -> io::Result<SmallVec<IfAddr>> {
      os::interface_multicast_addresses(self.index, |_| true)
    }

    /// Returns a list of multicast, joined group addrs
    /// for a specific interface. The filter is used to
    /// determine which multicast addresses to include.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use getifs::interfaces;
    ///
    /// let interface = interfaces().unwrap().into_iter().next().unwrap();
    ///
    /// let addrs = interface.multicast_addrs_by_filter(|addr| {
    ///   !addr.is_loopback()
    /// }).unwrap();
    ///
    /// for addr in addrs {
    ///   println!("Multicast Addr: {}", addr);
    /// }
    /// ```
    pub fn multicast_addrs_by_filter<F>(&self, f: F) -> io::Result<SmallVec<IfAddr>>
    where
      F: FnMut(&IpAddr) -> bool,
    {
      os::interface_multicast_addresses(self.index, f)
    }

    /// Returns a list of multicast, joined group IPv4 addrs
    /// for a specific interface.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use getifs::interfaces;
    ///
    /// let interface = interfaces().unwrap().into_iter().next().unwrap();
    ///
    /// let addrs = interface.ipv4_multicast_addrs().unwrap();
    ///
    /// for addr in addrs {
    ///   println!("Multicast IPv4 Addr: {}", addr);
    /// }
    /// ```
    pub fn ipv4_multicast_addrs(&self) -> io::Result<SmallVec<Ifv4Addr>> {
      os::interface_multicast_ipv4_addresses(self.index, |_| true)
    }

    /// Returns a list of multicast, joined group IPv4 addrs
    /// for a specific interface. The filter is used to
    /// determine which multicast addresses to include.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use getifs::interfaces;
    ///
    /// let interface = interfaces().unwrap().into_iter().next().unwrap();
    ///
    /// let addrs = interface.ipv4_multicast_addrs_by_filter(|addr| {
    ///   !addr.is_loopback()
    /// }).unwrap();
    ///
    /// for addr in addrs {
    ///   println!("Multicast IPv4 Addr: {}", addr);
    /// }
    /// ```
    pub fn ipv4_multicast_addrs_by_filter<F>(&self, f: F) -> io::Result<SmallVec<Ifv4Addr>>
    where
      F: FnMut(&Ipv4Addr) -> bool,
    {
      os::interface_multicast_ipv4_addresses(self.index, f)
    }

    /// Returns a list of multicast, joined group IPv6 addrs
    /// for a specific interface.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use getifs::interfaces;
    ///
    /// let interface = interfaces().unwrap().into_iter().next().unwrap();
    ///
    /// let addrs = interface.ipv6_multicast_addrs().unwrap();
    ///
    /// for addr in addrs {
    ///   println!("Multicast IPv6 Addr: {}", addr);
    /// }
    /// ```
    pub fn ipv6_multicast_addrs(&self) -> io::Result<SmallVec<Ifv6Addr>> {
      os::interface_multicast_ipv6_addresses(self.index, |_| true)
    }

    /// Returns a list of multicast, joined group IPv6 addrs
    /// for a specific interface. The filter is used to
    /// determine which multicast addresses to include.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use getifs::interfaces;
    ///
    /// let interface = interfaces().unwrap().into_iter().next().unwrap();
    ///
    /// let addrs = interface.ipv6_multicast_addrs_by_filter(|addr| {
    ///   !addr.is_loopback()
    /// }).unwrap();
    ///
    /// for addr in addrs {
    ///   println!("Multicast IPv6 Addr: {}", addr);
    /// }
    /// ```
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
pub fn interfaces() -> io::Result<TinyVec<Interface>> {
  os::interface_table(0)
}

/// Returns the interface specified by index.
///
/// ## Example
///
/// ```rust
/// use getifs::{interface_by_index, local_addrs};
///
/// let local_addr = local_addrs().unwrap().into_iter().next().unwrap();
/// let interface = interface_by_index(local_addr.index()).unwrap();
///
/// println!("{:?}", interface);
/// ```
pub fn interface_by_index(index: u32) -> io::Result<Option<Interface>> {
  os::interface_table(index).map(|v| v.into_iter().find(|ifi| ifi.index == index))
}

/// Returns the interface specified by name.
///
/// ## Example
///
/// ```rust
/// use getifs::{interface_by_name, ifindex_to_name, local_addrs};
///
/// let local_addr = local_addrs().unwrap().into_iter().next().unwrap();
/// let name = ifindex_to_name(local_addr.index()).unwrap();
/// let interface = interface_by_name(&name).unwrap();
/// println!("{:?}", interface);
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

/// Returns a list of the system's unicast interface
/// addrs.
///
/// The returned list does not identify the associated interface; use
/// [`interfaces`] and [`Interface::addrs`] for more detail.
///
/// ## Example
///
/// ```rust
/// use getifs::interface_addrs_by_filter;
///
/// let addrs = interface_addrs_by_filter(|addr| addr.is_loopback()).unwrap();
///
/// for addr in addrs {
///   println!("Addr: {:?}", addr);
/// }
/// ```
pub fn interface_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<IfNet>>
where
  F: FnMut(&IpAddr) -> bool,
{
  os::interface_addresses(0, f)
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
/// use getifs::interface_ipv4_addrs_by_filter;
///
/// let addrs = interface_ipv4_addrs_by_filter(|addr| addr.is_loopback()).unwrap();
///
/// for addr in addrs {
///   println!("IPv4 Addr: {:?}", addr);
/// }
/// ```
pub fn interface_ipv4_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv4Net>>
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  os::interface_ipv4_addresses(0, ipv4_filter_to_ip_filter(f))
}

/// Returns a list of the system's unicast, IPv6 interface
/// addrs.
///
/// Provides a filter to determine which addresses to include.
///
/// The returned list does not identify the associated interface; use
/// [`interfaces`] and [`Interface::ipv6_addrs_by_filter`] for more detail.
///
/// ## Example
///
/// ```rust
/// use getifs::interface_ipv6_addrs_by_filter;
///
/// let addrs = interface_ipv6_addrs_by_filter(|addr| addr.is_loopback()).unwrap();
///
/// for addr in addrs {
///   println!("IPv6 Addr: {:?}", addr);
/// }
/// ```
pub fn interface_ipv6_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv6Net>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  os::interface_ipv6_addresses(0, ipv6_filter_to_ip_filter(f))
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
    os::interface_multicast_addresses(0, |_| true)
  }

  /// Returns a list of the system's multicast interface
  /// addrs. The filter is used to determine which multicast
  /// addresses to include.
  ///
  /// The returned list does not identify the associated interface; use
  /// [`interfaces`] and [`Interface::multicast_addrs_by_filter`] for more detail.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use getifs::interface_multicast_addrs_by_filter;
  ///
  /// let addrs = interface_multicast_addrs_by_filter(|addr| {
  ///  !addr.is_loopback()
  /// }).unwrap();
  /// ```
  pub fn interface_multicast_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<IfAddr>>
  where
    F: FnMut(&IpAddr) -> bool,
  {
    os::interface_multicast_addresses(0, f)
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
  /// use getifs::interface_multicast_ipv4_addrs;
  ///
  /// let addrs = interface_multicast_ipv4_addrs().unwrap();
  ///
  /// for addr in addrs {
  ///  println!("Multicast IPv4 Addr: {:?}", addr);
  /// }
  /// ```
  pub fn interface_multicast_ipv4_addrs() -> io::Result<SmallVec<Ifv4Addr>> {
    os::interface_multicast_ipv4_addresses(0, |_| true)
  }

  /// Returns a list of the system's multicast, IPv4 interface
  /// addrs. The filter is used to determine which multicast
  /// addresses to include.
  ///
  /// The returned list does not identify the associated interface; use
  /// [`interfaces`] and [`Interface::ipv4_multicast_addrs_by_filter`] for more detail.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use getifs::interface_multicast_ipv4_addrs_by_filter;
  ///
  /// let addrs = interface_multicast_ipv4_addrs_by_filter(|addr| {
  ///   !addr.is_loopback()
  /// }).unwrap();
  /// ```
  pub fn interface_multicast_ipv4_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv4Addr>>
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
  /// use getifs::interface_multicast_ipv6_addrs;
  ///
  /// let addrs = interface_multicast_ipv6_addrs().unwrap();
  ///
  /// for addr in addrs {
  ///   println!("Multicast IPv6 Addr: {:?}", addr);
  /// }
  /// ```
  pub fn interface_multicast_ipv6_addrs() -> io::Result<SmallVec<Ifv6Addr>> {
    os::interface_multicast_ipv6_addresses(0, |_| true)
  }

  /// Returns a list of the system's multicast, IPv6 interface
  /// addrs. The filter is used to determine which multicast
  /// addresses to include.
  ///
  /// The returned list does not identify the associated interface; use
  /// [`interfaces`] and [`Interface::ipv6_multicast_addrs_by_filter`] for more detail.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use getifs::interface_multicast_ipv6_addrs_by_filter;
  ///
  /// let addrs = interface_multicast_ipv6_addrs_by_filter(|addr| {
  ///   !addr.is_loopback()
  /// }).unwrap();
  /// ```
  pub fn interface_multicast_ipv6_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv6Addr>>
  where
    F: FnMut(&Ipv6Addr) -> bool,
  {
    os::interface_multicast_ipv6_addresses(0, f)
  }
);
