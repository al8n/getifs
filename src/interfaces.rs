use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use hardware_address::MacAddr;
use smallvec_wrapper::{SmallVec, TinyVec};
use smol_str::SmolStr;

use super::{
  ifname_to_index, ipv4_filter_to_ip_filter, ipv6_filter_to_ip_filter, os, Flags, IfNet, Ifv4Net,
  Ifv6Net,
};

// `IfAddr` / `Ifv4Addr` / `Ifv6Addr` appear only inside `cfg_multicast!`
// blocks. Keep this import gate in lock-step with `cfg_multicast!`
// (src/macros.rs).
#[cfg(any(
  target_vendor = "apple",
  target_os = "freebsd",
  target_os = "dragonfly",
  target_os = "netbsd",
  target_os = "openbsd",
  target_os = "linux",
  target_os = "android",
  windows
))]
use super::{IfAddr, Ifv4Addr, Ifv6Addr};

/// The interface struct
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
  ///
  /// This is the local link MTU captured with this [`Interface`] snapshot, not
  /// a live query or a remote path MTU measurement.
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
    cfg_if::cfg_if! {
      if #[cfg(windows)] {
        os::interface_addresses(Some(self.index), |_| true)
      } else {
        os::interface_addresses(self.index, |_| true)
      }
    }
  }

  /// Returns a list of unicast interface addrs for a specific
  /// interface. The filter determines which unicast addresses to include.
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
  pub fn addrs_by_filter<F>(&self, f: F) -> io::Result<SmallVec<IfNet>>
  where
    F: FnMut(&IpAddr) -> bool,
  {
    cfg_if::cfg_if! {
      if #[cfg(windows)] {
        os::interface_addresses(Some(self.index), f)
      } else {
        os::interface_addresses(self.index, f)
      }
    }
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
    cfg_if::cfg_if! {
      if #[cfg(windows)] {
        os::interface_ipv4_addresses(Some(self.index), |_| true)
      } else {
        os::interface_ipv4_addresses(self.index, |_| true)
      }
    }
  }

  /// Returns a list of unicast, IPv4 interface addrs for a specific
  /// interface. The filter determines which unicast addresses to include.
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
    cfg_if::cfg_if! {
      if #[cfg(windows)] {
        os::interface_ipv4_addresses(Some(self.index), ipv4_filter_to_ip_filter(f))
      } else {
        os::interface_ipv4_addresses(self.index, ipv4_filter_to_ip_filter(f))
      }
    }
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
    cfg_if::cfg_if! {
      if #[cfg(windows)] {
        os::interface_ipv6_addresses(Some(self.index), |_| true)
      } else {
        os::interface_ipv6_addresses(self.index, |_| true)
      }
    }
  }

  /// Returns a list of unicast, IPv6 interface addrs for a specific
  /// interface. The filter determines which unicast addresses to include.
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
    cfg_if::cfg_if! {
      if #[cfg(windows)] {
        os::interface_ipv6_addresses(Some(self.index), ipv6_filter_to_ip_filter(f))
      } else {
        os::interface_ipv6_addresses(self.index, ipv6_filter_to_ip_filter(f))
      }
    }
  }

  cfg_multicast!(
    /// Returns a list of multicast, joined group addrs
    /// for a specific interface.
    ///
    /// Multicast membership is capability-dependent: Android, DragonFly,
    /// NetBSD, and OpenBSD return [`io::ErrorKind::Unsupported`]. Do not
    /// assume every Unix platform provides multicast-group enumeration.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use getifs::interfaces;
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let Some(interface) = interfaces()?.into_iter().next() else {
    ///   return Ok(());
    /// };
    ///
    /// let addrs = match interface.multicast_addrs() {
    ///   Ok(v) => v,
    ///   Err(e) if e.kind() == std::io::ErrorKind::Unsupported => return Ok(()),
    ///   Err(e) => return Err(e),
    /// };
    ///
    /// for addr in addrs {
    ///   println!("Multicast Addr: {}", addr);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn multicast_addrs(&self) -> io::Result<SmallVec<IfAddr>> {
      cfg_if::cfg_if! {
        if #[cfg(windows)] {
          os::interface_multicast_addresses(Some(self.index), |_| true)
        } else {
          os::interface_multicast_addresses(self.index, |_| true)
        }
      }
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
    /// # fn main() -> std::io::Result<()> {
    /// let Some(interface) = interfaces()?.into_iter().next() else {
    ///   return Ok(());
    /// };
    ///
    /// let addrs = match interface.multicast_addrs_by_filter(|addr| {
    ///   !addr.is_loopback()
    /// }) {
    ///   Ok(v) => v,
    ///   Err(e) if e.kind() == std::io::ErrorKind::Unsupported => return Ok(()),
    ///   Err(e) => return Err(e),
    /// };
    ///
    /// for addr in addrs {
    ///   println!("Multicast Addr: {}", addr);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn multicast_addrs_by_filter<F>(&self, f: F) -> io::Result<SmallVec<IfAddr>>
    where
      F: FnMut(&IpAddr) -> bool,
    {
      cfg_if::cfg_if! {
        if #[cfg(windows)] {
          os::interface_multicast_addresses(Some(self.index), f)
        } else {
          os::interface_multicast_addresses(self.index, f)
        }
      }
    }

    /// Returns a list of multicast, joined group IPv4 addrs
    /// for a specific interface.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use getifs::interfaces;
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let Some(interface) = interfaces()?.into_iter().next() else {
    ///   return Ok(());
    /// };
    ///
    /// let addrs = match interface.ipv4_multicast_addrs() {
    ///   Ok(v) => v,
    ///   Err(e) if e.kind() == std::io::ErrorKind::Unsupported => return Ok(()),
    ///   Err(e) => return Err(e),
    /// };
    ///
    /// for addr in addrs {
    ///   println!("Multicast IPv4 Addr: {}", addr);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn ipv4_multicast_addrs(&self) -> io::Result<SmallVec<Ifv4Addr>> {
      cfg_if::cfg_if! {
        if #[cfg(windows)] {
          os::interface_multicast_ipv4_addresses(Some(self.index), |_| true)
        } else {
          os::interface_multicast_ipv4_addresses(self.index, |_| true)
        }
      }
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
    /// # fn main() -> std::io::Result<()> {
    /// let Some(interface) = interfaces()?.into_iter().next() else {
    ///   return Ok(());
    /// };
    ///
    /// let addrs = match interface.ipv4_multicast_addrs_by_filter(|addr| {
    ///   !addr.is_loopback()
    /// }) {
    ///   Ok(v) => v,
    ///   Err(e) if e.kind() == std::io::ErrorKind::Unsupported => return Ok(()),
    ///   Err(e) => return Err(e),
    /// };
    ///
    /// for addr in addrs {
    ///   println!("Multicast IPv4 Addr: {}", addr);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn ipv4_multicast_addrs_by_filter<F>(&self, f: F) -> io::Result<SmallVec<Ifv4Addr>>
    where
      F: FnMut(&Ipv4Addr) -> bool,
    {
      cfg_if::cfg_if! {
        if #[cfg(windows)] {
          os::interface_multicast_ipv4_addresses(Some(self.index), f)
        } else {
          os::interface_multicast_ipv4_addresses(self.index, f)
        }
      }
    }

    /// Returns a list of multicast, joined group IPv6 addrs
    /// for a specific interface.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use getifs::interfaces;
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let Some(interface) = interfaces()?.into_iter().next() else {
    ///   return Ok(());
    /// };
    ///
    /// let addrs = match interface.ipv6_multicast_addrs() {
    ///   Ok(v) => v,
    ///   Err(e) if e.kind() == std::io::ErrorKind::Unsupported => return Ok(()),
    ///   Err(e) => return Err(e),
    /// };
    ///
    /// for addr in addrs {
    ///   println!("Multicast IPv6 Addr: {}", addr);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn ipv6_multicast_addrs(&self) -> io::Result<SmallVec<Ifv6Addr>> {
      cfg_if::cfg_if! {
        if #[cfg(windows)] {
          os::interface_multicast_ipv6_addresses(Some(self.index), |_| true)
        } else {
          os::interface_multicast_ipv6_addresses(self.index, |_| true)
        }
      }
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
    /// # fn main() -> std::io::Result<()> {
    /// let Some(interface) = interfaces()?.into_iter().next() else {
    ///   return Ok(());
    /// };
    ///
    /// let addrs = match interface.ipv6_multicast_addrs_by_filter(|addr| {
    ///   !addr.is_loopback()
    /// }) {
    ///   Ok(v) => v,
    ///   Err(e) if e.kind() == std::io::ErrorKind::Unsupported => return Ok(()),
    ///   Err(e) => return Err(e),
    /// };
    ///
    /// for addr in addrs {
    ///   println!("Multicast IPv6 Addr: {}", addr);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn ipv6_multicast_addrs_by_filter<F>(&self, f: F) -> io::Result<SmallVec<Ifv6Addr>>
    where
      F: FnMut(&Ipv6Addr) -> bool,
    {
      cfg_if::cfg_if! {
        if #[cfg(windows)] {
          os::interface_multicast_ipv6_addresses(Some(self.index), f)
        } else {
          os::interface_multicast_ipv6_addresses(self.index, f)
        }
      }
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
///
/// ## Android
///
/// On Android 11+ an app in the `untrusted_app` SELinux domain is denied the
/// `RTM_GETLINK` netlink dump that enumerates interfaces, so getifs falls
/// back to listing the interfaces discovered from their addresses
/// (`RTM_GETADDR`, which stays permitted). On those versions this therefore
/// returns only interfaces that currently have at least one address, and
/// their [`Interface::mac_addr`] is `None`. [`interface_by_index`] and
/// [`interface_by_name`] resolve a known interface directly and are not
/// affected by this limitation. This fallback also requires the app to hold
/// `android.permission.INTERNET` (it opens a datagram socket to issue the
/// `SIOCGIF*` ioctls).
pub fn interfaces() -> io::Result<TinyVec<Interface>> {
  cfg_if::cfg_if! {
    if #[cfg(windows)] {
      os::interface_table(None)
    } else {
      os::interface_table(0)
    }
  }
}

#[cfg(linux_like)]
pub(crate) fn is_missing_interface_errno(raw: i32) -> bool {
  raw == rustix::io::Errno::NODEV.raw_os_error() || raw == rustix::io::Errno::NXIO.raw_os_error()
}

#[cfg(bsd_like)]
pub(crate) fn is_missing_interface_errno(raw: i32) -> bool {
  raw == libc::ENODEV || raw == libc::ENXIO
}

#[cfg(windows)]
pub(crate) fn is_missing_interface_errno(raw: i32) -> bool {
  // ERROR_FILE_NOT_FOUND is the status ConvertInterfaceIndexToLuid documents
  // for an unknown interface. `ifname_to_index` reports an unknown name with
  // it as well, because ConvertInterfaceAliasToLuid documents only
  // ERROR_INVALID_PARAMETER and `if_nametoindex` provides no error code.
  // ERROR_NOT_FOUND is accepted as a defensive equivalent.
  matches!(raw, 2 | 1168)
}

fn is_missing_interface_error(error: &io::Error) -> bool {
  match error.raw_os_error() {
    Some(raw) => is_missing_interface_errno(raw),
    None => false,
  }
}

fn missing_interface_to_none<T>(result: io::Result<T>) -> io::Result<Option<T>> {
  match result {
    Ok(value) => Ok(Some(value)),
    Err(error) if is_missing_interface_error(&error) => Ok(None),
    Err(error) => Err(error),
  }
}

fn interface_table_for_index(index: u32) -> io::Result<TinyVec<Interface>> {
  cfg_if::cfg_if! {
    if #[cfg(windows)] {
      os::interface_table(Some(index))
    } else {
      os::interface_table(index)
    }
  }
}

/// Returns the interface specified by index.
///
/// Returns `Ok(None)` when the index is absent from the interface enumeration,
/// including an interface skipped because its name is not representable as
/// UTF-8, or when the platform reports a known missing-interface OS error.
/// Permission, parse, and other errors are returned as `Err`.
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
  let interfaces = match missing_interface_to_none(interface_table_for_index(index))? {
    Some(interfaces) => interfaces,
    None => return Ok(None),
  };

  Ok(
    interfaces
      .into_iter()
      .find(|interface| interface.index == index),
  )
}

/// Returns the interface specified by name.
///
/// Returns `Ok(None)` when the name does not resolve to an interface in the
/// enumeration, including one skipped because its name is not representable as
/// UTF-8, or when the platform reports a known missing-interface OS error.
/// Permission, parse, and other errors are returned as `Err`.
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
  let index = match missing_interface_to_none(ifname_to_index(name))? {
    Some(index) => index,
    None => return Ok(None),
  };
  let interfaces = match missing_interface_to_none(interface_table_for_index(index))? {
    Some(interfaces) => interfaces,
    None => return Ok(None),
  };

  cfg_if::cfg_if! {
    if #[cfg(windows)] {
      Ok(interfaces.into_iter().find(|interface| interface.index == index))
    } else {
      Ok(interfaces.into_iter().find(|interface| interface.index == index && interface.name == name))
    }
  }
}

/// Returns a list of the system's unicast interface
/// addrs.
///
/// Each returned [`IfNet`] retains its associated interface index through
/// [`IfNet::index`].
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
  cfg_if::cfg_if! {
    if #[cfg(windows)] {
      os::interface_addresses(None, |_| true)
    } else {
      os::interface_addresses(0, |_| true)
    }
  }
}

/// Returns a list of the system's unicast, IPv4 interface
/// addrs.
///
/// Each returned [`Ifv4Net`] retains its associated interface index through
/// [`Ifv4Net::index`].
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
  cfg_if::cfg_if! {
    if #[cfg(windows)] {
      os::interface_ipv4_addresses(None, |_| true)
    } else {
      os::interface_ipv4_addresses(0, |_| true)
    }
  }
}

/// Returns a list of the system's unicast, IPv6 interface
/// addrs.
///
/// Each returned [`Ifv6Net`] retains its associated interface index through
/// [`Ifv6Net::index`].
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
  cfg_if::cfg_if! {
    if #[cfg(windows)] {
      os::interface_ipv6_addresses(None, |_| true)
    } else {
      os::interface_ipv6_addresses(0, |_| true)
    }
  }
}

/// Returns a list of the system's unicast interface
/// addrs.
///
/// Each returned [`IfNet`] retains its associated interface index through
/// [`IfNet::index`].
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
  cfg_if::cfg_if! {
    if #[cfg(windows)] {
      os::interface_addresses(None, f)
    } else {
      os::interface_addresses(0, f)
    }
  }
}

/// Returns a list of the system's unicast, IPv4 interface
/// addrs.
///
/// Each returned [`Ifv4Net`] retains its associated interface index through
/// [`Ifv4Net::index`].
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
  cfg_if::cfg_if! {
    if #[cfg(windows)] {
      os::interface_ipv4_addresses(None, ipv4_filter_to_ip_filter(f))
    } else {
      os::interface_ipv4_addresses(0, ipv4_filter_to_ip_filter(f))
    }
  }
}

/// Returns a list of the system's unicast, IPv6 interface
/// addrs.
///
/// Provides a filter to determine which addresses to include.
///
/// Each returned [`Ifv6Net`] retains its associated interface index through
/// [`Ifv6Net::index`].
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
  cfg_if::cfg_if! {
    if #[cfg(windows)] {
      os::interface_ipv6_addresses(None, ipv6_filter_to_ip_filter(f))
    } else {
      os::interface_ipv6_addresses(0, ipv6_filter_to_ip_filter(f))
    }
  }
}

cfg_multicast!(
  /// Returns a list of the system's multicast interface
  /// addrs.
  ///
  /// Multicast membership is capability-dependent: Android, DragonFly,
  /// NetBSD, and OpenBSD return [`io::ErrorKind::Unsupported`]. Do not assume
  /// every Unix platform provides multicast-group enumeration.
  ///
  /// Each returned [`IfAddr`] retains its associated interface index through
  /// [`IfAddr::index`].
  ///
  /// ## Example
  ///
  /// ```rust
  /// use getifs::interface_multicast_addrs;
  ///
  /// # fn main() -> std::io::Result<()> {
  /// let addrs = match interface_multicast_addrs() {
  ///   Ok(v) => v,
  ///   Err(e) if e.kind() == std::io::ErrorKind::Unsupported => return Ok(()),
  ///   Err(e) => return Err(e),
  /// };
  ///
  /// for addr in addrs {
  ///   println!("Multicast Addr: {:?}", addr);
  /// }
  /// # Ok(())
  /// # }
  /// ```
  pub fn interface_multicast_addrs() -> io::Result<SmallVec<IfAddr>> {
    cfg_if::cfg_if! {
      if #[cfg(windows)] {
        os::interface_multicast_addresses(None, |_| true)
      } else {
        os::interface_multicast_addresses(0, |_| true)
      }
    }
  }

  /// Returns a list of the system's multicast interface
  /// addrs. The filter is used to determine which multicast
  /// addresses to include.
  ///
  /// Each returned [`IfAddr`] retains its associated interface index through
  /// [`IfAddr::index`].
  ///
  /// ## Example
  ///
  /// ```rust
  /// use getifs::interface_multicast_addrs_by_filter;
  ///
  /// # fn main() -> std::io::Result<()> {
  /// let addrs = match interface_multicast_addrs_by_filter(|addr| {
  ///   !addr.is_loopback()
  /// }) {
  ///   Ok(v) => v,
  ///   Err(e) if e.kind() == std::io::ErrorKind::Unsupported => return Ok(()),
  ///   Err(e) => return Err(e),
  /// };
  /// # Ok(())
  /// # }
  /// ```
  pub fn interface_multicast_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<IfAddr>>
  where
    F: FnMut(&IpAddr) -> bool,
  {
    cfg_if::cfg_if! {
      if #[cfg(windows)] {
        os::interface_multicast_addresses(None, f)
      } else {
        os::interface_multicast_addresses(0, f)
      }
    }
  }

  /// Returns a list of the system's multicast, IPv4 interface
  /// addrs.
  ///
  /// Each returned [`Ifv4Addr`] retains its associated interface index through
  /// [`Ifv4Addr::index`].
  ///
  /// ## Example
  ///
  /// ```rust
  /// use getifs::interface_multicast_ipv4_addrs;
  ///
  /// # fn main() -> std::io::Result<()> {
  /// let addrs = match interface_multicast_ipv4_addrs() {
  ///   Ok(v) => v,
  ///   Err(e) if e.kind() == std::io::ErrorKind::Unsupported => return Ok(()),
  ///   Err(e) => return Err(e),
  /// };
  ///
  /// for addr in addrs {
  ///  println!("Multicast IPv4 Addr: {:?}", addr);
  /// }
  /// # Ok(())
  /// # }
  /// ```
  pub fn interface_multicast_ipv4_addrs() -> io::Result<SmallVec<Ifv4Addr>> {
    cfg_if::cfg_if! {
      if #[cfg(windows)] {
        os::interface_multicast_ipv4_addresses(None, |_| true)
      } else {
        os::interface_multicast_ipv4_addresses(0, |_| true)
      }
    }
  }

  /// Returns a list of the system's multicast, IPv4 interface
  /// addrs. The filter is used to determine which multicast
  /// addresses to include.
  ///
  /// Each returned [`Ifv4Addr`] retains its associated interface index through
  /// [`Ifv4Addr::index`].
  ///
  /// ## Example
  ///
  /// ```rust
  /// use getifs::interface_multicast_ipv4_addrs_by_filter;
  ///
  /// # fn main() -> std::io::Result<()> {
  /// let addrs = match interface_multicast_ipv4_addrs_by_filter(|addr| {
  ///   !addr.is_loopback()
  /// }) {
  ///   Ok(v) => v,
  ///   Err(e) if e.kind() == std::io::ErrorKind::Unsupported => return Ok(()),
  ///   Err(e) => return Err(e),
  /// };
  /// # Ok(())
  /// # }
  /// ```
  pub fn interface_multicast_ipv4_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv4Addr>>
  where
    F: FnMut(&Ipv4Addr) -> bool,
  {
    cfg_if::cfg_if! {
      if #[cfg(windows)] {
        os::interface_multicast_ipv4_addresses(None, f)
      } else {
        os::interface_multicast_ipv4_addresses(0, f)
      }
    }
  }

  /// Returns a list of the system's multicast, IPv6 interface
  /// addrs.
  ///
  /// Each returned [`Ifv6Addr`] retains its associated interface index through
  /// [`Ifv6Addr::index`].
  ///
  /// ## Example
  ///
  /// ```rust
  /// use getifs::interface_multicast_ipv6_addrs;
  ///
  /// # fn main() -> std::io::Result<()> {
  /// let addrs = match interface_multicast_ipv6_addrs() {
  ///   Ok(v) => v,
  ///   Err(e) if e.kind() == std::io::ErrorKind::Unsupported => return Ok(()),
  ///   Err(e) => return Err(e),
  /// };
  ///
  /// for addr in addrs {
  ///   println!("Multicast IPv6 Addr: {:?}", addr);
  /// }
  /// # Ok(())
  /// # }
  /// ```
  pub fn interface_multicast_ipv6_addrs() -> io::Result<SmallVec<Ifv6Addr>> {
    cfg_if::cfg_if! {
      if #[cfg(windows)] {
        os::interface_multicast_ipv6_addresses(None, |_| true)
      } else {
        os::interface_multicast_ipv6_addresses(0, |_| true)
      }
    }
  }

  /// Returns a list of the system's multicast, IPv6 interface
  /// addrs. The filter is used to determine which multicast
  /// addresses to include.
  ///
  /// Each returned [`Ifv6Addr`] retains its associated interface index through
  /// [`Ifv6Addr::index`].
  ///
  /// ## Example
  ///
  /// ```rust
  /// use getifs::interface_multicast_ipv6_addrs_by_filter;
  ///
  /// # fn main() -> std::io::Result<()> {
  /// let addrs = match interface_multicast_ipv6_addrs_by_filter(|addr| {
  ///   !addr.is_loopback()
  /// }) {
  ///   Ok(v) => v,
  ///   Err(e) if e.kind() == std::io::ErrorKind::Unsupported => return Ok(()),
  ///   Err(e) => return Err(e),
  /// };
  /// # Ok(())
  /// # }
  /// ```
  pub fn interface_multicast_ipv6_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv6Addr>>
  where
    F: FnMut(&Ipv6Addr) -> bool,
  {
    cfg_if::cfg_if! {
      if #[cfg(windows)] {
        os::interface_multicast_ipv6_addresses(None, f)
      } else {
        os::interface_multicast_ipv6_addresses(0, f)
      }
    }
  }
);

#[cfg(test)]
mod tests {
  use super::*;

  #[cfg(linux_like)]
  fn missing_interface_errno() -> i32 {
    rustix::io::Errno::NODEV.raw_os_error()
  }

  #[cfg(bsd_like)]
  fn missing_interface_errno() -> i32 {
    libc::ENODEV
  }

  #[cfg(windows)]
  fn missing_interface_errno() -> i32 {
    2 // ERROR_FILE_NOT_FOUND
  }

  #[cfg(linux_like)]
  fn permission_errno() -> i32 {
    rustix::io::Errno::ACCESS.raw_os_error()
  }

  #[cfg(bsd_like)]
  fn permission_errno() -> i32 {
    libc::EACCES
  }

  #[cfg(windows)]
  fn permission_errno() -> i32 {
    5 // ERROR_ACCESS_DENIED
  }

  #[cfg(linux_like)]
  fn invalid_input_errno() -> i32 {
    rustix::io::Errno::INVAL.raw_os_error()
  }

  #[cfg(bsd_like)]
  fn invalid_input_errno() -> i32 {
    libc::EINVAL
  }

  #[cfg(windows)]
  fn invalid_input_errno() -> i32 {
    87 // ERROR_INVALID_PARAMETER
  }

  #[test]
  fn known_missing_interface_error_becomes_none() {
    let result =
      missing_interface_to_none::<()>(Err(io::Error::from_raw_os_error(missing_interface_errno())));
    assert_eq!(result.unwrap(), None);
  }

  #[test]
  fn permission_error_is_preserved() {
    let error =
      missing_interface_to_none::<()>(Err(io::Error::from_raw_os_error(permission_errno())))
        .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(permission_errno()));
  }

  #[test]
  fn invalid_input_error_is_preserved() {
    let error =
      missing_interface_to_none::<()>(Err(io::Error::from_raw_os_error(invalid_input_errno())))
        .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(invalid_input_errno()));
  }
}
