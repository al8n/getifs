use std::{io, net::Ipv4Addr};

/// Returns the IPv4 interface of by the given name.
///
/// In Rust, the IPv6 interface is the interface index of the given name.
///
/// ## Example
///
/// ```rust
/// use getifs::{ifname_to_v4_iface, interfaces};
///
/// let interface = interfaces().unwrap().into_iter().next().unwrap();
/// let iface = ifname_to_v4_iface(interface.name()).unwrap().unwrap();
///
/// let addrs = interface.ipv4_addrs().unwrap().into_iter().map(|net| net.addr()).collect::<Vec<_>>();
/// assert!(addrs.contains(&iface));
/// ```
pub fn ifname_to_v4_iface(name: &str) -> io::Result<Option<Ipv4Addr>> {
  let idx = super::name_to_idx::ifname_to_index(name)?;
  let iface = super::interface_by_index(idx)?;

  match iface {
    Some(iface) => {
      let addrs = iface.ipv4_addrs_by_filter(|ip| !ip.is_link_local())?;

      Ok(addrs.into_iter().next().map(|net| net.addr()))
    }
    None => Ok(None),
  }
}

/// Returns the IPv6 interface of by the given name.
///
/// In Rust, the IPv6 interface is the interface index of the given name.
///
/// ## Example
///
/// ```rust
/// use getifs::{ifname_to_v6_iface, interfaces};
///
/// let interface = interfaces().unwrap().into_iter().next().unwrap();
/// let iface = ifname_to_v6_iface(interface.name()).unwrap();
///
/// assert_eq!(interface.index(), iface.unwrap());
/// ```
pub fn ifname_to_v6_iface(name: &str) -> io::Result<Option<u32>> {
  super::name_to_idx::ifname_to_index(name).map(|idx| (idx != 0).then_some(idx))
}

/// Returns the IPv6 interface of by the given name.
///
/// In Rust, the IPv6 interface is the interface index of the given name.
///
/// ## Example
///
/// ```rust
/// use getifs::{ifname_to_iface, interfaces};
///
/// let interface = interfaces().unwrap().into_iter().next().unwrap();
/// let (v4_iface, v6_iface) = ifname_to_iface(interface.name()).unwrap();
///
/// assert_eq!(interface.index(), v6_iface.unwrap());
///
/// let addrs = interface.ipv4_addrs().unwrap().into_iter().map(|net| net.addr()).collect::<Vec<_>>();
/// assert!(addrs.contains(&v4_iface.unwrap()));
/// ```
pub fn ifname_to_iface(name: &str) -> io::Result<(Option<Ipv4Addr>, Option<u32>)> {
  let idx = super::name_to_idx::ifname_to_index(name)?;
  let v6_iface = (idx != 0).then_some(idx);
  let iface = super::interface_by_index(idx)?;

  match iface {
    Some(iface) => {
      let addrs = iface.ipv4_addrs_by_filter(|ip| !ip.is_link_local())?;
      let v4_iface = addrs.into_iter().next().map(|net| net.addr());
      Ok((v4_iface, v6_iface))
    }
    None => Ok((None, v6_iface)),
  }
}
