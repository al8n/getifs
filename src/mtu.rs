use core::net::IpAddr;
use std::{
  io,
  net::{Ipv4Addr, Ipv6Addr},
};

use super::{interface_addrs, interface_ipv4_addrs, interface_ipv6_addrs, interfaces};

#[inline]
fn interface_not_found_for_ip() -> io::Error {
  io::Error::other("interface not found")
}

/// Get the MTU of the given [`IpAddr`].
///
/// ## Example
///
/// ```rust
/// use getifs::get_ip_mtu;
///
/// let mtu = get_ip_mtu("127.0.0.1".parse().unwrap()).unwrap();
/// println!("MTU: {}", mtu);
/// ```
pub fn get_ip_mtu(ip: IpAddr) -> io::Result<u32> {
  // Fast path: enumerate interfaces (with their MTUs) and all
  // interface addresses exactly once each, then match by
  // `IpAddr` → index → MTU in memory. O(1) dumps regardless of
  // interface count.
  //
  // Fallback: if the bulk address dump fails (a malformed kernel
  // message or transient race on any *unrelated* interface), retry
  // by iterating per-interface — one bad interface no longer
  // poisons the whole lookup. The per-interface path is the older
  // O(N) dump-per-iface shape; resilience is worth the cost when
  // the fast path has already failed.
  let ifis = interfaces()?;
  if let Ok(addrs) = interface_addrs() {
    if let Some(mtu) = addrs
      .iter()
      .find(|a| a.addr() == ip)
      .and_then(|a| ifis.iter().find(|i| i.index() == a.index()))
      .map(|i| i.mtu())
    {
      return Ok(mtu);
    }
  }
  for iface in &ifis {
    if let Ok(addrs) = iface.addrs() {
      if addrs.iter().any(|a| a.addr() == ip) {
        return Ok(iface.mtu());
      }
    }
  }
  Err(interface_not_found_for_ip())
}

/// Get the MTU of the given [`Ipv4Addr`].
///
/// ## Example
///
/// ```rust
/// use std::net::Ipv4Addr;
/// use getifs::get_ipv4_mtu;
///
/// let mtu = get_ipv4_mtu(Ipv4Addr::LOCALHOST).unwrap();
/// println!("MTU: {}", mtu);
/// ```
pub fn get_ipv4_mtu(ip: Ipv4Addr) -> io::Result<u32> {
  // Same fast-path / per-interface fallback shape as `get_ip_mtu`
  // — see the comment there for rationale.
  let ifis = interfaces()?;
  if let Ok(addrs) = interface_ipv4_addrs() {
    if let Some(mtu) = addrs
      .iter()
      .find(|a| a.addr() == ip)
      .and_then(|a| ifis.iter().find(|i| i.index() == a.index()))
      .map(|i| i.mtu())
    {
      return Ok(mtu);
    }
  }
  for iface in &ifis {
    if let Ok(addrs) = iface.ipv4_addrs() {
      if addrs.iter().any(|a| a.addr() == ip) {
        return Ok(iface.mtu());
      }
    }
  }
  Err(interface_not_found_for_ip())
}

/// Get the MTU of the given [`Ipv6Addr`].
///
/// ## Example
///
/// ```rust
/// use std::net::Ipv6Addr;
/// use getifs::get_ipv6_mtu;
///
/// let mtu = get_ipv6_mtu(Ipv6Addr::LOCALHOST).unwrap();
/// println!("MTU: {}", mtu);
/// ```
pub fn get_ipv6_mtu(ip: Ipv6Addr) -> io::Result<u32> {
  // Same fast-path / per-interface fallback shape as `get_ip_mtu`
  // — see the comment there for rationale.
  let ifis = interfaces()?;
  if let Ok(addrs) = interface_ipv6_addrs() {
    if let Some(mtu) = addrs
      .iter()
      .find(|a| a.addr() == ip)
      .and_then(|a| ifis.iter().find(|i| i.index() == a.index()))
      .map(|i| i.mtu())
    {
      return Ok(mtu);
    }
  }
  for iface in &ifis {
    if let Ok(addrs) = iface.ipv6_addrs() {
      if addrs.iter().any(|a| a.addr() == ip) {
        return Ok(iface.mtu());
      }
    }
  }
  Err(interface_not_found_for_ip())
}

#[cfg(test)]
mod tests {
  use super::*;

  // Hits the `interface_not_found_for_ip()` constructor and the
  // trailing `Err(...)` returns in each of the three lookup
  // functions. Uses a documentation-reserved IP that's guaranteed
  // not to be assigned to any local interface (RFC 5737 TEST-NET-3
  // for IPv4; RFC 3849 documentation prefix for IPv6).
  #[test]
  fn get_ip_mtu_unknown_returns_not_found() {
    let v4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    assert!(get_ip_mtu(v4).is_err());
    assert!(get_ip_mtu(v6).is_err());
  }

  #[test]
  fn get_ipv4_mtu_unknown_returns_not_found() {
    let ip = Ipv4Addr::new(203, 0, 113, 2);
    assert!(get_ipv4_mtu(ip).is_err());
  }

  #[test]
  fn get_ipv6_mtu_unknown_returns_not_found() {
    let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    assert!(get_ipv6_mtu(ip).is_err());
  }

  // Happy path through the bulk lookup. The loopback address (v4
  // and v6) is universally configured on every supported platform,
  // so this hits the bulk-find branch and the
  // `addrs.find()...map(|i| i.mtu())` chain.
  #[test]
  fn get_ip_mtu_loopback_succeeds() {
    let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    assert!(get_ip_mtu(v4).is_ok());
    let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    // IPv6 loopback may not be present on every CI runner; only
    // assert positively when it is.
    if let Ok(mtu) = get_ip_mtu(v6) {
      assert!(mtu > 0);
    }
  }

  #[test]
  fn get_ipv4_mtu_loopback_succeeds() {
    assert!(get_ipv4_mtu(Ipv4Addr::LOCALHOST).is_ok());
  }
}
