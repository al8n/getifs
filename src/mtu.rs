use core::net::IpAddr;
use std::{
  io,
  net::{Ipv4Addr, Ipv6Addr},
};

use super::{interface_addrs, interface_ipv4_addrs, interface_ipv6_addrs, interfaces};

fn interface_not_found_for_ip() -> io::Error {
  io::Error::new(io::ErrorKind::Other, "interface not found")
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
