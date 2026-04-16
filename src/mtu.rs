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
  // Enumerate interfaces (with their MTUs) and all interface addresses
  // exactly once each, then match by `IpAddr` → index → MTU in memory.
  //
  // The previous implementation did a `for iface in interfaces() {
  // iface.addrs_by_filter(...) }`, which on Linux triggered a fresh
  // full-table netlink dump for every interface — O(1+N) dumps per
  // lookup. This version is O(1) dumps regardless of interface count,
  // which matters on hosts with many veth/tunnel interfaces.
  let ifis = interfaces()?;
  let addrs = interface_addrs()?;
  addrs
    .iter()
    .find(|a| a.addr() == ip)
    .and_then(|a| ifis.iter().find(|i| i.index() == a.index()))
    .map(|i| i.mtu())
    .ok_or_else(interface_not_found_for_ip)
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
  let ifis = interfaces()?;
  let addrs = interface_ipv4_addrs()?;
  addrs
    .iter()
    .find(|a| a.addr() == ip)
    .and_then(|a| ifis.iter().find(|i| i.index() == a.index()))
    .map(|i| i.mtu())
    .ok_or_else(interface_not_found_for_ip)
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
  let ifis = interfaces()?;
  let addrs = interface_ipv6_addrs()?;
  addrs
    .iter()
    .find(|a| a.addr() == ip)
    .and_then(|a| ifis.iter().find(|i| i.index() == a.index()))
    .map(|i| i.mtu())
    .ok_or_else(interface_not_found_for_ip)
}
