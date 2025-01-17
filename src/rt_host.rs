use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use smallvec_wrapper::SmallVec;

use super::{os, IfAddr, Ifv4Addr, Ifv6Addr};

/// Returns all host routes (both IPv4 and IPv6) configured on the system.
///
/// ## Example
///
/// ```rust
/// use getifs::rt_host_addrs;
///
/// let addrs = rt_host_addrs().unwrap();
/// for addr in addrs {
///   println!("{addr}");
/// }
/// ```
pub fn rt_host_addrs() -> io::Result<SmallVec<IfAddr>> {
  os::rt_host_addrs()
}

/// Returns all IPv4 host routes configured on the system.
///
/// ## Example
///
/// ```rust
/// use getifs::rt_host_ipv4_addrs;
///
/// let addrs = rt_host_ipv4_addrs().unwrap();
/// for addr in addrs {
///   println!("{addr}");
/// }
/// ```
pub fn rt_host_ipv4_addrs() -> io::Result<SmallVec<Ifv4Addr>> {
  os::rt_host_ipv4_addrs()
}

/// Returns all IPv6 host routes configured on the system.
///
/// ## Example
///
/// ```rust
/// use getifs::rt_host_ipv6_addrs;
///
/// let addrs = rt_host_ipv6_addrs().unwrap();
/// for addr in addrs {
///   println!("{addr}");
/// }
/// ```
pub fn rt_host_ipv6_addrs() -> io::Result<SmallVec<Ifv6Addr>> {
  os::rt_host_ipv6_addrs()
}

/// Returns all host routes (both IPv4 and IPv6) that match the provided filter.
/// The filter function can be used to select specific types of addresses.
///
/// ## Example
///
/// ```rust
/// use getifs::rt_host_addrs_by_filter;
///
/// // Only get non-loopback addresses
/// let addrs = rt_host_addrs_by_filter(|addr| !addr.is_loopback()).unwrap();
/// for addr in addrs {
///   println!("{addr}");
/// }
/// ```
pub fn rt_host_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<IfAddr>>
where
  F: FnMut(&IpAddr) -> bool,
{
  os::rt_host_addrs_by_filter(f)
}

/// Returns IPv4 host routes that match the provided filter.
/// The filter function can be used to select specific types of IPv4 addresses.
///
/// ## Example
///
/// ```rust
/// use getifs::rt_host_ipv4_addrs_by_filter;
///
/// // Only get private IPv4 addresses
/// let addrs = rt_host_ipv4_addrs_by_filter(|addr| addr.is_private()).unwrap();
/// for addr in addrs {
///   println!("{addr}");
/// }
/// ```
pub fn rt_host_ipv4_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv4Addr>>
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  os::rt_host_ipv4_addrs_by_filter(f)
}

/// Returns IPv6 host routes that match the provided filter.
/// The filter function can be used to select specific types of IPv6 addresses.
///
/// ## Example
///
/// ```rust
/// use getifs::rt_host_ipv6_addrs_by_filter;
///
/// // Only get global unicast addresses
/// let addrs = rt_host_ipv6_addrs_by_filter(|addr| !addr.is_unicast_link_local()).unwrap();
/// for addr in addrs {
///   println!("{addr}");
/// }
/// ```
pub fn rt_host_ipv6_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv6Addr>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  os::rt_host_ipv6_addrs_by_filter(f)
}
