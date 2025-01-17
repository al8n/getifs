use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use smallvec_wrapper::SmallVec;

use super::{os, IfNet, Ifv4Net, Ifv6Net};

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
/// let ipv4_addrs = local_ipv4_addrs().unwrap();
/// for addr in ipv4_addrs {
///   println!("{addr}");
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
/// let ipv6_addrs = local_ipv6_addrs().unwrap();
/// for addr in ipv6_addrs {
///   println!("{addr}");
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
/// let all_addrs = local_ip_addrs().unwrap();
/// for addr in all_addrs {
///   println!("{addr}");
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
/// let addrs = local_ipv4_addrs_by_filter(|addr| !addr.is_loopback()).unwrap();
/// for addr in addrs {
///   println!("{addr}");
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
/// let addrs = local_ipv6_addrs_by_filter(|addr| !addr.is_loopback()).unwrap();
/// for addr in addrs {
///   println!("{addr}");
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
/// let addrs = local_ip_addrs_by_filter(|addr| !addr.is_loopback()).unwrap();
/// for addr in addrs {
///   println!("{addr}");
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
/// let ipv4_addrs = best_local_ipv4_addrs().unwrap();
/// for addr in ipv4_addrs {
///   println!("{addr}");
/// }
/// ```
pub fn best_local_ipv4_addrs() -> io::Result<SmallVec<Ifv4Net>> {
  os::best_local_ipv4_addrs()
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
/// let ipv6_addrs = best_local_ipv6_addrs().unwrap();
/// // Will only contain addresses from the interface with best default route
/// for addr in ipv6_addrs {
///   println!("{addr}");
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
/// let all_addrs = best_local_ip_addrs().unwrap();
/// // Will only contain addresses from interfaces with best default routes
/// for addr in all_addrs {
///   println!("{addr}");
/// }
/// ```
pub fn best_local_ip_addrs() -> io::Result<SmallVec<IfNet>> {
  os::best_local_ip_addrs()
}
