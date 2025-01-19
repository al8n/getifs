use std::io;

use smallvec_wrapper::SmallVec;

use super::{os, IfAddr, Ifv4Addr, Ifv6Addr};

/// Returns all gateway IP addresses (both IPv4 and IPv6) configured on the system.
/// Only returns addresses from interfaces that have valid routes and
/// excludes any addresses that are not configured as gateways.
///
/// ## Example
///
/// ```rust
/// use getifs::gateway_addrs;
///
/// let gateways = gateway_addrs().unwrap();
/// for gw in gateways {
///   println!("Gateway: {}", gw);
/// }
/// ```
pub fn gateway_addrs() -> io::Result<SmallVec<IfAddr>> {
  os::gateway_addrs()
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

/// Returns all gateway IP addresses (both IPv4 and IPv6) configured on the system
/// that match the given filter.
/// Only returns addresses from interfaces that have valid routes and
/// excludes any addresses that are not configured as gateways.
///
/// ## Example
///
/// ```rust
/// use getifs::{gateway_addrs_by_filter, IfAddr};
/// use std::net::IpAddr;
///
/// let gateways = gateway_addrs_by_filter(|ip| {
///   match ip {
///     IpAddr::V4(_) => true,
///     IpAddr::V6(_) => false,
///   }
/// }).unwrap();
///
/// for gw in gateways {
///   println!("Gateway: {}", gw);
/// }
/// ```
pub fn gateway_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<IfAddr>>
where
  F: FnMut(&std::net::IpAddr) -> bool,
{
  os::gateway_addrs_by_filter(f)
}

/// Returns all IPv4 gateway addresses configured on the system
/// that match the given filter.
/// Only returns addresses from interfaces that have valid routes and
/// excludes any addresses that are not configured as gateways.
///
/// ## Example
///
/// ```rust
/// use getifs::gateway_ipv4_addrs_by_filter;
///
/// let gateways = gateway_ipv4_addrs_by_filter(|ip| {
///  ip.is_private()
/// }).unwrap();
///
/// for gw in gateways {
///   println!("IPv4 Gateway: {}", gw);
/// }
/// ```
pub fn gateway_ipv4_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv4Addr>>
where
  F: FnMut(&std::net::Ipv4Addr) -> bool,
{
  os::gateway_ipv4_addrs_by_filter(f)
}

/// Returns all IPv6 gateway addresses configured on the system
/// that match the given filter.
/// Only returns addresses from interfaces that have valid routes and
/// excludes any addresses that are not configured as gateways.
///
/// ## Example
///
/// ```rust
/// use getifs::gateway_ipv6_addrs_by_filter;
///
/// let gateways = gateway_ipv6_addrs_by_filter(|ip| {
///   true
/// }).unwrap();
///
/// for gw in gateways {
///   println!("IPv6 Gateway: {}", gw);
/// }
/// ```
pub fn gateway_ipv6_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv6Addr>>
where
  F: FnMut(&std::net::Ipv6Addr) -> bool,
{
  os::gateway_ipv6_addrs_by_filter(f)
}
