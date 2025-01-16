use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use smallvec_wrapper::SmallVec;

use super::{os, IfAddr, Ifv4Addr, Ifv6Addr};

/// Returns all network routes (both IPv4 and IPv6) configured on the system.
/// Network routes represent subnets rather than individual net addresses.
///
/// The returned routes include:
/// - Private network subnets (e.g., 10.0.0.0/8, 192.168.0.0/16)
/// - Loopback network (127.0.0.0/8)
/// - Link-local networks (169.254.0.0/16)
/// - Multicast networks (224.0.0.0/4)
/// - Global unicast IPv6 networks (2000::/3)
/// - Unique local IPv6 networks (fd00::/8)
///
/// Each route entry contains:
/// - The network address (always ends with zeros in net portion)
/// - The prefix length (subnet mask)
/// - The interface index it's associated with
///
/// ## Example
///
/// ```rust
/// use getifs::route_net_addrs;
///
/// let routes = route_net_addrs().unwrap();
/// for route in routes {
///   println!("{route}");
/// }
/// ```
pub fn rt_net_addrs() -> io::Result<SmallVec<IfAddr>> {
  os::rt_net_addrs()
}

/// Returns only IPv4 network routes.
/// See [`rt_net_addrs`] for details on network routes.
///
/// ## Example
///
/// ```rust
/// use getifs::rt_net_ipv4_addrs;
///
/// let routes = rt_net_ipv4_addrs().unwrap();
/// for route in routes {
///   println!("{route}");
/// }
/// ```
pub fn rt_net_ipv4_addrs() -> io::Result<SmallVec<Ifv4Addr>> {
  os::rt_net_ipv4_addrs()
}

/// Returns only IPv6 network routes.
/// See [`rt_net_addrs`] for details on network routes.
///
/// ## Example
///
/// ```rust
/// use getifs::rt_net_ipv6_addrs;
///
/// let routes = rt_net_ipv6_addrs().unwrap();
/// for route in routes {
///   println!("{route}");
/// }
/// ```
pub fn rt_net_ipv6_addrs() -> io::Result<SmallVec<Ifv6Addr>> {
  os::rt_net_ipv6_addrs()
}

/// Returns all network routes (both IPv4 and IPv6) that match the provided filter.
/// The filter function can be used to select specific types of addresses.
///
/// ## Example
///
/// ```rust
/// use getifs::rt_net_ip_addrs_by_filter;
///
/// // Only get private network routes
/// let routes = rt_net_ip_addrs_by_filter(|addr| match addr {
///   IpAddr::V4(ip) => ip.is_private(),
///   IpAddr::V6(ip) => ip.to_string().starts_with("fd"),
/// }).unwrap();
///
/// for route in routes {
///   println!("Private network route: {}", route);
/// }
/// ```
pub fn rt_net_ip_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<IfAddr>>
where
  F: FnMut(&IpAddr) -> bool,
{
  os::rt_net_addrs_by_filter(f)
}

/// Returns IPv4 network routes that match the provided filter.
/// The filter function can be used to select specific types of IPv4 addresses.
///
/// ## Example
///
/// ```rust
/// use getifs::rt_net_ipv4_addrs_by_filter;
///
/// // Only get Class C private networks (192.168.0.0/16)
/// let routes = rt_net_ipv4_addrs_by_filter(|addr| {
///     addr.octets()[0] == 192 && addr.octets()[1] == 168
/// }).unwrap();
///
/// for route in routes {
///     println!("Class C private network: {}", route);
/// }
/// ```
pub fn rt_net_ipv4_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv4Addr>>
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  os::rt_net_ipv4_addrs_by_filter(f)
}

/// Returns IPv6 network routes that match the provided filter.
/// The filter function can be used to select specific types of IPv6 addresses.
///
/// ## Example
///
/// ```rust
/// use getifs::rt_net_ipv6_addrs_by_filter;
///
/// // Only get Unique Local Address networks (fd00::/8)
/// let routes = rt_net_ipv6_addrs_by_filter(|addr| {
///   addr.segments()[0] & 0xff00 == 0xfd00
/// }).unwrap();
///
/// for route in routes {
///   println!("ULA network: {}", route);
/// }
/// ```
pub fn rt_net_ipv6_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv6Addr>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  os::rt_net_ipv6_addrs_by_filter(f)
}
