use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use smallvec_wrapper::SmallVec;

use super::{os, IfAddr, Ifv4Addr, Ifv6Addr};

/// Returns all rt_host routes (both IPv4 and IPv6) configured on the system.
/// Host routes are specific routes to individual IP addresses rather than networks.
/// This includes:
/// - Interface addresses
/// - Temporary/privacy addresses
/// - Multicast addresses
/// - Link-local addresses
/// - Cached remote addresses
///
/// ## Example
///
/// ```rust
/// use getifs::rt_host_ip_addrs;
///
/// let addrs = rt_host_ip_addrs()?;
/// for addr in addrs {
///   println!("Host route: {} on interface {}", addr.addr, addr.ifindex);
/// }
/// ```
pub fn rt_host_ip_addrs() -> io::Result<SmallVec<IfAddr>> {
  os::rt_host_ip_addrs()
}

/// Returns all IPv4 rt_host routes configured on the system.
/// This includes interface addresses, cached remote addresses, and special purpose addresses.
///
/// ## Example
///
/// ```rust
/// use getifs::rt_host_ipv4_addrs;
///
/// let addrs = rt_host_ipv4_addrs()?;
/// for addr in addrs {
///   println!("IPv4 rt_host route: {} on interface {}", addr.addr, addr.ifindex);
/// }
/// ```
pub fn rt_host_ipv4_addrs() -> io::Result<SmallVec<Ifv4Addr>> {
  os::rt_host_ipv4_addrs()
}

/// Returns all IPv6 rt_host routes configured on the system.
/// This includes interface addresses, temporary/privacy addresses, link-local addresses,
/// and auto-configured addresses.
///
/// ## Example
///
/// ```rust
/// use getifs::rt_host_ipv6_addrs;
///
/// let addrs = rt_host_ipv6_addrs()?;
/// for addr in addrs {
///   println!("IPv6 rt_host route: {} on interface {}", addr.addr, addr.ifindex);
/// }
/// ```
pub fn rt_host_ipv6_addrs() -> io::Result<SmallVec<Ifv6Addr>> {
  os::rt_host_ipv6_addrs()
}

/// Returns all rt_host routes (both IPv4 and IPv6) that match the provided filter.
/// The filter function can be used to select specific types of addresses.
///
/// ## Example
///
/// ```rust
/// use getifs::rt_host_ip_addrs_by_filter;
///
/// // Only get non-loopback addresses
/// let addrs = rt_host_ip_addrs_by_filter(|addr| !addr.is_loopback())?;
/// for addr in addrs {
///   println!("Filtered rt_host route: {}", addr);
/// }
/// ```
pub fn rt_host_ip_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<IfAddr>>
where
  F: FnMut(&IpAddr) -> bool,
{
  os::rt_host_ip_addrs_by_filter(f)
}

/// Returns IPv4 rt_host routes that match the provided filter.
/// The filter function can be used to select specific types of IPv4 addresses.
///
/// ## Example
///
/// ```rust
/// use getifs::rt_host_ipv4_addrs_by_filter;
///
/// // Only get private IPv4 addresses
/// let addrs = rt_host_ipv4_addrs_by_filter(|addr| addr.is_private())?;
/// for addr in addrs {
///   println!("Private IPv4 rt_host route: {}", addr);
/// }
/// ```
pub fn rt_host_ipv4_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv4Addr>>
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  os::rt_host_ipv4_addrs_by_filter(f)
}

/// Returns IPv6 rt_host routes that match the provided filter.
/// The filter function can be used to select specific types of IPv6 addresses.
///
/// ## Example
///
/// ```rust
/// use getifs::rt_host_ipv6_addrs_by_filter;
///
/// // Only get global unicast addresses
/// let addrs = rt_host_ipv6_addrs_by_filter(|addr| !addr.is_unicast_link_local())?;
/// for addr in addrs {
///   println!("Global IPv6 rt_host route: {}", addr);
/// }
/// ```
pub fn rt_host_ipv6_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv6Addr>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  os::rt_host_ipv6_addrs_by_filter(f)
}
