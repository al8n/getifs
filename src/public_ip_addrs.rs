use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use iprfc::RFC6890;
use smallvec_wrapper::SmallVec;

use crate::{ipv4_filter_to_ip_filter, ipv6_filter_to_ip_filter};

use super::{os, IfNet, Ifv4Net, Ifv6Net};

/// Returns all IPv4 addresses that are NOT part of [RFC
/// 6890] (regardless of whether or not there is a default route, unlike
/// [`private_ipv4_addrs`](super::private_ipv4_addrs)).
///
/// See also [`public_ipv4_addrs_by_filter`].
///
/// ## Example
///
/// ```rust
/// use getifs::public_ipv4_addrs;
///
/// let ipv4_addrs = public_ipv4_addrs().unwrap();
/// for addr in ipv4_addrs {
///   println!("{addr}");
/// }
/// ```
///
/// [RFC 6890]: https://tools.ietf.org/html/rfc6890
pub fn public_ipv4_addrs() -> io::Result<SmallVec<Ifv4Net>> {
  os::interface_ipv4_addresses(0, public_ip_filter)
}

/// Returns all IPv6 addresses that are NOT part of [RFC
/// 6890] (regardless of whether or not there is a default route, unlike
/// [`private_ipv6_addrs`](super::private_ipv6_addrs)).
///
/// See also [`public_ipv6_addrs_by_filter`].
///
/// ## Example
///
/// ```rust
/// use getifs::public_ipv6_addrs;
///
/// let ipv6_addrs = public_ipv6_addrs().unwrap();
/// for addr in ipv6_addrs {
///   println!("{addr}");
/// }
/// ```
///
/// [RFC 6890]: https://tools.ietf.org/html/rfc6890
pub fn public_ipv6_addrs() -> io::Result<SmallVec<Ifv6Net>> {
  os::interface_ipv6_addresses(0, public_ip_filter)
}

/// Returns all IP addresses that are NOT part of [RFC
/// 6890] (regardless of whether or not there is a default route, unlike
/// [`private_addrs`](super::private_addrs)).
///
/// See also [`public_addrs_by_filter`].
///
/// ## Example
///
/// ```rust
/// use getifs::public_addrs;
///
/// let all_addrs = public_addrs().unwrap();
/// for addr in all_addrs {
///   println!("{addr}");
/// }
/// ```
///
/// [RFC 6890]: https://tools.ietf.org/html/rfc6890
pub fn public_addrs() -> io::Result<SmallVec<IfNet>> {
  os::interface_addresses(0, public_ip_filter)
}

/// Returns all IP addresses that are NOT part of [RFC
/// 6890] (regardless of whether or not there is a default route, unlike
/// [`private_ipv4_addrs_by_filter`](super::private_ipv4_addrs_by_filter)).
///
/// Use the provided filter to further refine the results.
///
/// ## Example
///
/// ```rust
/// use getifs::public_ipv4_addrs_by_filter;
///
/// let addrs = public_ipv4_addrs_by_filter(|addr| !addr.is_loopback()).unwrap();
/// for addr in addrs {
///   println!("{addr}");
/// }
/// ```
///
/// [RFC 6890]: https://tools.ietf.org/html/rfc6890
pub fn public_ipv4_addrs_by_filter<F>(mut f: F) -> io::Result<SmallVec<Ifv4Net>>
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  os::interface_ipv4_addresses(0, |ip| {
    public_ip_filter(ip) && ipv4_filter_to_ip_filter(&mut f)(ip)
  })
}

/// Returns all IPv6 addresses that are NOT part of [RFC
/// 6890] (regardless of whether or not there is a default route, unlike
/// [`private_ipv6_addrs_by_filter`](super::private_ipv6_addrs_by_filter)).
///
/// Use the provided filter to further refine the results.
///
/// ## Example
///
/// ```rust
/// use getifs::public_ipv6_addrs_by_filter;
///
/// let addrs = public_ipv6_addrs_by_filter(|addr| !addr.is_loopback()).unwrap();
/// for addr in addrs {
///   println!("{addr}");
/// }
/// ```
///
/// [RFC 6890]: https://tools.ietf.org/html/rfc6890
pub fn public_ipv6_addrs_by_filter<F>(mut f: F) -> io::Result<SmallVec<Ifv6Net>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  os::interface_ipv6_addresses(0, |ip| {
    public_ip_filter(ip) && ipv6_filter_to_ip_filter(&mut f)(ip)
  })
}

/// Returns all IP addresses that are NOT part of [RFC
/// 6890] (regardless of whether or not there is a default route, unlike
/// [`private_addrs_by_filter`](super::private_addrs_by_filter)).
///
/// Use the provided filter to further refine the results.
///
/// ## Example
///
/// ```rust
/// use getifs::public_addrs_by_filter;
///
///
/// let addrs = public_addrs_by_filter(|addr| !addr.is_loopback()).unwrap();
/// for addr in addrs {
///   println!("{addr}");
/// }
/// ```
///
/// [RFC 6890]: https://tools.ietf.org/html/rfc6890
pub fn public_addrs_by_filter<F>(mut f: F) -> io::Result<SmallVec<IfNet>>
where
  F: FnMut(&IpAddr) -> bool,
{
  os::interface_addresses(0, |ip| public_ip_filter(ip) && f(ip))
}

#[inline]
fn public_ip_filter(ip: &IpAddr) -> bool {
  !RFC6890.contains(ip)
}
