use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use iprfc::{FORWARDING_BLACKLIST, RFC6890};
use smallvec_wrapper::SmallVec;

use crate::{ipv4_filter_to_ip_filter, ipv6_filter_to_ip_filter};

use super::{os, IfNet, Ifv4Net, Ifv6Net};

/// Returns all IPv4 addresses that are part of [RFC
/// 6890] (regardless of whether or not there is a default route, unlike
/// [`public_ipv4_addrs`](super::public_ipv4_addrs)).
///
/// See also [`private_ipv4_addrs_by_filter`].
///
/// ## Example
///
/// ```rust
/// use getifs::private_ipv4_addrs;
///
/// let ipv4_addrs = private_ipv4_addrs().unwrap();
/// for addr in ipv4_addrs {
///   println!("{addr}");
/// }
/// ```
///
/// [RFC 6890]: https://tools.ietf.org/html/rfc6890
pub fn private_ipv4_addrs() -> io::Result<SmallVec<Ifv4Net>> {
  cfg_if::cfg_if! {
    if #[cfg(windows)] {
      os::interface_ipv4_addresses(None, private_ip_filter)
    } else {
      os::interface_ipv4_addresses(0, private_ip_filter)
    }
  }
}

/// Returns all IPv6 addresses that are part of [RFC
/// 6890] (regardless of whether or not there is a default route, unlike
/// [`public_ipv6_addrs`](super::public_ipv6_addrs)).
///
/// See also [`private_ipv6_addrs_by_filter`].
///
/// ## Example
///
/// ```rust
/// use getifs::private_ipv6_addrs;
///
/// let ipv6_addrs = private_ipv6_addrs().unwrap();
/// for addr in ipv6_addrs {
///   println!("{addr}");
/// }
/// ```
///
/// [RFC 6890]: https://tools.ietf.org/html/rfc6890
pub fn private_ipv6_addrs() -> io::Result<SmallVec<Ifv6Net>> {
  cfg_if::cfg_if! {
    if #[cfg(windows)] {
      os::interface_ipv6_addresses(None, private_ip_filter)
    } else {
      os::interface_ipv6_addresses(0, private_ip_filter)
    }
  }
}

/// Returns all IP addresses that are part of [RFC
/// 6890] (regardless of whether or not there is a default route, unlike
/// [`public_addrs`](super::public_addrs)).
///
/// See also [`private_addrs_by_filter`].
///
/// ## Example
///
/// ```rust
/// use getifs::private_addrs;
///
/// let all_addrs = private_addrs().unwrap();
/// for addr in all_addrs {
///   println!("{addr}");
/// }
/// ```
///
/// [RFC 6890]: https://tools.ietf.org/html/rfc6890
pub fn private_addrs() -> io::Result<SmallVec<IfNet>> {
  cfg_if::cfg_if! {
    if #[cfg(windows)] {
      os::interface_addresses(None, private_ip_filter)
    } else {
      os::interface_addresses(0, private_ip_filter)
    }
  }
}

/// Returns all IPv4 addresses that are part of [RFC
/// 6890] (regardless of whether or not there is a default route, unlike
/// [`public_ipv4_addrs_by_filter`](super::public_ipv4_addrs_by_filter)).
///
/// Use the provided filter to further refine the results.
///
/// ## Example
///
/// ```rust
/// use getifs::private_ipv4_addrs_by_filter;
///
/// let addrs = private_ipv4_addrs_by_filter(|addr| !addr.is_loopback()).unwrap();
/// for addr in addrs {
///   println!("{addr}");
/// }
/// ```
///
/// [RFC 6890]: https://tools.ietf.org/html/rfc6890
pub fn private_ipv4_addrs_by_filter<F>(mut f: F) -> io::Result<SmallVec<Ifv4Net>>
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  cfg_if::cfg_if! {
    if #[cfg(windows)] {
      os::interface_ipv4_addresses(None, |ip| {
        private_ip_filter(ip) && ipv4_filter_to_ip_filter(&mut f)(ip)
      })
    } else {
      os::interface_ipv4_addresses(0, |ip| {
        private_ip_filter(ip) && ipv4_filter_to_ip_filter(&mut f)(ip)
      })
    }
  }
}

/// Returns all IPv6 addresses that are part of [RFC
/// 6890] (regardless of whether or not there is a default route, unlike
/// [`public_ipv6_addrs_by_filter`](super::public_ipv6_addrs_by_filter)).
///
/// Use the provided filter to further refine the results.
///
/// ## Example
///
/// ```rust
/// use getifs::private_ipv6_addrs_by_filter;
///
/// let addrs = private_ipv6_addrs_by_filter(|addr| !addr.is_loopback()).unwrap();
/// for addr in addrs {
///   println!("{addr}");
/// }
/// ```
///
/// [RFC 6890]: https://tools.ietf.org/html/rfc6890
pub fn private_ipv6_addrs_by_filter<F>(mut f: F) -> io::Result<SmallVec<Ifv6Net>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  cfg_if::cfg_if! {
    if #[cfg(windows)] {
      os::interface_ipv6_addresses(None, |ip| {
        private_ip_filter(ip) && ipv6_filter_to_ip_filter(&mut f)(ip)
      })
    } else {
      os::interface_ipv6_addresses(0, |ip| {
        private_ip_filter(ip) && ipv6_filter_to_ip_filter(&mut f)(ip)
      })
    }
  }
}

/// Returns all IP addresses that are part of [RFC
/// 6890] (regardless of whether or not there is a default route, unlike
/// [`public_addrs_by_filter`](super::public_addrs_by_filter)).
///
/// Use the provided filter to further refine the results.
///
/// ## Example
///
/// ```rust
/// use getifs::private_addrs_by_filter;
///
///
/// let addrs = private_addrs_by_filter(|addr| !addr.is_loopback()).unwrap();
/// for addr in addrs {
///   println!("{addr}");
/// }
/// ```
///
/// [RFC 6890]: https://tools.ietf.org/html/rfc6890
pub fn private_addrs_by_filter<F>(mut f: F) -> io::Result<SmallVec<IfNet>>
where
  F: FnMut(&IpAddr) -> bool,
{
  cfg_if::cfg_if! {
    if #[cfg(windows)] {
      os::interface_addresses(None, |ip| private_ip_filter(ip) && f(ip))
    } else {
      os::interface_addresses(0, |ip| private_ip_filter(ip) && f(ip))
    }
  }
}

#[inline]
fn private_ip_filter(ip: &IpAddr) -> bool {
  RFC6890.contains(ip) && !FORWARDING_BLACKLIST.contains(ip)
}
