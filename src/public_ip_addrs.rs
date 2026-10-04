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
/// Returned [`Ifv4Net`] values retain their local interface index through
/// [`Ifv4Net::index`].
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
  cfg_if::cfg_if! {
    if #[cfg(windows)] {
      os::interface_ipv4_addresses(None, public_ip_filter)
    } else {
      os::interface_ipv4_addresses(0, public_ip_filter)
    }
  }
}

/// Returns all IPv6 addresses that are NOT part of [RFC
/// 6890] (regardless of whether or not there is a default route, unlike
/// [`private_ipv6_addrs`](super::private_ipv6_addrs)).
///
/// Returned [`Ifv6Net`] values retain their local interface index through
/// [`Ifv6Net::index`].
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
  cfg_if::cfg_if! {
    if #[cfg(windows)] {
      os::interface_ipv6_addresses(None, public_ip_filter)
    } else {
      os::interface_ipv6_addresses(0, public_ip_filter)
    }
  }
}

/// Returns all IP addresses that are NOT part of [RFC
/// 6890] (regardless of whether or not there is a default route, unlike
/// [`private_addrs`](super::private_addrs)).
///
/// Public and private are the crate's RFC 6890 special-purpose classifications,
/// not a reachability or remote-path-MTU test. Returned [`IfNet`] values retain
/// their local interface index through [`IfNet::index`].
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
  cfg_if::cfg_if! {
    if #[cfg(windows)] {
      os::interface_addresses(None, public_ip_filter)
    } else {
      os::interface_addresses(0, public_ip_filter)
    }
  }
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
  cfg_if::cfg_if! {
    if #[cfg(windows)] {
      os::interface_ipv4_addresses(None, |ip| {
        public_ip_filter(ip) && ipv4_filter_to_ip_filter(&mut f)(ip)
      })
    } else {
      os::interface_ipv4_addresses(0, |ip| {
        public_ip_filter(ip) && ipv4_filter_to_ip_filter(&mut f)(ip)
      })
    }
  }
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
  cfg_if::cfg_if! {
    if #[cfg(windows)] {
      os::interface_ipv6_addresses(None, |ip| {
        public_ip_filter(ip) && ipv6_filter_to_ip_filter(&mut f)(ip)
      })
    } else {
      os::interface_ipv6_addresses(0, |ip| {
        public_ip_filter(ip) && ipv6_filter_to_ip_filter(&mut f)(ip)
      })
    }
  }
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
  cfg_if::cfg_if! {
    if #[cfg(windows)] {
      os::interface_addresses(None, |ip| public_ip_filter(ip) && f(ip))
    } else {
      os::interface_addresses(0, |ip| public_ip_filter(ip) && f(ip))
    }
  }
}

#[inline]
fn public_ip_filter(ip: &IpAddr) -> bool {
  !RFC6890.contains(ip)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn public_filter_preserves_rfc6890_classification() {
    for (addr, expected) in [
      ("2001:4860:4860::8888", true),
      ("192.0.2.1", false),
      ("2001:db8::1", false),
      ("10.0.0.1", false),
      ("100.64.0.1", false),
      ("fd00::1", false),
      ("127.0.0.1", false),
      ("::1", false),
      ("169.254.1.1", false),
      ("fe80::1", false),
      // Blocks the IANA registry added after RFC 6890.
      ("192.31.196.1", false),    // AS112-v4
      ("192.52.193.1", false),    // AMT
      ("192.175.48.1", false),    // Direct Delegation AS112 Service
      ("64:ff9b:1::1", false),    // IPv4-IPv6 translation, local use
      ("100:0:0:1::1", false),    // Dummy IPv6 Prefix
      ("2620:4f:8000::1", false), // Direct Delegation AS112 Service
      ("3fff::1", false),         // Documentation
      ("5f00::1", false),         // Segment Routing (SRv6) SIDs
    ] {
      let ip = addr.parse::<IpAddr>().unwrap();
      assert_eq!(
        public_ip_filter(&ip),
        expected,
        "unexpected public classification for {addr}"
      );
    }
  }
}
