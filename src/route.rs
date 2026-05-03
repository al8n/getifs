use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use smallvec_wrapper::SmallVec;
use smol_str::SmolStr;

use super::os;

macro_rules! routev_impl {
  ($kind:literal) => {
    paste::paste! {
      #[doc = "An IP" $kind " entry from the kernel routing table."]
      #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
      pub struct [<Route $kind>] {
        index: u32,
        destination: [<Ip $kind Net>],
        gateway: Option<[<Ip $kind Addr>]>,
      }

      impl core::fmt::Display for [<Route $kind>] {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
          match self.gateway {
            Some(gw) => write!(f, "{} via {} ({})", self.destination, gw, self.index),
            None => write!(f, "{} ({})", self.destination, self.index),
          }
        }
      }

      impl [<Route $kind>] {
        #[doc = "Creates a new IP" $kind " route entry."]
        #[inline]
        pub const fn new(
          index: u32,
          destination: [<Ip $kind Net>],
          gateway: Option<[<Ip $kind Addr>]>,
        ) -> Self {
          Self { index, destination, gateway }
        }

        /// Returns the output interface index for this route.
        #[inline]
        pub const fn index(&self) -> u32 {
          self.index
        }

        /// Returns the output interface name.
        ///
        /// This method invokes `if_indextoname` internally.
        pub fn name(&self) -> io::Result<SmolStr> {
          crate::idx_to_name::ifindex_to_name(self.index)
        }

        /// Returns the destination network of this route.
        ///
        /// A default route has prefix length `0` (`0.0.0.0/0` or `::/0`).
        #[inline]
        pub const fn destination(&self) -> &[<Ip $kind Net>] {
          &self.destination
        }

        /// Returns the next-hop gateway, or `None` for a directly-connected
        /// (link-scope) route.
        #[inline]
        pub const fn gateway(&self) -> Option<[<Ip $kind Addr>]> {
          self.gateway
        }

        /// Returns `true` if this is a default route.
        #[inline]
        pub const fn is_default(&self) -> bool {
          self.destination.prefix_len() == 0
        }
      }
    }
  };
}

routev_impl!("v4");
routev_impl!("v6");

impl From<Routev4> for Route {
  #[inline]
  fn from(value: Routev4) -> Self {
    Self::V4(value)
  }
}

impl From<Routev6> for Route {
  #[inline]
  fn from(value: Routev6) -> Self {
    Self::V6(value)
  }
}

/// An entry from the kernel routing table.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Route {
  /// An IPv4 route.
  V4(Routev4),
  /// An IPv6 route.
  V6(Routev6),
}

impl core::fmt::Display for Route {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::V4(r) => write!(f, "{r}"),
      Self::V6(r) => write!(f, "{r}"),
    }
  }
}

impl Route {
  /// Returns the output interface index.
  #[inline]
  pub const fn index(&self) -> u32 {
    match self {
      Self::V4(r) => r.index(),
      Self::V6(r) => r.index(),
    }
  }

  /// Returns the output interface name.
  ///
  /// This method invokes `if_indextoname` internally.
  pub fn name(&self) -> io::Result<SmolStr> {
    crate::idx_to_name::ifindex_to_name(self.index())
  }

  /// Returns the destination network of this route.
  #[inline]
  pub const fn destination(&self) -> IpNet {
    match self {
      Self::V4(r) => IpNet::V4(*r.destination()),
      Self::V6(r) => IpNet::V6(*r.destination()),
    }
  }

  /// Returns the next-hop gateway, or `None` for a directly-connected route.
  #[inline]
  pub const fn gateway(&self) -> Option<IpAddr> {
    match self {
      Self::V4(r) => match r.gateway() {
        Some(ip) => Some(IpAddr::V4(ip)),
        None => None,
      },
      Self::V6(r) => match r.gateway() {
        Some(ip) => Some(IpAddr::V6(ip)),
        None => None,
      },
    }
  }

  /// Returns `true` if this is a default route.
  #[inline]
  pub const fn is_default(&self) -> bool {
    match self {
      Self::V4(r) => r.is_default(),
      Self::V6(r) => r.is_default(),
    }
  }
}

/// Returns every entry in the kernel routing table (both IPv4 and IPv6).
///
/// ## Platform notes
///
/// **NetBSD and OpenBSD: result may be incomplete.** The kernel emits
/// some sockaddr forms in `NET_RT_DUMP` messages that the shared BSD
/// parser doesn't yet decode (notably AF_LINK gateways and certain
/// kernel-form netmasks). Those routes are silently skipped rather
/// than failing the whole call, and there is no signal in the return
/// value to distinguish "no such route" from "route present but
/// unparseable." Code that needs an authoritative table on NetBSD or
/// OpenBSD should cross-check against the OS routing tool until the
/// per-OS sockaddr decoders land. Linux, macOS, FreeBSD, DragonFlyBSD,
/// and Windows return a complete table.
///
/// ## Example
///
/// ```rust
/// use getifs::route_table;
///
/// for route in route_table().unwrap() {
///   println!("{route}");
/// }
/// ```
pub fn route_table() -> io::Result<SmallVec<Route>> {
  os::route_table_by_filter(|_| true)
}

/// Returns every IPv4 entry in the kernel routing table.
///
/// ## Example
///
/// ```rust
/// use getifs::route_ipv4_table;
///
/// for route in route_ipv4_table().unwrap() {
///   println!("{route}");
/// }
/// ```
pub fn route_ipv4_table() -> io::Result<SmallVec<Routev4>> {
  os::route_ipv4_table_by_filter(|_| true)
}

/// Returns every IPv6 entry in the kernel routing table.
///
/// ## Example
///
/// ```rust
/// use getifs::route_ipv6_table;
///
/// for route in route_ipv6_table().unwrap() {
///   println!("{route}");
/// }
/// ```
pub fn route_ipv6_table() -> io::Result<SmallVec<Routev6>> {
  os::route_ipv6_table_by_filter(|_| true)
}

/// Returns routing-table entries that match the given filter.
///
/// ## Example
///
/// ```rust
/// use getifs::{route_table_by_filter, Route};
///
/// // Only default routes
/// let defaults = route_table_by_filter(|r| r.is_default()).unwrap();
/// for route in defaults {
///   println!("{route}");
/// }
/// ```
pub fn route_table_by_filter<F>(f: F) -> io::Result<SmallVec<Route>>
where
  F: FnMut(&Route) -> bool,
{
  os::route_table_by_filter(f)
}

/// Returns IPv4 routing-table entries that match the given filter.
///
/// ## Example
///
/// ```rust
/// use getifs::route_ipv4_table_by_filter;
///
/// // Only routes with a gateway
/// let with_gw = route_ipv4_table_by_filter(|r| r.gateway().is_some()).unwrap();
/// for route in with_gw {
///   println!("{route}");
/// }
/// ```
pub fn route_ipv4_table_by_filter<F>(f: F) -> io::Result<SmallVec<Routev4>>
where
  F: FnMut(&Routev4) -> bool,
{
  os::route_ipv4_table_by_filter(f)
}

/// Returns IPv6 routing-table entries that match the given filter.
///
/// ## Example
///
/// ```rust
/// use getifs::route_ipv6_table_by_filter;
///
/// let v6 = route_ipv6_table_by_filter(|_| true).unwrap();
/// for route in v6 {
///   println!("{route}");
/// }
/// ```
pub fn route_ipv6_table_by_filter<F>(f: F) -> io::Result<SmallVec<Routev6>>
where
  F: FnMut(&Routev6) -> bool,
{
  os::route_ipv6_table_by_filter(f)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn route_v4_basic() {
    let dst = Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap();
    let gw = Some(Ipv4Addr::new(10, 0, 0, 1));
    let r = Routev4::new(2, dst, gw);
    assert_eq!(r.index(), 2);
    assert_eq!(r.destination(), &dst);
    assert_eq!(r.gateway(), gw);
    assert!(!r.is_default());
    assert!(r.name().is_ok());

    let default = Routev4::new(0, Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap(), None);
    assert!(default.is_default());
    assert!(default.gateway().is_none());
  }

  #[test]
  fn route_v6_basic() {
    let dst = Ipv6Net::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32).unwrap();
    let gw = Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    let r = Routev6::new(3, dst, gw);
    assert_eq!(r.index(), 3);
    assert_eq!(r.destination(), &dst);
    assert_eq!(r.gateway(), gw);
    assert!(!r.is_default());
  }

  #[test]
  fn route_enum_dispatch() {
    let v4 = Routev4::new(
      1,
      Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap(),
      None,
    );
    let r: Route = v4.into();
    assert_eq!(r.index(), 1);
    assert!(r.gateway().is_none());
    assert!(matches!(r.destination(), IpNet::V4(_)));
    assert!(!r.is_default());

    let v6 = Routev6::new(
      1,
      Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).unwrap(),
      Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
    );
    let r: Route = v6.into();
    assert!(r.is_default());
    assert!(matches!(r.destination(), IpNet::V6(_)));
    assert_eq!(
      r.gateway(),
      Some(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))),
    );
  }

  #[test]
  fn route_table_returns() {
    let routes = route_table().unwrap();
    for r in &routes {
      // exercise the accessors so this test catches accidental panics
      // (e.g. from invalid prefix lengths) coming back from the kernel.
      let _ = r.index();
      let _ = r.destination();
      let _ = r.gateway();
      let _ = r.is_default();
      let _ = format!("{r}");
    }
  }

  #[test]
  fn route_table_filter_default_only() {
    let defaults = route_table_by_filter(|r| r.is_default()).unwrap();
    for r in &defaults {
      assert!(
        r.is_default(),
        "got non-default route through is_default filter: {r}"
      );
    }
  }

  #[test]
  fn route_v4_table_returns() {
    let routes = route_ipv4_table().unwrap();
    for r in &routes {
      let _ = r.index();
      let _ = r.destination();
      let _ = r.gateway();
    }
  }

  #[test]
  fn route_v6_table_returns() {
    let routes = route_ipv6_table().unwrap();
    for r in &routes {
      let _ = r.index();
      let _ = r.destination();
      let _ = r.gateway();
    }
  }
}
