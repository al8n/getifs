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
      pub struct [<Ip $kind Route>] {
        index: u32,
        destination: [<Ip $kind Net>],
        gateway: Option<[<Ip $kind Addr>]>,
      }

      impl core::fmt::Display for [<Ip $kind Route>] {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
          match self.gateway {
            Some(gw) => write!(f, "{} via {} ({})", self.destination, gw, self.index),
            None => write!(f, "{} ({})", self.destination, self.index),
          }
        }
      }

      impl [<Ip $kind Route>] {
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

impl From<Ipv4Route> for IpRoute {
  #[inline]
  fn from(value: Ipv4Route) -> Self {
    Self::V4(value)
  }
}

impl From<Ipv6Route> for IpRoute {
  #[inline]
  fn from(value: Ipv6Route) -> Self {
    Self::V6(value)
  }
}

/// An entry from the kernel routing table.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum IpRoute {
  /// An IPv4 route.
  V4(Ipv4Route),
  /// An IPv6 route.
  V6(Ipv6Route),
}

impl core::fmt::Display for IpRoute {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::V4(r) => write!(f, "{r}"),
      Self::V6(r) => write!(f, "{r}"),
    }
  }
}

impl IpRoute {
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

/// Returns the **unicast and local** entries from the kernel routing
/// table (both IPv4 and IPv6). Other route classes are intentionally
/// excluded — the [`IpRoute`] type only models a single (`destination`,
/// `gateway`, `index`) tuple, so route kinds without a usable
/// next-hop interface are filtered out at the platform layer:
///
/// - **Linux**: only `RTN_UNICAST` and `RTN_LOCAL` rows from the
///   `RT_TABLE_MAIN` and `RT_TABLE_LOCAL` tables are emitted. Routes
///   from custom policy tables (selected via `ip rule` with fwmark,
///   iif, uid, etc.), TOS-specific rows (`rtm_tos != 0`), source-
///   constrained rows (`rtm_src_len != 0` or `RTA_SRC` set), and
///   blackhole / unreachable / prohibit / broadcast / multicast / nat
///   types are dropped — they can't be represented faithfully as a
///   single (oif, gw) tuple, and surfacing them would mislead callers
///   into using a route the kernel would not consult for ordinary
///   traffic. ECMP routes (`RTA_MULTIPATH`) are decoded into one
///   [`IpRoute`] per nexthop. Routes that reference a separate nexthop
///   object via `RTA_NH_ID` (the `ip nexthop`-managed indirection
///   added in Linux 5.3) are resolved against an up-front
///   `RTM_GETNEXTHOP` dump: leaves emit one route, groups fan out to
///   one route per member (group-of-groups is rare and skipped).
///   Blackhole nexthops are filtered.
/// - **BSD-like / macOS**: only routes with `RTF_UP` and a usable
///   destination are emitted; AF_LINK gateways surface as
///   `gateway = None`.
/// - **Windows**: only families whose `GetIpForwardTable2` call
///   succeeds are included; an `ERROR_NOT_FOUND` for one family is
///   treated as an empty table for that family rather than a failure.
///
/// ## Platform notes
///
/// `parse_addrs` decodes both the full `sockaddr_in[6]` form and the
/// BSD compact form (`sa_family = AF_INET[6]` but `sa_len <
/// size_of::<sockaddr_in[6]>()`) that NetBSD and OpenBSD emit for
/// netmasks. AF_LINK gateways (no IP equivalent) decode to
/// `gateway = None`. A `parse_addrs` error is treated as a malformed
/// message and surfaced to the caller rather than being swallowed.
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
pub fn route_table() -> io::Result<SmallVec<IpRoute>> {
  os::route_table_by_filter(|_| true)
}

/// Returns the IPv4 unicast/local entries from the kernel routing
/// table. See [`route_table`] for the exact set of route kinds
/// included and the platform notes.
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
pub fn route_ipv4_table() -> io::Result<SmallVec<Ipv4Route>> {
  os::route_ipv4_table_by_filter(|_| true)
}

/// Returns the IPv6 unicast/local entries from the kernel routing
/// table. See [`route_table`] for the exact set of route kinds
/// included and the platform notes.
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
pub fn route_ipv6_table() -> io::Result<SmallVec<Ipv6Route>> {
  os::route_ipv6_table_by_filter(|_| true)
}

/// Returns routing-table entries that match the given filter. Only
/// the unicast/local route classes (see [`route_table`]) are visible
/// to the filter; non-unicast kinds are excluded at the platform
/// layer before `f` runs.
///
/// ## Example
///
/// ```rust
/// use getifs::{route_table_by_filter, IpRoute};
///
/// // Only default routes
/// let defaults = route_table_by_filter(|r| r.is_default()).unwrap();
/// for route in defaults {
///   println!("{route}");
/// }
/// ```
pub fn route_table_by_filter<F>(f: F) -> io::Result<SmallVec<IpRoute>>
where
  F: FnMut(&IpRoute) -> bool,
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
pub fn route_ipv4_table_by_filter<F>(f: F) -> io::Result<SmallVec<Ipv4Route>>
where
  F: FnMut(&Ipv4Route) -> bool,
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
pub fn route_ipv6_table_by_filter<F>(f: F) -> io::Result<SmallVec<Ipv6Route>>
where
  F: FnMut(&Ipv6Route) -> bool,
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
    let r = Ipv4Route::new(2, dst, gw);
    assert_eq!(r.index(), 2);
    assert_eq!(r.destination(), &dst);
    assert_eq!(r.gateway(), gw);
    assert!(!r.is_default());
    assert!(r.name().is_ok());

    let default = Ipv4Route::new(0, Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap(), None);
    assert!(default.is_default());
    assert!(default.gateway().is_none());
  }

  #[test]
  fn route_v6_basic() {
    let dst = Ipv6Net::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32).unwrap();
    let gw = Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    let r = Ipv6Route::new(3, dst, gw);
    assert_eq!(r.index(), 3);
    assert_eq!(r.destination(), &dst);
    assert_eq!(r.gateway(), gw);
    assert!(!r.is_default());
  }

  #[test]
  fn route_enum_dispatch() {
    let v4 = Ipv4Route::new(
      1,
      Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap(),
      None,
    );
    let r: IpRoute = v4.into();
    assert_eq!(r.index(), 1);
    assert!(r.gateway().is_none());
    assert!(matches!(r.destination(), IpNet::V4(_)));
    assert!(!r.is_default());

    let v6 = Ipv6Route::new(
      1,
      Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).unwrap(),
      Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
    );
    let r: IpRoute = v6.into();
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
