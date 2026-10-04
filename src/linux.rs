use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

// Only the /proc/net/igmp* parsers use xtoi2, and those are not compiled on
// Android (see the parser stubs below).
#[cfg(not(target_os = "android"))]
use hardware_address::xtoi2;
use ipnet::{Ipv4Net, Ipv6Net};
use rustix::net::AddressFamily;
use smallvec_wrapper::{SmallVec, TinyVec};
use smol_str::SmolStr;

use super::{
  IfAddr, IfNet, Ifv4Addr, Ifv4Net, Ifv6Addr, Ifv6Net, Interface, IpRoute, Ipv4Route, Ipv6Route,
  MacAddr, Net, MAC_ADDRESS_SIZE,
};

pub(super) use local_addr::*;

#[path = "linux/netlink.rs"]
mod netlink;

#[cfg(fuzzing)]
pub(crate) use netlink::fuzz_netlink_dump;

#[path = "linux/local_addr.rs"]
mod local_addr;

#[cfg(target_os = "android")]
#[path = "linux/android.rs"]
mod android;

use netlink::{
  netlink_addr, netlink_interface, netlink_routes_into, FilterMode, FILTER_DEFER_LIMIT,
};

macro_rules! rt_generic_mod {
  ($($name:ident($rta:expr, $rtn:expr)), +$(,)?) => {
    $(
      paste::paste! {
        pub(super) use [< rt_ $name >]::*;

        mod [< rt_ $name >] {
          use rustix::net::AddressFamily;
          use smallvec_wrapper::SmallVec;
          use std::{
            io,
            net::{IpAddr, Ipv4Addr, Ipv6Addr},
          };

          use crate::{ipv4_filter_to_ip_filter, ipv6_filter_to_ip_filter};

          use super::{
            super::{IfAddr, Ifv4Addr, Ifv6Addr},
            netlink::{rt_generic_addrs, FilterMode, FILTER_DEFER_LIMIT},
          };

          pub(crate) fn [< $name _addrs >]() -> io::Result<SmallVec<IfAddr>> {
            rt_generic_addrs(AddressFamily::UNSPEC, $rta, $rtn, |_| true, FilterMode::Pure)
          }

          pub(crate) fn [< $name _ipv4_addrs >]() -> io::Result<SmallVec<Ifv4Addr>> {
            rt_generic_addrs(AddressFamily::INET, $rta, $rtn, |_| true, FilterMode::Pure)
          }

          pub(crate) fn [< $name _ipv6_addrs >]() -> io::Result<SmallVec<Ifv6Addr>> {
            rt_generic_addrs(AddressFamily::INET6, $rta, $rtn, |_| true, FilterMode::Pure)
          }

          pub(crate) fn [< $name _addrs_by_filter >]<F>(f: F) -> io::Result<SmallVec<IfAddr>>
          where
            F: FnMut(&IpAddr) -> bool,
          {
            rt_generic_addrs(
              AddressFamily::UNSPEC,
              $rta,
              $rtn,
              f,
              FilterMode::Deferred(FILTER_DEFER_LIMIT),
            )
          }

          pub(crate) fn [< $name _ipv4_addrs_by_filter >]<F>(f: F) -> io::Result<SmallVec<Ifv4Addr>>
          where
            F: FnMut(&Ipv4Addr) -> bool,
          {
            rt_generic_addrs(
              AddressFamily::INET,
              $rta,
              $rtn,
              ipv4_filter_to_ip_filter(f),
              FilterMode::Deferred(FILTER_DEFER_LIMIT),
            )
          }

          pub(crate) fn [< $name _ipv6_addrs_by_filter >]<F>(f: F) -> io::Result<SmallVec<Ifv6Addr>>
          where
            F: FnMut(&Ipv6Addr) -> bool,
          {
            rt_generic_addrs(
              AddressFamily::INET6,
              $rta,
              $rtn,
              ipv6_filter_to_ip_filter(f),
              FilterMode::Deferred(FILTER_DEFER_LIMIT),
            )
          }
        }
      }
    )*
  };
}

rt_generic_mod!(gateway(
  linux_raw_sys::netlink::rtattr_type_t::RTA_GATEWAY as u16,
  None
),);

#[inline]
fn route_v4_from_raw(
  oif: u32,
  dst_len: u8,
  dst: Option<IpAddr>,
  gw: Option<IpAddr>,
) -> Option<Ipv4Route> {
  if dst_len > 32 {
    return None;
  }
  // Treat absent `dst` as the default route only when `dst_len == 0`.
  // The walker rejects "dst absent + dst_len != 0" as malformed; this
  // is a defence-in-depth check for any future caller that doesn't
  // pre-validate.
  let dst_ip = match dst {
    Some(IpAddr::V4(ip)) => ip,
    Some(_) => return None,
    None if dst_len == 0 => Ipv4Addr::UNSPECIFIED,
    None => return None,
  };
  let net = Ipv4Net::new(dst_ip, dst_len).ok()?;
  let gw = match gw {
    Some(IpAddr::V4(ip)) => Some(ip),
    Some(_) => return None,
    None => None,
  };
  Some(Ipv4Route::new(oif, net, gw))
}

#[inline]
fn route_v6_from_raw(
  oif: u32,
  dst_len: u8,
  dst: Option<IpAddr>,
  gw: Option<IpAddr>,
) -> Option<Ipv6Route> {
  if dst_len > 128 {
    return None;
  }
  let dst_ip = match dst {
    Some(IpAddr::V6(ip)) => ip,
    Some(_) => return None,
    None if dst_len == 0 => Ipv6Addr::UNSPECIFIED,
    None => return None,
  };
  let net = Ipv6Net::new(dst_ip, dst_len).ok()?;
  let gw = match gw {
    Some(IpAddr::V6(ip)) => Some(ip),
    Some(_) => return None,
    None => None,
  };
  Some(Ipv6Route::new(oif, net, gw))
}

/// Converts a route of the `AF_INET` dump, skipping any other family.
fn ipv4_route(
  family: u8,
  oif: u32,
  dst_len: u8,
  dst: Option<IpAddr>,
  gw: Option<IpAddr>,
) -> Option<Ipv4Route> {
  if family as u16 != AddressFamily::INET.as_raw() {
    return None;
  }
  route_v4_from_raw(oif, dst_len, dst, gw)
}

/// Converts a route of the `AF_INET6` dump, skipping any other family.
fn ipv6_route(
  family: u8,
  oif: u32,
  dst_len: u8,
  dst: Option<IpAddr>,
  gw: Option<IpAddr>,
) -> Option<Ipv6Route> {
  if family as u16 != AddressFamily::INET6.as_raw() {
    return None;
  }
  route_v6_from_raw(oif, dst_len, dst, gw)
}

pub(super) fn route_table() -> io::Result<SmallVec<IpRoute>> {
  route_table_with_mode(|_| true, FilterMode::Pure)
}

pub(super) fn route_table_by_filter<F>(f: F) -> io::Result<SmallVec<IpRoute>>
where
  F: FnMut(&IpRoute) -> bool,
{
  route_table_with_mode(f, FilterMode::Deferred(FILTER_DEFER_LIMIT))
}

pub(super) fn route_ipv4_table() -> io::Result<SmallVec<Ipv4Route>> {
  route_ipv4_table_with_mode(|_| true, FilterMode::Pure)
}

pub(super) fn route_ipv4_table_by_filter<F>(f: F) -> io::Result<SmallVec<Ipv4Route>>
where
  F: FnMut(&Ipv4Route) -> bool,
{
  route_ipv4_table_with_mode(f, FilterMode::Deferred(FILTER_DEFER_LIMIT))
}

pub(super) fn route_ipv6_table() -> io::Result<SmallVec<Ipv6Route>> {
  route_ipv6_table_with_mode(|_| true, FilterMode::Pure)
}

pub(super) fn route_ipv6_table_by_filter<F>(f: F) -> io::Result<SmallVec<Ipv6Route>>
where
  F: FnMut(&Ipv6Route) -> bool,
{
  route_ipv6_table_with_mode(f, FilterMode::Deferred(FILTER_DEFER_LIMIT))
}

fn route_table_with_mode<F>(mut f: F, mode: FilterMode) -> io::Result<SmallVec<IpRoute>>
where
  F: FnMut(&IpRoute) -> bool,
{
  // Walk `AF_INET` and `AF_INET6` separately rather than relying on
  // `AF_UNSPEC` to deliver both. Linux's `RTM_GETROUTE` with
  // `rtm_family = AF_UNSPEC` is documented as a "give me all
  // families" request, but in practice some kernel versions /
  // configurations can return only IPv4 — pyroute2 and similar
  // bindings document the same workaround
  // (https://pyroute2.org/docs/iproute_linux.html). On a dual-stack
  // host the union API would silently drop every IPv6 route while
  // `route_ipv6_table()` still surfaced them; the BSD path already
  // walks per-family for the same reason. Two dumps is the right
  // tradeoff for a consistent answer. Each dump retries on its own.
  let mut out: SmallVec<IpRoute> = SmallVec::new();
  netlink_routes_into(
    AddressFamily::INET,
    |family, oif, dst_len, dst, gw| ipv4_route(family, oif, dst_len, dst, gw).map(IpRoute::V4),
    &mut f,
    mode,
    &mut out,
  )?;
  netlink_routes_into(
    AddressFamily::INET6,
    |family, oif, dst_len, dst, gw| ipv6_route(family, oif, dst_len, dst, gw).map(IpRoute::V6),
    &mut f,
    mode,
    &mut out,
  )?;
  Ok(out)
}

fn route_ipv4_table_with_mode<F>(f: F, mode: FilterMode) -> io::Result<SmallVec<Ipv4Route>>
where
  F: FnMut(&Ipv4Route) -> bool,
{
  let mut out: SmallVec<Ipv4Route> = SmallVec::new();
  netlink_routes_into(AddressFamily::INET, ipv4_route, f, mode, &mut out)?;
  Ok(out)
}

fn route_ipv6_table_with_mode<F>(f: F, mode: FilterMode) -> io::Result<SmallVec<Ipv6Route>>
where
  F: FnMut(&Ipv6Route) -> bool,
{
  let mut out: SmallVec<Ipv6Route> = SmallVec::new();
  netlink_routes_into(AddressFamily::INET6, ipv6_route, f, mode, &mut out)?;
  Ok(out)
}

impl Interface {
  #[inline]
  fn new(index: u32, flags: Flags) -> Self {
    Self {
      index,
      mtu: 0,
      name: SmolStr::default(),
      mac_addr: None,
      flags,
    }
  }
}

bitflags::bitflags! {
  /// Flags represents the interface flags.
  #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
  pub struct Flags: u32 {
    /// Interface is administratively up
    const UP = 0x1;
    /// Interface supports broadcast access capability
    const BROADCAST = 0x2;
    /// Turn on debugging
    const DEBUG = 0x4;
    /// Interface is a loopback net
    const LOOPBACK = 0x8;
    /// Interface is point-to-point link
    const POINTOPOINT = 0x10;
    /// Obsolete: avoid use of trailers
    const NOTRAILERS = 0x20;
    /// Resources allocated
    const RUNNING = 0x40;
    /// No address resolution protocol
    const NOARP = 0x80;
    /// Receive all packets
    const PROMISC = 0x100;
    /// Receive all multicast packets
    const ALLMULTI = 0x200;
    /// Transmission is in progress
    const MASTER = 0x400;
    /// Can't hear own transmissions
    const SLAVE = 0x800;
    /// Supports multicast access capability
    const MULTICAST = 0x1000;
    /// Per link layer defined bit
    const PORTSEL = 0x2000;
    /// Per link layer defined bit
    const AUTOMEDIA = 0x4000;
    /// Dialup device with changing addresses
    const DYNAMIC = 0x8000;
  }
}

#[cfg(not(target_os = "android"))]
pub(super) fn interface_table(index: u32) -> io::Result<TinyVec<Interface>> {
  netlink_interface(AddressFamily::UNSPEC, index)
}

#[cfg(target_os = "android")]
pub(super) fn interface_table(index: u32) -> io::Result<TinyVec<Interface>> {
  // Android 11+ untrusted_app is denied RTM_GETLINK (it needs the SELinux
  // `nlmsg_readpriv` permission, neverallowed for apps targeting API >= 30),
  // so the netlink interface dump fails with PermissionDenied even though
  // the socket is never bound explicitly. Fall back to the RTM_GETADDR +
  // SIOCGIF* ioctl path (see linux/android.rs) — the same combination
  // bionic's getifaddrs and Go's net package use. Older Android / app
  // domains that still permit RTM_GETLINK keep the richer netlink result
  // (including the MAC address).
  match netlink_interface(AddressFamily::UNSPEC, index) {
    Err(e) if e.kind() == io::ErrorKind::PermissionDenied => android::interface_table(index),
    other => other,
  }
}

// Cross-platform code calls these with arbitrary filters, so they defer them.

pub(super) fn interface_ipv4_addresses<F>(index: u32, f: F) -> io::Result<SmallVec<Ifv4Net>>
where
  F: FnMut(&IpAddr) -> bool,
{
  netlink_addr(
    AddressFamily::INET,
    index,
    f,
    FilterMode::Deferred(FILTER_DEFER_LIMIT),
  )
}

pub(super) fn interface_ipv6_addresses<F>(index: u32, f: F) -> io::Result<SmallVec<Ifv6Net>>
where
  F: FnMut(&IpAddr) -> bool,
{
  netlink_addr(
    AddressFamily::INET6,
    index,
    f,
    FilterMode::Deferred(FILTER_DEFER_LIMIT),
  )
}

pub(super) fn interface_addresses<F>(index: u32, f: F) -> io::Result<SmallVec<IfNet>>
where
  F: FnMut(&IpAddr) -> bool,
{
  netlink_addr(
    AddressFamily::UNSPEC,
    index,
    f,
    FilterMode::Deferred(FILTER_DEFER_LIMIT),
  )
}

const IGMP_PATH: &str = "/proc/net/igmp";
const IGMP6_PATH: &str = "/proc/net/igmp6";

pub(super) fn interface_multicast_ipv4_addresses<F>(
  ifi: u32,
  f: F,
) -> io::Result<SmallVec<Ifv4Addr>>
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  parse_proc_net_igmp(IGMP_PATH, ifi, f)
}

pub(super) fn interface_multicast_ipv6_addresses<F>(
  ifi: u32,
  f: F,
) -> io::Result<SmallVec<Ifv6Addr>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  parse_proc_net_igmp6(IGMP6_PATH, ifi, f)
}

pub(super) fn interface_multicast_addresses<F>(ifi: u32, mut f: F) -> io::Result<SmallVec<IfAddr>>
where
  F: FnMut(&IpAddr) -> bool,
{
  let ifmat4 = parse_proc_net_igmp("/proc/net/igmp", ifi, |addr| f(&(*addr).into()))?;
  let ifmat6 = parse_proc_net_igmp6("/proc/net/igmp6", ifi, |addr| f(&(*addr).into()))?;

  Ok(
    ifmat4
      .into_iter()
      .map(From::from)
      .chain(ifmat6.into_iter().map(From::from))
      .collect(),
  )
}

// Android 10+ denies apps access to /proc/net, so the parsers that read
// /proc/net/igmp* are not compiled there. The Android stubs return
// `Unsupported` (matching the DragonFly multicast stub in bsd_like.rs): the
// public `interface_multicast_*` surface still exists for cross-platform
// callers, but a real call reports the limitation instead of a misleading
// empty result or a raw permission error.
#[cfg(target_os = "android")]
fn parse_proc_net_igmp<F>(_path: &str, _ifi: u32, _f: F) -> std::io::Result<SmallVec<Ifv4Addr>>
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  Err(io::Error::new(
    io::ErrorKind::Unsupported,
    "multicast group enumeration is unavailable on Android (/proc/net is restricted for apps)",
  ))
}

#[cfg(not(target_os = "android"))]
fn parse_proc_net_igmp<F>(path: &str, ifi: u32, mut f: F) -> std::io::Result<SmallVec<Ifv4Addr>>
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  use std::io::BufRead;

  let file = std::fs::File::open(path)?;
  let reader = std::io::BufReader::new(file);
  let mut ifmat = SmallVec::new();
  let mut idx = 0;
  let mut lines = reader.lines();

  // The first line is the column header.
  lines.next();

  for line in lines {
    let line = line?;

    // Both line kinds have at least four whitespace-separated tokens and only
    // the first is read, so the tokens are iterated instead of collected. That
    // token never contains a colon, so whitespace alone delimits it.
    let mut it = line.split_ascii_whitespace();
    let field0 = match it.next() {
      Some(s) => s,
      None => continue,
    };
    if it.nth(2).is_none() {
      // Fewer than 4 tokens on this line.
      continue;
    }

    // Interface lines start in column 0; the group lines below are indented.
    if !line.starts_with(' ') && !line.starts_with('\t') {
      match field0.parse() {
        Ok(res) => idx = res,
        Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
      }
    } else if field0.len() == 8 && (ifi == 0 || ifi == idx) {
      let ip = igmp_group(field0);
      if f(&ip) {
        ifmat.push(Ifv4Addr::new(idx, ip));
      }
    }
  }

  Ok(ifmat)
}

/// Parses a `/proc/net/igmp` group: the kernel prints the `__be32` with `%08X`,
/// so 224.0.0.251 is `FB0000E0` on little-endian and `E00000FB` on big-endian.
#[cfg(not(target_os = "android"))]
fn igmp_group(field: &str) -> Ipv4Addr {
  let mut printed = [0u8; 4];
  for (byte, pair) in printed.iter_mut().zip(field.as_bytes().chunks_exact(2)) {
    *byte = xtoi2(pair, 0).unwrap_or(0);
  }

  Ipv4Addr::from(u32::from_be_bytes(printed).to_ne_bytes())
}

#[cfg(target_os = "android")]
fn parse_proc_net_igmp6<F>(_path: &str, _ifi: u32, _f: F) -> io::Result<SmallVec<Ifv6Addr>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  Err(io::Error::new(
    io::ErrorKind::Unsupported,
    "multicast group enumeration is unavailable on Android (/proc/net is restricted for apps)",
  ))
}

#[cfg(not(target_os = "android"))]
fn parse_proc_net_igmp6<F>(path: &str, ifi: u32, mut f: F) -> io::Result<SmallVec<Ifv6Addr>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  use std::io::BufRead;

  let file = std::fs::File::open(path)?;
  let reader = std::io::BufReader::new(file);
  let mut ifmat = SmallVec::new();

  for line in reader.lines() {
    let line = line?;

    // A record has six tokens: the interface index and name, the group
    // address, and the user count, flags and timer. Only the index and the
    // address are read, so the tokens are iterated instead of collected.
    let mut it = line.split_ascii_whitespace();
    let field0 = match it.next() {
      Some(s) => s,
      None => continue,
    };
    // The interface name is not read.
    if it.next().is_none() {
      continue;
    }
    let field2 = match it.next() {
      Some(s) => s,
      None => continue,
    };
    // The user count, flags and timer must be present but are not read.
    if it.nth(2).is_none() {
      continue;
    }

    let idx = match field0.parse() {
      Ok(res) => res,
      Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
    };

    if ifi == 0 || ifi == idx {
      // The kernel prints the address with `%pi6`: its 16 bytes in network
      // order as hex digits, so unlike the IPv4 field it needs no byte swap.
      let mut i = 0;
      let src = field2.as_bytes();
      let mut data = [0u8; 16];
      while i + 1 < src.len() {
        data[i / 2] = xtoi2(&src[i..i + 2], 0).unwrap_or(0);
        i += 2;
      }

      let ip = data.into();
      if f(&ip) {
        ifmat.push(Ifv6Addr::new(idx, ip));
      }
    }
  }

  Ok(ifmat)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn flags_retain_unknown_bits() {
    let unknown = 1 << 31;
    assert_eq!(Flags::from_bits_retain(unknown).bits(), unknown);
  }

  // `route_v4_from_raw` and `route_v6_from_raw` sit between the netlink
  // walker and `IpRoute`, so a regression silently affects every
  // `route_*_table*()` caller. A live dump exercises only the success arm;
  // these tests cover every branch of the family, length and gateway
  // validation matrix.

  #[test]
  fn route_v4_from_raw_rejects_oversize_prefix() {
    assert!(route_v4_from_raw(1, 33, Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), None).is_none());
  }

  #[test]
  fn route_v4_from_raw_rejects_wrong_family_dst() {
    assert!(route_v4_from_raw(1, 0, Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)), None).is_none());
  }

  #[test]
  fn route_v4_from_raw_treats_absent_dst_as_default() {
    let r = route_v4_from_raw(1, 0, None, None).unwrap();
    assert_eq!(r.destination().addr(), Ipv4Addr::UNSPECIFIED);
  }

  #[test]
  fn route_v4_from_raw_rejects_absent_dst_with_nonzero_prefix() {
    assert!(route_v4_from_raw(1, 8, None, None).is_none());
  }

  #[test]
  fn route_v4_from_raw_rejects_wrong_family_gateway() {
    let dst = Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let gw_v6 = Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    assert!(route_v4_from_raw(1, 0, dst, gw_v6).is_none());
  }

  #[test]
  fn route_v4_from_raw_accepts_absent_gateway() {
    let dst = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
    let r = route_v4_from_raw(1, 8, dst, None).unwrap();
    assert!(r.gateway().is_none());
  }

  #[test]
  fn route_v6_from_raw_rejects_oversize_prefix() {
    assert!(route_v6_from_raw(1, 129, Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)), None).is_none());
  }

  #[test]
  fn route_v6_from_raw_rejects_wrong_family_dst() {
    assert!(route_v6_from_raw(1, 0, Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), None).is_none());
  }

  #[test]
  fn route_v6_from_raw_treats_absent_dst_as_default() {
    let r = route_v6_from_raw(1, 0, None, None).unwrap();
    assert_eq!(r.destination().addr(), Ipv6Addr::UNSPECIFIED);
  }

  #[test]
  fn route_v6_from_raw_rejects_absent_dst_with_nonzero_prefix() {
    assert!(route_v6_from_raw(1, 64, None, None).is_none());
  }

  #[test]
  fn route_v6_from_raw_rejects_wrong_family_gateway() {
    let dst = Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    let gw_v4 = Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    assert!(route_v6_from_raw(1, 0, dst, gw_v4).is_none());
  }

  #[test]
  fn route_v6_from_raw_accepts_absent_gateway() {
    let dst = Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)));
    let r = route_v6_from_raw(1, 32, dst, None).unwrap();
    assert!(r.gateway().is_none());
  }

  #[cfg(not(target_os = "android"))]
  mod igmp {
    use super::*;

    const GROUPS: [Ipv4Addr; 3] = [
      Ipv4Addr::new(224, 0, 0, 1),
      Ipv4Addr::new(224, 0, 0, 251),
      Ipv4Addr::new(239, 255, 255, 250),
    ];

    // The field that a kernel with this target's byte order prints for `addr`.
    fn host_endian_field(addr: Ipv4Addr) -> String {
      format!("{:08X}", u32::from_ne_bytes(addr.octets()))
    }

    #[test]
    fn group_decodes_the_field_the_kernel_prints() {
      for addr in GROUPS {
        assert_eq!(igmp_group(&host_endian_field(addr)), addr);
      }
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn group_decodes_a_little_endian_field() {
      assert_eq!(igmp_group("FB0000E0"), Ipv4Addr::new(224, 0, 0, 251));
    }

    #[cfg(target_endian = "big")]
    #[test]
    fn group_decodes_a_big_endian_field() {
      assert_eq!(igmp_group("E00000FB"), Ipv4Addr::new(224, 0, 0, 251));
    }

    #[test]
    fn group_decodes_each_malformed_byte_as_zero() {
      assert_eq!(igmp_group("ZZZZZZZZ"), Ipv4Addr::UNSPECIFIED);
      // The outer bytes match, so byte order does not change the result.
      assert_eq!(igmp_group("FF00ZZFF"), Ipv4Addr::new(255, 0, 0, 255));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn parse_proc_net_igmp_reads_host_endian_groups() {
      use std::io::Write;

      let group_line = |addr| format!("\t\t\t\t{} 1 0:00000000\t\t0\n", host_endian_field(addr));
      let listing = [
        "Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n",
        "1\tlo        :     1      V3\n",
        &group_line(GROUPS[0]),
        "2\teth0      :     2      V3\n",
        &group_line(GROUPS[1]),
        &group_line(GROUPS[2]),
      ]
      .concat();

      let path = std::env::temp_dir().join(format!("getifs-igmp-{}.txt", std::process::id()));
      let mut file = std::fs::File::create_new(&path).unwrap();
      scopeguard::defer! {
        let _ = std::fs::remove_file(&path);
      }
      file.write_all(listing.as_bytes()).unwrap();

      let groups = |ifi| {
        parse_proc_net_igmp(path.to_str().unwrap(), ifi, |_| true)
          .unwrap()
          .iter()
          .map(|group| (group.index(), group.addr()))
          .collect::<Vec<_>>()
      };
      assert_eq!(groups(0), [(1, GROUPS[0]), (2, GROUPS[1]), (2, GROUPS[2])]);
      assert_eq!(groups(2), [(2, GROUPS[1]), (2, GROUPS[2])]);
    }
  }
}
