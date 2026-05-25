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

#[path = "linux/local_addr.rs"]
mod local_addr;

#[cfg(target_os = "android")]
#[path = "linux/android.rs"]
mod android;

use netlink::{netlink_addr, netlink_interface, netlink_walk_routes};

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
            netlink::rt_generic_addrs,
          };

          pub(crate) fn [< $name _addrs >]() -> io::Result<SmallVec<IfAddr>> {
            rt_generic_addrs(AddressFamily::UNSPEC, $rta, $rtn, |_| true)
          }

          pub(crate) fn [< $name _ipv4_addrs >]() -> io::Result<SmallVec<Ifv4Addr>> {
            rt_generic_addrs(AddressFamily::INET, $rta, $rtn, |_| true)
          }

          pub(crate) fn [< $name _ipv6_addrs >]() -> io::Result<SmallVec<Ifv6Addr>> {
            rt_generic_addrs(AddressFamily::INET6, $rta, $rtn, |_| true)
          }

          pub(crate) fn [< $name _addrs_by_filter >]<F>(f: F) -> io::Result<SmallVec<IfAddr>>
          where
            F: FnMut(&IpAddr) -> bool,
          {
            rt_generic_addrs(AddressFamily::UNSPEC, $rta, $rtn, f)
          }

          pub(crate) fn [< $name _ipv4_addrs_by_filter >]<F>(f: F) -> io::Result<SmallVec<Ifv4Addr>>
          where
            F: FnMut(&Ipv4Addr) -> bool,
          {
            rt_generic_addrs(AddressFamily::INET, $rta, $rtn, ipv4_filter_to_ip_filter(f))
          }

          pub(crate) fn [< $name _ipv6_addrs_by_filter >]<F>(f: F) -> io::Result<SmallVec<Ifv6Addr>>
          where
            F: FnMut(&Ipv6Addr) -> bool,
          {
            rt_generic_addrs(AddressFamily::INET6, $rta, $rtn, ipv6_filter_to_ip_filter(f))
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

pub(super) fn route_table_by_filter<F>(mut f: F) -> io::Result<SmallVec<IpRoute>>
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
  // tradeoff for a consistent answer.
  let mut out: SmallVec<IpRoute> = SmallVec::new();
  netlink_walk_routes(AddressFamily::INET, |fam, oif, dst_len, dst, gw| {
    if fam as u16 == AddressFamily::INET.as_raw() {
      if let Some(r) = route_v4_from_raw(oif, dst_len, dst, gw).map(IpRoute::V4) {
        if f(&r) {
          out.push(r);
        }
      }
    }
  })?;
  netlink_walk_routes(AddressFamily::INET6, |fam, oif, dst_len, dst, gw| {
    if fam as u16 == AddressFamily::INET6.as_raw() {
      if let Some(r) = route_v6_from_raw(oif, dst_len, dst, gw).map(IpRoute::V6) {
        if f(&r) {
          out.push(r);
        }
      }
    }
  })?;
  Ok(out)
}

pub(super) fn route_ipv4_table_by_filter<F>(mut f: F) -> io::Result<SmallVec<Ipv4Route>>
where
  F: FnMut(&Ipv4Route) -> bool,
{
  let mut out: SmallVec<Ipv4Route> = SmallVec::new();
  netlink_walk_routes(AddressFamily::INET, |fam, oif, dst_len, dst, gw| {
    if fam as u16 != AddressFamily::INET.as_raw() {
      return;
    }
    if let Some(r) = route_v4_from_raw(oif, dst_len, dst, gw) {
      if f(&r) {
        out.push(r);
      }
    }
  })?;
  Ok(out)
}

pub(super) fn route_ipv6_table_by_filter<F>(mut f: F) -> io::Result<SmallVec<Ipv6Route>>
where
  F: FnMut(&Ipv6Route) -> bool,
{
  let mut out: SmallVec<Ipv6Route> = SmallVec::new();
  netlink_walk_routes(AddressFamily::INET6, |fam, oif, dst_len, dst, gw| {
    if fam as u16 != AddressFamily::INET6.as_raw() {
      return;
    }
    if let Some(r) = route_v6_from_raw(oif, dst_len, dst, gw) {
      if f(&r) {
        out.push(r);
      }
    }
  })?;
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
  #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
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
    /// Per link layer defined bit
    const MULTICAST = 0x1000;
    /// Per link layer defined bit
    const PORTSEL = 0x2000;
    /// Per link layer defined bit
    const AUTOMEDIA = 0x4000;
    /// Supports multicast access capability
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
  // the bind is gone. Fall back to the RTM_GETADDR + SIOCGIF* ioctl path
  // (see linux/android.rs) — the same combination bionic's getifaddrs and
  // Go's net package use. Older Android / app domains that still permit
  // RTM_GETLINK keep the richer netlink result (including the MAC address).
  match netlink_interface(AddressFamily::UNSPEC, index) {
    Err(e) if e.kind() == io::ErrorKind::PermissionDenied => android::interface_table(index),
    other => other,
  }
}

pub(super) fn interface_ipv4_addresses<F>(index: u32, f: F) -> io::Result<SmallVec<Ifv4Net>>
where
  F: FnMut(&IpAddr) -> bool,
{
  netlink_addr(AddressFamily::INET, index, f)
}

pub(super) fn interface_ipv6_addresses<F>(index: u32, f: F) -> io::Result<SmallVec<Ifv6Net>>
where
  F: FnMut(&IpAddr) -> bool,
{
  netlink_addr(AddressFamily::INET6, index, f)
}

pub(super) fn interface_addresses<F>(index: u32, f: F) -> io::Result<SmallVec<IfNet>>
where
  F: FnMut(&IpAddr) -> bool,
{
  netlink_addr(AddressFamily::UNSPEC, index, f)
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
  // Parse IPv4 multicast addrs
  let ifmat4 = parse_proc_net_igmp("/proc/net/igmp", ifi, |addr| f(&(*addr).into()))?;

  // Parse IPv6 multicast addrs
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

  // Skip first line
  lines.next();

  for line in lines {
    let line = line?;

    // Only `fields[0]` is consulted below and we need ≥4 fields total.
    // Walking the whitespace-delimited iterator directly avoids the
    // per-line allocation of the old `split([' ',':','\r','\t','\n'])
    // .filter(...).collect::<MediumVec<_>>()`. Colons are never in
    // `fields[0]` (neither in the leading index nor in an 8-char
    // group-address column), so dropping them from the delimiter set
    // does not affect parsing.
    let mut it = line.split_ascii_whitespace();
    let field0 = match it.next() {
      Some(s) => s,
      None => continue,
    };
    if it.nth(2).is_none() {
      // Fewer than 4 tokens on this line.
      continue;
    }

    if !line.starts_with(' ') && !line.starts_with('\t') {
      // New interface line
      match field0.parse() {
        Ok(res) => idx = res,
        Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
      }
    } else if field0.len() == 8 {
      if ifi == 0 || ifi == idx {
        // The Linux kernel puts the IP address in /proc/net/igmp in
        // native endianness.
        let src = field0.as_bytes();
        let mut b = [0u8; 4];
        for i in (0..src.len()).step_by(2) {
          b[i / 2] = xtoi2(&src[i..i + 2], 0).unwrap_or(0);
        }

        b.reverse();
        let ip = b.into();
        if f(&ip) {
          ifmat.push(Ifv4Addr::new(idx, ip));
        }
      }
    }
  }

  Ok(ifmat)
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

    // `split_ascii_whitespace` already handles spaces/tabs/CR/LF without
    // a collect+filter, and we only use `fields[0]` and `fields[2]`.
    let mut it = line.split_ascii_whitespace();
    let field0 = match it.next() {
      Some(s) => s,
      None => continue,
    };
    // skip field1
    if it.next().is_none() {
      continue;
    }
    let field2 = match it.next() {
      Some(s) => s,
      None => continue,
    };
    // need 3 more tokens (fields[3..=5]) for a total of 6+.
    if it.nth(2).is_none() {
      continue;
    }

    let idx = match field0.parse() {
      Ok(res) => res,
      Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
    };

    if ifi == 0 || ifi == idx {
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

  // `route_v4_from_raw` / `route_v6_from_raw` cover every branch of
  // the family / length / gateway validation matrix. They live on
  // the hot path between the netlink walker and `IpRoute`, so any
  // regression silently affects every `route_*_table*()` caller.
  // Live tarpaulin runs only exercise the success arm; these unit
  // tests fill in the wrong-family / out-of-range / absent-dst
  // branches.

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
}
