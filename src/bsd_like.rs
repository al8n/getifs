use ipnet::{ip_mask_to_prefix, Ipv4Net, Ipv6Net};
use libc::{
  c_void, if_msghdr, size_t, sysctl, AF_INET, AF_INET6, AF_LINK, AF_ROUTE, AF_UNSPEC, CTL_NET,
  NET_RT_IFLIST, RTAX_BRD, RTAX_DST, RTAX_GATEWAY, RTAX_IFA, RTAX_MAX, RTAX_NETMASK, RTM_IFINFO,
  RTM_NEWADDR, RTM_VERSION,
};
// `NET_RT_IFLIST2` is an Apple-only sysctl target. Keep it out of the
// cross-BSD top-level import — the libc crate does not expose it on
// FreeBSD/DragonFly/NetBSD/OpenBSD.
#[cfg(apple)]
use libc::NET_RT_IFLIST2;

// `libc::ifa_msghdr` is absent on DragonFly, NetBSD and OpenBSD. Route
// it through the compat module, which defines it locally on those
// targets and re-exports `libc::ifa_msghdr` on Apple and FreeBSD.
use compat::IfaMsghdr as ifa_msghdr;
use smallvec_wrapper::{SmallVec, TinyVec};
use smol_str::SmolStr;
use std::{
  io, mem,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
  ptr::null_mut,
};

use super::{HardwareAddr, IfNet, Ifv4Net, Ifv6Net, Interface, IpRoute, Ipv4Route, Ipv6Route, Net};

use super::{Address, IfAddr, Ifv4Addr, Ifv6Addr};

macro_rules! rt_generic_mod {
  ($($name:ident($rtf:ident, $rta:ident)), +$(,)?) => {
    $(
      paste::paste! {
        pub(super) use [< rt_ $name >]::*;

        mod [<rt_ $name>] {
          use std::{
            io,
            net::{IpAddr, Ipv4Addr, Ipv6Addr},
          };

          use libc::{AF_INET, AF_INET6, AF_UNSPEC, $rta, $rtf};
          use smallvec_wrapper::SmallVec;

          use crate::{ipv4_filter_to_ip_filter, ipv6_filter_to_ip_filter};

          use super::super::{Address, IfAddr, Ifv4Addr, Ifv6Addr};

          pub(crate) fn [<$name _addrs >]() -> io::Result<SmallVec<IfAddr>> {
            [< $name _addrs_in >](AF_UNSPEC, |_| true)
          }

          pub(crate) fn [<$name _ipv4_addrs >]() -> io::Result<SmallVec<Ifv4Addr>> {
            [< $name _addrs_in >](AF_INET, |_| true)
          }

          pub(crate) fn [<$name _ipv6_addrs >]() -> io::Result<SmallVec<Ifv6Addr>> {
            [< $name _addrs_in >](AF_INET6, |_| true)
          }

          pub(crate) fn [<$name _addrs_by_filter >]<F>(f: F) -> io::Result<SmallVec<IfAddr>>
          where
            F: FnMut(&IpAddr) -> bool,
          {
            [< $name _addrs_in >](AF_UNSPEC, f)
          }

          pub(crate) fn [<$name _ipv4_addrs_by_filter >]<F>(f: F) -> io::Result<SmallVec<Ifv4Addr>>
          where
            F: FnMut(&Ipv4Addr) -> bool,
          {
            [< $name _addrs_in >](AF_INET, ipv4_filter_to_ip_filter(f))
          }

          pub(crate) fn [<$name _ipv6_addrs_by_filter >]<F>(f: F) -> io::Result<SmallVec<Ifv6Addr>>
          where
            F: FnMut(&Ipv6Addr) -> bool,
          {
            [< $name _addrs_in >](AF_INET6, ipv6_filter_to_ip_filter(f))
          }

          fn [<$name _addrs_in >]<A, F>(family: i32, f: F) -> io::Result<SmallVec<A>>
          where
            A: Address + Eq,
            F: FnMut(&IpAddr) -> bool,
          {
            super::rt_generic::rt_generic_addrs_in(family, $rtf, $rta, f)
          }
        }
      }
    )*
  };
}

rt_generic_mod!(gateway(RTF_GATEWAY, RTA_GATEWAY),);

pub(super) use local_addr::*;

#[inline]
fn build_routev4(
  index: u32,
  rtm_flags: libc::c_int,
  dst: IpAddr,
  gateway: Option<IpAddr>,
  netmask: Option<IpAddr>,
) -> Option<Ipv4Route> {
  let dst_v4 = match dst {
    IpAddr::V4(ip) => ip,
    _ => return None,
  };
  // The public `route_table` contract is unicast/local routes only.
  // BSD's `NET_RT_DUMP` happily includes the kernel's multicast cone
  // (e.g. `224.0.0/4` on macOS) and the limited-broadcast entry as
  // ordinary `RTM_GET` records — drop them here so they don't leak
  // through. `Ipv4Addr::is_multicast()` covers `224.0.0.0/4`,
  // `is_broadcast()` covers `255.255.255.255`.
  if dst_v4.is_multicast() || dst_v4.is_broadcast() {
    return None;
  }
  // Resolving `prefix_len` from the kernel's encoding is fiddly:
  //
  // - `Some(IpAddr::V4(m))` with a v4 dst: real netmask, decode it.
  // - Anything else (`None`, or family-mismatched `Some(IpAddr::V6(_))`
  //   from an ambiguous family-less mask): the kernel didn't give us a
  //   decodable same-family mask, so fall back to the per-route default
  //   below.
  //
  // Default rules when the explicit mask is unavailable:
  // - `dst.is_unspecified()`: BSD encodes the default route's mask
  //   as `0.0.0.0` (or omits it entirely); treat as `/0`.
  // - `RTF_HOST` set: explicit host route, prefix is `/32`.
  // - Otherwise: a network route whose mask we can't decode — skip
  //   rather than fabricate a host prefix (`/32`, or `/128` for IPv6),
  //   which would turn `fe80::/64` into `fe80::/128`.
  let prefix_len = match netmask {
    Some(IpAddr::V4(m)) => ip_mask_to_prefix(IpAddr::V4(m)).ok()?,
    _ if dst_v4.is_unspecified() => 0,
    _ if (rtm_flags & libc::RTF_HOST) != 0 => 32,
    _ => return None,
  };
  let net = Ipv4Net::new(dst_v4, prefix_len).ok()?;
  let gw = match gateway {
    Some(IpAddr::V4(g)) if g != Ipv4Addr::UNSPECIFIED => Some(g),
    _ => None,
  };
  Some(Ipv4Route::new(index, net, gw))
}

#[inline]
fn build_routev6(
  index: u32,
  rtm_flags: libc::c_int,
  dst: IpAddr,
  gateway: Option<IpAddr>,
  netmask: Option<IpAddr>,
) -> Option<Ipv6Route> {
  let dst_v6 = match dst {
    IpAddr::V6(ip) => ip,
    _ => return None,
  };
  // Same rationale as `build_routev4`: drop multicast destinations
  // (`ff00::/8` on BSD/macOS) so the public `route_table` stays
  // consistent with its unicast/local contract.
  if dst_v6.is_multicast() {
    return None;
  }
  // See `build_routev4` for the full per-arm rationale; the v6 case
  // reads identically, with `/128` for host routes and `/0` for the
  // unspecified destination. The `_` arm catches both `None` and a
  // family-mismatched `Some(IpAddr::V4(_))` from an ambiguous,
  // family-less compact mask.
  let prefix_len = match netmask {
    Some(IpAddr::V6(m)) => ip_mask_to_prefix(IpAddr::V6(m)).ok()?,
    _ if dst_v6.is_unspecified() => 0,
    _ if (rtm_flags & libc::RTF_HOST) != 0 => 128,
    _ => return None,
  };
  let net = Ipv6Net::new(dst_v6, prefix_len).ok()?;
  let gw = match gateway {
    Some(IpAddr::V6(g)) if g != Ipv6Addr::UNSPECIFIED => Some(g),
    _ => None,
  };
  Some(Ipv6Route::new(index, net, gw))
}

/// `Ok(())` if the result is "this address-family stack isn't
/// installed on this host" — `EAFNOSUPPORT`, `EPROTONOSUPPORT`, or
/// `EOPNOTSUPP`. Anything else propagates. The numeric values for
/// these errnos vary across BSDs (macOS `EOPNOTSUPP = 102` vs.
/// FreeBSD/NetBSD/OpenBSD `EOPNOTSUPP = 45`), so we read them from
/// `libc::E*` rather than hardcoding — getifs does not use `rustix` on
/// BSD.
///
/// Used by the two-family BSD union APIs (`route_table_by_filter`,
/// `best_local_addrs`) so a single-stack host that successfully
/// returns the populated family doesn't lose the result when the
/// other family's `sysctl` dump comes back with one of the above.
/// The single-family entry points (`route_ipv4_table_by_filter`,
/// `best_local_ipv4_addrs`, etc.) deliberately keep propagating —
/// asking for IPv6 routes on a v6-disabled host should not silently
/// return `Ok([])`.
pub(super) fn family_unavailable_to_empty(result: io::Result<()>) -> io::Result<()> {
  match result {
    Ok(()) => Ok(()),
    Err(e) => match e.raw_os_error() {
      Some(c) if c == libc::EAFNOSUPPORT || c == libc::EPROTONOSUPPORT || c == libc::EOPNOTSUPP => {
        Ok(())
      }
      _ => Err(e),
    },
  }
}

pub(super) fn route_table() -> io::Result<SmallVec<IpRoute>> {
  route_table_by_filter(|_| true)
}

pub(super) fn route_ipv4_table() -> io::Result<SmallVec<Ipv4Route>> {
  route_ipv4_table_by_filter(|_| true)
}

pub(super) fn route_ipv6_table() -> io::Result<SmallVec<Ipv6Route>> {
  route_ipv6_table_by_filter(|_| true)
}

pub(super) fn route_table_by_filter<F>(mut f: F) -> io::Result<SmallVec<IpRoute>>
where
  F: FnMut(&IpRoute) -> bool,
{
  // Walk AF_INET and AF_INET6 separately rather than one AF_UNSPEC
  // dump. BSD sysctl can omit `RTAX_DST` for the default-route entry
  // (encoding the destination as "unspecified") — with a single
  // AF_UNSPEC walk we can't recover the family from a message that
  // omits dst, so a default route would silently disappear from the
  // union API while the family-specific APIs (`route_ipv4_table_by_filter`
  // / `route_ipv6_table_by_filter`) would still surface it. Two
  // sysctl calls is the right tradeoff for keeping the union API
  // consistent with its single-family counterparts.
  let mut out: SmallVec<IpRoute> = SmallVec::new();
  // Each family is wrapped so a single-stack host (no v4 OR no v6)
  // gets the populated family back instead of `Err`. The
  // family-specific entry points further down still propagate the
  // error — see `family_unavailable_to_empty` for why.
  family_unavailable_to_empty(route::walk_route_table(
    AF_INET,
    |index, flags, dst, gw, mask| {
      let dst = dst.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
      if let Some(r) = build_routev4(index, flags, dst, gw, mask) {
        let r = IpRoute::V4(r);
        if f(&r) {
          out.push(r);
        }
      }
    },
  ))?;
  family_unavailable_to_empty(route::walk_route_table(
    AF_INET6,
    |index, flags, dst, gw, mask| {
      let dst = dst.unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
      if let Some(r) = build_routev6(index, flags, dst, gw, mask) {
        let r = IpRoute::V6(r);
        if f(&r) {
          out.push(r);
        }
      }
    },
  ))?;
  Ok(out)
}

pub(super) fn route_ipv4_table_by_filter<F>(mut f: F) -> io::Result<SmallVec<Ipv4Route>>
where
  F: FnMut(&Ipv4Route) -> bool,
{
  let mut out: SmallVec<Ipv4Route> = SmallVec::new();
  route::walk_route_table(AF_INET, |index, flags, dst, gw, mask| {
    // BSD sysctl can omit `RTAX_DST` for the default route — fold that
    // case to `0.0.0.0` here so `build_routev4` can pair it with the
    // implicit `/0` mask.
    let dst = dst.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    if let Some(r) = build_routev4(index, flags, dst, gw, mask) {
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
  route::walk_route_table(AF_INET6, |index, flags, dst, gw, mask| {
    // Same as the v4 path — missing `RTAX_DST` on AF_INET6 is BSD's
    // way of describing the `::/0` default route.
    let dst = dst.unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    if let Some(r) = build_routev6(index, flags, dst, gw, mask) {
      if f(&r) {
        out.push(r);
      }
    }
  })?;
  Ok(out)
}

#[path = "bsd_like/compat.rs"]
mod compat;
#[path = "bsd_like/local_addr.rs"]
mod local_addr;
#[path = "bsd_like/route.rs"]
mod route;
#[path = "bsd_like/rt_generic.rs"]
mod rt_generic;

#[cfg(target_vendor = "apple")]
const KERNAL_ALIGN: usize = 4;

#[cfg(any(target_os = "dragonfly", target_os = "freebsd", target_os = "openbsd",))]
const KERNAL_ALIGN: usize = core::mem::size_of::<usize>();

#[cfg(target_os = "netbsd")]
const KERNAL_ALIGN: usize = 8;

fn invalid_address() -> io::Error {
  io::Error::new(io::ErrorKind::InvalidData, "invalid address")
}

fn invalid_message() -> io::Error {
  io::Error::new(io::ErrorKind::InvalidData, "invalid message")
}

fn message_too_short() -> io::Error {
  io::Error::new(io::ErrorKind::InvalidData, "message too short")
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
    const OACTIVE = 0x400;
    /// Can't hear own transmissions
    const SIMPLEX = 0x800;
    /// Per link layer defined bit
    const LINK0 = 0x1000;
    /// Per link layer defined bit
    const LINK1 = 0x2000;
    /// Per link layer defined bit
    const LINK2 = 0x4000;
    /// Use alternate physical connection
    const ALTPHYS = 0x4000;
    /// Supports multicast access capability
    const MULTICAST = 0x8000;
  }
}

fn parse(b: &[u8]) -> io::Result<Option<(SmolStr, Option<HardwareAddr>)>> {
  if b.len() < 8 {
    return Err(invalid_address());
  }

  // `sdl_len` bounds this sockaddr inside the containing routing message.
  // Parse no padding or following frame bytes even when a malformed length
  // field claims they belong to the name, address, or selector.
  let declared_len = b[0] as usize;
  if declared_len < 8 || declared_len > b.len() {
    return Err(invalid_address());
  }
  let b = &b[4..declared_len];

  // The encoding looks like the following:
  // +----------------------------+
  // | Type             (1 octet) |
  // +----------------------------+
  // | Name length      (1 octet) |
  // +----------------------------+
  // | Address length   (1 octet) |
  // +----------------------------+
  // | Selector length  (1 octet) |
  // +----------------------------+
  // | Data            (variable) |
  // +----------------------------+
  //
  // On some platforms, all-bit-one of length field means "don't
  // care".

  let (mut nlen, mut alen, mut slen) = (b[1] as usize, b[2] as usize, b[3] as usize);
  if nlen == 0xff {
    nlen = 0
  }
  if alen == 0xff {
    alen = 0
  }
  if slen == 0xff {
    slen = 0
  }

  let l = 4usize
    .checked_add(nlen)
    .and_then(|len| len.checked_add(alen))
    .and_then(|len| len.checked_add(slen))
    .ok_or_else(invalid_address)?;
  if b.len() < l {
    return Err(invalid_address());
  }

  let data = &b[4..l];
  let name = if nlen > 0 {
    // The public interface name is UTF-8 and is expected to round-trip
    // through `interface_by_name`. A lossy replacement would invent a name
    // the kernel cannot look up, while failing here would discard every
    // otherwise valid interface in the snapshot. Skip only this interface.
    let Ok(name) = core::str::from_utf8(&data[..nlen]) else {
      return Ok(None);
    };
    SmolStr::from(name)
  } else {
    SmolStr::default()
  };

  let address_start = nlen;
  let address_end = address_start + alen;
  let addr = HardwareAddr::from_bytes(&data[address_start..address_end]);

  Ok(Some((name, addr)))
}

#[cfg(fuzzing)]
fn parse_kernel_inet_addr(b: &[u8]) -> io::Result<(usize, IpAddr)> {
  if b.is_empty() {
    return Err(invalid_address());
  }

  // The encoding looks similar to the NLRI encoding.
  // +----------------------------+
  // | Length           (1 octet) |
  // +----------------------------+
  // | Address prefix  (variable) |
  // +----------------------------+
  //
  // The differences between the kernel form and the NLRI
  // encoding are:
  //
  // - The length field of the kernel form indicates the prefix
  //   length in bytes, not in bits
  //
  // - In the kernel form, zero value of the length field
  //   doesn't mean 0.0.0.0/0 or ::/0
  //
  // - The kernel form appends leading bytes to the prefix field
  //   to make the <length, prefix> tuple to be conformed with
  //   the routing message boundary
  // On Darwin, an address in the kernel form is also
  // used as a message filler.
  #[cfg(any(target_os = "macos", target_os = "ios"))]
  let l = {
    let mut l = b[0] as usize;
    if l == 0 || b.len() > roundup(l) {
      l = roundup(l);
    }
    l
  };
  #[cfg(not(any(target_os = "macos", target_os = "ios")))]
  let l = roundup(b[0] as usize);

  if b.len() < l {
    return Err(invalid_address());
  }

  // Don't reorder case expressions.
  // The case expressions for IPv6 must come first.
  const OFF4: usize = 4; // offset of in_addr
  const OFF6: usize = 8; // offset of in6_addr

  match () {
    () if b[0] as usize == size_of::<libc::sockaddr_in>() => {
      let mut ip = [0u8; 4];
      ip.copy_from_slice(&b[OFF4..OFF4 + 4]);
      Ok((b[0] as usize, IpAddr::V4(ip.into())))
    }
    () if b[0] as usize == size_of::<libc::sockaddr_in6>() => {
      let mut ip = [0u8; 16];
      ip.copy_from_slice(&b[OFF6..OFF6 + 16]);
      Ok((b[0] as usize, IpAddr::V6(ip.into())))
    }
    _ => {
      // an old fashion, AF_UNSPEC or unknown means AF_INET
      let mut ip = [0u8; 4];
      let remaining = l - 1;
      if remaining < OFF4 {
        ip[..remaining].copy_from_slice(&b[1..l]);
      } else {
        ip.copy_from_slice(&b[l - OFF4..l]);
      }

      Ok((b[0] as usize, IpAddr::V4(ip.into())))
    }
  }
}

#[inline]
const fn roundup(l: usize) -> usize {
  if l == 0 {
    return KERNAL_ALIGN;
  }

  (l + KERNAL_ALIGN - 1) & !(KERNAL_ALIGN - 1)
}

#[cfg(any(test, fuzzing))]
const SOCK4: usize = size_of::<libc::sockaddr_in>();
const SOCK6: usize = size_of::<libc::sockaddr_in6>();

/// Decode a BSD route-message sockaddr whose `sa_len` is shorter than
/// the full `sockaddr_in[6]` size. The kernel emits this compact form
/// for netmasks where trailing zero bytes are omitted — e.g., a /24
/// IPv4 netmask carries `sa_len = 8` (1 sa_len + 1 sa_family + 2 port +
/// 4 sin_addr) but only the three significant bytes of the mask. We
/// zero-pad to the full struct shape and then read the address bytes
/// at the same offset the full-length decoder would.
///
/// `sa` is the slice covering exactly `sa_len` bytes; the caller has
/// already verified `b.len() >= sa_len`.
fn parse_short_inet_addr(af: i32, sa: &[u8]) -> io::Result<IpAddr> {
  match af {
    AF_INET => {
      // sockaddr_in layout: sa_len, sa_family, sin_port (2), sin_addr (4), sin_zero (8)
      const OFF: usize = 4;
      let mut ip = [0u8; 4];
      if sa.len() > OFF {
        let n = (sa.len() - OFF).min(4);
        ip[..n].copy_from_slice(&sa[OFF..OFF + n]);
      }
      Ok(IpAddr::V4(ip.into()))
    }
    AF_INET6 => {
      // sockaddr_in6 layout: sa_len, sa_family, sin6_port (2), sin6_flowinfo (4), sin6_addr (16), sin6_scope_id (4)
      const OFF: usize = 8;
      let mut ip = [0u8; 16];
      if sa.len() > OFF {
        let n = (sa.len() - OFF).min(16);
        ip[..n].copy_from_slice(&sa[OFF..OFF + n]);
      }
      Ok(IpAddr::V6(Ipv6Addr::from(ip)))
    }
    _ => Err(invalid_address()),
  }
}

/// Decode a BSD route-message sockaddr from exactly its declared `sa_len`
/// bytes, `sa`, without requiring the full `sockaddr_in[6]` size. A kernel
/// can store a gateway or destination compactly, e.g. a `sockaddr_in` with
/// `sin_len = 8` that ends right after `sin_addr`.
///
/// Returns `None` unless `sa` holds every address byte. Unlike the netmask
/// short form, the missing bytes of an address are unknown rather than zero,
/// so this never zero-extends.
fn decode_full_inet_addr(af: i32, sa: &[u8]) -> Option<IpAddr> {
  match af {
    // sockaddr_in: sa_len, sa_family, sin_port (2), sin_addr (4), ...
    AF_INET => {
      let ip: [u8; 4] = sa.get(4..8)?.try_into().ok()?;
      Some(IpAddr::V4(ip.into()))
    }
    // sockaddr_in6: sa_len, sa_family, sin6_port (2), sin6_flowinfo (4), sin6_addr (16), ...
    AF_INET6 => {
      let ip: [u8; 16] = sa.get(8..24)?.try_into().ok()?;
      Some(IpAddr::V6(strip_kame_scope(ip)))
    }
    _ => None,
  }
}

fn strip_kame_scope(mut ip: [u8; 16]) -> Ipv6Addr {
  if ip[0] == 0xfe && ip[1] & 0xc0 == 0x80
    || ip[0] == 0xff && (ip[1] & 0x0f == 0x01 || ip[1] & 0x0f == 0x02)
  {
    // KAME based IPv6 protocol stack usually
    // embeds the interface index in the
    // interface-local or link-local address as
    // the kernel-internal form.
    let id = u16::from_be_bytes([ip[2], ip[3]]);
    if id != 0 {
      ip[2] = 0;
      ip[3] = 0;
    }
  }
  ip.into()
}

#[cfg(any(test, fuzzing))]
pub(super) fn parse_inet_addr(af: i32, b: &[u8]) -> io::Result<(usize, IpAddr)> {
  // Sysctl returns a `Vec<u8>`, which only formally guarantees u8
  // alignment for its data pointer. The kernel pads each routing
  // message to KERNAL_ALIGN bytes (4 on Apple, 8 on NetBSD, the pointer
  // size on the other BSDs), so the sockaddr offsets happen to land on
  // a usable boundary in practice
  // — but creating `&libc::sockaddr_in[6]` from `b.as_ptr()` is still
  // UB by the language rules whenever `b` isn't aligned for the
  // target type. `read_unaligned` copies into an aligned local
  // without that assumption; the resulting load is the same on x86 /
  // ARM, but defined behaviour everywhere (including strict-alignment
  // targets like SPARC). Production routing parsing decodes bounded frames
  // with `decode_full_inet_addr` and `parse_short_inet_addr`, so this helper
  // is compiled only for tests and fuzzing.
  match af {
    AF_INET => {
      if b.len() < SOCK4 {
        return Err(invalid_address());
      }

      let sockaddr: libc::sockaddr_in =
        unsafe { core::ptr::read_unaligned(b.as_ptr() as *const libc::sockaddr_in) };
      Ok((
        SOCK4,
        IpAddr::V4(sockaddr.sin_addr.s_addr.to_ne_bytes().into()),
      ))
    }
    AF_INET6 => {
      if b.len() < SOCK6 {
        return Err(invalid_address());
      }

      let sockaddr: libc::sockaddr_in6 =
        unsafe { core::ptr::read_unaligned(b.as_ptr() as *const libc::sockaddr_in6) };

      // `Ipv6Addr` has no zone, so the scope id is read but dropped.
      let _zone_id = sockaddr.sin6_scope_id;
      let addr = strip_kame_scope(sockaddr.sin6_addr.s6_addr);

      Ok((SOCK6, addr.into()))
    }
    _ => Err(invalid_address()),
  }
}

/// Split the advertised routing-message sockaddrs into exact declared-length
/// frames before decoding any of them. In particular, do not let a compact
/// address read padding or the beginning of the next sockaddr.
fn sockaddr_frames(addrs: u32, mut b: &[u8]) -> io::Result<[Option<&[u8]>; RTAX_MAX as usize]> {
  let mut frames = [None; RTAX_MAX as usize];

  #[allow(clippy::needless_range_loop)]
  for i in 0..RTAX_MAX as usize {
    if addrs & (1 << i) == 0 {
      continue;
    }

    // An advertised slot needs at least one alignment unit, the size of the
    // all-zero filler of an empty sockaddr. A shorter remainder is truncation,
    // not an absent slot: reading it as absent would fabricate data, such as a
    // default route from a missing `RTAX_DST`.
    if b.len() < KERNAL_ALIGN {
      return Err(message_too_short());
    }

    let sa_len = b[0] as usize;
    let padded_len = roundup(sa_len);
    if b.len() < sa_len || b.len() < padded_len {
      // Darwin can omit the trailing alignment bytes of the final sockaddr.
      // It cannot do so before another advertised sockaddr, because that
      // would make the next frame's offset ambiguous.
      #[cfg(apple)]
      {
        let has_later = ((i + 1)..RTAX_MAX as usize).any(|next| addrs & (1 << next) != 0);
        if !has_later && sa_len != 0 && b.len() >= sa_len {
          frames[i] = Some(&b[..sa_len]);
          b = &b[sa_len..];
          continue;
        }
      }
      return Err(message_too_short());
    }

    // `sa_len == 0` is an aligned filler, not an unspecified address or a
    // `/0` mask. Keep the slot absent but consume its alignment unit.
    if sa_len != 0 {
      frames[i] = Some(&b[..sa_len]);
    }
    b = &b[padded_len..];
  }

  Ok(frames)
}

#[inline]
fn explicit_inet_family(sa: Option<&[u8]>) -> Option<i32> {
  match sa?.get(1).copied().map(i32::from) {
    Some(AF_INET) => Some(AF_INET),
    Some(AF_INET6) => Some(AF_INET6),
    _ => None,
  }
}

/// Decode a family-less sockaddr without letting it reach beyond its declared
/// frame. Only a full `sockaddr_in6` is read as IPv6; any other frame is read
/// as IPv4, the kernel's old-fashioned meaning of a missing family. Returns
/// `None` unless the frame holds a whole address.
fn decode_legacy_inet_addr(sa: &[u8]) -> Option<IpAddr> {
  let af = if sa.len() == SOCK6 { AF_INET6 } else { AF_INET };
  decode_full_inet_addr(af, sa)
}

fn decode_address_frame(slot: usize, sa: &[u8]) -> io::Result<Option<IpAddr>> {
  if slot > RTAX_BRD as usize {
    return Ok(None);
  }

  match explicit_inet_family(Some(sa)) {
    Some(af) => decode_full_inet_addr(af, sa)
      .ok_or_else(invalid_address)
      .map(Some),
    None if sa.get(1).copied().map(i32::from) == Some(AF_LINK) => Ok(None),
    None => {
      let addr = decode_legacy_inet_addr(sa);
      if matches!(slot, x if x == RTAX_DST as usize || x == RTAX_GATEWAY as usize) {
        // An incomplete destination or gateway is malformed, not absent: an
        // absent destination reads as a default route and an absent gateway
        // as an on-link route.
        addr.ok_or_else(invalid_address).map(Some)
      } else {
        Ok(addr)
      }
    }
  }
}

fn decode_netmask_frame(sa: &[u8], family_hint: Option<i32>) -> io::Result<IpAddr> {
  match explicit_inet_family(Some(sa)).or(family_hint) {
    Some(af) => parse_short_inet_addr(af, sa),
    // With no explicit family and no hint, only a full `sockaddr_in6` is read
    // as IPv6; an ambiguous compact mask is read as IPv4.
    None if sa.len() == SOCK6 => parse_short_inet_addr(AF_INET6, sa),
    None => parse_short_inet_addr(AF_INET, sa),
  }
}

pub(super) fn parse_addrs(addrs: u32, b: &[u8]) -> io::Result<[Option<IpAddr>; RTAX_MAX as usize]> {
  let frames = sockaddr_frames(addrs, b)?;
  let mut as_ = [None; RTAX_MAX as usize];

  #[allow(clippy::needless_range_loop)]
  for i in 0..RTAX_MAX as usize {
    if i == RTAX_NETMASK as usize {
      continue;
    }
    if let Some(sa) = frames[i] {
      as_[i] = decode_address_frame(i, sa)?;
    }
  }

  let family_hint = [RTAX_DST, RTAX_GATEWAY, RTAX_IFA]
    .into_iter()
    .find_map(|slot| explicit_inet_family(frames[slot as usize]));
  if let Some(sa) = frames[RTAX_NETMASK as usize] {
    as_[RTAX_NETMASK as usize] = Some(decode_netmask_frame(sa, family_hint)?);
  }

  Ok(as_)
}

/// Exercises the pure BSD wire decoders and the sysctl message walkers
/// without performing any syscalls: `data` stands in for both a single
/// sockaddr and a complete sysctl buffer.
///
/// This hook exists only in cargo-fuzz builds and is not part of the normal
/// crate API. Decoder errors are expected for arbitrary input; the invariant
/// is that no input may panic or access bytes outside its declared frame.
#[cfg(fuzzing)]
#[doc(hidden)]
pub(crate) fn fuzz_bsd_parsers(data: &[u8]) {
  let addrs = data
    .get(..4)
    .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
    .map(u32::from_ne_bytes)
    .unwrap_or(u32::MAX);

  let _ = parse(data);
  let _ = parse_addrs(addrs, data);
  let _ = parse_kernel_inet_addr(data);
  let _ = parse_short_inet_addr(AF_INET, data);
  let _ = parse_short_inet_addr(AF_INET6, data);
  let _ = parse_inet_addr(AF_INET, data);
  let _ = parse_inet_addr(AF_INET6, data);
  let _ = decode_full_inet_addr(AF_INET, data);
  let _ = decode_full_inet_addr(AF_INET6, data);
  rt_generic::fuzz_sockaddr_frame(data);

  // Each walker runs with its most permissive arguments: all interfaces,
  // all addresses, `AF_UNSPEC` for the gateway walk, and a family-specific
  // best-local walk, which also accepts a default route without `RTAX_DST`.
  let _ = parse_interface_table(data);
  let _ = parse_interface_addr_table_into::<IfNet, _>(data, 0, |_| true, &mut SmallVec::new());
  #[cfg(any(apple, target_os = "freebsd"))]
  let _ = parse_multiaddr_table::<super::IfAddr, _>(data, |_| true);
  let _ = rt_generic::parse_rt_generic_addrs::<super::IfAddr, _>(
    data,
    AF_UNSPEC,
    libc::RTF_GATEWAY,
    libc::RTA_GATEWAY,
    |_| true,
  );
  let _ = route::parse_route_table(data, |_, _, _, _, _| {});
  let _ = local_addr::best_route_interfaces(data, AF_INET);
}

fn fetch(family: i32, rt: i32, flag: i32) -> io::Result<Vec<u8>> {
  // The routing table can grow between the sizing call and the data call.
  // BSD sysctl reports that race as ENOMEM; retry the complete pair a small,
  // bounded number of times, matching Go's internal/routebsd strategy.
  const MAX_TRIES: usize = 3;

  for attempt in 0..MAX_TRIES {
    let mut mib = [CTL_NET, AF_ROUTE, 0, family, rt, flag];

    let mut len: size_t = 0;
    if unsafe { sysctl(mib.as_mut_ptr(), 6, null_mut(), &mut len, null_mut(), 0) } < 0 {
      return Err(io::Error::last_os_error());
    }

    if len == 0 {
      return Ok(Vec::new());
    }

    // `len` is both the capacity supplied to the kernel and, on return, the
    // number of initialized bytes. Keep the Vec fully initialized so no
    // `set_len` is needed at this FFI boundary.
    let mut buf = vec![0u8; len];
    let capacity = buf.len();
    let status = unsafe {
      sysctl(
        mib.as_mut_ptr(),
        6,
        buf.as_mut_ptr() as *mut c_void,
        &mut len,
        null_mut(),
        0,
      )
    };

    if status == 0 {
      if len > capacity {
        return Err(io::Error::new(
          io::ErrorKind::InvalidData,
          "sysctl returned a length larger than its output buffer",
        ));
      }

      // The kernel may write fewer bytes when entries disappear between the
      // two calls. Exclude the zero-initialized tail from message parsing.
      buf.truncate(len);
      return Ok(buf);
    }

    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ENOMEM) && attempt + 1 < MAX_TRIES {
      continue;
    }
    return Err(err);
  }

  unreachable!("bounded sysctl retry loop always returns")
}

pub(super) fn interface_table(idx: u32) -> io::Result<TinyVec<Interface>> {
  parse_interface_table(&fetch(AF_UNSPEC, NET_RT_IFLIST, idx as i32)?)
}

fn parse_interface_table(buf: &[u8]) -> io::Result<TinyVec<Interface>> {
  unsafe {
    let mut results = TinyVec::new();

    let mut src = buf;
    while src.len() > 4 {
      let l = u16::from_ne_bytes(src[..2].try_into().unwrap()) as usize;
      if l == 0 {
        return Err(invalid_message());
      }
      if src.len() < l {
        return Err(message_too_short());
      }

      if src[2] as i32 != libc::RTM_VERSION {
        src = &src[l..];
        continue;
      }

      if src[3] as i32 == libc::RTM_IFINFO {
        const HEADER_SIZE: usize = size_of::<if_msghdr>();
        // The outer `src.len() < l` guard only proves the message fits
        // in the sysctl buffer. We *also* need `l >= HEADER_SIZE` so
        // the upcoming `read_unaligned` doesn't read past the message
        // and the slice below can't underflow.
        if l < HEADER_SIZE {
          return Err(message_too_short());
        }
        // SAFETY: `src` is a `Vec<u8>` from sysctl which only
        // formally guarantees u8 alignment; `read_unaligned` copies
        // into an aligned local without that requirement.
        let ifm: if_msghdr = core::ptr::read_unaligned(src.as_ptr() as *const if_msghdr);
        if ifm.ifm_type as i32 == RTM_IFINFO {
          if let Some((name, hardware_addr)) = parse(&src[HEADER_SIZE..l])? {
            let interface = Interface {
              index: ifm.ifm_index as u32,
              // `ifi_mtu` is `u_int32_t` on Apple, `u_long` on FreeBSD/
              // DragonFly, `uint64_t` on NetBSD, `u_int` on OpenBSD. Cast
              // narrows to `u32` to match `Interface.mtu`'s type —
              // realistic MTUs never exceed 65535 so this is lossless in
              // practice.
              mtu: ifm.ifm_data.ifi_mtu as u32,
              name,
              hardware_addr,
              flags: Flags::from_bits_retain(ifm.ifm_flags as u32),
            };
            results.push(interface);
          }
        }
      }

      src = &src[l..];
    }

    Ok(results)
  }
}

pub(super) fn interface_ipv4_addresses<F>(idx: u32, f: F) -> io::Result<SmallVec<Ifv4Net>>
where
  F: FnMut(&IpAddr) -> bool,
{
  interface_addr_table(AF_INET, idx, f)
}

pub(super) fn interface_ipv6_addresses<F>(idx: u32, f: F) -> io::Result<SmallVec<Ifv6Net>>
where
  F: FnMut(&IpAddr) -> bool,
{
  interface_addr_table(AF_INET6, idx, f)
}

pub(super) fn interface_addresses<F>(idx: u32, f: F) -> io::Result<SmallVec<IfNet>>
where
  F: FnMut(&IpAddr) -> bool,
{
  interface_addr_table(AF_UNSPEC, idx, f)
}

pub(super) fn interface_addr_table<T, F>(family: i32, idx: u32, f: F) -> io::Result<SmallVec<T>>
where
  T: Net,
  F: FnMut(&IpAddr) -> bool,
{
  let mut out = SmallVec::new();
  interface_addr_table_into(family, idx, f, &mut out)?;
  Ok(out)
}

/// Variant of [`interface_addr_table`] that pushes results into the
/// caller's buffer. Used by `best_local_addrs()` to merge per-family
/// walks without intermediate `SmallVec`s.
pub(super) fn interface_addr_table_into<T, F>(
  family: i32,
  idx: u32,
  f: F,
  results: &mut SmallVec<T>,
) -> io::Result<()>
where
  T: Net,
  F: FnMut(&IpAddr) -> bool,
{
  parse_interface_addr_table_into(&fetch(family, NET_RT_IFLIST, idx as i32)?, idx, f, results)
}

fn parse_interface_addr_table_into<T, F>(
  buf: &[u8],
  idx: u32,
  mut f: F,
  results: &mut SmallVec<T>,
) -> io::Result<()>
where
  T: Net,
  F: FnMut(&IpAddr) -> bool,
{
  const HEADER_SIZE: usize = mem::size_of::<ifa_msghdr>();

  unsafe {
    let mut b = buf;

    while b.len() > HEADER_SIZE {
      // SAFETY: u8-aligned sysctl buffer; copy header out before reading fields.
      let ifam: ifa_msghdr = core::ptr::read_unaligned(b.as_ptr() as *const ifa_msghdr);
      let len = ifam.ifam_msglen as usize;

      // The outer `b.len() > HEADER_SIZE` guard proves we could read
      // the header, but the kernel-reported `len` still needs its own
      // checks: it must be at least `HEADER_SIZE` (so the slice
      // `&b[HEADER_SIZE..len]` can't underflow), and at most `b.len()`
      // (so the trailing `b = &b[len..]` won't slice past the buffer).
      if len < HEADER_SIZE || len > b.len() {
        return Err(message_too_short());
      }

      if (ifam.ifam_version as i32 != RTM_VERSION) || (ifam.ifam_index as u32 != idx && idx != 0) {
        b = &b[len..];
        continue;
      }

      if ifam.ifam_type as i32 == RTM_NEWADDR {
        let addrs = parse_addrs(ifam.ifam_addrs as u32, &b[HEADER_SIZE..len])?;
        let mask = addrs[RTAX_NETMASK as usize]
          .as_ref()
          .map(|ip| ip_mask_to_prefix(*ip));

        let ip: Option<IpAddr> = addrs[RTAX_IFA as usize].as_ref().map(|ip| *ip);

        // A non-contiguous mask (`PrefixLenError` from `ipnet`) is
        // skipped per-address rather than failing the whole walk.
        // BSD kernels — especially NetBSD — can emit a non-canonical
        // `RTAX_NETMASK` for point-to-point and tunnel interfaces
        // (the mask slot sometimes carries peer-address bytes
        // instead of a clean prefix mask). Propagating that error
        // would kill `interfaces()` / `Interface::addrs()` entirely on
        // those hosts even though the rest of the addresses are
        // perfectly readable. A skipped address is strictly better
        // than no addresses; if the caller only cares about a
        // single interface they can detect the gap themselves.
        if let (Some(ip), Some(Ok(prefix))) = (ip, mask) {
          if let Some(ifa) =
            T::try_from_with_filter(ifam.ifam_index as u32, ip, prefix, |addr| f(addr))
          {
            results.push(ifa);
          }
        }
      }

      b = &b[len..];
    }

    Ok(())
  }
}

pub(super) fn interface_multicast_ipv4_addresses<F>(
  idx: u32,
  mut f: F,
) -> io::Result<SmallVec<Ifv4Addr>>
where
  F: FnMut(&std::net::Ipv4Addr) -> bool,
{
  interface_multiaddr_table(AF_INET, idx, |addr| match addr {
    IpAddr::V4(ip) => f(ip),
    _ => false,
  })
}

pub(super) fn interface_multicast_ipv6_addresses<F>(
  idx: u32,
  mut f: F,
) -> io::Result<SmallVec<Ifv6Addr>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  interface_multiaddr_table(AF_INET6, idx, |addr| match addr {
    IpAddr::V6(ip) => f(ip),
    _ => false,
  })
}

pub(super) fn interface_multicast_addresses<F>(idx: u32, f: F) -> io::Result<SmallVec<IfAddr>>
where
  F: FnMut(&IpAddr) -> bool,
{
  interface_multiaddr_table(AF_UNSPEC, idx, f)
}

cfg_apple!(
  pub(super) fn interface_multiaddr_table<T, F>(
    family: i32,
    idx: u32,
    f: F,
  ) -> io::Result<SmallVec<T>>
  where
    T: Address,
    F: FnMut(&IpAddr) -> bool,
  {
    parse_multiaddr_table(&fetch(family, NET_RT_IFLIST2, idx as i32)?, f)
  }

  fn parse_multiaddr_table<T, F>(buf: &[u8], mut f: F) -> io::Result<SmallVec<T>>
  where
    T: Address,
    F: FnMut(&IpAddr) -> bool,
  {
    const HEADER_SIZE: usize = mem::size_of::<libc::ifma_msghdr2>();

    unsafe {
      let mut results = SmallVec::new();
      let mut b = buf;

      while b.len() > HEADER_SIZE {
        // SAFETY: u8-aligned sysctl buffer; copy header out before reading fields.
        let ifam: libc::ifma_msghdr2 =
          core::ptr::read_unaligned(b.as_ptr() as *const libc::ifma_msghdr2);
        let len = ifam.ifmam_msglen as usize;

        // Same per-message length checks as `parse_interface_addr_table_into`.
        if len < HEADER_SIZE || len > b.len() {
          return Err(message_too_short());
        }

        if ifam.ifmam_version as i32 != RTM_VERSION {
          b = &b[len..];
          continue;
        }

        if ifam.ifmam_type as i32 == libc::RTM_NEWMADDR2 {
          let addrs = parse_addrs(ifam.ifmam_addrs as u32, &b[HEADER_SIZE..len])?;

          if let Some(ip) = addrs[RTAX_IFA as usize].as_ref() {
            if let Some(ip) = T::try_from_with_filter(ifam.ifmam_index as u32, *ip, |addr| f(addr))
            {
              results.push(ip);
            }
          }
        }

        b = &b[len..];
      }

      Ok(results)
    }
  }
);

// FreeBSD has both `NET_RT_IFMALIST` and the `ifma_msghdr` struct
// exported via libc, so this is the real walker. DragonFly, NetBSD and
// OpenBSD share a stub below — their kernels don't expose multicast group
// enumeration via sysctl at all.
#[cfg(target_os = "freebsd")]
pub(super) fn interface_multiaddr_table<T, F>(
  family: i32,
  idx: u32,
  f: F,
) -> io::Result<SmallVec<T>>
where
  T: Address,
  F: FnMut(&IpAddr) -> bool,
{
  use compat::NET_RT_IFMALIST;

  parse_multiaddr_table(&fetch(family, NET_RT_IFMALIST, idx as i32)?, f)
}

#[cfg(target_os = "freebsd")]
fn parse_multiaddr_table<T, F>(buf: &[u8], mut f: F) -> io::Result<SmallVec<T>>
where
  T: Address,
  F: FnMut(&IpAddr) -> bool,
{
  use compat::IfmaMsghdr;

  const HEADER_SIZE: usize = mem::size_of::<IfmaMsghdr>();

  unsafe {
    let mut results = SmallVec::new();
    let mut b = buf;

    while b.len() > HEADER_SIZE {
      // SAFETY: u8-aligned sysctl buffer; copy header out before reading fields.
      let ifam: IfmaMsghdr = core::ptr::read_unaligned(b.as_ptr() as *const IfmaMsghdr);
      let len = ifam.ifmam_msglen as usize;

      // Same per-message length checks as `parse_interface_addr_table_into`.
      if len < HEADER_SIZE || len > b.len() {
        return Err(message_too_short());
      }

      if ifam.ifmam_version as i32 != RTM_VERSION {
        b = &b[len..];
        continue;
      }

      if ifam.ifmam_type as i32 == libc::RTM_NEWMADDR {
        let addrs = parse_addrs(ifam.ifmam_addrs as u32, &b[HEADER_SIZE..len])?;

        if let Some(ip) = addrs[RTAX_IFA as usize].as_ref() {
          if let Some(ip) = T::try_from_with_filter(ifam.ifmam_index as u32, *ip, |addr| f(addr)) {
            results.push(ip);
          }
        }
      }

      b = &b[len..];
    }

    Ok(results)
  }
}

// DragonFly, NetBSD and OpenBSD stub: none of these kernels exposes
// multicast group enumeration via sysctl, because none of them defines a
// `NET_RT_IFMALIST` route selector to call. DragonFly's `<sys/socket.h>`,
// for example, defines only `NET_RT_DUMP` / `NET_RT_FLAGS` /
// `NET_RT_IFLIST` (`NET_RT_MAXID = 4`).
//
// The public API still surfaces on these targets so cross-platform
// callers compile and link without target-specific cfgs, but a real
// call returns `ErrorKind::Unsupported` rather than a misleading
// empty `Ok` — `Ok(SmallVec::new())` would be indistinguishable from
// a host with multicast enumeration available but no current
// memberships, which is wrong-by-default semantics for everyone
// reading the result. Callers can match on `ErrorKind::Unsupported`
// when they want to treat these targets the same way as platforms with
// the kernel API absent.
#[cfg(any(target_os = "dragonfly", target_os = "netbsd", target_os = "openbsd"))]
pub(super) fn interface_multiaddr_table<T, F>(
  _family: i32,
  _idx: u32,
  _f: F,
) -> io::Result<SmallVec<T>>
where
  T: Address,
  F: FnMut(&IpAddr) -> bool,
{
  Err(io::Error::new(
    io::ErrorKind::Unsupported,
    "multicast group enumeration is not supported on this platform \
     (no NET_RT_IFMALIST sysctl selector)",
  ))
}

#[cfg(test)]
mod tests {
  use super::*;
  use hardware_address::MacAddr;
  use libc::{RTAX_DST, RTAX_GATEWAY};

  // Pure-function unit tests for the BSD parser helpers and the
  // `family_unavailable_to_empty` errno classifier. These run on
  // every BSD CI target (the FreeBSD, OpenBSD, NetBSD and DragonFly
  // VMs, and macOS) and exercise branches that are otherwise
  // reachable only via specific kernel-message shapes which a live
  // test environment doesn't necessarily emit.

  #[test]
  fn family_unavailable_collapses_known_errnos() {
    for c in [libc::EAFNOSUPPORT, libc::EPROTONOSUPPORT, libc::EOPNOTSUPP] {
      let e = io::Error::from_raw_os_error(c);
      let r = family_unavailable_to_empty(Err(e));
      assert!(r.is_ok(), "expected Ok for errno {c}");
    }
  }

  #[test]
  fn family_unavailable_propagates_other_errnos() {
    // Any errno outside the family-unavailable whitelist should
    // surface. EINVAL is convenient and never confused with the
    // whitelist.
    let e = io::Error::from_raw_os_error(libc::EINVAL);
    let r = family_unavailable_to_empty(Err(e));
    assert!(r.is_err());
  }

  #[test]
  fn family_unavailable_passthrough_ok() {
    assert!(family_unavailable_to_empty(Ok(())).is_ok());
  }

  #[test]
  fn flags_retain_unknown_bits() {
    let unknown = 1 << 31;
    assert_eq!(Flags::from_bits_retain(unknown).bits(), unknown);
  }

  #[test]
  fn roundup_matches_kernel_alignment() {
    // `roundup(0)` returns one alignment unit (the kernel's
    // documented behaviour for empty sockaddrs).
    assert_eq!(roundup(0), KERNAL_ALIGN);
    // Already-aligned values stay put.
    assert_eq!(roundup(KERNAL_ALIGN), KERNAL_ALIGN);
    assert_eq!(roundup(2 * KERNAL_ALIGN), 2 * KERNAL_ALIGN);
    // Sub-alignment values round up.
    assert_eq!(roundup(1), KERNAL_ALIGN);
    assert_eq!(roundup(KERNAL_ALIGN + 1), 2 * KERNAL_ALIGN);
  }

  #[test]
  fn parse_short_inet_addr_zero_extends_v4() {
    // BSD compact `RTAX_NETMASK` for `255.255.255.0` (a `/24`):
    // sa_len = 7, sa_family = AF_INET, port = 0, then 3 bytes of
    // address (`255.255.255`). Trailing byte is implicit zero.
    let bytes = [7u8, libc::AF_INET as u8, 0, 0, 255, 255, 255];
    let ip = parse_short_inet_addr(libc::AF_INET, &bytes).unwrap();
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)));
  }

  #[test]
  fn parse_short_inet_addr_zero_extends_v6() {
    // Compact short-form for `ff00::` netmask (/8): sa_len = 9,
    // sa_family = AF_INET6, then 1 byte (`0xff`).
    let mut bytes = [0u8; 9];
    bytes[0] = 9;
    bytes[1] = libc::AF_INET6 as u8;
    bytes[8] = 0xff;
    let ip = parse_short_inet_addr(libc::AF_INET6, &bytes).unwrap();
    assert!(matches!(ip, IpAddr::V6(_)));
  }

  #[test]
  fn parse_short_inet_addr_unknown_family_errors() {
    let bytes = [4u8, 99, 0, 0]; // sa_family = 99 (not INET/INET6)
    assert!(parse_short_inet_addr(99, &bytes).is_err());
  }

  #[test]
  fn parse_inet_addr_truncated_v4_errors() {
    // Buffer shorter than `sockaddr_in` (16 bytes on most BSDs)
    // surfaces as `Err(invalid_address())`.
    let buf = [0u8; 4];
    assert!(parse_inet_addr(libc::AF_INET, &buf).is_err());
  }

  #[test]
  fn parse_inet_addr_truncated_v6_errors() {
    let buf = [0u8; 8];
    assert!(parse_inet_addr(libc::AF_INET6, &buf).is_err());
  }

  #[test]
  fn parse_inet_addr_unknown_family_errors() {
    let buf = [0u8; 32];
    assert!(parse_inet_addr(0xff, &buf).is_err());
  }

  #[test]
  fn parse_inet_addr_strips_kame_scope_from_link_local_v6() {
    let mut buf = [0u8; SOCK6];
    buf[0] = SOCK6 as u8;
    buf[1] = libc::AF_INET6 as u8;
    // sockaddr_in6::sin6_addr starts at byte 8. KAME stores the
    // interface index in bytes 2..4 of a link-local address.
    buf[8..24].copy_from_slice(&[0xfe, 0x80, 0x00, 0x0e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    let (_, addr) = parse_inet_addr(libc::AF_INET6, &buf).unwrap();
    assert_eq!(addr, IpAddr::V6("fe80::1".parse().unwrap()));
  }

  /// The `rtm_addrs`-style bitmask that marks each `RTAX_*` slot present.
  pub(super) fn addrs_mask(slots: &[libc::c_int]) -> u32 {
    slots.iter().fold(0, |mask, &slot| mask | 1 << slot)
  }

  /// `sa` followed by the alignment padding its `sa_len` (first byte) implies.
  pub(super) fn padded_sockaddr(sa: &[u8]) -> Vec<u8> {
    let mut padded = sa.to_vec();
    padded.resize(roundup(sa[0] as usize), 0);
    padded
  }

  pub(super) fn sockaddr_in(ip: Ipv4Addr) -> Vec<u8> {
    let mut sa = vec![0u8; SOCK4];
    sa[0] = SOCK4 as u8;
    sa[1] = AF_INET as u8;
    sa[4..8].copy_from_slice(&ip.octets());
    padded_sockaddr(&sa)
  }

  pub(super) fn sockaddr_in6(ip: Ipv6Addr) -> Vec<u8> {
    let mut sa = vec![0u8; SOCK6];
    sa[0] = SOCK6 as u8;
    sa[1] = AF_INET6 as u8;
    sa[8..24].copy_from_slice(&ip.octets());
    padded_sockaddr(&sa)
  }

  /// A compact `AF_UNSPEC` sockaddr whose IPv4-shaped address bytes start at
  /// the regular `sockaddr_in::sin_addr` offset. Route netmasks use this
  /// family-less shape on several BSDs.
  fn unspec_v4_sockaddr(bytes: &[u8]) -> Vec<u8> {
    assert!(bytes.len() <= 4);
    let mut sa = vec![0u8; 4 + bytes.len()];
    sa[0] = sa.len() as u8;
    sa[1] = AF_UNSPEC as u8;
    sa[4..].copy_from_slice(bytes);
    padded_sockaddr(&sa)
  }

  /// A compact `AF_UNSPEC` sockaddr whose IPv6-shaped address bytes start at
  /// the regular `sockaddr_in6::sin6_addr` offset.
  fn unspec_v6_sockaddr(bytes: &[u8]) -> Vec<u8> {
    assert!(bytes.len() <= 16);
    let mut sa = vec![0u8; 8 + bytes.len()];
    sa[0] = sa.len() as u8;
    sa[1] = AF_UNSPEC as u8;
    sa[8..].copy_from_slice(bytes);
    padded_sockaddr(&sa)
  }

  /// A routing message: a zeroed `H` header that carries the length,
  /// version, and type every BSD routing message starts with, then `body`.
  /// The header layout differs per BSD, so callers set any other field
  /// through the target's own struct definition.
  fn routing_message<H>(ty: libc::c_int, body: &[u8]) -> Vec<u8> {
    let header_size = mem::size_of::<H>();
    let mut message = vec![0u8; header_size + body.len()];
    let len = u16::try_from(message.len()).unwrap();
    message[..2].copy_from_slice(&len.to_ne_bytes());
    message[2] = RTM_VERSION as u8;
    message[3] = ty as u8;
    message[header_size..].copy_from_slice(body);
    message
  }

  /// An `RTM_GET` route message whose sockaddrs are `body`.
  pub(super) fn rt_message(index: u16, flags: libc::c_int, addrs: u32, body: &[u8]) -> Vec<u8> {
    let mut message = routing_message::<compat::RtMsghdr>(libc::RTM_GET, body);
    let header = message.as_mut_ptr().cast::<compat::RtMsghdr>();
    // SAFETY: `message` starts with a whole header, so every field place is
    // in bounds, and unaligned writes need no alignment from the buffer.
    unsafe {
      core::ptr::addr_of_mut!((*header).rtm_index).write_unaligned(index);
      core::ptr::addr_of_mut!((*header).rtm_flags).write_unaligned(flags);
      core::ptr::addr_of_mut!((*header).rtm_addrs).write_unaligned(addrs as libc::c_int);
    }
    message
  }

  fn link_addr(index: u16, name: &[u8], hardware_addr: &[u8], selector: &[u8]) -> Vec<u8> {
    // sockaddr_dl: sdl_len, sdl_family, sdl_index (2), sdl_type (IFT_ETHER),
    // sdl_nlen, sdl_alen, sdl_slen, then the name and address in sdl_data.
    let mut sdl = vec![0, AF_LINK as u8];
    sdl.extend(index.to_ne_bytes());
    sdl.extend([
      6,
      u8::try_from(name.len()).unwrap(),
      u8::try_from(hardware_addr.len()).unwrap(),
      u8::try_from(selector.len()).unwrap(),
    ]);
    sdl.extend(name);
    sdl.extend(hardware_addr);
    sdl.extend(selector);
    sdl[0] = u8::try_from(sdl.len()).unwrap();
    sdl
  }

  /// An `RTM_IFINFO` message followed by the interface's link-layer sockaddr.
  fn ifinfo_message(
    index: u16,
    flags: Flags,
    mtu: u16,
    name: &str,
    hardware_addr: &[u8],
  ) -> Vec<u8> {
    let sdl = link_addr(index, name.as_bytes(), hardware_addr, &[]);

    let mut message = routing_message::<if_msghdr>(RTM_IFINFO, &padded_sockaddr(&sdl));
    let header = message.as_mut_ptr().cast::<if_msghdr>();
    // SAFETY: as in `rt_message`.
    unsafe {
      core::ptr::addr_of_mut!((*header).ifm_flags).write_unaligned(flags.bits() as libc::c_int);
      core::ptr::addr_of_mut!((*header).ifm_index).write_unaligned(index);
      core::ptr::addr_of_mut!((*header).ifm_data.ifi_mtu).write_unaligned(mtu.into());
    }
    message
  }

  /// An `RTM_NEWADDR` message whose sockaddrs are `body`.
  fn newaddr_message(index: u16, addrs: u32, body: &[u8]) -> Vec<u8> {
    let mut message = routing_message::<ifa_msghdr>(RTM_NEWADDR, body);
    let header = message.as_mut_ptr().cast::<ifa_msghdr>();
    // SAFETY: as in `rt_message`.
    unsafe {
      core::ptr::addr_of_mut!((*header).ifam_addrs).write_unaligned(addrs as libc::c_int);
      core::ptr::addr_of_mut!((*header).ifam_index).write_unaligned(index);
    }
    message
  }

  #[test]
  fn parse_link_addr_preserves_known_and_raw_widths() {
    let parsed = |address: &[u8]| {
      parse(&link_addr(7, b"en7", address, &[]))
        .unwrap()
        .unwrap()
        .1
        .unwrap()
    };

    let mac = parsed(&[1; 6]);
    assert!(matches!(mac, HardwareAddr::Mac(_)));
    assert_eq!(mac.as_bytes(), &[1; 6]);

    let eui64 = parsed(&[2; 8]);
    assert!(matches!(eui64, HardwareAddr::Eui64(_)));
    assert_eq!(eui64.as_bytes(), &[2; 8]);

    let infiniband = parsed(&[3; 20]);
    assert!(matches!(infiniband, HardwareAddr::InfiniBand(_)));
    assert_eq!(infiniband.as_bytes(), &[3; 20]);

    let raw = parsed(&[4; 5]);
    assert!(matches!(raw, HardwareAddr::Raw(_)));
    assert_eq!(raw.as_bytes(), &[4; 5]);
  }

  #[test]
  fn parse_link_addr_uses_name_address_and_selector_offsets() {
    let frame = link_addr(7, b"bridge7", &[1, 2, 3, 4, 5], &[0xaa, 0xbb, 0xcc]);
    let (name, hardware_addr) = parse(&frame).unwrap().unwrap();
    assert_eq!(name, "bridge7");
    assert_eq!(hardware_addr.unwrap().as_bytes(), &[1, 2, 3, 4, 5]);
  }

  #[test]
  fn parse_link_addr_normalizes_empty_and_all_zero_addresses() {
    for address in [&[][..], &[0; 5], &[0; 6], &[0; 8], &[0; 20]] {
      let (_, hardware_addr) = parse(&link_addr(7, b"en7", address, &[])).unwrap().unwrap();
      assert!(hardware_addr.is_none(), "address length {}", address.len());
    }
  }

  #[test]
  fn parse_link_addr_rejects_malformed_declared_lengths() {
    let frame = link_addr(7, b"en7", &[1; 6], &[9; 3]);

    let mut declared_too_long = frame.clone();
    declared_too_long[0] = u8::try_from(frame.len() + 1).unwrap();
    assert_eq!(
      parse(&declared_too_long).unwrap_err().kind(),
      io::ErrorKind::InvalidData
    );

    let mut declared_too_short = frame.clone();
    declared_too_short[0] = 7;
    assert_eq!(
      parse(&declared_too_short).unwrap_err().kind(),
      io::ErrorKind::InvalidData
    );

    let mut address_borrows_selector = frame;
    address_borrows_selector[6] = 10;
    assert_eq!(
      parse(&address_borrows_selector).unwrap_err().kind(),
      io::ErrorKind::InvalidData
    );
  }

  #[test]
  fn parse_interface_table_decodes_ifinfo_fixture() {
    let mac = [0x02, 0, 0, 0, 0, 0x01];
    let mut buf = ifinfo_message(7, Flags::UP | Flags::RUNNING, 1500, "en7", &mac);
    // A message from another routing-socket version is skipped whole.
    let mut other_version = ifinfo_message(8, Flags::UP, 1500, "en8", &mac);
    other_version[2] = RTM_VERSION as u8 + 1;
    buf.extend(other_version);

    let interfaces = parse_interface_table(&buf).unwrap();
    assert_eq!(interfaces.len(), 1);
    assert_eq!(interfaces[0].index(), 7);
    assert_eq!(interfaces[0].name(), "en7");
    assert_eq!(interfaces[0].mtu(), 1500);
    assert_eq!(interfaces[0].mac_addr(), Some(MacAddr::from_raw(mac)));
    assert_eq!(interfaces[0].flags(), Flags::UP | Flags::RUNNING);
  }

  #[test]
  fn parse_interface_table_normalizes_an_all_zero_mac() {
    let message = ifinfo_message(7, Flags::UP, 1500, "en7", &[0; 6]);
    let interfaces = parse_interface_table(&message).unwrap();
    assert_eq!(interfaces.len(), 1);
    assert!(interfaces[0].hardware_addr().is_none());
    assert!(interfaces[0].mac_addr().is_none());
  }

  #[test]
  fn parse_interface_table_rejects_truncated_fixture() {
    let message = ifinfo_message(7, Flags::UP, 1500, "en7", &[0x02, 0, 0, 0, 0, 0x01]);
    // The message declares more bytes than the buffer holds.
    let err = parse_interface_table(&message[..message.len() - 1]).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);

    // The declared length ends inside the header.
    let mut short = message.clone();
    short[..2].copy_from_slice(&8u16.to_ne_bytes());
    let err = parse_interface_table(&short).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
  }

  #[test]
  fn parse_interface_addr_table_decodes_newaddr_fixture() {
    let mut body = padded_sockaddr(&[7, AF_INET as u8, 0, 0, 255, 255, 255]);
    body.extend(sockaddr_in(Ipv4Addr::new(192, 0, 2, 10)));
    let buf = newaddr_message(2, addrs_mask(&[RTAX_NETMASK, RTAX_IFA]), &body);

    let mut nets = SmallVec::<IfNet>::new();
    parse_interface_addr_table_into(&buf, 0, |_| true, &mut nets).unwrap();
    assert_eq!(nets.len(), 1);
    assert_eq!(nets[0].index(), 2);
    assert_eq!(nets[0].addr(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
    assert_eq!(nets[0].prefix_len(), 24);

    // Another interface's address and a rejecting filter are both skipped.
    let mut skipped = SmallVec::<IfNet>::new();
    parse_interface_addr_table_into(&buf, 3, |_| true, &mut skipped).unwrap();
    parse_interface_addr_table_into(&buf, 2, |_| false, &mut skipped).unwrap();
    assert!(skipped.is_empty());
  }

  #[test]
  fn parse_interface_addr_table_rejects_truncated_fixture() {
    let addrs = addrs_mask(&[RTAX_IFA]);
    let address = sockaddr_in(Ipv4Addr::new(192, 0, 2, 10));
    let mut nets = SmallVec::<IfNet>::new();

    // The message declares more bytes than the buffer holds.
    let message = newaddr_message(2, addrs, &address);
    let truncated = &message[..message.len() - 1];
    let err = parse_interface_addr_table_into(truncated, 0, |_| true, &mut nets).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);

    // The address sockaddr runs past the end of its message.
    let message = newaddr_message(2, addrs, &address[..4]);
    let err = parse_interface_addr_table_into(&message, 0, |_| true, &mut nets).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(nets.is_empty());
  }

  #[cfg(apple)]
  type MultiaddrHeader = libc::ifma_msghdr2;
  #[cfg(apple)]
  const RTM_NEWMULTIADDR: libc::c_int = libc::RTM_NEWMADDR2;
  #[cfg(target_os = "freebsd")]
  type MultiaddrHeader = compat::IfmaMsghdr;
  #[cfg(target_os = "freebsd")]
  const RTM_NEWMULTIADDR: libc::c_int = libc::RTM_NEWMADDR;

  /// A multicast-membership message whose sockaddrs are `body`.
  #[cfg(any(apple, target_os = "freebsd"))]
  fn newmaddr_message(index: u16, addrs: u32, body: &[u8]) -> Vec<u8> {
    let mut message = routing_message::<MultiaddrHeader>(RTM_NEWMULTIADDR, body);
    let header = message.as_mut_ptr().cast::<MultiaddrHeader>();
    // SAFETY: as in `rt_message`.
    unsafe {
      core::ptr::addr_of_mut!((*header).ifmam_addrs).write_unaligned(addrs as libc::c_int);
      core::ptr::addr_of_mut!((*header).ifmam_index).write_unaligned(index);
    }
    message
  }

  #[cfg(any(apple, target_os = "freebsd"))]
  #[test]
  fn parse_multiaddr_table_decodes_group_fixture() {
    let group = Ipv4Addr::new(224, 0, 0, 251);
    let buf = newmaddr_message(4, addrs_mask(&[RTAX_IFA]), &sockaddr_in(group));

    let groups = parse_multiaddr_table::<IfAddr, _>(&buf, |_| true).unwrap();
    assert_eq!(groups.as_slice(), &[IfAddr::new(4, IpAddr::V4(group))]);
    let rejected = parse_multiaddr_table::<IfAddr, _>(&buf, |_| false).unwrap();
    assert!(rejected.is_empty());
  }

  #[cfg(any(apple, target_os = "freebsd"))]
  #[test]
  fn parse_multiaddr_table_rejects_truncated_fixture() {
    let group = sockaddr_in(Ipv4Addr::new(224, 0, 0, 251));
    let message = newmaddr_message(4, addrs_mask(&[RTAX_IFA]), &group);
    let truncated = &message[..message.len() - 1];
    let err = parse_multiaddr_table::<IfAddr, _>(truncated, |_| true).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
  }

  #[test]
  fn parse_addrs_decodes_compact_v4_gateway() {
    // A full destination, a `sin_len = 8` gateway that ends right after
    // `sin_addr`, and a compact /24 netmask.
    let mut b = sockaddr_in(Ipv4Addr::new(198, 51, 100, 0));
    b.extend(padded_sockaddr(&[8, AF_INET as u8, 0, 0, 192, 0, 2, 1]));
    b.extend(padded_sockaddr(&[7, AF_INET as u8, 0, 0, 255, 255, 255]));

    let addrs = parse_addrs(addrs_mask(&[RTAX_DST, RTAX_GATEWAY, RTAX_NETMASK]), &b).unwrap();
    assert_eq!(
      addrs[RTAX_DST as usize],
      Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)))
    );
    assert_eq!(
      addrs[RTAX_GATEWAY as usize],
      Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
    );
    assert_eq!(
      addrs[RTAX_NETMASK as usize],
      Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)))
    );
  }

  #[test]
  fn parse_addrs_decodes_complete_compact_unspec_destination_and_gateway() {
    let mut body = unspec_v4_sockaddr(&[198, 51, 100, 0]);
    body.extend(unspec_v4_sockaddr(&[192, 0, 2, 1]));

    let addrs = parse_addrs(addrs_mask(&[RTAX_DST, RTAX_GATEWAY]), &body).unwrap();
    assert_eq!(
      addrs[RTAX_DST as usize],
      Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)))
    );
    assert_eq!(
      addrs[RTAX_GATEWAY as usize],
      Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
    );
  }

  #[test]
  fn parse_addrs_strips_kame_scope_from_compact_v6_gateway() {
    // A 24-byte `sockaddr_in6` ends right after `sin6_addr`. KAME stores the
    // interface index in bytes 2..4 of a link-local address.
    let mut gateway = [0u8; 24];
    gateway[0] = 24;
    gateway[1] = AF_INET6 as u8;
    gateway[8..24].copy_from_slice(&[0xfe, 0x80, 0x00, 0x0e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    let addrs = parse_addrs(addrs_mask(&[RTAX_GATEWAY]), &padded_sockaddr(&gateway)).unwrap();
    assert_eq!(
      addrs[RTAX_GATEWAY as usize],
      Some(IpAddr::V6("fe80::1".parse().unwrap()))
    );
  }

  #[test]
  fn parse_addrs_rejects_gateway_without_whole_address() {
    // Seven declared bytes stop one byte short of `sin_addr`, and twenty stop
    // inside `sin6_addr`. The missing bytes are unknown, not zero.
    let v4 = padded_sockaddr(&[7, AF_INET as u8, 0, 0, 192, 0, 2]);
    let err = parse_addrs(addrs_mask(&[RTAX_GATEWAY]), &v4).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);

    let mut v6 = [0u8; 20];
    v6[0] = 20;
    v6[1] = AF_INET6 as u8;
    let err = parse_addrs(addrs_mask(&[RTAX_GATEWAY]), &padded_sockaddr(&v6)).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
  }

  #[test]
  fn parse_addrs_zero_extends_only_the_netmask_short_form() {
    // The same five declared bytes are a valid /8 netmask but an incomplete
    // gateway address.
    let short = padded_sockaddr(&[5, AF_INET as u8, 0, 0, 255]);
    let addrs = parse_addrs(addrs_mask(&[RTAX_NETMASK]), &short).unwrap();
    assert_eq!(
      addrs[RTAX_NETMASK as usize],
      Some(IpAddr::V4(Ipv4Addr::new(255, 0, 0, 0)))
    );
    assert!(parse_addrs(addrs_mask(&[RTAX_GATEWAY]), &short).is_err());
  }

  #[test]
  fn route_walker_builds_connected_v6_from_compact_unspec_mask() {
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0, 0, 0, 0, 1);
    let mut body = sockaddr_in6(dst);
    body.extend(unspec_v6_sockaddr(&[0xff; 8]));
    let message = rt_message(
      9,
      libc::RTF_UP,
      addrs_mask(&[RTAX_DST, RTAX_NETMASK]),
      &body,
    );

    let mut routes = Vec::new();
    route::parse_route_table(&message, |index, flags, dst, gateway, netmask| {
      if let Some(dst) = dst {
        if let Some(route) = build_routev6(index, flags, dst, gateway, netmask) {
          routes.push(route);
        }
      }
    })
    .unwrap();

    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].index(), 9);
    assert_eq!(routes[0].destination(), &Ipv6Net::new(dst, 64).unwrap());
    assert_eq!(routes[0].gateway(), None);
  }

  #[test]
  fn route_walker_builds_tunnel_v6_from_compact_unspec_mask() {
    let dst = Ipv6Addr::new(2001, 0xdb8, 0xfeed, 0, 0, 0, 0, 4);
    let gateway = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let mut body = sockaddr_in6(dst);
    body.extend(sockaddr_in6(gateway));
    body.extend(unspec_v6_sockaddr(&[
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xfc,
    ]));
    let message = rt_message(
      4,
      libc::RTF_UP | libc::RTF_GATEWAY,
      addrs_mask(&[RTAX_DST, RTAX_GATEWAY, RTAX_NETMASK]),
      &body,
    );

    let mut routes = Vec::new();
    route::parse_route_table(&message, |index, flags, dst, gateway, netmask| {
      if let Some(dst) = dst {
        if let Some(route) = build_routev6(index, flags, dst, gateway, netmask) {
          routes.push(route);
        }
      }
    })
    .unwrap();

    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].destination(), &Ipv6Net::new(dst, 126).unwrap());
    assert_eq!(routes[0].gateway(), Some(gateway));
  }

  #[test]
  fn parse_addrs_uses_destination_context_for_compact_unspec_v4_mask() {
    let mut body = sockaddr_in(Ipv4Addr::new(198, 51, 100, 0));
    body.extend(unspec_v4_sockaddr(&[255, 255, 255]));

    let addrs = parse_addrs(addrs_mask(&[RTAX_DST, RTAX_NETMASK]), &body).unwrap();
    assert_eq!(
      addrs[RTAX_NETMASK as usize],
      Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)))
    );
  }

  #[test]
  fn parse_addrs_uses_gateway_context_for_compact_unspec_v6_mask() {
    let gateway = Ipv6Addr::new(0x2001, 0xdb8, 0xbeef, 0, 0, 0, 0, 1);
    let mut body = sockaddr_in6(gateway);
    body.extend(unspec_v6_sockaddr(&[0xff; 8]));

    let addrs = parse_addrs(addrs_mask(&[RTAX_GATEWAY, RTAX_NETMASK]), &body).unwrap();
    assert_eq!(
      addrs[RTAX_NETMASK as usize],
      Some(IpAddr::V6(Ipv6Addr::new(
        0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0
      )))
    );
  }

  #[test]
  fn parse_addrs_uses_later_ifa_context_for_compact_unspec_v6_mask() {
    let ifa = Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0, 0, 0, 0, 1);
    let mut body = unspec_v6_sockaddr(&[0xff; 8]);
    body.extend(sockaddr_in6(ifa));

    let addrs = parse_addrs(addrs_mask(&[RTAX_NETMASK, RTAX_IFA]), &body).unwrap();
    assert_eq!(
      addrs[RTAX_NETMASK as usize],
      Some(IpAddr::V6(Ipv6Addr::new(
        0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0
      )))
    );
    assert_eq!(addrs[RTAX_IFA as usize], Some(IpAddr::V6(ifa)));
  }

  #[test]
  fn parse_addrs_preserves_full_and_explicit_v6_masks() {
    let full = Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0);
    let mut full_unspec = vec![0u8; SOCK6];
    full_unspec[0] = SOCK6 as u8;
    full_unspec[1] = AF_UNSPEC as u8;
    full_unspec[8..24].copy_from_slice(&full.octets());
    let addrs = parse_addrs(addrs_mask(&[RTAX_NETMASK]), &padded_sockaddr(&full_unspec)).unwrap();
    assert_eq!(addrs[RTAX_NETMASK as usize], Some(IpAddr::V6(full)));

    let explicit = Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0);
    let mut explicit_unspec = vec![0u8; 16];
    explicit_unspec[0] = explicit_unspec.len() as u8;
    explicit_unspec[1] = AF_INET6 as u8;
    explicit_unspec[8..].copy_from_slice(&explicit.octets()[..8]);
    let addrs = parse_addrs(
      addrs_mask(&[RTAX_NETMASK]),
      &padded_sockaddr(&explicit_unspec),
    )
    .unwrap();
    assert_eq!(addrs[RTAX_NETMASK as usize], Some(IpAddr::V6(explicit)));
  }

  #[test]
  fn parse_addrs_keeps_zero_filler_absent() {
    let filler = padded_sockaddr(&[0]);
    let addrs = parse_addrs(addrs_mask(&[RTAX_NETMASK]), &filler).unwrap();
    assert_eq!(addrs[RTAX_NETMASK as usize], None);

    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    assert!(build_routev6(1, libc::RTF_UP, dst.into(), None, None).is_none());
  }

  #[test]
  fn parse_addrs_rejects_truncated_declared_sockaddr() {
    let mut truncated = vec![0u8; SOCK4 - 1];
    truncated[0] = SOCK4 as u8;
    truncated[1] = AF_INET as u8;
    let err = parse_addrs(addrs_mask(&[RTAX_NETMASK]), &truncated).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
  }

  #[test]
  fn parse_addrs_does_not_borrow_next_frame_for_short_unspec_addresses() {
    let short = unspec_v4_sockaddr(&[192, 0, 2]);
    let mask = padded_sockaddr(&[8, AF_INET as u8, 0, 0, 255, 255, 255, 0]);

    let mut dst_then_mask = short.clone();
    dst_then_mask.extend(&mask);
    let err = parse_addrs(addrs_mask(&[RTAX_DST, RTAX_NETMASK]), &dst_then_mask).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);

    let mut gateway_then_mask = short;
    gateway_then_mask.extend(&mask);
    let err = parse_addrs(
      addrs_mask(&[RTAX_GATEWAY, RTAX_NETMASK]),
      &gateway_then_mask,
    )
    .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
  }

  #[cfg(apple)]
  #[test]
  fn parse_addrs_accepts_unpadded_final_unspec_mask_on_apple() {
    let mut body = sockaddr_in(Ipv4Addr::new(198, 51, 100, 0));
    body.extend([7, AF_UNSPEC as u8, 0, 0, 255, 255, 255]);

    let addrs = parse_addrs(addrs_mask(&[RTAX_DST, RTAX_NETMASK]), &body).unwrap();
    assert_eq!(
      addrs[RTAX_NETMASK as usize],
      Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)))
    );
  }

  #[test]
  fn parse_link_addr_skips_non_utf8_name() {
    let mut buf = [0u8; 9];
    // sockaddr_dl fields after len/family/index: type, nlen, alen, slen.
    buf[0] = buf.len() as u8;
    buf[5] = 1;
    buf[8] = 0xff;
    assert!(parse(&buf).unwrap().is_none());
  }

  #[cfg(target_os = "dragonfly")]
  #[test]
  fn dragonfly_v7_ifa_header_decodes_loopback_fixture() {
    use super::compat::IfaMsghdr;

    const HEADER_SIZE: usize = 24;
    let addrs_mask = (1u32 << RTAX_NETMASK as u32) | (1u32 << RTAX_IFA as u32);
    let mut message = vec![0u8; HEADER_SIZE + 8 + 16];

    let message_len = message.len() as u16;
    message[0..2].copy_from_slice(&message_len.to_ne_bytes());
    message[2] = RTM_VERSION as u8;
    message[3] = RTM_NEWADDR as u8;
    message[4..6].copy_from_slice(&2u16.to_ne_bytes()); // lo0 in the CI VM
    message[8..12].copy_from_slice(&1i32.to_ne_bytes()); // ifam_flags
    message[12..16].copy_from_slice(&(addrs_mask as i32).to_ne_bytes());

    // Compact IPv4 /8 netmask followed by a full 127.0.0.1 sockaddr.
    message[HEADER_SIZE..HEADER_SIZE + 8].copy_from_slice(&[8, AF_INET as u8, 0, 0, 255, 0, 0, 0]);
    message[HEADER_SIZE + 8..].copy_from_slice(&[
      16,
      AF_INET as u8,
      0,
      0,
      127,
      0,
      0,
      1,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
    ]);

    assert_eq!(mem::size_of::<IfaMsghdr>(), HEADER_SIZE);
    // SAFETY: `message` contains at least HEADER_SIZE initialized bytes;
    // read_unaligned copies the repr(C) header into an aligned local.
    let header: IfaMsghdr = unsafe { core::ptr::read_unaligned(message.as_ptr().cast()) };
    assert_eq!(header.ifam_index, 2);
    assert_eq!(header.ifam_addrs as u32, addrs_mask);

    let addrs = parse_addrs(header.ifam_addrs as u32, &message[HEADER_SIZE..]).unwrap();
    let mask = addrs[RTAX_NETMASK as usize].unwrap();
    assert_eq!(ip_mask_to_prefix(mask).unwrap(), 8);
    assert_eq!(
      addrs[RTAX_IFA as usize],
      Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
    );
  }
}
