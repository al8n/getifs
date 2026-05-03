use ipnet::{ip_mask_to_prefix, Ipv4Net, Ipv6Net};
use libc::{
  c_void, if_msghdr, size_t, sysctl, AF_INET, AF_INET6, AF_LINK, AF_ROUTE, AF_UNSPEC, CTL_NET,
  NET_RT_IFLIST, RTAX_BRD, RTAX_IFA, RTAX_MAX, RTAX_NETMASK, RTM_IFINFO, RTM_NEWADDR, RTM_VERSION,
};
// `NET_RT_IFLIST2` is an Apple-only sysctl target. Keep it out of the
// cross-BSD top-level import — the libc crate does not expose it on
// FreeBSD/DragonFly/NetBSD/OpenBSD.
#[cfg(apple)]
use libc::NET_RT_IFLIST2;

// `libc::ifa_msghdr` is absent on NetBSD/OpenBSD. Route it through the
// compat module, which provides a local definition on those targets
// and re-exports `libc::ifa_msghdr` everywhere else.
use compat::IfaMsghdr as ifa_msghdr;
use smallvec_wrapper::{SmallVec, TinyVec};
use smol_str::SmolStr;
use std::{
  io, mem,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
  ptr::null_mut,
};

use super::{
  IfNet, Ifv4Net, Ifv6Net, Interface, MacAddr, Net, Route, Routev4, Routev6, MAC_ADDRESS_SIZE,
};

// `Address` / `IfAddr` / `Ifv4Addr` / `Ifv6Addr` are only referenced
// inside the `cfg_bsd_multicast!`-gated `interface_multiaddr_table`
// impls, which only expand for Apple, FreeBSD, and DragonFly. Gating
// the import to the same cfg keeps NetBSD/OpenBSD builds warning-free.
#[cfg(any(
  target_vendor = "apple",
  target_os = "freebsd",
  target_os = "dragonfly"
))]
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
  dst: IpAddr,
  gateway: Option<IpAddr>,
  netmask: Option<IpAddr>,
) -> Option<Routev4> {
  let dst_v4 = match dst {
    IpAddr::V4(ip) => ip,
    _ => return None,
  };
  // BSD encodes a default route's netmask as either an all-zero
  // sockaddr or as the kernel-form length=0 entry, both of which come
  // back from `parse_addrs` as 0.0.0.0 and yield prefix 0. A missing
  // RTAX_NETMASK on a v4 route means the kernel is describing a host
  // route — fall back to /32 in that case.
  let prefix_len = match netmask {
    Some(IpAddr::V4(m)) => ip_mask_to_prefix(IpAddr::V4(m)).ok()?,
    Some(IpAddr::V6(_)) => return None,
    None => 32,
  };
  let net = Ipv4Net::new(dst_v4, prefix_len).ok()?;
  let gw = match gateway {
    Some(IpAddr::V4(g)) if g != Ipv4Addr::UNSPECIFIED => Some(g),
    _ => None,
  };
  Some(Routev4::new(index, net, gw))
}

#[inline]
fn build_routev6(
  index: u32,
  dst: IpAddr,
  gateway: Option<IpAddr>,
  netmask: Option<IpAddr>,
) -> Option<Routev6> {
  let dst_v6 = match dst {
    IpAddr::V6(ip) => ip,
    _ => return None,
  };
  let prefix_len = match netmask {
    Some(IpAddr::V6(m)) => ip_mask_to_prefix(IpAddr::V6(m)).ok()?,
    Some(IpAddr::V4(_)) => return None,
    None => 128,
  };
  let net = Ipv6Net::new(dst_v6, prefix_len).ok()?;
  let gw = match gateway {
    Some(IpAddr::V6(g)) if g != Ipv6Addr::UNSPECIFIED => Some(g),
    _ => None,
  };
  Some(Routev6::new(index, net, gw))
}

pub(super) fn route_table_by_filter<F>(mut f: F) -> io::Result<SmallVec<Route>>
where
  F: FnMut(&Route) -> bool,
{
  let mut out: SmallVec<Route> = SmallVec::new();
  route::walk_route_table(AF_UNSPEC, |index, dst, gw, mask| {
    let dst = match dst {
      Some(ip) => ip,
      None => return,
    };
    let route = match dst {
      IpAddr::V4(_) => build_routev4(index, dst, gw, mask).map(Route::V4),
      IpAddr::V6(_) => build_routev6(index, dst, gw, mask).map(Route::V6),
    };
    if let Some(r) = route {
      if f(&r) {
        out.push(r);
      }
    }
  })?;
  Ok(out)
}

pub(super) fn route_ipv4_table_by_filter<F>(mut f: F) -> io::Result<SmallVec<Routev4>>
where
  F: FnMut(&Routev4) -> bool,
{
  let mut out: SmallVec<Routev4> = SmallVec::new();
  route::walk_route_table(AF_INET, |index, dst, gw, mask| {
    let dst = match dst {
      Some(ip) => ip,
      None => return,
    };
    if let Some(r) = build_routev4(index, dst, gw, mask) {
      if f(&r) {
        out.push(r);
      }
    }
  })?;
  Ok(out)
}

pub(super) fn route_ipv6_table_by_filter<F>(mut f: F) -> io::Result<SmallVec<Routev6>>
where
  F: FnMut(&Routev6) -> bool,
{
  let mut out: SmallVec<Routev6> = SmallVec::new();
  route::walk_route_table(AF_INET6, |index, dst, gw, mask| {
    let dst = match dst {
      Some(ip) => ip,
      None => return,
    };
    if let Some(r) = build_routev6(index, dst, gw, mask) {
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

#[inline]
fn invalid_mask(e: ipnet::PrefixLenError) -> io::Error {
  io::Error::new(io::ErrorKind::InvalidData, e)
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

fn parse(mut b: &[u8]) -> io::Result<(SmolStr, Option<MacAddr>)> {
  if b.len() < 8 {
    return Err(invalid_address());
  }

  b = &b[4..];

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

  let l = 4 + nlen + alen + slen;
  if b.len() < l {
    return Err(invalid_address());
  }

  let mut data = &b[4..];
  let name = if nlen > 0 {
    let name = core::str::from_utf8(&data[..nlen])
      .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    data = &data[nlen..];
    SmolStr::from(name)
  } else {
    SmolStr::default()
  };

  let addr = if alen == MAC_ADDRESS_SIZE {
    Some(MacAddr::from_raw(data[..alen].try_into().unwrap()))
  } else {
    None
  };

  Ok((name, addr))
}

fn parse_kernel_inet_addr(b: &[u8]) -> io::Result<(usize, IpAddr)> {
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

fn parse_inet_addr(af: i32, b: &[u8]) -> io::Result<(usize, IpAddr)> {
  const SOCK4: usize = size_of::<libc::sockaddr_in>();
  const SOCK6: usize = size_of::<libc::sockaddr_in6>();

  // Sysctl returns a `Vec<u8>`, which only formally guarantees u8
  // alignment for its data pointer. The kernel pads each routing
  // message to KERNAL_ALIGN bytes (4 on Apple, 8 elsewhere), so the
  // sockaddr offsets happen to land on a usable boundary in practice
  // — but creating `&libc::sockaddr_in[6]` from `b.as_ptr()` is still
  // UB by the language rules whenever `b` isn't aligned for the
  // target type. `read_unaligned` copies into an aligned local
  // without that assumption; the resulting load is the same on x86 /
  // ARM, but defined behaviour everywhere (including strict-alignment
  // targets like SPARC). All BSD callers — gateway, address, route,
  // and multicast walkers — go through this function.
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

      let mut ip = sockaddr.sin6_addr.s6_addr;
      // TODO: create own Ipv6Addr
      let _zone_id = sockaddr.sin6_scope_id;
      let mut addr: Ipv6Addr = ip.into();
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
          addr = ip.into();
        }
      }

      Ok((SOCK6, addr.into()))
    }
    _ => Err(invalid_address()),
  }
}

fn parse_addrs(addrs: u32, mut b: &[u8]) -> io::Result<[Option<IpAddr>; RTAX_MAX as usize]> {
  let mut as_ = [None; RTAX_MAX as usize];

  #[allow(clippy::needless_range_loop)]
  for i in 0..RTAX_MAX as usize {
    if b.len() < KERNAL_ALIGN {
      break;
    }

    if addrs & (1 << i) == 0 {
      continue;
    }

    if i <= RTAX_BRD as usize {
      match b[1] as i32 {
        AF_LINK => {
          let l = roundup(b[0] as usize);
          if b.len() < l {
            return Err(io::Error::new(
              io::ErrorKind::InvalidData,
              "message too short",
            ));
          }
          b = &b[l..];
        }
        AF_INET | AF_INET6 => {
          let (_, addr) = parse_inet_addr(b[1] as i32, b)?;
          as_[i] = Some(addr);
          let l = roundup(b[0] as usize);
          if b.len() < l {
            return Err(io::Error::new(
              io::ErrorKind::InvalidData,
              "message too short",
            ));
          }
          b = &b[l..];
        }
        _ => {
          let (l, addr) = parse_kernel_inet_addr(b)?;
          as_[i] = Some(addr);
          let ll = roundup(l);
          if b.len() < ll {
            b = &b[l..];
          } else {
            b = &b[ll..];
          }
        }
      }
    } else {
      let l = roundup(b[0] as usize);
      if b.len() < l {
        return Err(io::Error::new(
          io::ErrorKind::InvalidData,
          "message too short",
        ));
      }
      b = &b[l..];
    }
  }

  Ok(as_)
}

fn fetch(family: i32, rt: i32, flag: i32) -> io::Result<Vec<u8>> {
  unsafe {
    let mut mib = [CTL_NET, AF_ROUTE, 0, family, rt, flag];

    // Get buffer size
    let mut len: size_t = 0;
    if sysctl(mib.as_mut_ptr(), 6, null_mut(), &mut len, null_mut(), 0) < 0 {
      return Err(io::Error::last_os_error());
    }

    // Allocate buffer
    let mut buf = vec![0u8; len];
    if sysctl(
      mib.as_mut_ptr(),
      6,
      buf.as_mut_ptr() as *mut c_void,
      &mut len,
      null_mut(),
      0,
    ) < 0
    {
      return Err(io::Error::last_os_error());
    }

    Ok(buf)
  }
}

pub(super) fn interface_table(idx: u32) -> io::Result<TinyVec<Interface>> {
  unsafe {
    let buf = fetch(AF_UNSPEC, NET_RT_IFLIST, idx as i32)?;
    let mut results = TinyVec::new();

    let mut src = buf.as_slice();
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
          let (name, mac) = parse(&src[HEADER_SIZE..l])?;
          let interface = Interface {
            index: ifm.ifm_index as u32,
            // `ifi_mtu` is `u_int32_t` on Apple, `u_long` on FreeBSD/
            // DragonFly, `uint64_t` on NetBSD, `u_int` on OpenBSD. Cast
            // narrows to `u32` to match `Interface.mtu`'s type —
            // realistic MTUs never exceed 65535 so this is lossless in
            // practice.
            mtu: ifm.ifm_data.ifi_mtu as u32,
            name,
            mac_addr: mac,
            flags: Flags::from_bits_truncate(ifm.ifm_flags as u32),
          };
          results.push(interface);
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

pub(super) fn interface_addr_table<T, F>(family: i32, idx: u32, mut f: F) -> io::Result<SmallVec<T>>
where
  T: Net,
  F: FnMut(&IpAddr) -> bool,
{
  const HEADER_SIZE: usize = mem::size_of::<ifa_msghdr>();

  unsafe {
    let buf = fetch(family, NET_RT_IFLIST, idx as i32)?;
    let mut results = SmallVec::new();
    let mut b = buf.as_slice();

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

        if let (Some(ip), Some(mask)) = (ip, mask) {
          if let Some(ifa) = T::try_from_with_filter(
            ifam.ifam_index as u32,
            ip,
            mask.map_err(invalid_mask)?,
            |addr| f(addr),
          ) {
            results.push(ifa);
          }
        }
      }

      b = &b[len..];
    }

    Ok(results)
  }
}

cfg_bsd_multicast!(
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
);

cfg_apple!(
  pub(super) fn interface_multiaddr_table<T, F>(
    family: i32,
    idx: u32,
    mut f: F,
  ) -> io::Result<SmallVec<T>>
  where
    T: Address,
    F: FnMut(&IpAddr) -> bool,
  {
    const HEADER_SIZE: usize = mem::size_of::<libc::ifma_msghdr2>();

    unsafe {
      let buf = fetch(family, NET_RT_IFLIST2, idx as i32)?;

      let mut results = SmallVec::new();
      let mut b = buf.as_slice();

      while b.len() > HEADER_SIZE {
        // SAFETY: u8-aligned sysctl buffer; copy header out before reading fields.
        let ifam: libc::ifma_msghdr2 =
          core::ptr::read_unaligned(b.as_ptr() as *const libc::ifma_msghdr2);
        let len = ifam.ifmam_msglen as usize;

        // Same per-message length checks as `interface_addr_table`.
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

// FreeBSD and DragonFly share the same `NET_RT_IFMALIST` sysctl ABI and
// `ifma_msghdr` layout (DragonFly forked from FreeBSD before the
// multicast group enumeration sysctl was added on either side and they
// haven't diverged). The constant + struct just aren't exposed by
// `libc` for DragonFly, so they are defined locally in
// `bsd_like/compat.rs`.
#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
pub(super) fn interface_multiaddr_table<T, F>(
  family: i32,
  idx: u32,
  mut f: F,
) -> io::Result<SmallVec<T>>
where
  T: Address,
  F: FnMut(&IpAddr) -> bool,
{
  use compat::{IfmaMsghdr, NET_RT_IFMALIST};

  const HEADER_SIZE: usize = mem::size_of::<IfmaMsghdr>();

  unsafe {
    let buf = fetch(family, NET_RT_IFMALIST, idx as i32)?;
    let mut results = SmallVec::new();
    let mut b = buf.as_slice();

    while b.len() > HEADER_SIZE {
      // SAFETY: u8-aligned sysctl buffer; copy header out before reading fields.
      let ifam: IfmaMsghdr = core::ptr::read_unaligned(b.as_ptr() as *const IfmaMsghdr);
      let len = ifam.ifmam_msglen as usize;

      // Same per-message length checks as `interface_addr_table`.
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
