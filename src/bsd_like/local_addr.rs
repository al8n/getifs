use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use libc::{
  AF_INET, AF_INET6, NET_RT_DUMP, RTAX_DST, RTF_BLACKHOLE, RTF_BROADCAST, RTF_REJECT, RTF_UP,
};

// Same `RTF_MULTICAST` cfg shim as `bsd_like/route.rs`: NetBSD's libc
// bindings don't export it, so fall back to 0 (no-op bit).
#[cfg(any(
  apple,
  target_os = "freebsd",
  target_os = "dragonfly",
  target_os = "openbsd"
))]
use libc::RTF_MULTICAST;
#[cfg(target_os = "netbsd")]
const RTF_MULTICAST: libc::c_int = 0;
use smallvec_wrapper::SmallVec;

use super::{
  super::{ipv4_filter_to_ip_filter, ipv6_filter_to_ip_filter, local_ip_filter},
  compat::RtMsghdr,
  fetch, interface_addr_table_into, interface_addresses, interface_ipv4_addresses,
  interface_ipv6_addresses, message_too_short, parse_addrs, IfNet, Ifv4Net, Ifv6Net, Net,
};

pub(crate) fn best_local_ipv4_addrs() -> io::Result<SmallVec<Ifv4Net>> {
  let mut out = SmallVec::new();
  best_local_addrs_in(AF_INET, &mut out)?;
  Ok(out)
}

pub(crate) fn best_local_ipv6_addrs() -> io::Result<SmallVec<Ifv6Net>> {
  let mut out = SmallVec::new();
  best_local_addrs_in(AF_INET6, &mut out)?;
  Ok(out)
}

pub(crate) fn best_local_addrs() -> io::Result<SmallVec<IfNet>> {
  // Walk AF_INET and AF_INET6 separately rather than one AF_UNSPEC
  // dump. The kernel encodes "default route" by omitting `RTAX_DST`
  // entirely, and `best_local_addrs_in` only treats absent dst as
  // default in family-specific dumps (we'd otherwise have no way to
  // attribute the default to the right address family). With a single
  // AF_UNSPEC walk, hosts whose only default route uses that encoding
  // would silently get `Ok([])` from this call. Same tradeoff as
  // `route_table_by_filter` — two sysctl calls, one consistent answer.
  //
  // Both walks push into one shared `SmallVec<IfNet>` via the `_into`
  // helpers — the kernel only emits the requested family's addresses,
  // and `IfNet`'s `Net::try_from` accepts both, so this avoids the
  // intermediate per-family allocations.
  let mut out: SmallVec<IfNet> = SmallVec::new();
  // Wrap each family's walk so a single-stack BSD host (no v6 stack
  // / no v4 stack) returns the populated family rather than `Err`.
  // Same rationale and predicate as `route_table_by_filter`; see
  // `family_unavailable_to_empty` for the errno set.
  super::family_unavailable_to_empty(best_local_addrs_in(AF_INET, &mut out))?;
  super::family_unavailable_to_empty(best_local_addrs_in(AF_INET6, &mut out))?;
  Ok(out)
}

/// Per-route priority used to rank competing default routes. OpenBSD
/// is the only BSD that exposes a documented routing priority on the
/// route header (`rtm_priority`, lower wins — added when its
/// kernel grew per-priority routing). FreeBSD / NetBSD / DragonFly /
/// macOS have no equivalent field on `rt_msghdr`; the fields actually
/// present (`rmx_recvpipe`, `rmx_pksent`, etc.) are TCP-pipe metrics,
/// not routing priority. Returning `0` for those targets makes every
/// candidate compare equal, and the caller-side selector then
/// collects every default-route ifindex instead of arbitrarily
/// picking by an irrelevant TCP metric.
#[cfg(target_os = "openbsd")]
#[inline]
fn route_priority(rtm: &RtMsghdr) -> u8 {
  rtm.rtm_priority
}

#[cfg(not(target_os = "openbsd"))]
#[inline]
fn route_priority(_rtm: &RtMsghdr) -> u8 {
  0
}

fn best_local_addrs_in<T: Net>(family: i32, out: &mut SmallVec<T>) -> io::Result<()> {
  let best_oifs = best_route_interfaces(&fetch(family, NET_RT_DUMP, 0)?, family)?;

  // Fetch addresses for every selected interface, appending into the
  // caller-provided buffer. Returns immediately on the first syscall
  // failure and leaves the addresses already appended in `out`, unlike
  // `netlink_best_local_addrs_into`, which truncates `out` on error.
  for idx in best_oifs {
    interface_addr_table_into(family, idx as u32, local_ip_filter, out)?;
  }
  Ok(())
}

/// The interfaces of the best usable default routes for `family` in a
/// `NET_RT_DUMP` buffer, sorted and deduplicated.
pub(super) fn best_route_interfaces(routes: &[u8], family: i32) -> io::Result<SmallVec<u16>> {
  // Selection key: route priority (lower wins on OpenBSD, all-zero
  // elsewhere). `best_oifs` holds every interface that ties at the
  // current best priority. `rtm_rmx.rmx_recvpipe` is not a key: it is
  // a TCP receive-pipe metric, not a routing priority, so keying on it
  // would pick an interface based on irrelevant TCP state instead of
  // the one the kernel actually uses. On non-OpenBSD BSDs there is no
  // usable priority field at all, so we collect every default-route
  // oif and emit addresses for all of them; that's strictly more
  // conservative than picking arbitrarily.
  let mut best_oifs: SmallVec<u16> = SmallVec::new();
  let mut best_priority: u8 = u8::MAX;

  unsafe {
    let mut src = routes;
    while src.len() > 4 {
      let l = u16::from_ne_bytes(src[..2].try_into().unwrap()) as usize;
      // `l == 0` is the kernel's normal end-of-stream sentinel for
      // residual zero padding past the last valid record — same
      // contract as `walk_route_table`. Treating it as `InvalidData`
      // here would discard otherwise-valid default routes for one
      // family whenever the dump happened to land on a padded
      // boundary. Terminate the loop cleanly instead.
      if l == 0 {
        break;
      }
      if src.len() < l {
        return Err(message_too_short());
      }
      if src[2] as i32 != libc::RTM_VERSION {
        src = &src[l..];
        continue;
      }

      // SAFETY: `src` is a `Vec<u8>` (u8-aligned); copy the header
      // out via `read_unaligned` before reading fields. Same rationale
      // as `parse_route_table` / `parse_rt_generic_addrs` /
      // `parse_inet_addr` — see comments there.
      let header_size = std::mem::size_of::<RtMsghdr>();
      if l < header_size {
        // Message claims a length shorter than its own header type —
        // a kernel-side bug or version skew. Surface it (consistent
        // with `parse_route_table` / `parse_rt_generic_addrs`) rather
        // than reading past the message into the next entry.
        return Err(message_too_short());
      }
      let rtm: RtMsghdr = std::ptr::read_unaligned(src.as_ptr() as *const RtMsghdr);

      // Same usable-route filter as `bsd_like/route.rs`. A
      // `RTF_REJECT` / `RTF_BLACKHOLE` default route can be `RTF_UP`
      // with a low metric and would otherwise win the selection,
      // making `best_local_*` return addresses on an interface the
      // kernel never delivers via. `RTF_BROADCAST` / `RTF_MULTICAST`
      // are housekeeping routes the kernel attaches to interfaces
      // and not candidates for default-route selection.
      let unusable = RTF_REJECT | RTF_BLACKHOLE | RTF_BROADCAST | RTF_MULTICAST;
      if (rtm.rtm_flags & RTF_UP) == 0 || (rtm.rtm_flags & unusable) != 0 {
        src = &src[l..];
        continue;
      }

      // Source-specific default routes constrain selection to a
      // particular packet source, so a "best local address for any
      // outbound traffic" walk must not pick them — the addresses
      // returned would only be correct for traffic that already has
      // a matching source bound. Same per-platform shape as
      // `parse_route_table` (NetBSD: `RTF_SRC`; OpenBSD:
      // `RTAX_SRC` / `RTAX_SRCMASK` slots in `rtm_addrs`).
      #[cfg(target_os = "netbsd")]
      {
        if (rtm.rtm_flags & libc::RTF_SRC) != 0 {
          src = &src[l..];
          continue;
        }
      }
      #[cfg(target_os = "openbsd")]
      {
        let src_mask = (1u32 << libc::RTAX_SRC as u32) | (1u32 << libc::RTAX_SRCMASK as u32);
        if (rtm.rtm_addrs as u32 & src_mask) != 0 {
          src = &src[l..];
          continue;
        }
      }

      // Decode the address slots through the shared `parse_addrs`
      // helper so default-route detection here matches the
      // route-table walker. That helper:
      //   - returns `None` for the dst slot when the kernel omits
      //     `RTAX_DST` entirely (one BSD encoding of the default
      //     route is "no destination, only a gateway");
      //   - decodes the compact `sa_family = AF_INET[6]` short
      //     sockaddrs that NetBSD/OpenBSD emit for netmasks; a decoder
      //     that silently dropped them would leave `is_default` false
      //     for valid default routes.
      let addrs = parse_addrs(rtm.rtm_addrs as u32, &src[header_size..l])?;
      let dst = addrs[RTAX_DST as usize];
      let dst_present = (rtm.rtm_addrs as u32 & libc::RTA_DST as u32) != 0;
      let is_default = match (family, dst) {
        // Family-specific dump with no RTA_DST attribute at all → BSD's
        // alternate encoding for "default route for this family".
        (AF_INET, None) | (AF_INET6, None) if !dst_present => true,
        // Explicit unspecified destination, regardless of dump family.
        (_, Some(IpAddr::V4(v4))) if v4.is_unspecified() => true,
        (_, Some(IpAddr::V6(v6))) if v6.is_unspecified() => true,
        _ => false,
      };

      // Update the candidate set on lower priority; ties extend.
      // Same `< / ==` semantics as Linux's best-local walker.
      if is_default {
        let prio = route_priority(&rtm);
        if prio < best_priority {
          best_priority = prio;
          best_oifs.clear();
          best_oifs.push(rtm.rtm_index);
        } else if prio == best_priority {
          best_oifs.push(rtm.rtm_index);
        }
      }

      src = &src[l..];
    }
  }

  // Sort + dedup so a multipath default that lists the same interface
  // twice (or two separate defaults that share an interface) doesn't
  // make us walk the address dump twice for the same ifindex.
  best_oifs.sort_unstable();
  best_oifs.dedup();

  Ok(best_oifs)
}

pub(crate) fn local_ipv4_addrs() -> io::Result<SmallVec<Ifv4Net>> {
  interface_ipv4_addresses(0, local_ip_filter)
}

pub(crate) fn local_ipv6_addrs() -> io::Result<SmallVec<Ifv6Net>> {
  interface_ipv6_addresses(0, local_ip_filter)
}

pub(crate) fn local_addrs() -> io::Result<SmallVec<IfNet>> {
  interface_addresses(0, local_ip_filter)
}

pub(crate) fn local_ipv4_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv4Net>>
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  let mut f = ipv4_filter_to_ip_filter(f);
  interface_ipv4_addresses(0, move |addr| f(addr) && local_ip_filter(addr))
}

pub(crate) fn local_ipv6_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv6Net>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  let mut f = ipv6_filter_to_ip_filter(f);
  interface_ipv6_addresses(0, move |addr| f(addr) && local_ip_filter(addr))
}

pub(crate) fn local_addrs_by_filter<F>(mut f: F) -> io::Result<SmallVec<IfNet>>
where
  F: FnMut(&IpAddr) -> bool,
{
  interface_addresses(0, |addr| f(addr) && local_ip_filter(addr))
}

#[cfg(test)]
mod tests {
  use libc::{AF_UNSPEC, RTAX_GATEWAY, RTF_GATEWAY};

  use super::{
    super::tests::{addrs_mask, rt_message, sockaddr_in},
    *,
  };

  /// A route via `index` to `dst`, with no `RTAX_DST` slot when `dst` is
  /// `None`.
  fn route(index: u16, flags: libc::c_int, dst: Option<Ipv4Addr>) -> Vec<u8> {
    let gateway = sockaddr_in(Ipv4Addr::new(192, 0, 2, 1));
    match dst {
      Some(dst) => {
        let mut body = sockaddr_in(dst);
        body.extend(gateway);
        rt_message(index, flags, addrs_mask(&[RTAX_DST, RTAX_GATEWAY]), &body)
      }
      None => rt_message(index, flags, addrs_mask(&[RTAX_GATEWAY]), &gateway),
    }
  }

  #[test]
  fn selects_every_usable_default_route_interface() {
    let up = RTF_UP | RTF_GATEWAY;
    let mut buf = route(3, up, Some(Ipv4Addr::UNSPECIFIED));
    buf.extend(route(9, up, Some(Ipv4Addr::new(10, 0, 0, 0))));
    buf.extend(route(2, up, Some(Ipv4Addr::UNSPECIFIED)));
    buf.extend(route(3, up, Some(Ipv4Addr::UNSPECIFIED)));
    buf.extend(route(8, up | RTF_BLACKHOLE, Some(Ipv4Addr::UNSPECIFIED)));
    // A family-specific dump encodes a default route by omitting `RTAX_DST`.
    buf.extend(route(7, up, None));

    let oifs = best_route_interfaces(&buf, AF_INET).unwrap();
    assert_eq!(oifs.as_slice(), &[2, 3, 7]);
    // Without a family, a route with no destination is not a default route.
    let oifs = best_route_interfaces(&buf, AF_UNSPEC).unwrap();
    assert_eq!(oifs.as_slice(), &[2, 3]);
  }

  #[test]
  fn rejects_truncated_messages() {
    let message = route(3, RTF_UP, Some(Ipv4Addr::UNSPECIFIED));
    // The message declares more bytes than the buffer holds.
    let err = best_route_interfaces(&message[..message.len() - 1], AF_INET).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);

    // The declared length ends inside the header.
    let mut short = message.clone();
    short[..2].copy_from_slice(&8u16.to_ne_bytes());
    let err = best_route_interfaces(&short, AF_INET).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
  }
}
