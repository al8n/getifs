use std::{io, net::IpAddr};

use libc::{
  NET_RT_DUMP, RTAX_DST, RTAX_GATEWAY, RTAX_NETMASK, RTF_BLACKHOLE, RTF_BROADCAST, RTF_REJECT,
  RTF_UP, RTM_GET,
};

// `RTF_MULTICAST` exists on Apple / FreeBSD / DragonFly / OpenBSD but
// not on NetBSD's libc bindings. Pull it from libc where it exists,
// otherwise fall back to 0 so the bitmask is a no-op there.
#[cfg(any(
  apple,
  target_os = "freebsd",
  target_os = "dragonfly",
  target_os = "openbsd"
))]
use libc::RTF_MULTICAST;
#[cfg(target_os = "netbsd")]
const RTF_MULTICAST: libc::c_int = 0;

use super::{compat::RtMsghdr, fetch, message_too_short, parse_addrs};

/// Walk every entry in the kernel routing-table sysctl dump (`NET_RT_DUMP`).
/// Calls `on_route(index, rtm_flags, destination, gateway, netmask)` for
/// each `RTM_GET` message — all five come straight from the kernel
/// header / `parse_addrs` so the caller decides how to merge them into a
/// CIDR. `rtm_flags` is needed because BSD's "missing RTAX_NETMASK"
/// means different things for host routes (`RTF_HOST` set, implicit
/// `/max`) vs network routes (which must carry an explicit mask) — the
/// builder decides per-route whether `/max` is the right default.
///
/// `family` is forwarded to sysctl: `AF_UNSPEC` for both families,
/// `AF_INET` / `AF_INET6` to limit the dump to one family.
///
/// **Per-message parse failures are propagated**, not swallowed.
/// NetBSD and OpenBSD's compact-form netmask sockaddrs (where
/// `sa_family = AF_INET[6]` but `sa_len < size_of::<sockaddr_in[6]>()`)
/// decode through `parse_short_inet_addr`, so a `parse_addrs` failure
/// here is a real malformed message. Tolerating it would return a
/// successful but silently incomplete routing table, so it surfaces to
/// the caller.
///
/// Length-shorter-than-header (`l < size_of::<RtMsghdr>()`) is *not*
/// tolerated — that's a real kernel-side bug. A message that declares
/// more bytes than remain (`src.len() < l`) is truncation and fails the
/// walk too. Trailing zero padding (`l == 0`) is the kernel's normal
/// end-of-stream sentinel and terminates the loop cleanly.
pub(super) fn walk_route_table<F>(family: i32, on_route: F) -> io::Result<()>
where
  F: FnMut(u32, libc::c_int, Option<IpAddr>, Option<IpAddr>, Option<IpAddr>),
{
  parse_route_table(&fetch(family, NET_RT_DUMP, 0)?, on_route)
}

/// The message walk of [`walk_route_table`] over an already fetched
/// `NET_RT_DUMP` buffer.
pub(super) fn parse_route_table<F>(buf: &[u8], mut on_route: F) -> io::Result<()>
where
  F: FnMut(u32, libc::c_int, Option<IpAddr>, Option<IpAddr>, Option<IpAddr>),
{
  unsafe {
    let mut src = buf;

    while src.len() > 4 {
      let l = u16::from_ne_bytes(src[..2].try_into().unwrap()) as usize;

      // `l == 0` only happens for residual zero-padding past the last
      // valid message — terminate cleanly.
      if l == 0 {
        break;
      }
      // `src.len() < l` is *not* end-of-stream. The kernel just told
      // us "next message is `l` bytes" while only handing us fewer —
      // that's truncation (size-race / kernel-bug / buffer-too-small)
      // and silently breaking would surface as a partial routing
      // table with no signal to the caller.
      if src.len() < l {
        return Err(message_too_short());
      }

      if src[2] as i32 != libc::RTM_VERSION {
        src = &src[l..];
        continue;
      }

      if src[3] as i32 != RTM_GET {
        src = &src[l..];
        continue;
      }

      let header_size = std::mem::size_of::<RtMsghdr>();
      if l < header_size {
        // Message claims its own length but is shorter than the
        // header type we'd cast it to. That's a kernel-side bug or
        // truncation — surface it rather than silently dropping the
        // route.
        return Err(message_too_short());
      }

      // `Vec<u8>` only formally guarantees u8 alignment for its data
      // pointer, so creating `&*(src.as_ptr() as *const RtMsghdr)` is
      // UB even when each BSD's sysctl kernel-side padding makes the
      // bytes happen to land aligned in practice. `read_unaligned`
      // copies into a properly-aligned local without that assumption.
      let rtm: RtMsghdr = std::ptr::read_unaligned(src.as_ptr() as *const RtMsghdr);

      // Match the public-API contract: `route_table` returns
      // unicast/local routes, not every kernel routing entry.
      //   - `RTF_UP == 0`: down/expired routes the kernel keeps for
      //     tracking. Skip.
      //   - `RTF_REJECT`: deliberately drops packets with ICMP
      //     unreachable. Up, ordinary unicast destination, but the
      //     kernel never delivers traffic via it.
      //   - `RTF_BLACKHOLE`: silent drop. Same shape as REJECT.
      //   - `RTF_BROADCAST`: per-subnet broadcast routes (e.g.
      //     `192.168.1.255/32`) are kernel housekeeping for the
      //     broadcast address; their destination IP is *not*
      //     `255.255.255.255` so `Ipv4Addr::is_broadcast()` doesn't
      //     catch them downstream. Filter at the flag level.
      //   - `RTF_MULTICAST`: same idea for multicast routing entries
      //     where they are tagged. (Defence-in-depth in addition to
      //     the per-family multicast-IP check in `build_routev*`.)
      let unusable = RTF_REJECT | RTF_BLACKHOLE | RTF_BROADCAST | RTF_MULTICAST;
      if (rtm.rtm_flags & RTF_UP) == 0 || (rtm.rtm_flags & unusable) != 0 {
        src = &src[l..];
        continue;
      }

      // Source-specific routes constrain the kernel's selection to
      // packets matching a particular source prefix. A caller asking
      // "what route does the system use to reach X?" via
      // `route_table()` / default-route filters must not receive one
      // of these — applying it without honouring the source side
      // would describe a forwarding decision the kernel would not
      // actually make. Linux's netlink path already drops
      // `rtm_src_len != 0` / `RTA_SRC` routes; mirror that here for
      // the two BSDs that expose source-specific routing in the
      // sysctl dump.
      //   - NetBSD tags such routes with `RTF_SRC` in `rtm_flags`.
      //   - OpenBSD has no flag but emits `RTAX_SRC` / `RTAX_SRCMASK`
      //     slots in `rtm_addrs` (slot indices 8 and 9 — beyond
      //     `RTAX_BRD`, so `parse_addrs` ignores their addresses;
      //     the bitmask is the only signal).
      // FreeBSD / Apple / DragonFly have neither concept.
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

      // Per-message parse errors propagate — see function doc.
      let addrs = parse_addrs(rtm.rtm_addrs as u32, &src[header_size..l])?;

      let dst = addrs[RTAX_DST as usize];
      let gateway = addrs[RTAX_GATEWAY as usize];
      let netmask = addrs[RTAX_NETMASK as usize];

      on_route(rtm.rtm_index as u32, rtm.rtm_flags, dst, gateway, netmask);

      src = &src[l..];
    }
  }

  Ok(())
}

#[cfg(test)]
mod tests {
  use std::net::Ipv4Addr;

  use libc::{AF_INET, RTF_GATEWAY};

  use super::{
    super::tests::{addrs_mask, padded_sockaddr, rt_message, sockaddr_in},
    *,
  };

  type Route = (
    u32,
    libc::c_int,
    Option<IpAddr>,
    Option<IpAddr>,
    Option<IpAddr>,
  );

  fn routes(buf: &[u8]) -> io::Result<Vec<Route>> {
    let mut routes = Vec::new();
    parse_route_table(buf, |index, flags, dst, gateway, netmask| {
      routes.push((index, flags, dst, gateway, netmask));
    })?;
    Ok(routes)
  }

  #[test]
  fn reports_usable_route_with_compact_gateway_and_netmask() {
    let flags = RTF_UP | RTF_GATEWAY;
    let addrs = addrs_mask(&[RTAX_DST, RTAX_GATEWAY, RTAX_NETMASK]);
    let mut body = sockaddr_in(Ipv4Addr::new(10, 0, 0, 0));
    body.extend(padded_sockaddr(&[8, AF_INET as u8, 0, 0, 192, 0, 2, 1]));
    body.extend(padded_sockaddr(&[5, AF_INET as u8, 0, 0, 255]));

    let mut buf = rt_message(4, flags, addrs, &body);
    // A reject route is up but never delivers traffic.
    buf.extend(rt_message(5, RTF_UP | RTF_REJECT, addrs, &body));
    // Zero padding after the last message ends the dump.
    buf.extend([0u8; 8]);

    assert_eq!(
      routes(&buf).unwrap(),
      [(
        4,
        flags,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))),
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        Some(IpAddr::V4(Ipv4Addr::new(255, 0, 0, 0))),
      )]
    );
  }

  #[test]
  fn rejects_truncated_messages() {
    let addrs = addrs_mask(&[RTAX_DST]);
    let message = rt_message(4, RTF_UP, addrs, &sockaddr_in(Ipv4Addr::new(10, 0, 0, 0)));
    // The message declares more bytes than the buffer holds.
    let err = routes(&message[..message.len() - 1]).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);

    // The header claims a destination that the message does not carry; it
    // must not become a default route.
    let err = routes(&rt_message(4, RTF_UP, addrs, &[])).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
  }
}
