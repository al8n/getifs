use std::{io, net::IpAddr};

use libc::{NET_RT_DUMP, RTAX_DST, RTAX_GATEWAY, RTAX_NETMASK, RTF_UP, RTM_GET};

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
/// **Per-message parse failures are tolerated**, not propagated. The
/// alternative (erroring out the whole walk on the first message that
/// `parse_addrs` can't decode) makes `route_table` unusable on NetBSD
/// and OpenBSD, where the kernel emits some sockaddr forms (notably
/// AF_LINK gateways and short netmasks) that the FreeBSD/Apple-shaped
/// `parse_addrs` doesn't yet decode — even though most other route
/// entries on those hosts parse fine. Returning a partial table with
/// the parseable entries is strictly more useful than returning
/// nothing, but does mean callers on NetBSD/OpenBSD may not see every
/// route the kernel knows about. Teaching `parse_addrs` the per-OS
/// encodings is a follow-up.
///
/// Length-shorter-than-header (`l < size_of::<RtMsghdr>()`) is *not*
/// tolerated — that's a real kernel-side bug. Trailing zero padding
/// (`l == 0` or `src.len() < l`) is the kernel's normal end-of-stream
/// sentinel and terminates the loop cleanly.
pub(super) fn walk_route_table<F>(family: i32, mut on_route: F) -> io::Result<()>
where
  F: FnMut(u32, libc::c_int, Option<IpAddr>, Option<IpAddr>, Option<IpAddr>),
{
  let buf = fetch(family, NET_RT_DUMP, 0)?;

  unsafe {
    let mut src = buf.as_slice();

    while src.len() > 4 {
      let l = u16::from_ne_bytes(src[..2].try_into().unwrap()) as usize;

      // `l == 0` only happens for residual zero-padding past the last
      // valid message. `src.len() < l` means the kernel told us the
      // next message would extend past the buffer it just handed us —
      // either way, treat as end-of-stream rather than an error.
      if l == 0 || src.len() < l {
        break;
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
      // unicast/local routes, not every kernel routing entry. `RTF_UP`
      // weeds out down/expired routes the kernel keeps for tracking;
      // multicast destinations are filtered downstream in
      // `bsd_like.rs::build_routev4` / `build_routev6` (where we know
      // the parsed family).
      if (rtm.rtm_flags & RTF_UP) == 0 {
        src = &src[l..];
        continue;
      }

      // Tolerate per-message `parse_addrs` failures on NetBSD/OpenBSD
      // (see the function-level doc comment). Skip the route, advance
      // to the next message — don't fail the whole walk.
      let addrs = match parse_addrs(rtm.rtm_addrs as u32, &src[header_size..l]) {
        Ok(addrs) => addrs,
        Err(_) => {
          src = &src[l..];
          continue;
        }
      };

      let dst = addrs[RTAX_DST as usize];
      let gateway = addrs[RTAX_GATEWAY as usize];
      let netmask = addrs[RTAX_NETMASK as usize];

      on_route(rtm.rtm_index as u32, rtm.rtm_flags, dst, gateway, netmask);

      src = &src[l..];
    }
  }

  Ok(())
}
