use std::{io, net::IpAddr};

use libc::{NET_RT_DUMP, RTAX_DST, RTAX_GATEWAY, RTAX_NETMASK, RTM_GET};

use super::{compat::RtMsghdr, fetch, message_too_short, parse_addrs};

/// Walk every entry in the kernel routing-table sysctl dump (`NET_RT_DUMP`).
/// Calls `on_route(index, destination, gateway, netmask)` for each
/// `RTM_GET` message — all four come straight from `parse_addrs` so the
/// caller decides how to merge the destination address with the netmask
/// to form a CIDR.
///
/// `family` is forwarded to sysctl: `AF_UNSPEC` for both families,
/// `AF_INET` / `AF_INET6` to limit the dump to one family.
///
/// Errors propagate. We do *not* swallow `parse_addrs` failures: a
/// silent skip would let `route_table_by_filter(|r| r.is_default())`
/// return `Ok(empty)` even when the host has a default route the parser
/// happened to choke on, and the caller has no way to detect the
/// result is incomplete. With the `parse_inet_addr` alignment fix in
/// place (`bsd_like.rs`), the only remaining failure mode is a
/// genuinely malformed kernel message — which deserves an explicit
/// `io::Error`. Trailing zero padding (`l == 0` / `src.len() < l`) is
/// the kernel's normal end-of-stream sentinel and still terminates the
/// loop cleanly.
pub(super) fn walk_route_table<F>(family: i32, mut on_route: F) -> io::Result<()>
where
  F: FnMut(u32, Option<IpAddr>, Option<IpAddr>, Option<IpAddr>),
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

      // Propagate parse failures: silently dropping routes here would
      // corrupt the caller's view of the routing table (e.g. lose the
      // default route on multi-WAN hosts).
      let addrs = parse_addrs(rtm.rtm_addrs as u32, &src[header_size..l])?;

      let dst = addrs[RTAX_DST as usize];
      let gateway = addrs[RTAX_GATEWAY as usize];
      let netmask = addrs[RTAX_NETMASK as usize];

      on_route(rtm.rtm_index as u32, dst, gateway, netmask);

      src = &src[l..];
    }
  }

  Ok(())
}
