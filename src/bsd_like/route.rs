use std::{io, net::IpAddr};

use libc::{NET_RT_DUMP, RTAX_DST, RTAX_GATEWAY, RTAX_NETMASK, RTM_GET};

use super::{compat::RtMsghdr, fetch, parse_addrs};

/// Walk every entry in the kernel routing-table sysctl dump (`NET_RT_DUMP`).
/// Calls `on_route(index, destination, gateway, netmask)` for each
/// `RTM_GET` message — all four come straight from `parse_addrs` so the
/// caller decides how to merge the destination address with the netmask
/// to form a CIDR.
///
/// `family` is forwarded to sysctl: `AF_UNSPEC` for both families,
/// `AF_INET` / `AF_INET6` to limit the dump to one family.
///
/// Per-message parse failures (`parse_addrs` errors, length-truncated
/// entries, sentinel zero-length padding at the buffer tail, messages
/// shorter than the rt_msghdr header) are tolerated — those routes are
/// silently skipped instead of failing the whole walk. NetBSD and
/// OpenBSD in particular emit `NET_RT_DUMP` messages whose sockaddr
/// layout doesn't match the FreeBSD/Apple shape `parse_addrs` was built
/// for, and erroring out mid-walk would discard every route on those
/// platforms. Only sysctl-level errors propagate as `io::Error`.
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
        // Message is shorter than the header type we'd cast it to —
        // can't safely interpret it. Skip rather than UB-cast.
        src = &src[l..];
        continue;
      }

      // `Vec<u8>` only formally guarantees u8 alignment for its data
      // pointer, so creating `&*(src.as_ptr() as *const RtMsghdr)` is
      // UB even when each BSD's sysctl kernel-side padding makes the
      // bytes happen to land aligned in practice. `read_unaligned`
      // copies into a properly-aligned local without that assumption.
      // (The same caveat applies to the sockaddr derefs reached via
      // `parse_addrs` — those live in shared pre-existing code paths
      // and are tracked separately.)
      let rtm: RtMsghdr = std::ptr::read_unaligned(src.as_ptr() as *const RtMsghdr);

      // Tolerate per-message sockaddr parse failures: this is the only
      // way to get *any* routes back on NetBSD/OpenBSD where
      // `parse_addrs` is too strict for some entries.
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

      on_route(rtm.rtm_index as u32, dst, gateway, netmask);

      src = &src[l..];
    }
  }

  Ok(())
}
