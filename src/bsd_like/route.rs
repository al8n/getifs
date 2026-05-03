use std::{io, net::IpAddr};

use libc::{NET_RT_DUMP, RTAX_DST, RTAX_GATEWAY, RTAX_NETMASK, RTM_GET};

use super::{compat::RtMsghdr, fetch, invalid_message, message_too_short, parse_addrs};

/// Walk every entry in the kernel routing-table sysctl dump (`NET_RT_DUMP`).
/// Calls `on_route(index, destination, gateway, netmask)` for each
/// `RTM_GET` message — all four come straight from `parse_addrs` so the
/// caller decides how to merge the destination address with the netmask
/// to form a CIDR.
///
/// `family` is forwarded to sysctl: `AF_UNSPEC` for both families,
/// `AF_INET` / `AF_INET6` to limit the dump to one family.
pub(super) fn walk_route_table<F>(family: i32, mut on_route: F) -> io::Result<()>
where
  F: FnMut(u32, Option<IpAddr>, Option<IpAddr>, Option<IpAddr>),
{
  let buf = fetch(family, NET_RT_DUMP, 0)?;

  unsafe {
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

      if src[3] as i32 != RTM_GET {
        src = &src[l..];
        continue;
      }

      let rtm = &*(src.as_ptr() as *const RtMsghdr);

      let header_size = std::mem::size_of::<RtMsghdr>();
      if l < header_size {
        return Err(message_too_short());
      }

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
