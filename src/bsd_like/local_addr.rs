use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use libc::{AF_INET, AF_INET6, AF_UNSPEC, NET_RT_DUMP, RTA_DST, RTF_UP};
use smallvec_wrapper::SmallVec;

use crate::is_ipv6_unspecified;

use super::{
  super::{ipv4_filter_to_ip_filter, ipv6_filter_to_ip_filter, local_ip_filter},
  compat::RtMsghdr,
  fetch, interface_addresses, interface_ipv4_addresses, interface_ipv6_addresses, invalid_message,
  message_too_short, roundup, IfNet, Ifv4Net, Ifv6Net, Net,
};

pub(crate) fn best_local_ipv4_addrs() -> io::Result<SmallVec<Ifv4Net>> {
  best_local_addrs_in(AF_INET)
}

pub(crate) fn best_local_ipv6_addrs() -> io::Result<SmallVec<Ifv6Net>> {
  best_local_addrs_in(AF_INET6)
}

pub(crate) fn best_local_addrs() -> io::Result<SmallVec<IfNet>> {
  best_local_addrs_in(AF_UNSPEC)
}

fn best_local_addrs_in<T: Net>(family: i32) -> io::Result<SmallVec<T>> {
  // First get the default route to find the interface index
  let routes = fetch(family, NET_RT_DUMP, 0)?;
  let mut best_ifindex = None;
  // Widened to `u64` so the same variable can hold `rmx_recvpipe` across
  // BSDs — on Apple/OpenBSD the field is 32-bit, on FreeBSD/DragonFly
  // it's `u_long` (64-bit on LP64 hosts).
  let mut best_metric: u64 = u64::MAX;

  unsafe {
    let mut src = routes.as_slice();
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

      // SAFETY: `src` is a `Vec<u8>` (u8-aligned); copy the header
      // out via `read_unaligned` before reading fields. Same rationale
      // as `walk_route_table` / `rt_generic_addrs_in` /
      // `parse_inet_addr` — see comments there.
      let header_size = std::mem::size_of::<RtMsghdr>();
      if l < header_size {
        // Message claims a length shorter than its own header type;
        // skip rather than read past the message.
        src = &src[l..];
        continue;
      }
      let rtm: RtMsghdr = std::ptr::read_unaligned(src.as_ptr() as *const RtMsghdr);

      // Only consider UP routes
      if (rtm.rtm_flags & RTF_UP) == 0 {
        src = &src[l..];
        continue;
      }

      // Bounded address cursor — protects every read below from
      // overflowing into the next route message or off the sysctl
      // buffer if `sa_len` is malformed or the layout differs.
      let mut cur = &src[header_size..l];
      let mut addrs = rtm.rtm_addrs;
      let mut i = 1;
      let mut is_default = false;

      while addrs != 0 {
        if (addrs & 1) != 0 {
          const SA_HEADER: usize = std::mem::size_of::<libc::sockaddr>();
          if cur.len() < SA_HEADER {
            break;
          }
          // SAFETY: bounds-checked above.
          let sa: libc::sockaddr = std::ptr::read_unaligned(cur.as_ptr() as *const libc::sockaddr);
          match (family, sa.sa_family as i32, i) {
            (AF_INET, AF_INET, RTA_DST) | (AF_UNSPEC, AF_INET, RTA_DST) => {
              const SA_IN: usize = std::mem::size_of::<libc::sockaddr_in>();
              if cur.len() >= SA_IN {
                let sa_in: libc::sockaddr_in =
                  std::ptr::read_unaligned(cur.as_ptr() as *const libc::sockaddr_in);
                if sa_in.sin_addr.s_addr == 0 {
                  is_default = true;
                }
              }
            }
            (AF_INET6, AF_INET6, RTA_DST) | (AF_UNSPEC, AF_INET6, RTA_DST) => {
              const SA_IN6: usize = std::mem::size_of::<libc::sockaddr_in6>();
              if cur.len() >= SA_IN6 {
                let sa_in6: libc::sockaddr_in6 =
                  std::ptr::read_unaligned(cur.as_ptr() as *const libc::sockaddr_in6);
                if is_ipv6_unspecified(sa_in6.sin6_addr.s6_addr) {
                  is_default = true;
                }
              }
            }
            _ => {}
          }

          let sa_len = if sa.sa_len == 0 {
            SA_HEADER
          } else {
            sa.sa_len as usize
          };
          let advance = roundup(sa_len);
          if advance == 0 || advance > cur.len() {
            break;
          }
          cur = &cur[advance..];
        }
        i += 1;
        addrs >>= 1;
      }

      // If this is a default route and has better metric, update best_ifindex
      let metric = rtm.rtm_rmx.rmx_recvpipe as u64;
      if is_default && metric < best_metric {
        best_metric = metric;
        best_ifindex = Some(rtm.rtm_index);
      }

      src = &src[l..];
    }
  }

  // Only pass the interface index if we found a valid default route
  match best_ifindex {
    Some(idx) => super::interface_addr_table(family, idx as u32, local_ip_filter),
    None => Ok(SmallVec::new()),
  }
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
