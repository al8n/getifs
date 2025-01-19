use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use libc::{AF_INET, AF_INET6, AF_UNSPEC, NET_RT_DUMP, RTA_DST, RTF_UP};
use smallvec_wrapper::SmallVec;

use crate::is_ipv6_unspecified;

use super::{
  super::{ipv4_filter_to_ip_filter, ipv6_filter_to_ip_filter, local_ip_filter},
  fetch, interface_addresses, interface_ipv4_addresses, interface_ipv6_addresses, invalid_message,
  message_too_short, roundup, IfNet, Ifv4Net, Ifv6Net, Net,
};

pub(crate) fn best_local_ipv4_addrs() -> io::Result<SmallVec<Ifv4Net>> {
  bast_local_addrs_in(AF_INET)
}

pub(crate) fn best_local_ipv6_addrs() -> io::Result<SmallVec<Ifv6Net>> {
  bast_local_addrs_in(AF_INET6)
}

pub(crate) fn best_local_addrs() -> io::Result<SmallVec<IfNet>> {
  bast_local_addrs_in(AF_UNSPEC)
}

fn bast_local_addrs_in<T: Net>(family: i32) -> io::Result<SmallVec<T>> {
  // First get the default route to find the interface index
  let routes = fetch(family, NET_RT_DUMP, 0)?;
  let mut best_ifindex = None;
  let mut best_metric = u32::MAX;

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

      let rtm = &*(src.as_ptr() as *const libc::rt_msghdr);

      // Only consider UP routes
      if (rtm.rtm_flags & RTF_UP) == 0 {
        src = &src[l..];
        continue;
      }

      let mut addr_ptr = src.as_ptr().add(std::mem::size_of::<libc::rt_msghdr>());
      let mut addrs = rtm.rtm_addrs;
      let mut i = 1;
      let mut is_default = false;

      while addrs != 0 {
        if (addrs & 1) != 0 {
          let sa = &*(addr_ptr as *const libc::sockaddr);
          match (family, sa.sa_family as i32, i) {
            (AF_INET, AF_INET, RTA_DST) | (AF_UNSPEC, AF_INET, RTA_DST) => {
              let sa_in = &*(addr_ptr as *const libc::sockaddr_in);
              if sa_in.sin_addr.s_addr == 0 {
                is_default = true;
              }
            }
            (AF_INET6, AF_INET6, RTA_DST) | (AF_UNSPEC, AF_INET6, RTA_DST) => {
              let sa_in6 = &*(addr_ptr as *const libc::sockaddr_in6);
              if is_ipv6_unspecified(sa_in6.sin6_addr.s6_addr) {
                is_default = true;
              }
            }
            _ => {}
          }

          let sa_len = if sa.sa_len == 0 {
            std::mem::size_of::<libc::sockaddr>()
          } else {
            sa.sa_len as usize
          };
          addr_ptr = addr_ptr.add(roundup(sa_len));
        }
        i += 1;
        addrs >>= 1;
      }

      // If this is a default route and has better metric, update best_ifindex
      if is_default && rtm.rtm_rmx.rmx_recvpipe < best_metric {
        best_metric = rtm.rtm_rmx.rmx_recvpipe;
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
