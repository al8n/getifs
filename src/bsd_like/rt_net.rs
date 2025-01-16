use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use libc::{AF_INET, AF_INET6, AF_UNSPEC, NET_RT_DUMP, RTA_DST, RTF_HOST, RTF_IFSCOPE, RTF_UP};
use smallvec_wrapper::SmallVec;

use crate::{ipv4_filter_to_ip_filter, ipv6_filter_to_ip_filter};

use super::{
  super::{Address, IfAddr, Ifv4Addr, Ifv6Addr},
  fetch, invalid_message, message_too_short,
};

pub(crate) fn rt_net_addrs() -> io::Result<SmallVec<IfAddr>> {
  rt_net_addrs_in(AF_UNSPEC, |_| true)
}

pub(crate) fn rt_net_ipv4_addrs() -> io::Result<SmallVec<Ifv4Addr>> {
  rt_net_addrs_in(AF_INET, |_| true)
}

pub(crate) fn rt_net_ipv6_addrs() -> io::Result<SmallVec<Ifv6Addr>> {
  rt_net_addrs_in(AF_INET6, |_| true)
}

pub(crate) fn rt_net_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<IfAddr>>
where
  F: FnMut(&IpAddr) -> bool,
{
  rt_net_addrs_in(AF_UNSPEC, f)
}

pub(crate) fn rt_net_ipv4_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv4Addr>>
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  rt_net_addrs_in(AF_INET, ipv4_filter_to_ip_filter(f))
}

pub(crate) fn rt_net_ipv6_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv6Addr>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  rt_net_addrs_in(AF_INET6, ipv6_filter_to_ip_filter(f))
}

fn rt_net_addrs_in<A, F>(family: i32, mut f: F) -> io::Result<SmallVec<A>>
where
  A: Address + Eq,
  F: FnMut(&IpAddr) -> bool,
{
  let buf = fetch(family, NET_RT_DUMP, 0)?;
  let mut results = SmallVec::new();
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
      if src[3] as i32 != libc::RTM_GET {
        src = &src[l..];
        continue;
      }

      let rtm = &*(src.as_ptr() as *const libc::rt_msghdr);

      // Only consider UP routes but not host routes and not interface routes
      if (rtm.rtm_flags & RTF_UP) == 0
        || (rtm.rtm_flags & RTF_HOST) != 0
        || (rtm.rtm_flags & RTF_IFSCOPE) != 0
      {
        src = &src[l..];
        continue;
      }

      let base_ptr = src.as_ptr().add(std::mem::size_of::<libc::rt_msghdr>());
      let mut addr_ptr = base_ptr;
      let mut i = 1;
      let mut addrs = rtm.rtm_addrs;
      while addrs != 0 {
        if (addrs & 1) != 0 {
          let sa = &*(addr_ptr as *const libc::sockaddr);
          match (family, sa.sa_family as i32, i) {
            (AF_INET, AF_INET, RTA_DST) | (AF_UNSPEC, AF_INET, RTA_DST) => {
              let sa_in = &*(addr_ptr as *const libc::sockaddr_in);
              if sa_in.sin_addr.s_addr != 0 {
                let addr = Ipv4Addr::from(sa_in.sin_addr.s_addr.swap_bytes()).into();
                if is_network_route(&addr, rtm) {
                  if let Some(addr) =
                    A::try_from_with_filter(rtm.rtm_index as u32, addr, |addr| f(addr))
                  {
                    if !results.contains(&addr) {
                      results.push(addr);
                    }
                  }
                }
              }
            }
            (AF_INET6, AF_INET6, RTA_DST) | (AF_UNSPEC, AF_INET6, RTA_DST) => {
              let sa_in6 = &*(addr_ptr as *const libc::sockaddr_in6);
              if !sa_in6.sin6_addr.s6_addr.iter().all(|&x| x == 0) {
                let addr = Ipv6Addr::from(sa_in6.sin6_addr.s6_addr).into();
                if is_network_route(&addr, rtm) {
                  if let Some(addr) =
                    A::try_from_with_filter(rtm.rtm_index as u32, addr, |addr| f(addr))
                  {
                    if !results.contains(&addr) {
                      results.push(addr);
                    }
                  }
                }
              }
            }
            _ => {}
          }

          let sa_len = if sa.sa_len == 0 {
            std::mem::size_of::<libc::sockaddr>()
          } else {
            sa.sa_len as usize
          };
          addr_ptr = addr_ptr.add((sa_len + 7) & !7);
        }
        i += 1;
        addrs >>= 1;
      }
      src = &src[l..];
    }
  }
  Ok(results)
}

fn is_network_route(addr: &IpAddr, rtm: &libc::rt_msghdr) -> bool {
  if (rtm.rtm_flags & RTF_HOST) != 0 {
    return false;
  }

  match addr {
    IpAddr::V4(ipv4) => {
      // Exclude:
      // - Broadcast address
      // - Individual IPs (when the address doesn't look like a network address)
      // - Zero address
      if ipv4.is_broadcast() ||
        ipv4.octets()[3] != 0 ||  // Last octet should be 0 for network addresses
        ipv4.is_unspecified()
      {
        return false;
      }
      true
    }
    IpAddr::V6(ipv6) => {
      // For IPv6, check if it's a network prefix
      // The last 8 bytes should be zeros for a network address
      let octets = ipv6.octets();
      octets[8..].iter().all(|&b| b == 0)
    }
  }
}
