use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use libc::{AF_INET, AF_INET6, AF_UNSPEC, NET_RT_FLAGS, RTA_DST, RTF_BROADCAST, RTF_UP};
use smallvec_wrapper::SmallVec;

use crate::{ipv4_filter_to_ip_filter, ipv6_filter_to_ip_filter};

use super::{
  super::{Address, IfAddr, Ifv4Addr, Ifv6Addr},
  fetch, invalid_message, message_too_short, roundup,
};

/// Returns all broadcast addresses configured on the system.
pub(crate) fn rt_broadcast_addrs() -> io::Result<SmallVec<IfAddr>> {
  rt_broadcast_addrs_in(AF_UNSPEC, |_| true)
}

/// Returns IPv4 broadcast addresses.
pub(crate) fn rt_broadcast_ipv4_addrs() -> io::Result<SmallVec<Ifv4Addr>> {
  rt_broadcast_addrs_in(AF_INET, |_| true)
}

/// Returns IPv6 broadcast addresses (usually empty as IPv6 uses multicast).
pub(crate) fn rt_broadcast_ipv6_addrs() -> io::Result<SmallVec<Ifv6Addr>> {
  rt_broadcast_addrs_in(AF_INET6, |_| true)
}

pub(crate) fn rt_broadcast_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<IfAddr>>
where
  F: FnMut(&IpAddr) -> bool,
{
  rt_broadcast_addrs_in(AF_UNSPEC, f)
}

pub(crate) fn rt_broadcast_ipv4_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv4Addr>>
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  rt_broadcast_addrs_in(AF_INET, ipv4_filter_to_ip_filter(f))
}

pub(crate) fn rt_broadcast_ipv6_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv6Addr>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  rt_broadcast_addrs_in(AF_INET6, ipv6_filter_to_ip_filter(f))
}

fn rt_broadcast_addrs_in<A, F>(family: i32, mut f: F) -> io::Result<SmallVec<A>>
where
  A: Address + Eq,
  F: FnMut(&IpAddr) -> bool,
{
  let buf = fetch(family, NET_RT_FLAGS, RTF_BROADCAST)?;
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

      // Only consider UP routes
      if (rtm.rtm_flags & (RTF_UP | RTF_BROADCAST)) == 0 {
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
                let addr = Ipv4Addr::from(sa_in.sin_addr.s_addr.swap_bytes());
                let octets = addr.octets();
                if octets[3] == 255 || octets == [255, 255, 255, 255] {
                  if let Some(addr) =
                    A::try_from_with_filter(rtm.rtm_index as u32, addr.into(), |addr| f(addr))
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

          addr_ptr = addr_ptr.add(roundup(sa_len));
        }
        i += 1;
        addrs >>= 1;
      }

      src = &src[l..];
    }
  }

  Ok(results)
}

