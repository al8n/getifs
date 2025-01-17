use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use libc::{AF_INET, AF_INET6, AF_UNSPEC, NET_RT_FLAGS, RTF_UP};
use smallvec_wrapper::SmallVec;

use crate::is_ipv6_unspecified;

use super::{
  super::Address,
  fetch, invalid_message, message_too_short, roundup,
};

pub(super) fn rt_generic_addrs_in<A, F>(family: i32, rtf: i32, rta: i32, mut f: F) -> io::Result<SmallVec<A>>
where
  A: Address + Eq,
  F: FnMut(&IpAddr) -> bool,
{
  let buf = fetch(family, NET_RT_FLAGS, rtf)?;
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

      // Cast the buffer to rt_msghdr to read the sa_len fields
      let rtm = &*(src.as_ptr() as *const libc::rt_msghdr);

      // Only consider UP routes
      if (rtm.rtm_flags & (RTF_UP | rtf)) == 0 {
        src = &src[l..];
        continue;
      }

      // Skip header to get to addresses
      let base_ptr = src.as_ptr().add(std::mem::size_of::<libc::rt_msghdr>());
      let mut addr_ptr = base_ptr;

      // Iterate through addresses
      let mut i = 1;
      let mut addrs = rtm.rtm_addrs;
      while addrs != 0 {
        if (addrs & 1) != 0 {
          let sa = &*(addr_ptr as *const libc::sockaddr);
          match (family, sa.sa_family as i32) {
            (AF_INET, AF_INET) | (AF_UNSPEC, AF_INET) if i == rta => {
              let sa_in = &*(addr_ptr as *const libc::sockaddr_in);
              if sa_in.sin_addr.s_addr != 0 {
                let addr = Ipv4Addr::from(sa_in.sin_addr.s_addr.swap_bytes());
                if let Some(addr) =
                  A::try_from_with_filter(rtm.rtm_index as u32, addr.into(), |addr| f(addr))
                {
                  if !results.contains(&addr) {
                    results.push(addr);
                  }
                }
              }
            }
            (AF_INET6, AF_INET6) | (AF_UNSPEC, AF_INET6) if i == rta => {
              let sa_in6 = &*(addr_ptr as *const libc::sockaddr_in6);
              if !is_ipv6_unspecified(sa_in6.sin6_addr.s6_addr) {
                let addr = Ipv6Addr::from(sa_in6.sin6_addr.s6_addr);
                if let Some(addr) =
                  A::try_from_with_filter(rtm.rtm_index as u32, addr.into(), |addr| f(addr))
                {
                  if !results.contains(&addr) {
                    results.push(addr);
                  }
                }
              }
            }
            _ => {}
          }

          // Move to next address
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
