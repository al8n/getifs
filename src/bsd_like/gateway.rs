use std::{
  io,
  net::{Ipv4Addr, Ipv6Addr},
};

use libc::{AF_INET, AF_INET6, NET_RT_FLAGS, RTF_GATEWAY, RTF_UP};

use crate::os::{invalid_message, message_too_short};

use super::fetch;

pub(crate) fn gateway_ipv4() -> io::Result<Option<Ipv4Addr>> {
  let buf = fetch(AF_INET, NET_RT_FLAGS, RTF_GATEWAY)?;

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

      // Skip header to get to addresses
      let mut addr_ptr = src.as_ptr().add(std::mem::size_of::<libc::rt_msghdr>());
      let mut addrs = rtm.rtm_addrs;

      // Iterate through addresses
      let mut i = 1;
      while addrs != 0 {
        if (addrs & 1) != 0 {
          let sa = &*(addr_ptr as *const libc::sockaddr);
          if sa.sa_family as i32 == libc::AF_INET {
            let sa_in = &*(addr_ptr as *const libc::sockaddr_in);
            if i == libc::RTA_GATEWAY {
              return Ok(Some(Ipv4Addr::from(sa_in.sin_addr.s_addr.swap_bytes())));
            }
          }

          // Move to next address
          let sa_len = if sa.sa_len == 0 {
            std::mem::size_of::<libc::sockaddr>()
          } else {
            sa.sa_len as usize
          };
          addr_ptr = addr_ptr.add((sa_len + 7) & !7); // Align to 8-byte boundary
        }
        i += 1;
        addrs >>= 1;
      }

      src = &src[l..];
    }
  }

  Ok(None)
}

pub(crate) fn gateway_ipv6() -> io::Result<Option<Ipv6Addr>> {
  let buf = fetch(AF_INET6, NET_RT_FLAGS, RTF_GATEWAY)?;

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

      // Skip header to get to addresses
      let mut addr_ptr = src.as_ptr().add(std::mem::size_of::<libc::rt_msghdr>());
      let mut addrs = rtm.rtm_addrs;

      // Iterate through addresses
      let mut i = 1;
      while addrs != 0 {
        if (addrs & 1) != 0 {
          let sa = &*(addr_ptr as *const libc::sockaddr);
          if sa.sa_family as i32 == libc::AF_INET6 {
            let sa_in6 = &*(addr_ptr as *const libc::sockaddr_in6);
            if i == libc::RTA_GATEWAY {
              return Ok(Some(Ipv6Addr::from(sa_in6.sin6_addr.s6_addr)));
            }
          }

          // Move to next address
          let sa_len = if sa.sa_len == 0 {
            std::mem::size_of::<libc::sockaddr>()
          } else {
            sa.sa_len as usize
          };
          addr_ptr = addr_ptr.add((sa_len + 7) & !7); // Align to 8-byte boundary
        }
        i += 1;
        addrs >>= 1;
      }

      src = &src[l..];
    }
  }

  Ok(None)
}

#[test]
fn t() {
  let res = gateway_ipv4().unwrap();
  println!("{:?}", res);

  let res = gateway_ipv6().unwrap();
  println!("{:?}", res);
}
