use std::{
  collections::HashSet,
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use libc::{AF_INET, AF_INET6, AF_UNSPEC, NET_RT_FLAGS, RTF_UP};
use smallvec_wrapper::SmallVec;

use crate::is_ipv6_unspecified;

use super::{super::Address, compat::RtMsghdr, fetch, invalid_message, message_too_short, roundup};

pub(super) fn rt_generic_addrs_in<A, F>(
  family: i32,
  rtf: i32,
  rta: i32,
  mut f: F,
) -> io::Result<SmallVec<A>>
where
  A: Address + Eq,
  F: FnMut(&IpAddr) -> bool,
{
  let buf = fetch(family, NET_RT_FLAGS, rtf)?;
  let mut results = SmallVec::new();
  // The routing table can contain many duplicates (same address
  // reached via different routes). Previously the code used
  // `results.contains(&addr)` which is O(n²); this tracks dedup in a
  // HashSet keyed by `(index, IpAddr)` for O(1) check per candidate.
  let mut seen: HashSet<(u32, IpAddr)> = HashSet::new();
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

      // SAFETY: `src` is a `Vec<u8>` (u8-aligned), `read_unaligned`
      // copies into an aligned local before we read fields. Same
      // rationale as in `walk_route_table` / `parse_inet_addr`.
      let rtm: RtMsghdr = std::ptr::read_unaligned(src.as_ptr() as *const RtMsghdr);

      // Only consider UP routes
      if (rtm.rtm_flags & (RTF_UP | rtf)) == 0 {
        src = &src[l..];
        continue;
      }

      // The address area starts after the message header and is
      // bounded by the message length `l`. Walking a `&[u8]` cursor
      // (instead of raw pointers) gives us cheap length checks before
      // every `read_unaligned`, so a malformed `sa_len` or unexpected
      // `RtMsghdr` layout on a single BSD target can no longer make us
      // read past the message into the next entry or off the end of
      // the sysctl buffer.
      let header_size = std::mem::size_of::<RtMsghdr>();
      if l < header_size {
        // Message claims a length shorter than its own header type;
        // skip rather than risk a backwards slice.
        src = &src[l..];
        continue;
      }
      let mut cur = &src[header_size..l];

      // Iterate through addresses
      let mut i = 1;
      let mut addrs = rtm.rtm_addrs;
      while addrs != 0 {
        if (addrs & 1) != 0 {
          const SA_HEADER: usize = std::mem::size_of::<libc::sockaddr>();
          if cur.len() < SA_HEADER {
            // Out of bytes for even a sockaddr header — kernel
            // truncation or a layout mismatch we don't model. Stop
            // walking this message rather than over-read.
            break;
          }
          // SAFETY: bounds-checked above; `read_unaligned` copies the
          // header into an aligned local, tolerating the u8 alignment
          // of the underlying `Vec<u8>`.
          let sa: libc::sockaddr = std::ptr::read_unaligned(cur.as_ptr() as *const libc::sockaddr);

          match (family, sa.sa_family as i32) {
            (AF_INET, AF_INET) | (AF_UNSPEC, AF_INET) if i == rta => {
              const SA_IN: usize = std::mem::size_of::<libc::sockaddr_in>();
              if cur.len() >= SA_IN {
                let sa_in: libc::sockaddr_in =
                  std::ptr::read_unaligned(cur.as_ptr() as *const libc::sockaddr_in);
                if sa_in.sin_addr.s_addr != 0 {
                  let ip = IpAddr::V4(Ipv4Addr::from(sa_in.sin_addr.s_addr.swap_bytes()));
                  if let Some(addr) =
                    A::try_from_with_filter(rtm.rtm_index as u32, ip, |addr| f(addr))
                  {
                    if seen.insert((addr.index(), addr.addr())) {
                      results.push(addr);
                    }
                  }
                }
              }
            }
            (AF_INET6, AF_INET6) | (AF_UNSPEC, AF_INET6) if i == rta => {
              const SA_IN6: usize = std::mem::size_of::<libc::sockaddr_in6>();
              if cur.len() >= SA_IN6 {
                let sa_in6: libc::sockaddr_in6 =
                  std::ptr::read_unaligned(cur.as_ptr() as *const libc::sockaddr_in6);
                if !is_ipv6_unspecified(sa_in6.sin6_addr.s6_addr) {
                  let ip = IpAddr::V6(Ipv6Addr::from(sa_in6.sin6_addr.s6_addr));
                  if let Some(addr) =
                    A::try_from_with_filter(rtm.rtm_index as u32, ip, |addr| f(addr))
                  {
                    if seen.insert((addr.index(), addr.addr())) {
                      results.push(addr);
                    }
                  }
                }
              }
            }
            _ => {}
          }

          // Advance the cursor. Fall back to `sockaddr` size when the
          // kernel reports `sa_len == 0` (historical behaviour). Bail
          // out if the advance would step past the end of the message
          // — that's the bound that prevents reads from leaking into
          // the next route or past the sysctl buffer.
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

      src = &src[l..];
    }
  }

  Ok(results)
}
