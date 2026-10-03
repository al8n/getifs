use std::{collections::HashSet, io, net::IpAddr};

use libc::{AF_UNSPEC, NET_RT_FLAGS, RTF_UP};
use smallvec_wrapper::SmallVec;

use super::{
  super::Address, compat::RtMsghdr, decode_full_inet_addr, fetch, message_too_short, roundup,
};

/// One length-delimited sockaddr from a BSD routing message.
///
/// `bytes` contains exactly the kernel-declared `sa_len` bytes. It is empty
/// for the historical zero-length filler form; `rest` starts after the
/// kernel-required alignment padding.
struct SockaddrFrame<'a> {
  family: i32,
  bytes: &'a [u8],
  rest: &'a [u8],
}

fn take_sockaddr_frame(cur: &[u8]) -> io::Result<SockaddrFrame<'_>> {
  // Every BSD sockaddr starts with a one-byte length. Zero is a historical
  // filler and one is a valid compact kernel-form netmask with no family
  // byte; both still occupy one kernel alignment unit.
  if cur.is_empty() {
    return Err(message_too_short());
  }

  let declared = cur[0] as usize;
  let advance = roundup(declared);
  if declared > cur.len() || advance > cur.len() {
    return Err(message_too_short());
  }

  let bytes = if declared == 0 {
    &cur[..0]
  } else {
    &cur[..declared]
  };
  Ok(SockaddrFrame {
    family: if declared >= 2 {
      cur[1] as i32
    } else {
      AF_UNSPEC
    },
    bytes,
    rest: &cur[advance..],
  })
}

/// The frame's address, or `None` for a non-IP family or a frame whose
/// declared bytes do not hold a whole address. A compact `sin_len = 8`
/// gateway decodes; a shorter one is skipped, because completing it would
/// borrow bytes from the next frame.
fn parse_sockaddr_ip(frame: &SockaddrFrame<'_>) -> Option<IpAddr> {
  decode_full_inet_addr(frame.family, frame.bytes)
}

pub(super) fn rt_generic_addrs_in<A, F>(
  family: i32,
  rtf: i32,
  rta: i32,
  f: F,
) -> io::Result<SmallVec<A>>
where
  A: Address + Eq,
  F: FnMut(&IpAddr) -> bool,
{
  parse_rt_generic_addrs(&fetch(family, NET_RT_FLAGS, rtf)?, family, rtf, rta, f)
}

pub(super) fn parse_rt_generic_addrs<A, F>(
  buf: &[u8],
  family: i32,
  rtf: i32,
  rta: i32,
  mut f: F,
) -> io::Result<SmallVec<A>>
where
  A: Address + Eq,
  F: FnMut(&IpAddr) -> bool,
{
  let mut results = SmallVec::new();
  // The routing table can contain many duplicates (same address
  // reached via different routes). Previously the code used
  // `results.contains(&addr)` which is O(n²); this tracks dedup in a
  // HashSet keyed by `(index, IpAddr)` for O(1) check per candidate.
  let mut seen: HashSet<(u32, IpAddr)> = HashSet::new();
  unsafe {
    let mut src = buf;

    while src.len() > 4 {
      let l = u16::from_ne_bytes(src[..2].try_into().unwrap()) as usize;
      // Same end-of-stream sentinel as `walk_route_table` /
      // `best_local_addrs_in`: a zero-length record byte-pair is the
      // kernel's residual padding past the last valid message, not a
      // malformed message. Erroring here would discard the entire
      // gateway/best-local result on platforms whose sysctl response
      // happens to land on a padded boundary.
      if l == 0 {
        break;
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

      let header_size = std::mem::size_of::<RtMsghdr>();
      // The outer `src.len() < l` guard above only proves the message
      // fits in the buffer. We *also* need `l >= header_size` so the
      // upcoming `read_unaligned` doesn't read past this message into
      // the next one when the kernel reports a short / version-skewed
      // record. (Same defence the route walker has at
      // `bsd_like/route.rs::walk_route_table`.)
      if l < header_size {
        return Err(message_too_short());
      }

      // SAFETY: `src` is a `Vec<u8>` (u8-aligned), `read_unaligned`
      // copies into an aligned local before we read fields. Same
      // rationale as in `walk_route_table` / `parse_inet_addr`.
      let rtm: RtMsghdr = std::ptr::read_unaligned(src.as_ptr() as *const RtMsghdr);

      // Require *both* `RTF_UP` and the caller's requested flag
      // (e.g. `RTF_GATEWAY` for `gateway_addrs*`). The previous
      // `(rtm_flags & (RTF_UP | rtf)) == 0` predicate was an OR
      // mask that admitted any route with *either* bit set — so a
      // down gateway (`RTF_GATEWAY` without `RTF_UP`) would still
      // pass through and surface in the output even though the
      // kernel will not use it for forwarding. Although
      // `NET_RT_FLAGS` asks the kernel to filter by `rtf`,
      // entries can still come back with `RTF_UP` cleared during
      // churn or shutdown.
      if (rtm.rtm_flags & RTF_UP) == 0 || (rtm.rtm_flags & rtf) == 0 {
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
          let frame = take_sockaddr_frame(cur)?;

          if i == rta {
            let family_matches = family == AF_UNSPEC || family == frame.family;
            if family_matches {
              if let Some(ip) = parse_sockaddr_ip(&frame) {
                if !ip.is_unspecified() {
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
          }

          cur = frame.rest;
        }
        i += 1;
        addrs >>= 1;
      }

      src = &src[l..];
    }
  }

  Ok(results)
}

#[allow(dead_code, unexpected_cfgs)]
#[cfg(fuzzing)]
#[doc(hidden)]
pub(super) fn fuzz_sockaddr_frame(data: &[u8]) {
  if let Ok(frame) = take_sockaddr_frame(data) {
    let _ = parse_sockaddr_ip(&frame);
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use libc::{AF_INET, AF_INET6, RTAX_DST, RTAX_GATEWAY, RTA_GATEWAY, RTF_GATEWAY};
  use std::net::{Ipv4Addr, Ipv6Addr};

  use super::super::tests::{addrs_mask, padded_sockaddr, rt_message, sockaddr_in, sockaddr_in6};
  use crate::IfAddr;

  fn gateway_route(index: u16, flags: i32, dst: Vec<u8>, gateway: Vec<u8>) -> Vec<u8> {
    let mut body = dst;
    body.extend(gateway);
    rt_message(index, flags, addrs_mask(&[RTAX_DST, RTAX_GATEWAY]), &body)
  }

  fn gateways(buf: &[u8]) -> io::Result<SmallVec<IfAddr>> {
    parse_rt_generic_addrs(buf, AF_UNSPEC, RTF_GATEWAY, RTA_GATEWAY, |_| true)
  }

  #[test]
  fn gateway_walk_reports_each_up_gateway_once() {
    let up = RTF_UP | RTF_GATEWAY;
    let v4_default = || sockaddr_in(Ipv4Addr::UNSPECIFIED);
    let compact = padded_sockaddr(&[8, AF_INET as u8, 0, 0, 192, 0, 2, 1]);
    let kame = "fe80:e::1".parse().unwrap();

    let mut buf = gateway_route(4, up, v4_default(), compact);
    // A gateway route that is not up is not used for forwarding.
    buf.extend(gateway_route(
      5,
      RTF_GATEWAY,
      v4_default(),
      sockaddr_in(Ipv4Addr::new(192, 0, 2, 2)),
    ));
    // The full-size form of the first gateway on the same interface.
    buf.extend(gateway_route(
      4,
      up,
      v4_default(),
      sockaddr_in(Ipv4Addr::new(192, 0, 2, 1)),
    ));
    buf.extend(gateway_route(
      6,
      up,
      sockaddr_in6(Ipv6Addr::UNSPECIFIED),
      sockaddr_in6(kame),
    ));

    assert_eq!(
      gateways(&buf).unwrap().as_slice(),
      &[
        IfAddr::new(4, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        IfAddr::new(6, IpAddr::V6("fe80::1".parse().unwrap())),
      ]
    );
  }

  #[test]
  fn gateway_walk_rejects_truncated_messages() {
    let up = RTF_UP | RTF_GATEWAY;
    let dst = sockaddr_in(Ipv4Addr::UNSPECIFIED);
    let gateway = sockaddr_in(Ipv4Addr::new(192, 0, 2, 1));

    // The message declares more bytes than the buffer holds.
    let message = gateway_route(4, up, dst.clone(), gateway.clone());
    let err = gateways(&message[..message.len() - 1]).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);

    // The gateway sockaddr runs past the end of its message.
    let message = gateway_route(4, up, dst, gateway[..8].to_vec());
    let err = gateways(&message).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
  }

  #[test]
  fn sockaddr_decode_cannot_borrow_bytes_from_next_frame() {
    let full_v6_len = std::mem::size_of::<libc::sockaddr_in6>();
    let mut data = vec![0u8; 8 + roundup(full_v6_len)];

    // The current frame declares only eight bytes. The following frame is a
    // complete IPv6 sockaddr; a decoder using the entire cursor could
    // incorrectly borrow its bytes to complete the first address.
    data[0] = 8;
    data[1] = AF_INET6 as u8;
    data[8] = full_v6_len as u8;
    data[9] = AF_INET6 as u8;
    data[16..32].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());

    let frame = take_sockaddr_frame(&data).unwrap();
    assert_eq!(frame.bytes.len(), 8);
    assert_eq!(frame.rest[0] as usize, full_v6_len);
    assert_eq!(parse_sockaddr_ip(&frame), None);
  }

  #[test]
  fn sockaddr_decode_normalizes_kame_gateway() {
    let full_v6_len = std::mem::size_of::<libc::sockaddr_in6>();
    let mut data = vec![0u8; roundup(full_v6_len)];
    data[0] = full_v6_len as u8;
    data[1] = AF_INET6 as u8;
    data[8..24].copy_from_slice(&[
      0xfe, 0x80, 0x00, 0x0e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]);

    let frame = take_sockaddr_frame(&data).unwrap();
    assert_eq!(
      parse_sockaddr_ip(&frame),
      Some(IpAddr::V6("fe80::1".parse().unwrap()))
    );
  }

  #[test]
  fn sockaddr_decode_accepts_compact_v4_gateway() {
    // A `sockaddr_in` with `sin_len = 8` ends right after `sin_addr`.
    let mut data = vec![0u8; roundup(8)];
    data[0] = 8;
    data[1] = AF_INET as u8;
    data[4..8].copy_from_slice(&[192, 0, 2, 1]);

    let frame = take_sockaddr_frame(&data).unwrap();
    assert_eq!(frame.bytes.len(), 8);
    assert_eq!(
      parse_sockaddr_ip(&frame),
      Some(IpAddr::V4([192, 0, 2, 1].into()))
    );
  }

  #[test]
  fn sockaddr_decode_normalizes_compact_kame_gateway() {
    // A 24-byte `sockaddr_in6` ends right after `sin6_addr`.
    let mut data = vec![0u8; roundup(24)];
    data[0] = 24;
    data[1] = AF_INET6 as u8;
    data[8..24].copy_from_slice(&[0xfe, 0x80, 0x00, 0x0e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    let frame = take_sockaddr_frame(&data).unwrap();
    assert_eq!(frame.bytes.len(), 24);
    assert_eq!(
      parse_sockaddr_ip(&frame),
      Some(IpAddr::V6("fe80::1".parse().unwrap()))
    );
  }

  #[test]
  fn zero_length_sockaddr_uses_one_alignment_unit() {
    let data = vec![0u8; 2 * roundup(0)];
    let frame = take_sockaddr_frame(&data).unwrap();
    assert!(frame.bytes.is_empty());
    assert_eq!(frame.rest.len(), roundup(0));
    assert_eq!(parse_sockaddr_ip(&frame), None);
  }

  #[test]
  fn one_byte_kernel_form_uses_one_alignment_unit() {
    let mut data = vec![0u8; 2 * roundup(1)];
    data[0] = 1;
    let frame = take_sockaddr_frame(&data).unwrap();
    assert_eq!(frame.bytes, &[1]);
    assert_eq!(frame.family, AF_UNSPEC);
    assert_eq!(frame.rest.len(), roundup(1));
    assert_eq!(parse_sockaddr_ip(&frame), None);
  }
}
