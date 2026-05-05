use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use libc::{
  AF_INET, AF_INET6, NET_RT_DUMP, RTAX_DST, RTF_BLACKHOLE, RTF_BROADCAST, RTF_REJECT, RTF_UP,
};

// Same `RTF_MULTICAST` cfg shim as `bsd_like/route.rs`: NetBSD's libc
// bindings don't export it, so fall back to 0 (no-op bit).
#[cfg(any(
  apple,
  target_os = "freebsd",
  target_os = "dragonfly",
  target_os = "openbsd"
))]
use libc::RTF_MULTICAST;
#[cfg(target_os = "netbsd")]
const RTF_MULTICAST: libc::c_int = 0;
use smallvec_wrapper::SmallVec;

use super::{
  super::{ipv4_filter_to_ip_filter, ipv6_filter_to_ip_filter, local_ip_filter},
  compat::RtMsghdr,
  fetch, interface_addr_table_into, interface_addresses, interface_ipv4_addresses,
  interface_ipv6_addresses, invalid_message, message_too_short, parse_addrs, IfNet, Ifv4Net,
  Ifv6Net, Net,
};

pub(crate) fn best_local_ipv4_addrs() -> io::Result<SmallVec<Ifv4Net>> {
  let mut out = SmallVec::new();
  best_local_addrs_in(AF_INET, &mut out)?;
  Ok(out)
}

pub(crate) fn best_local_ipv6_addrs() -> io::Result<SmallVec<Ifv6Net>> {
  let mut out = SmallVec::new();
  best_local_addrs_in(AF_INET6, &mut out)?;
  Ok(out)
}

pub(crate) fn best_local_addrs() -> io::Result<SmallVec<IfNet>> {
  // Walk AF_INET and AF_INET6 separately rather than one AF_UNSPEC
  // dump. The kernel encodes "default route" by omitting `RTAX_DST`
  // entirely, and `best_local_addrs_in` only treats absent dst as
  // default in family-specific dumps (we'd otherwise have no way to
  // attribute the default to the right address family). With a single
  // AF_UNSPEC walk, hosts whose only default route uses that encoding
  // would silently get `Ok([])` from this call. Same tradeoff as
  // `route_table_by_filter` — two sysctl calls, one consistent answer.
  //
  // Both walks push into one shared `SmallVec<IfNet>` via the `_into`
  // helpers — the kernel only emits the requested family's addresses,
  // and `IfNet`'s `Net::try_from` accepts both, so this avoids the
  // intermediate per-family allocations.
  let mut out: SmallVec<IfNet> = SmallVec::new();
  best_local_addrs_in(AF_INET, &mut out)?;
  best_local_addrs_in(AF_INET6, &mut out)?;
  Ok(out)
}

fn best_local_addrs_in<T: Net>(family: i32, out: &mut SmallVec<T>) -> io::Result<()> {
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
        // Message claims a length shorter than its own header type —
        // a kernel-side bug or version skew. Surface it (consistent
        // with `walk_route_table` / `rt_generic_addrs_in`) rather
        // than reading past the message into the next entry.
        return Err(message_too_short());
      }
      let rtm: RtMsghdr = std::ptr::read_unaligned(src.as_ptr() as *const RtMsghdr);

      // Same usable-route filter as `bsd_like/route.rs`. A
      // `RTF_REJECT` / `RTF_BLACKHOLE` default route can be `RTF_UP`
      // with a low metric and would otherwise win `best_ifindex`,
      // making `best_local_*` return addresses on an interface the
      // kernel never delivers via. `RTF_BROADCAST` / `RTF_MULTICAST`
      // are housekeeping routes the kernel attaches to interfaces
      // and not candidates for default-route selection.
      let unusable = RTF_REJECT | RTF_BLACKHOLE | RTF_BROADCAST | RTF_MULTICAST;
      if (rtm.rtm_flags & RTF_UP) == 0 || (rtm.rtm_flags & unusable) != 0 {
        src = &src[l..];
        continue;
      }

      // Source-specific default routes constrain selection to a
      // particular packet source, so a "best local address for any
      // outbound traffic" walk must not pick them — the addresses
      // returned would only be correct for traffic that already has
      // a matching source bound. Same per-platform shape as
      // `walk_route_table` (NetBSD: `RTF_SRC`; OpenBSD:
      // `RTAX_SRC` / `RTAX_SRCMASK` slots in `rtm_addrs`).
      #[cfg(target_os = "netbsd")]
      {
        if (rtm.rtm_flags & libc::RTF_SRC) != 0 {
          src = &src[l..];
          continue;
        }
      }
      #[cfg(target_os = "openbsd")]
      {
        let src_mask = (1u32 << libc::RTAX_SRC as u32) | (1u32 << libc::RTAX_SRCMASK as u32);
        if (rtm.rtm_addrs as u32 & src_mask) != 0 {
          src = &src[l..];
          continue;
        }
      }

      // Decode the address slots through the shared `parse_addrs`
      // helper so default-route detection here matches the
      // route-table walker. That helper:
      //   - returns `None` for the dst slot when the kernel omits
      //     `RTAX_DST` entirely (one BSD encoding of the default
      //     route is "no destination, only a gateway");
      //   - decodes the compact `sa_family = AF_INET[6]` short
      //     sockaddrs that NetBSD/OpenBSD emit for netmasks and that
      //     the previous inline decode here silently dropped, leaving
      //     `is_default` false for valid default routes.
      let addrs = parse_addrs(rtm.rtm_addrs as u32, &src[header_size..l])?;
      let dst = addrs[RTAX_DST as usize];
      let dst_present = (rtm.rtm_addrs as u32 & libc::RTA_DST as u32) != 0;
      let is_default = match (family, dst) {
        // Family-specific dump with no RTA_DST attribute at all → BSD's
        // alternate encoding for "default route for this family".
        (AF_INET, None) | (AF_INET6, None) if !dst_present => true,
        // Explicit unspecified destination, regardless of dump family.
        (_, Some(IpAddr::V4(v4))) if v4.is_unspecified() => true,
        (_, Some(IpAddr::V6(v6))) if v6.is_unspecified() => true,
        _ => false,
      };

      // If this is a default route and has better metric, update best_ifindex
      let metric = rtm.rtm_rmx.rmx_recvpipe as u64;
      if is_default && metric < best_metric {
        best_metric = metric;
        best_ifindex = Some(rtm.rtm_index);
      }

      src = &src[l..];
    }
  }

  // Only pass the interface index if we found a valid default route.
  // Push into the caller-provided buffer instead of allocating.
  match best_ifindex {
    Some(idx) => interface_addr_table_into(family, idx as u32, local_ip_filter, out),
    None => Ok(()),
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
