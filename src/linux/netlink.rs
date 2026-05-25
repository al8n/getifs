use linux_raw_sys::{
  if_arp::{self, ARPHRD_IPGRE, ARPHRD_TUNNEL, ARPHRD_TUNNEL6},
  netlink::{self, NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST},
};
use rustix::net::{
  getsockname, netlink::SocketAddrNetlink, recvfrom, sendto, socket, AddressFamily, RecvFlags,
  SendFlags, SocketType,
};

use smallvec_wrapper::{SmallVec, TinyVec};
use std::{collections::HashSet, io, mem, net::IpAddr, os::fd::OwnedFd};

use crate::local_ip_filter;

use super::{super::Address, Flags, Interface, MacAddr, Net, MAC_ADDRESS_SIZE};

const NLMSG_HDRLEN: usize = mem::size_of::<MessageHeader>();
const NLMSG_ALIGNTO: u32 = netlink::NLMSG_ALIGNTO;
const NLMSG_DONE: u32 = netlink::NLMSG_DONE;
const NLMSG_ERROR: u32 = netlink::NLMSG_ERROR;

const RTM_GETLINK: u32 = netlink::RTM_GETLINK as u32;
const RTM_GETADDR: u32 = netlink::RTM_GETADDR as u32;
const RTM_GETROUTE: u32 = netlink::RTM_GETROUTE as u32;
const RTM_NEWLINK: u32 = netlink::RTM_NEWLINK as u32;
const RTM_NEWADDR: u32 = netlink::RTM_NEWADDR as u32;
const RTM_NEWROUTE: u32 = netlink::RTM_NEWROUTE as u32;
// Nexthop subsystem (Linux 5.3+). Used to resolve RTA_NH_ID on route
// entries that reference an `ip nexthop`-managed indirection.
const RTM_GETNEXTHOP: u32 = netlink::RTM_GETNEXTHOP as u32;
const RTM_NEWNEXTHOP: u32 = netlink::RTM_NEWNEXTHOP as u32;

// `enum` from <linux/nexthop.h> (stable kernel UAPI). linux-raw-sys
// 0.12 doesn't expose these as named constants yet, so spell them out.
const NHA_ID: u16 = 1;
const NHA_GROUP: u16 = 2;
const NHA_BLACKHOLE: u16 = 4;
const NHA_OIF: u16 = 5;
const NHA_GATEWAY: u16 = 6;

const RTA_DST: u16 = netlink::rtattr_type_t::RTA_DST as u16;
const RTA_GATEWAY: u16 = netlink::rtattr_type_t::RTA_GATEWAY as u16;
const RTA_OIF: u16 = netlink::rtattr_type_t::RTA_OIF as u16;
const RTA_PRIORITY: u16 = netlink::rtattr_type_t::RTA_PRIORITY as u16;
const RTA_MULTIPATH: u16 = netlink::rtattr_type_t::RTA_MULTIPATH as u16;
const RTA_SRC: u16 = netlink::rtattr_type_t::RTA_SRC as u16;
// RTA_TABLE carries the full 32-bit table id when it doesn't fit in the
// 8-bit `rtm_table` field (table > 255). Without parsing it we'd treat
// custom policy tables as if they were the main table.
const RTA_TABLE: u16 = netlink::rtattr_type_t::RTA_TABLE as u16;
// RTA_NH_ID indicates the route is installed via an `ip nexthop`
// nexthop-object (resolved by a separate netlink subsystem). The
// current `IpRoute` model has no way to dereference it, so we skip
// these routes deliberately rather than letting them fall through the
// `oif == 0` guard. Decoding nexthop objects is documented as a
// known gap in `route_table`.
const RTA_NH_ID: u16 = netlink::rtattr_type_t::RTA_NH_ID as u16;
// RTA_VIA carries a cross-family gateway: an `__kernel_sa_family_t`
// followed by the address payload, used when the nexthop's family
// differs from the route's family (e.g. an IPv4 route via an IPv6
// link-local nexthop). `IpRoute` only models same-family gateways
// (`Ipv4Route::gateway: Option<Ipv4Addr>`, etc.), so we can't faithfully
// represent these — the walker treats RTA_VIA's presence as a marker
// to skip the route, rather than emitting it as a directly-connected
// route (which is what reading only `RTA_GATEWAY` would do).
const RTA_VIA: u16 = netlink::rtattr_type_t::RTA_VIA as u16;
// `RTA_PREF` carries the RFC 4191 router-preference flag (`high` /
// `medium` / `low`) that an IPv6 default route picks up when it's
// installed by an RA. The kernel's IPv6 route selection uses this as
// a tie-breaker between equal-metric defaults — without it, two
// equal-metric defaults (the common dual-router IPv6 setup) extend
// `best_oifs` together, including a backup router the kernel itself
// would not choose for outbound traffic. IPv4 routes never carry the
// attribute; absence falls back to MEDIUM, the documented default,
// so v4 selection is unchanged.
const RTA_PREF: u16 = netlink::rtattr_type_t::RTA_PREF as u16;

// `struct rtnexthop` flag bits from <linux/rtnetlink.h>. Nexthops with
// any of these set are not currently usable, so the multipath walker
// skips them rather than emit them as if they were live.
const RTNH_F_DEAD: u8 = 1;
const RTNH_F_LINKDOWN: u8 = 16;
const RTNH_F_UNRESOLVED: u8 = 32;

// rtm_type values from <linux/rtnetlink.h> (stable kernel UAPI).
const RTN_UNICAST: u8 = 1;
const RTN_LOCAL: u8 = 2;

const RT_TABLE_MAIN: u16 = netlink::rt_class_t::RT_TABLE_MAIN as u16;
// `route_table` only emits routes from the kernel's standard RPDB
// tables — `local` (255), `main` (254), and `default` (253). These
// are the three the default rule chain `0: lookup local; 32766:
// lookup main; 32767: lookup default` consults for every outbound
// packet on a host without custom `ip rule` policy, so they reflect
// "what would the kernel actually do for this destination".
//
// Custom policy tables (selected via `ip rule` with fwmark, iif,
// uid, etc.) carry constraints that aren't representable in
// `IpRoute`, so surfacing them would mislead callers — the route
// would look generally usable when the kernel only consults it for
// matching policy rules.
const RT_TABLE_LOCAL: u32 = netlink::rt_class_t::RT_TABLE_LOCAL as u32;
// `RT_TABLE_DEFAULT` (253) is the kernel's last-resort table —
// queried by the default rule `32767: from all lookup default`. A
// host with a fallback default route installed there
// (`ip route add default via X table default`) has the kernel route
// real traffic via that entry, so the route walker must include it
// or `route_table()` and best-local selection will silently miss
// the route the kernel would actually use.
const RT_TABLE_DEFAULT: u32 = netlink::rt_class_t::RT_TABLE_DEFAULT as u32;

/// RPDB precedence rank for the three built-in tables `route_table`
/// admits. Lower rank = consulted first by the kernel rule chain
/// (`0: lookup local; 32766: lookup main; 32767: lookup default`)
/// = wins regardless of numeric metric. Used by
/// `netlink_best_local_addrs_into` so a `RT_TABLE_DEFAULT` fallback
/// can never beat a `RT_TABLE_MAIN` default with worse metric — the
/// kernel itself wouldn't select the fallback in that situation.
///
/// `RT_TABLE_LOCAL` is ranked first for completeness; in practice it
/// holds broadcast / address-owning routes, not transit defaults, so
/// `dst_len == 0` candidates never come from there.
///
/// Any other table (`local` / `main` / `default` are the only ones
/// upstream code admits — see the table allow-list at the
/// `route_table` walker filter) returns `u8::MAX`, which is
/// unreachable in normal flow but keeps the function total.
#[inline]
fn table_rank_for(table_id: u32) -> u8 {
  if table_id == RT_TABLE_LOCAL {
    0
  } else if table_id == RT_TABLE_MAIN as u32 {
    1
  } else if table_id == RT_TABLE_DEFAULT {
    2
  } else {
    u8::MAX
  }
}

/// RFC 4191 router-preference rank for IPv6 default routes, lex-ready
/// (smaller wins). The wire values from
/// `include/uapi/linux/icmpv6.h` are non-monotonic
/// (`HIGH = 0x1`, `MEDIUM = 0x0`, `LOW = 0x3`, plus the reserved
/// `INVALID = 0x2`), which we can't sort directly — remap to a clean
/// `HIGH < MEDIUM < LOW` order so `(table_rank, metric, pref_rank)`
/// lex-compare matches the kernel's tie-break for equal-metric IPv6
/// defaults.
///
/// Absence of `RTA_PREF` and reserved/unknown values both fold to
/// MEDIUM — that's the kernel's default and the value applied to
/// every IPv4 route (no preference attribute), so v4 selection is
/// unaffected by introducing this tier.
#[inline]
fn pref_rank_for(pref: u8) -> u8 {
  // Constants from `include/uapi/linux/icmpv6.h`
  // (`enum icmpv6_router_pref`). MEDIUM (0x0) and INVALID (0x2) are
  // covered by the fall-through arm, so they don't need named
  // constants here.
  const ICMPV6_ROUTER_PREF_HIGH: u8 = 0x1;
  const ICMPV6_ROUTER_PREF_LOW: u8 = 0x3;
  match pref {
    ICMPV6_ROUTER_PREF_HIGH => 0,
    ICMPV6_ROUTER_PREF_LOW => 2,
    // MEDIUM (0x0) and INVALID (0x2) / unknown / absent all land
    // here. The kernel uses MEDIUM as the default; treating
    // unknown as MEDIUM is conservative — it can't downgrade a
    // valid route below LOW or upgrade it above HIGH.
    _ => 1,
  }
}

const IFA_LOCAL: u32 = netlink::IFA_LOCAL as u32;
const IFA_ADDRESS: u32 = netlink::IFA_ADDRESS as u32;

const IFLA_MTU: u32 = if_arp::IFLA_MTU as u32;
const IFLA_IFNAME: u32 = if_arp::IFLA_IFNAME as u32;
const IFLA_ADDRESS: u32 = if_arp::IFLA_ADDRESS as u32;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct MessageHeader {
  nlmsg_len: u32,
  nlmsg_type: u16,
  nlmsg_flags: u16,
  nlmsg_seq: u32,
  nlmsg_pid: u32,
}

struct Handle {
  fd: OwnedFd,
  sa: SocketAddrNetlink,
}

impl Handle {
  unsafe fn new() -> io::Result<Self> {
    // Create the netlink socket. We deliberately do NOT bind() it.
    //
    // The kernel auto-binds a unique portid on the first sendto()
    // (netlink_autobind), and that path does not pass through the SELinux
    // `bind` permission check that an explicit bind() triggers. Android's
    // `untrusted_app` domain denies `bind` on netlink_route_socket
    // (b/155595000) but allows the autobind-on-send that getifaddrs() and
    // Go's net package rely on — so skipping the explicit bind is what lets
    // this crate run inside an Android app. There is no behavioural change
    // on other platforms: the socket ends up with the same kernel-assigned
    // portid either way, and every entry point sends before calling
    // getsockname(), so the portid is set before the nlmsg_pid filter reads
    // it.
    let sock = socket(AddressFamily::NETLINK, SocketType::RAW, None)?;
    let sa = SocketAddrNetlink::new(0, 0);
    Ok(Self { fd: sock, sa })
  }

  unsafe fn send(&self, req: &NetlinkRouteRequest) -> io::Result<usize> {
    self.send_bytes(req.as_bytes())
  }

  unsafe fn send_bytes(&self, bytes: &[u8]) -> io::Result<usize> {
    sendto(&self.fd, bytes, SendFlags::empty(), &self.sa).map_err(Into::into)
  }

  unsafe fn sock(&self) -> io::Result<SocketAddrNetlink> {
    getsockname(&self.fd)
      .and_then(|addr| addr.try_into())
      .map_err(Into::into)
  }

  unsafe fn recv(&self, dst: &mut [u8]) -> io::Result<usize> {
    let (nr, _, _) = recvfrom(&self.fd, dst, RecvFlags::empty())?;

    if nr < NLMSG_HDRLEN {
      return Err(rustix::io::Errno::INVAL.into());
    }

    Ok(nr)
  }
}

/// Receive-buffer size for route / nexthop dumps.
///
/// A single `RTM_NEWROUTE` message can comfortably exceed 4 KiB on
/// hosts with large ECMP `RTA_MULTIPATH` lists or `RTM_NEWNEXTHOP`
/// dumps with deep `NHA_GROUP` payloads (8 bytes per member). The
/// per-interface and per-address walks stay on a page (their messages
/// are small and bounded), but route walks must accept any single
/// message the kernel produces — the OS truncates oversize messages
/// silently, surfacing later as `nlmsg_len > nr` → spurious
/// `EINVAL` aborting the whole walk.
///
/// `iproute2` uses 32 KiB for the same dumps; matching that gives
/// plenty of headroom for ECMP across dozens of nexthops without
/// resorting to the more invasive `recvmsg` + `MSG_TRUNC` retry
/// pattern.
const ROUTE_RECV_BUF_SIZE: usize = 32 * 1024;

pub(super) fn netlink_interface(family: AddressFamily, ifi: u32) -> io::Result<TinyVec<Interface>> {
  unsafe {
    let handle = Handle::new()?;

    // Create and send netlink request
    let req = NetlinkRouteRequest::new(RTM_GETLINK as u16, 1, family.as_raw() as u8, ifi);
    handle.send(&req)?;

    // Get socket name
    let lsa = handle.sock()?;

    // Receive and process messages
    let page_size = rustix::param::page_size();
    let mut rb = vec![0u8; page_size];

    let mut interfaces = TinyVec::new();

    'outer: loop {
      let nr = handle.recv(&mut rb)?;

      let mut received = &rb[..nr];

      while received.len() >= NLMSG_HDRLEN {
        let h = decode_nlmsghdr(received);
        let hlen = h.nlmsg_len as usize;
        let l = nlm_align_of(hlen);
        if hlen < NLMSG_HDRLEN || l > received.len() {
          return Err(rustix::io::Errno::INVAL.into());
        }

        if h.nlmsg_seq != 1 || h.nlmsg_pid != lsa.pid() {
          return Err(rustix::io::Errno::INVAL.into());
        }

        // Bound the per-message slice to `hlen` rather than the rest
        // of the recv buffer. Netlink dumps routinely pack multiple
        // messages into one recv() and an unbounded slice would let
        // the attribute walker run past the current message into the
        // next message's header — corrupting fields or returning
        // EINVAL on healthy kernel output.
        let msg_buf = &received[NLMSG_HDRLEN..hlen];

        match h.nlmsg_type as u32 {
          NLMSG_DONE => break 'outer,
          // Decode the errno instead of flattening every NLMSG_ERROR to
          // EINVAL: a denial delivered in-band (e.g. RTM_GETLINK ->
          // -EACCES/-EPERM for Android's untrusted_app) must surface as
          // PermissionDenied so the ioctl fallback in
          // `super::interface_table` can engage. Mirrors the route walkers.
          NLMSG_ERROR => match decode_nlmsgerr(received, hlen)? {
            NlmsgErrOutcome::Ack => {
              received = &received[l..];
              continue;
            }
            NlmsgErrOutcome::FamilyUnavailable => break 'outer,
          },
          val if val == RTM_NEWLINK => {
            let info_hdr = IfInfoMessageHeader::parse(msg_buf)?;
            let mut info_data = &msg_buf[IfInfoMessageHeader::SIZE..];
            if ifi != 0 && ifi != info_hdr.index as u32 {
              // move forward
              received = &received[l..];
              continue;
            }

            let mut interface = Interface::new(
              info_hdr.index as u32,
              Flags::from_bits_truncate(info_hdr.flags),
            );
            while info_data.len() >= RtAttr::SIZE {
              let attr = RtAttr {
                len: u16::from_ne_bytes(info_data[..2].try_into().unwrap()),
                ty: u16::from_ne_bytes(info_data[2..4].try_into().unwrap()),
              };
              let attrlen = attr.len as usize;
              if attrlen < RtAttr::SIZE || attrlen > info_data.len() {
                return Err(rustix::io::Errno::INVAL.into());
              }

              // Payload excludes the header and excludes any trailing
              // padding (the padding is counted by `alen` for iterator
              // advance but is not part of the attribute value).
              let data = &info_data[RtAttr::SIZE..attrlen];
              // Aligned length is used to walk to the next attribute,
              // but must not be allowed to exceed the buffer — a
              // malformed last attribute could otherwise make the
              // slice below panic.
              let alen = rta_align_of(attrlen).min(info_data.len());

              match attr.ty as u32 {
                IFLA_MTU if data.len() >= 4 => {
                  interface.mtu = u32::from_ne_bytes(data[..4].try_into().unwrap());
                }
                IFLA_IFNAME => {
                  // Kernel-emitted IFLA_IFNAME is null-terminated, but
                  // we still bound the read to `data` in case of a
                  // malformed message (avoids UB from `CStr::from_ptr`
                  // scanning past the attribute). Use the lossy UTF-8
                  // conversion — matching the pre-refactor
                  // `CStr::to_string_lossy` behaviour — so an interface
                  // with non-UTF8 bytes surfaces as a replacement-char
                  // string rather than silently becoming empty and
                  // colliding with other nameless interfaces.
                  let nul = data.iter().position(|&b| b == 0).unwrap_or(data.len());
                  interface.name = String::from_utf8_lossy(&data[..nul]).as_ref().into();
                }
                IFLA_ADDRESS => match data.len() {
                  // We never return any /32 or /128 IP address
                  // prefix on any IP tunnel interface as the
                  // hardware address.
                  // ipv4
                  4 if info_hdr.ty == ARPHRD_IPGRE as u16
                    || info_hdr.ty == ARPHRD_TUNNEL as u16 =>
                  {
                    info_data = &info_data[alen..];
                    continue;
                  }
                  // ipv6
                  16 if info_hdr.ty == ARPHRD_TUNNEL6 as u16 || info_hdr.ty == 823 => {
                    info_data = &info_data[alen..];
                    continue;
                  } // 823 is any over GRE over IPv6 tunneling
                  _ => {
                    let mut nonzero = false;
                    for b in data {
                      if *b != 0 {
                        nonzero = true;
                        break;
                      }
                    }
                    if nonzero {
                      let mut buf = [0; MAC_ADDRESS_SIZE];
                      let len = data.len().min(MAC_ADDRESS_SIZE);
                      buf[..len].copy_from_slice(&data[..len]);
                      interface.mac_addr = Some(MacAddr::from_raw(buf));
                    }
                  }
                },
                _ => {}
              }

              info_data = &info_data[alen..];
            }
            interfaces.push(interface);
          }
          _ => {}
        }

        received = &received[l..];
      }
    }

    Ok(interfaces)
  }
}

pub(super) fn netlink_addr<N, F>(family: AddressFamily, ifi: u32, f: F) -> io::Result<SmallVec<N>>
where
  N: Net,
  F: FnMut(&IpAddr) -> bool,
{
  let mut out = SmallVec::new();
  netlink_addr_into(family, ifi, f, &mut out)?;
  Ok(out)
}

/// Same as `netlink_addr` but pushes results into the caller's buffer
/// instead of allocating a fresh one. Used by `best_local_addrs()` to
/// merge per-family walks without three intermediate `SmallVec`s.
pub(super) fn netlink_addr_into<N, F>(
  family: AddressFamily,
  ifi: u32,
  mut f: F,
  addrs: &mut SmallVec<N>,
) -> io::Result<()>
where
  N: Net,
  F: FnMut(&IpAddr) -> bool,
{
  unsafe {
    let handle = Handle::new()?;

    // Create and send netlink request
    let req = NetlinkRouteRequest::new(RTM_GETADDR as u16, 1, family.as_raw() as u8, ifi);
    handle.send(&req)?;

    // Get socket name
    let lsa = handle.sock()?;

    // Receive and process messages
    let page_size = rustix::param::page_size();
    let mut rb = vec![0u8; page_size];

    'outer: loop {
      let nr = handle.recv(&mut rb)?;
      let mut received = &rb[..nr];

      // means auto choose interface for addr fetching
      while received.len() >= NLMSG_HDRLEN {
        let h = decode_nlmsghdr(received);
        let hlen = h.nlmsg_len as usize;
        let l = nlm_align_of(hlen);
        if hlen < NLMSG_HDRLEN || l > received.len() {
          return Err(rustix::io::Errno::INVAL.into());
        }

        if h.nlmsg_seq != 1 || h.nlmsg_pid != lsa.pid() {
          return Err(rustix::io::Errno::INVAL.into());
        }

        // See `netlink_interface` for why this is bounded to `hlen`.
        let msg_buf = &received[NLMSG_HDRLEN..hlen];

        match h.nlmsg_type as u32 {
          NLMSG_DONE => break 'outer,
          // Decode the errno rather than flattening to EINVAL, mirroring the
          // route walkers — a real error (e.g. EACCES/EPERM) propagates with
          // its `ErrorKind` intact instead of becoming InvalidInput.
          NLMSG_ERROR => match decode_nlmsgerr(received, hlen)? {
            NlmsgErrOutcome::Ack => {
              received = &received[l..];
              continue;
            }
            NlmsgErrOutcome::FamilyUnavailable => break 'outer,
          },
          val if val == RTM_NEWADDR => {
            let ifam = IfNetMessageHeader::parse(msg_buf)?;
            let mut ifa_msg_data = &msg_buf[IfNetMessageHeader::SIZE..];
            let mut point_to_point = false;
            let mut attrs = SmallVec::new();
            while ifa_msg_data.len() >= RtAttr::SIZE {
              let attr = RtAttr {
                len: u16::from_ne_bytes(ifa_msg_data[..2].try_into().unwrap()),
                ty: u16::from_ne_bytes(ifa_msg_data[2..4].try_into().unwrap()),
              };
              let attrlen = attr.len as usize;
              if attrlen < RtAttr::SIZE || attrlen > ifa_msg_data.len() {
                return Err(rustix::io::Errno::INVAL.into());
              }
              // `data` excludes trailing padding; `alen` (aligned) is
              // used only to advance to the next attribute, and is
              // clamped so a malformed last attribute cannot panic.
              let data = &ifa_msg_data[RtAttr::SIZE..attrlen];
              let alen = rta_align_of(attrlen).min(ifa_msg_data.len());

              if ifi == 0 || ifi == ifam.index {
                attrs.push((attr, data));
              }
              ifa_msg_data = &ifa_msg_data[alen..];
            }

            for (attr, _) in attrs.iter() {
              if attr.ty == IFA_LOCAL as u16 {
                point_to_point = true;
                break;
              }
            }

            for (attr, data) in attrs.iter() {
              if point_to_point && attr.ty == IFA_ADDRESS as u16 {
                continue;
              }

              match AddressFamily::from_raw(ifam.family as u16) {
                AddressFamily::INET if data.len() >= 4 => {
                  let ip: [u8; 4] = data[..4].try_into().unwrap();
                  if attr.ty == IFA_ADDRESS as u16 || attr.ty == IFA_LOCAL as u16 {
                    if let Some(addr) =
                      N::try_from_with_filter(ifam.index, ip.into(), ifam.prefix_len, |addr| {
                        f(addr)
                      })
                    {
                      addrs.push(addr);
                    }
                  }
                }
                AddressFamily::INET6 if data.len() >= 16 => {
                  let ip: [u8; 16] = data[..16].try_into().unwrap();
                  if attr.ty == IFA_ADDRESS as u16 || attr.ty == IFA_LOCAL as u16 {
                    if let Some(addr) =
                      N::try_from_with_filter(ifam.index, ip.into(), ifam.prefix_len, |addr| {
                        f(addr)
                      })
                    {
                      addrs.push(addr);
                    }
                  }
                }
                _ => {}
              }
            }
          }
          _ => {}
        }

        received = &received[l..];
      }
    }

    Ok(())
  }
}

pub fn netlink_best_local_addrs<N>(family: AddressFamily) -> io::Result<SmallVec<N>>
where
  N: Net,
{
  let mut out = SmallVec::new();
  netlink_best_local_addrs_into(family, &mut out)?;
  Ok(out)
}

/// Variant of [`netlink_best_local_addrs`] that pushes into the
/// caller's buffer. Lets the union `best_local_addrs()` walk both
/// families without allocating intermediate per-family `SmallVec`s.
pub fn netlink_best_local_addrs_into<N>(
  family: AddressFamily,
  out: &mut SmallVec<N>,
) -> io::Result<()>
where
  N: Net,
{
  unsafe {
    // Lazy nexthop-dump: don't pay the `RTM_GETNEXTHOP` round-trip
    // unless the route walk actually encounters an `RTA_NH_ID`
    // attribute on a default route. Most Linux hosts have no `ip
    // nexthop`-managed routes (Linux 5.3+ opt-in feature); on those
    // hosts `best_local_*` no longer fails when an unrelated nexthop
    // dump returns `EINTR` / `NLM_F_DUMP_INTR` from concurrent
    // nexthop-subsystem churn. Same pattern `netlink_walk_routes`
    // and `rt_generic_addrs` already use; keeping all three
    // consistent.
    //
    // Selection key for deferred candidates:
    // `(table_rank, metric, pref_rank, nh_id)`. `table_rank` carries
    // Linux RPDB precedence (`local` < `main` < `default`); within
    // the same table, lower metric wins; within the same metric,
    // lower pref_rank wins (HIGH < MEDIUM < LOW per RFC 4191). See
    // `table_rank_for` and `pref_rank_for` below.
    let mut deferred_best: Vec<(u8, u32, u8, u32)> = Vec::new();

    let handle = Handle::new()?;

    let req = NetlinkRouteRequest::new(RTM_GETROUTE as u16, 1, family.as_raw() as u8, 0);
    handle.send(&req)?;

    // Snapshot the kernel-assigned address so we can reject any reply
    // that doesn't belong to this socket — same defence the other
    // netlink walkers use.
    let lsa = handle.sock()?;

    // Route walks must accept any single message the kernel emits —
    // see `ROUTE_RECV_BUF_SIZE` for why a page is too small here.
    let mut rb = vec![0u8; ROUTE_RECV_BUF_SIZE];
    // Set of interfaces tied at `best_metric`. ECMP / nexthop-object
    // groups can list multiple usable nexthops behind a single route,
    // and equal-metric default routes on different interfaces are
    // also valid; both should contribute their addresses. The
    // previous `Option<u32>` form silently dropped every nexthop
    // past the first, returning an order-dependent partial address
    // set on multi-WAN hosts.
    let mut best_oifs: SmallVec<u32> = SmallVec::new();
    // Lex key for "best default": `(table_rank, metric)`. The kernel
    // walks the RPDB rule chain in order — `0: lookup local`,
    // `32766: lookup main`, `32767: lookup default` — so a
    // higher-ranked table is queried first and any route there will
    // be picked before the kernel ever consults a lower-ranked
    // table, *regardless of metric*. Comparing on metric alone made
    // a low-metric `RT_TABLE_DEFAULT` fallback beat a higher-metric
    // `RT_TABLE_MAIN` default — even though the kernel would never
    // do that. The lex key matches kernel selection exactly.
    let mut best_rank: u8 = u8::MAX;
    let mut best_metric: u32 = u32::MAX;
    // Lex tier: RFC 4191 router preference rank. See `pref_rank_for`.
    // `u8::MAX` is the "no candidate yet" sentinel; any real route
    // will produce a strictly smaller value.
    let mut best_pref_rank: u8 = u8::MAX;

    'outer: loop {
      let nr = handle.recv(&mut rb)?;

      let mut received = &rb[..nr];

      while received.len() >= NLMSG_HDRLEN {
        let h = decode_nlmsghdr(received);
        let hlen = h.nlmsg_len as usize;
        let l = nlm_align_of(hlen);

        // Validate the message length before slicing on `hlen` /
        // advancing by `l`. Without these guards a malformed
        // `RTM_NEWROUTE` would either panic the slice below or — if
        // `l == 0` — keep the inner loop from advancing forever.
        if hlen < NLMSG_HDRLEN || l > received.len() {
          return Err(rustix::io::Errno::INVAL.into());
        }
        if h.nlmsg_seq != 1 || h.nlmsg_pid != lsa.pid() {
          return Err(rustix::io::Errno::INVAL.into());
        }

        match h.nlmsg_type as u32 {
          NLMSG_DONE => {
            // Mirror `netlink_walk_routes`: surface EINTR if the
            // dump was interrupted by routing-table churn (DHCP /
            // VPN / interface flap mid-walk). Selecting a best
            // interface from a partial snapshot would be a silent
            // wrong answer; EINTR lets the caller retry.
            if h.nlmsg_flags as u32 & NLM_F_DUMP_INTR != 0 {
              return Err(rustix::io::Errno::INTR.into());
            }
            break 'outer;
          }
          NLMSG_ERROR => match decode_nlmsgerr(received, hlen)? {
            NlmsgErrOutcome::Ack => {
              received = &received[l..];
              continue;
            }
            // No stack for this family — surface as "no best route"
            // instead of `Err`. Lets `best_local_addrs()` keep the
            // populated v4 result on a v6-disabled host (and vice
            // versa).
            NlmsgErrOutcome::FamilyUnavailable => return Ok(()),
          },
          val if val == RTM_NEWROUTE => {
            // See `netlink_interface` for why this is bounded to `hlen`.
            let rtm = &received[NLMSG_HDRLEN..hlen];
            let rtm_header = RtmMessageHeader::parse(rtm)?;

            // Same eligibility checks as `netlink_walk_routes`. Without
            // these a low-metric `blackhole default`, an `unreachable
            // default`, or a TOS / source-constrained default could win
            // `best_ifindex` and steer `best_local_*` at an interface
            // the kernel would never use for ordinary traffic.
            //
            //   - rtm_type ∈ {RTN_UNICAST, RTN_LOCAL}: filters
            //     blackhole / unreachable / prohibit / multicast / nat /
            //     broadcast types.
            //   - rtm_tos == 0: skip TOS-conditional routes.
            //   - rtm_src_len == 0: skip source-prefix-constrained
            //     policy routes.
            // RTA_TABLE override (for table id > 255) and RTA_SRC are
            // applied after the attribute walk below.
            if rtm_header.rtm_type != RTN_UNICAST && rtm_header.rtm_type != RTN_LOCAL {
              received = &received[l..];
              continue;
            }
            if rtm_header.rtm_tos != 0 || rtm_header.rtm_src_len != 0 {
              received = &received[l..];
              continue;
            }

            // We're hunting for the *default route*, not any gateway-
            // bearing entry. A specific route like
            // `10.0.0.0/8 via 10.0.0.1 dev eth1` would otherwise be
            // treated as eligible here — combined with the
            // metric-zero fallback below it could beat the actual
            // default route on a different interface, so
            // `best_local_ipv4_addrs()` would hand back addresses
            // for an interface the kernel doesn't use for ordinary
            // outbound traffic.
            //
            // The default route's defining property in rtnetlink is
            // `rtm_dst_len == 0`. We do NOT additionally check
            // `rtm_flags & RTF_UP`: rtnetlink's `rtm_flags` is the
            // RTM_F_* set (NOTIFY, CLONED, PREFIX, ...) — not the
            // BSD/legacy SIOCADDRT `RTF_*` set, where `RTF_UP` lives.
            // Ordinary installed Linux defaults have `rtm_flags == 0`
            // and would be incorrectly skipped. Reachability filters
            // (RTN_UNICAST/RTN_LOCAL above, table-id and source
            // constraints below, multipath / nh_id usability flags
            // around `RTNH_F_DEAD` etc.) cover the "is it deliverable"
            // question without mis-applying a BSD flag bit.
            if rtm_header.rtm_dst_len != 0 {
              received = &received[l..];
              continue;
            }

            let mut rtattr_buf = &rtm[RtmMessageHeader::SIZE..];
            let mut current_metric = None;
            // Output interfaces this route targets — populated from
            // `RTA_OIF` (one entry), or from the resolved nexthop set
            // for `RTA_MULTIPATH` / `RTA_NH_ID` routes (multiple).
            let mut current_oifs: SmallVec<u32> = SmallVec::new();
            // Track whether we found a top-level `RTA_OIF` so the
            // post-walk multipath / nh_id resolution doesn't override
            // an explicit oif.
            let mut have_top_oif = false;
            // `RTA_MULTIPATH` (ECMP) and `RTA_NH_ID` (nexthop-object)
            // routes don't carry a top-level `RTA_OIF`. We capture the
            // payload / id here and resolve them after the attribute
            // walk so the best-interface selection covers the same
            // route encodings `netlink_walk_routes` does — otherwise
            // `best_local_*` returns empty on hosts whose only default
            // is ECMP or `ip nexthop`-based.
            let mut multipath: Option<&[u8]> = None;
            let mut nh_id: Option<u32> = None;
            // Effective table id (RTA_TABLE override for > 255) and
            // source-constraint detection — shared with
            // `netlink_walk_routes`.
            let mut table_id: u32 = rtm_header.rtm_table as u32;
            let mut has_src_constraint = false;
            // Track whether RTA_DST claimed a non-unspecified address.
            // The outer guard already required `rtm_dst_len == 0`, so
            // a sane default route either omits RTA_DST entirely or
            // emits 0.0.0.0 / ::. A kernel-emitted route with
            // `dst_len == 0` but `RTA_DST = 192.0.2.1` is malformed —
            // skip it rather than steer best-local at the wrong oif.
            let mut dst_specific = false;
            // Separately track "RTA_DST present but failed to parse"
            // (truncated payload, wrong-family). Without this, a
            // malformed RTA_DST returned `None` from
            // `parse_rta_ipaddr`, which left `dst_specific = false`
            // and the row stayed eligible for best-local selection.
            // The full route walker has the same `dst_malformed`
            // guard — keep the two paths consistent so a malformed
            // default route is suppressed from `best_local_*` for
            // the same reason it's suppressed from `route_table*`.
            let mut dst_malformed = false;
            // RFC 4191 router preference for IPv6 RA-installed
            // defaults. Kernel default (and the value applied to
            // every IPv4 route, which never carries the attribute)
            // is `MEDIUM = 0x0`. See `pref_rank_for`.
            let mut current_pref: u8 = 0;

            while rtattr_buf.len() >= RtAttr::SIZE {
              let attr = RtAttr {
                len: u16::from_ne_bytes(rtattr_buf[..2].try_into().unwrap()),
                ty: u16::from_ne_bytes(rtattr_buf[2..4].try_into().unwrap()),
              };

              let attrlen = attr.len as usize;
              if attrlen < RtAttr::SIZE || attrlen > rtattr_buf.len() {
                // A malformed attribute must not be silently used to
                // select `best_ifindex`: if we `break`ed here and then
                // applied partial `current_metric` / `current_oif`,
                // corrupted kernel output could steer us to the wrong
                // interface. Bail out in the same way the interface
                // and address parsers above do.
                return Err(rustix::io::Errno::INVAL.into());
              }
              let data = &rtattr_buf[RtAttr::SIZE..attrlen];
              let alen = rta_align_of(attrlen).min(rtattr_buf.len());

              match attr.ty {
                RTA_PRIORITY if data.len() >= 4 => {
                  current_metric = Some(u32::from_ne_bytes(data[..4].try_into().unwrap()));
                }
                RTA_OIF if data.len() >= 4 => {
                  let idx = u32::from_ne_bytes(data[..4].try_into().unwrap());
                  if idx != 0 {
                    current_oifs.push(idx);
                  }
                  have_top_oif = true;
                }
                RTA_DST => match parse_rta_ipaddr(rtm_header.rtm_family, data) {
                  Some(addr) if !addr.is_unspecified() => {
                    dst_specific = true;
                  }
                  Some(_) => {}
                  None => {
                    dst_malformed = true;
                  }
                },
                RTA_MULTIPATH => {
                  multipath = Some(data);
                }
                RTA_NH_ID if data.len() >= 4 => {
                  nh_id = Some(u32::from_ne_bytes(data[..4].try_into().unwrap()));
                }
                RTA_TABLE if data.len() >= 4 => {
                  table_id = u32::from_ne_bytes(data[..4].try_into().unwrap());
                }
                RTA_SRC => {
                  // Source constraint via attribute (rtm_src_len was
                  // zero but kernel still emitted RTA_SRC) — defence
                  // in depth.
                  has_src_constraint = true;
                }
                RTA_PREF if !data.is_empty() => {
                  current_pref = data[0];
                }
                _ => {}
              }

              rtattr_buf = &rtattr_buf[alen..];
            }

            // Drop routes from custom policy tables and any
            // post-walk-discovered source constraints, plus any
            // dst_len=0 row that smuggled in a specific destination
            // or carried a malformed RTA_DST (which the route walker
            // also drops).
            if has_src_constraint
              || dst_specific
              || dst_malformed
              || (table_id != RT_TABLE_MAIN as u32
                && table_id != RT_TABLE_LOCAL
                && table_id != RT_TABLE_DEFAULT)
            {
              received = &received[l..];
              continue;
            }

            // Resolve oifs from RTA_MULTIPATH or RTA_NH_ID when
            // top-level RTA_OIF is absent. Both encodings can list
            // multiple usable nexthops on different interfaces — for
            // a multi-WAN ECMP default we want addresses from *all*
            // of them, not just the first. The previous "first only"
            // form silently dropped the rest.
            //
            // For RTA_NH_ID:
            //   - `Some(non-empty)`: collect every resolved oif.
            //   - `Some(empty)`: id known but kernel-marked unusable
            //     (blackhole / linkdown / ...) — skip silently, no
            //     retry.
            //   - `None`: id absent from snapshot. Defer to a
            //     post-walk retry pass so a nexthop installed between
            //     our two dumps doesn't silently misroute.
            if !have_top_oif {
              if let Some(mp) = multipath {
                multipath_oifs_into(mp, &mut current_oifs);
              } else if let Some(id) = nh_id {
                // Lazy resolution: defer every `RTA_NH_ID` default
                // candidate to the post-walk pass. The pass dumps
                // nexthops once and resolves the entire batch — same
                // correctness as the previous "try inline, defer to
                // retry" two-dump pattern, but we skip the dump
                // entirely when no default route uses nexthop
                // objects.
                let metric = current_metric.unwrap_or(0);
                let rank = table_rank_for(table_id);
                let pref_rank = pref_rank_for(current_pref);
                deferred_best.push((rank, metric, pref_rank, id));
                received = &received[l..];
                continue;
              }
            }

            // Update the candidate set on `(table_rank, metric)` lex
            // order. A strictly better key resets the set (the new
            // route supersedes everything collected so far); an
            // equal key extends it (equal-cost ECMP across separate
            // route entries, including the same destination listed
            // in two route messages).
            //
            // Comparing on metric alone made a low-metric
            // `RT_TABLE_DEFAULT` fallback beat a higher-metric
            // `RT_TABLE_MAIN` default — kernel-incorrect. Lex
            // comparison matches the kernel's rule-chain semantics:
            // `local < main < default`, with metric only as a
            // tie-breaker within the same table.
            //
            // A missing `RTA_PRIORITY` is the kernel's convention
            // for "metric 0"; collapse missing/explicit into one
            // comparison so a metric-less default can correctly
            // beat an earlier explicit-metric default in the same
            // table regardless of dump order.
            if !current_oifs.is_empty() {
              let metric = current_metric.unwrap_or(0);
              let rank = table_rank_for(table_id);
              let pref_rank = pref_rank_for(current_pref);
              let cur_key = (rank, metric, pref_rank);
              let best_key = (best_rank, best_metric, best_pref_rank);
              if cur_key < best_key {
                best_rank = rank;
                best_metric = metric;
                best_pref_rank = pref_rank;
                best_oifs.clear();
                best_oifs.extend(current_oifs.iter().copied());
              } else if cur_key == best_key {
                best_oifs.extend(current_oifs.iter().copied());
              }
            }
          }
          _ => {}
        }

        received = &received[l..];
      }
    }

    // Resolve any deferred `RTA_NH_ID` default-route references in a
    // single batch. Skipping this block when nothing was deferred is
    // the whole point of the lazy-dump optimization — most Linux
    // hosts have no `ip nexthop`-managed default routes and never
    // pay the `RTM_GETNEXTHOP` round-trip. `None` from
    // `resolve_nh_id` means the id wasn't in the dump (kernel state
    // changed during enumeration); surface as `EINTR` so the caller
    // can retry rather than silently lose the route. `Some(empty)`
    // means the nexthop is present but unusable (blackhole / down)
    // — skip silently. `Some(non-empty)` contributes oifs to the
    // selection key; same `<` / `==` lex semantics as the first
    // pass.
    if !deferred_best.is_empty() {
      let nh_map = dump_nexthops()?;
      for (rank, metric, pref_rank, id) in deferred_best {
        match resolve_nh_id(&nh_map, id) {
          None => return Err(rustix::io::Errno::INTR.into()),
          Some(resolved) => {
            let oifs: SmallVec<u32> = resolved
              .iter()
              .filter_map(|(oif, _)| if *oif != 0 { Some(*oif) } else { None })
              .collect();
            if oifs.is_empty() {
              continue;
            }
            let cur_key = (rank, metric, pref_rank);
            let best_key = (best_rank, best_metric, best_pref_rank);
            if cur_key < best_key {
              best_rank = rank;
              best_metric = metric;
              best_pref_rank = pref_rank;
              best_oifs.clear();
              best_oifs.extend(oifs);
            } else if cur_key == best_key {
              best_oifs.extend(oifs);
            }
          }
        }
      }
    }

    // Sort + dedup so a multipath route that lists the same
    // interface twice (or two separate routes that share an
    // interface) doesn't make us walk the address dump twice for
    // the same ifindex.
    best_oifs.sort_unstable();
    best_oifs.dedup();

    // Fetch addresses for every selected interface, appending into
    // the caller-provided buffer. Returns immediately on the first
    // syscall failure; partial results stay in `out` (consistent with
    // every other walker that pushes into a sink).
    for idx in best_oifs {
      netlink_addr_into(family, idx, local_ip_filter, out)?;
    }
    Ok(())
  }
}

/// One nexthop-object entry from a `RTM_GETNEXTHOP` dump. Either a
/// "leaf" (single `oif` + optional gateway) or a `group` of member ids
/// (each member resolves recursively against the same map).
///
/// Filtered nexthops (`NHA_BLACKHOLE` or `nh_flags` carrying
/// `RTNH_F_DEAD` / `RTNH_F_LINKDOWN` / `RTNH_F_UNRESOLVED`) are still
/// inserted into the map with `filtered = true`. The route walker
/// needs that signal to tell "id present but unusable" (skip silently,
/// no retry) apart from "id genuinely absent" (deferred for a single
/// retry pass, then surfaced as EINTR). Without that distinction, one
/// blackhole route would fail `route_table()` for the whole host.
#[derive(Debug, Clone)]
struct NexthopInfo {
  oif: u32,
  gw: Option<IpAddr>,
  /// `Some(member_ids)` for `NHA_GROUP`. Empty list means a malformed
  /// group; we treat those as unusable. Single-leaf nexthops carry
  /// `None`.
  group: Option<SmallVec<u32>>,
  /// Kernel-side "this nexthop won't deliver traffic" marker.
  filtered: bool,
}

/// Build the wire bytes for `RTM_GETNEXTHOP` + `NLM_F_DUMP`. The body
/// is `struct nhmsg` (all-zero); zero `nh_family` is `AF_UNSPEC`, which
/// returns leaf nexthops of every family AND nexthop *group* objects
/// (containers carrying `NHA_GROUP`). The kernel filters group objects
/// out of any dump with a nonzero `nh_family`, because a group is
/// family-agnostic and doesn't satisfy a per-family filter — so the
/// only safe family to ask for is `AF_UNSPEC`. Even routes belonging
/// to a single family may reference a group via `RTA_NH_ID`, so we
/// must dump unfiltered.
fn build_nh_dump_request(seq: u32) -> [u8; 24] {
  let mut bytes = [0u8; 24];
  // nlmsghdr (16 bytes)
  bytes[0..4].copy_from_slice(&24u32.to_ne_bytes());
  bytes[4..6].copy_from_slice(&(RTM_GETNEXTHOP as u16).to_ne_bytes());
  bytes[6..8].copy_from_slice(&((NLM_F_DUMP | NLM_F_REQUEST) as u16).to_ne_bytes());
  bytes[8..12].copy_from_slice(&seq.to_ne_bytes());
  bytes[12..16].copy_from_slice(&std::process::id().to_ne_bytes());
  // nhmsg body (8 bytes) left zero: family=AF_UNSPEC, scope=0,
  // protocol=0, resvd=0, flags=0.
  bytes
}

/// Dump every `RTM_NEWNEXTHOP` entry the kernel knows about and return
/// them as a map keyed by nexthop id. Always dumps with
/// `nh_family = AF_UNSPEC` — see `build_nh_dump_request` for why
/// per-family dumps are unsafe (they drop group objects). Used by
/// `netlink_walk_routes` to resolve routes that arrive with an
/// `RTA_NH_ID` reference rather than an inline `RTA_OIF` / `RTA_GATEWAY`.
fn dump_nexthops() -> io::Result<std::collections::HashMap<u32, NexthopInfo>> {
  use std::collections::HashMap;
  unsafe {
    let handle = Handle::new()?;

    let req = build_nh_dump_request(1);
    handle.send_bytes(&req)?;

    let lsa = handle.sock()?;
    // Nexthop dumps can carry deep `NHA_GROUP` payloads (8 bytes per
    // member); use the route-walk buffer size for the same reason
    // detailed at `ROUTE_RECV_BUF_SIZE`.
    let mut rb = vec![0u8; ROUTE_RECV_BUF_SIZE];

    let mut map: HashMap<u32, NexthopInfo> = HashMap::new();

    'outer: loop {
      let nr = handle.recv(&mut rb)?;
      let mut received = &rb[..nr];

      while received.len() >= NLMSG_HDRLEN {
        let h = decode_nlmsghdr(received);
        let hlen = h.nlmsg_len as usize;
        let l = nlm_align_of(hlen);
        if hlen < NLMSG_HDRLEN || l > received.len() {
          return Err(rustix::io::Errno::INVAL.into());
        }
        if h.nlmsg_seq != 1 || h.nlmsg_pid != lsa.pid() {
          return Err(rustix::io::Errno::INVAL.into());
        }

        match h.nlmsg_type as u32 {
          NLMSG_DONE => {
            // The kernel sets `NLM_F_DUMP_INTR` on the closing
            // NLMSG_DONE if the routing/nexthop table changed during
            // the dump (e.g. an interface flap or a DHCP renewal mid-
            // walk). Treating an interrupted snapshot as complete
            // would silently return missing entries.
            if h.nlmsg_flags as u32 & NLM_F_DUMP_INTR != 0 {
              return Err(rustix::io::Errno::INTR.into());
            }
            break 'outer;
          }
          NLMSG_ERROR => match decode_nlmsgerr(received, hlen)? {
            NlmsgErrOutcome::Ack => {
              received = &received[l..];
              continue;
            }
            // Pre-5.3 kernels without the nexthop subsystem return
            // EOPNOTSUPP / EPROTONOSUPPORT here; we surface those as
            // an empty map so the route walker can proceed.
            NlmsgErrOutcome::FamilyUnavailable => return Ok(map),
          },
          val if val == RTM_NEWNEXTHOP => {
            // nhmsg occupies the first 8 bytes after the netlink
            // header: family (u8), scope (u8), protocol (u8), resvd
            // (u8), flags (u32). The flags field uses the same
            // RTNH_F_* bits as `struct rtnexthop` — we use it to skip
            // dead / linkdown / unresolved nexthops, matching the
            // multipath walker's behaviour. Without this filter, a
            // route pointing at a downed nexthop would be reported as
            // live by `route_table()`.
            if hlen < NLMSG_HDRLEN + 8 {
              received = &received[l..];
              continue;
            }
            let nh_family = received[NLMSG_HDRLEN];
            let nh_flags = u32::from_ne_bytes(
              received[NLMSG_HDRLEN + 4..NLMSG_HDRLEN + 8]
                .try_into()
                .unwrap(),
            );
            let unusable = (RTNH_F_DEAD | RTNH_F_LINKDOWN | RTNH_F_UNRESOLVED) as u32;
            let nh_unusable = nh_flags & unusable != 0;
            let mut attr_buf = &received[NLMSG_HDRLEN + 8..hlen];

            let mut id: u32 = 0;
            let mut oif: u32 = 0;
            let mut gw: Option<IpAddr> = None;
            // Track presence + parse outcome of `NHA_GATEWAY`. Without
            // this, a malformed gateway (truncated payload, wrong
            // family) leaves `gw = None`, and `resolve_nh_id` then
            // hands `(oif, None)` to the caller, which builds a
            // directly-connected on-link route — the very output mode
            // we use for "no gateway, send straight to oif". Treating
            // a corrupted nexthop as on-link can route via no gateway
            // when the kernel actually meant a (broken) indirect
            // hop. Mirror the route walker's `gw_malformed` guard:
            // mark such nexthops `filtered` so `resolve_nh_id` skips
            // them silently rather than emitting a synthetic on-link
            // entry.
            let mut gw_malformed = false;
            let mut group: Option<SmallVec<u32>> = None;
            let mut blackhole = false;
            // A malformed attribute length means the rest of this
            // nexthop's attribute stream is unrecoverable: we may
            // have already parsed `NHA_ID` and `NHA_OIF`, while a
            // truncated `NHA_GATEWAY` / `NHA_GROUP` we never got to
            // would have changed the result. Don't trust the partial
            // parse: mark the nexthop filtered so `resolve_nh_id`
            // skips it instead of emitting a synthetic on-link
            // entry. (We still record the id — the route walker's
            // "id present but unusable" path is the safe place to
            // land here, vs. "id absent → potential race → EINTR".)
            let mut attr_malformed = false;

            while attr_buf.len() >= RtAttr::SIZE {
              let attr = RtAttr {
                len: u16::from_ne_bytes(attr_buf[..2].try_into().unwrap()),
                ty: u16::from_ne_bytes(attr_buf[2..4].try_into().unwrap()),
              };
              let attrlen = attr.len as usize;
              if attrlen < RtAttr::SIZE || attrlen > attr_buf.len() {
                attr_malformed = true;
                break;
              }
              let data = &attr_buf[RtAttr::SIZE..attrlen];
              let alen = rta_align_of(attrlen).min(attr_buf.len());

              match attr.ty {
                NHA_ID if data.len() >= 4 => {
                  id = u32::from_ne_bytes(data[..4].try_into().unwrap());
                }
                NHA_OIF if data.len() >= 4 => {
                  oif = u32::from_ne_bytes(data[..4].try_into().unwrap());
                }
                NHA_GATEWAY => {
                  gw = parse_rta_ipaddr(nh_family, data);
                  if gw.is_none() {
                    gw_malformed = true;
                  }
                }
                NHA_GROUP => {
                  // Payload is an array of `struct nexthop_grp`:
                  // `{ u32 id; u8 weight; u8 weight_high/resvd1;
                  //    u16 resvd2 }` = 8 bytes per member. We only
                  // need the `id` field; weights and reserved bytes
                  // are ignored.
                  let mut members: SmallVec<u32> = SmallVec::new();
                  let mut p = data;
                  while p.len() >= 8 {
                    members.push(u32::from_ne_bytes(p[..4].try_into().unwrap()));
                    p = &p[8..];
                  }
                  group = Some(members);
                }
                NHA_BLACKHOLE => {
                  blackhole = true;
                }
                _ => {}
              }
              attr_buf = &attr_buf[alen..];
            }

            // Always insert known ids — even unusable ones. The route
            // walker needs to tell `id absent from map` (potential
            // race, retry / EINTR) apart from `id present but
            // unusable` (skip the route silently). The `filtered`
            // flag captures the latter without losing the
            // "kernel-knows-this-id" signal.
            if id != 0 {
              let filtered = blackhole || nh_unusable || gw_malformed || attr_malformed;
              map.insert(
                id,
                NexthopInfo {
                  oif,
                  gw,
                  group,
                  filtered,
                },
              );
            }
          }
          _ => {}
        }

        received = &received[l..];
      }
    }

    Ok(map)
  }
}

/// Resolve an `RTA_NH_ID` reference.
///
/// Return value distinguishes three cases the caller has to handle
/// differently:
///
/// - `None`: a referenced id is **not** in the map. This is the
///   "stale snapshot / race" case — either the top-level id, or a
///   member id inside a group, was likely added between our nexthop
///   dump and the route dump. Caller defers for a retry pass; on
///   the second miss, surfaces `EINTR`. Same return for both
///   missing-top-level and missing-group-member so a partial group
///   can't silently lose a leg.
/// - `Some(empty)`: the id **is** in the map but the kernel marked
///   it unusable (`NHA_BLACKHOLE`, `RTNH_F_DEAD`, `RTNH_F_LINKDOWN`,
///   `RTNH_F_UNRESOLVED`), or it's a group whose members are all
///   filtered or nested-groups. Every member is present; nothing
///   usable. The route can't deliver traffic; skip it silently —
///   no retry, no error.
/// - `Some(non-empty)`: one or more `(oif, gw)` pairs to emit.
///
/// Conflating the bottom two cases (the previous `SmallVec`-only API
/// did) made `route_table()` fail with `EINTR` whenever any single
/// route pointed at a downed nexthop.
fn resolve_nh_id(
  map: &std::collections::HashMap<u32, NexthopInfo>,
  id: u32,
) -> Option<SmallVec<(u32, Option<IpAddr>)>> {
  let nh = map.get(&id)?;
  let mut out: SmallVec<(u32, Option<IpAddr>)> = SmallVec::new();
  if nh.filtered {
    return Some(out);
  }
  if let Some(members) = &nh.group {
    for member_id in members {
      match map.get(member_id) {
        Some(member) => {
          // Skip nested groups — keep the depth bounded.
          // Skip filtered members — kernel marked them unusable.
          if member.group.is_none() && !member.filtered && member.oif != 0 {
            out.push((member.oif, member.gw));
          }
        }
        None => {
          // Missing group member: the route dump told us this group
          // contains `member_id`, but our nexthop snapshot doesn't.
          // Treating that as `Some(out)` would silently drop a leg of
          // the group — callers turn `Some(empty)` into "skip this
          // route" and `Some(non-empty)` into "emit what we got",
          // both of which lose the missing leg without any retry
          // signal. Mirror the top-level missing-id path (`None`
          // here) so the caller retries with a fresh dump and either
          // resolves the member or surfaces `EINTR` if the kernel
          // state is genuinely flapping.
          return None;
        }
      }
    }
  } else if nh.oif != 0 {
    out.push((nh.oif, nh.gw));
  }
  Some(out)
}

/// Yields one entry per `RTM_NEWROUTE` message: `(family, oif, dst_len, dst,
/// gateway)`. `dst` is `None` when the kernel omits `RTA_DST` (default
/// route). `gateway` is `None` when there is no `RTA_GATEWAY` (a directly
/// attached / link-scope route). All other parsing is the caller's
/// responsibility — this lets `route_table` / `route_ipv4_table` /
/// `route_ipv6_table` build different concrete types from the same walk.
pub(super) fn netlink_walk_routes<F>(family: AddressFamily, mut on_route: F) -> io::Result<()>
where
  F: FnMut(u8, u32, u8, Option<IpAddr>, Option<IpAddr>),
{
  unsafe {
    // Lazy nexthop-dump: we collect every `RTA_NH_ID` route we see
    // during the route walk and resolve them in a single post-walk
    // dump. This avoids paying the `RTM_GETNEXTHOP` round-trip when
    // no route uses nexthop objects (the typical Linux host today,
    // since `ip nexthop`-managed routes are a 5.3+ opt-in feature).
    // It also decouples ordinary route enumeration from nexthop-
    // subsystem availability — a transient `NLM_F_DUMP_INTR` or
    // unrelated nexthop churn during the upfront dump used to fail
    // `route_table()` even on hosts whose route table contains no
    // `RTA_NH_ID` references.
    //
    // Same pattern `rt_generic_addrs` (the gateway walker) already
    // uses; matching it here keeps the two paths consistent.
    let mut deferred_nh: Vec<(u8, u8, Option<IpAddr>, u32)> = Vec::new();

    let handle = Handle::new()?;

    let req = NetlinkRouteRequest::new(RTM_GETROUTE as u16, 1, family.as_raw() as u8, 0);
    handle.send(&req)?;

    let lsa = handle.sock()?;
    // See `ROUTE_RECV_BUF_SIZE`: a page is too small for routes that
    // carry large `RTA_MULTIPATH` ECMP payloads.
    let mut rb = vec![0u8; ROUTE_RECV_BUF_SIZE];

    'outer: loop {
      let nr = handle.recv(&mut rb)?;
      let mut received = &rb[..nr];

      while received.len() >= NLMSG_HDRLEN {
        let h = decode_nlmsghdr(received);
        let hlen = h.nlmsg_len as usize;
        let l = nlm_align_of(hlen);
        if hlen < NLMSG_HDRLEN || l > received.len() {
          return Err(rustix::io::Errno::INVAL.into());
        }
        if h.nlmsg_seq != 1 || h.nlmsg_pid != lsa.pid() {
          return Err(rustix::io::Errno::INVAL.into());
        }

        match h.nlmsg_type as u32 {
          NLMSG_DONE => {
            // The kernel marks the closing NLMSG_DONE with
            // `NLM_F_DUMP_INTR` if the routing table changed during
            // the dump (DHCP renewal, VPN connect/disconnect, an
            // interface flap, container start, etc.). The snapshot
            // we accumulated is silently incomplete in that case —
            // surface as EINTR rather than treat it as success and
            // hand back a half-walked table.
            if h.nlmsg_flags as u32 & NLM_F_DUMP_INTR != 0 {
              return Err(rustix::io::Errno::INTR.into());
            }
            break 'outer;
          }
          NLMSG_ERROR => match decode_nlmsgerr(received, hlen)? {
            NlmsgErrOutcome::Ack => {
              received = &received[l..];
              continue;
            }
            // The requested family has no stack — surface as "no
            // routes" so callers of `route_ipv6_table()` on a
            // v4-only host get `Ok([])` instead of `Err`, and the
            // union `route_table()` keeps whichever family is
            // populated.
            NlmsgErrOutcome::FamilyUnavailable => return Ok(()),
          },
          val if val == RTM_NEWROUTE => {
            // Bound the per-message slice to `hlen` rather than the
            // rest of the recv buffer. Netlink dumps routinely pack
            // multiple `RTM_NEWROUTE` messages into one recv(); an
            // unbounded slice would let the attribute walker below
            // run into the next message's header, mixing fields
            // across routes (or returning EINVAL on healthy kernel
            // output).
            let rtm = &received[NLMSG_HDRLEN..hlen];
            let rtm_header = RtmMessageHeader::parse(rtm)?;

            // The `IpRoute` model (destination + single gateway + single
            // output interface) only meaningfully represents
            // RTN_UNICAST and RTN_LOCAL routes. Skip everything else
            // — broadcast, multicast, blackhole, unreachable, prohibit,
            // nat, etc. don't have a usable single (oif, gw) tuple,
            // and emitting them as if they did would mislead callers.
            if rtm_header.rtm_type != RTN_UNICAST && rtm_header.rtm_type != RTN_LOCAL {
              received = &received[l..];
              continue;
            }

            // Source-constrained policy routes (`rtm_src_len != 0` or
            // an `RTA_SRC` attribute present) only apply when the
            // packet's source matches that prefix. The current
            // `IpRoute` model has no field for the source constraint,
            // so emitting these rows would make a constrained route
            // look generally usable. Skip until the model carries
            // source prefixes (the `RTA_SRC` check happens during the
            // attribute walk below — flagged via `has_src_constraint`
            // and applied before the final on_route call).
            if rtm_header.rtm_src_len != 0 {
              received = &received[l..];
              continue;
            }

            // TOS-specific routes only apply to packets whose IP ToS
            // byte matches `rtm_tos`. Emitting them as ordinary routes
            // would make a TOS-conditional route look usable for any
            // traffic. `IpRoute` has no TOS field, so skip.
            if rtm_header.rtm_tos != 0 {
              received = &received[l..];
              continue;
            }

            let mut rtattr_buf = &rtm[RtmMessageHeader::SIZE..];
            let mut oif: u32 = 0;
            let mut dst: Option<IpAddr> = None;
            let mut gw: Option<IpAddr> = None;
            let mut has_src_constraint = false;
            // Track present-but-malformed for RTA_DST / RTA_GATEWAY.
            // `parse_rta_ipaddr` returns `None` for either "the
            // attribute had a wrong-family / too-short payload" *or*
            // "the attribute wasn't there." Keeping a separate
            // present-flag lets us reject a malformed attribute
            // outright without conflating it with the legitimate
            // "default-route" / "on-link" encodings (`dst` absent
            // with `rtm_dst_len == 0`, `gw` absent for direct
            // routes). Without this, a kernel emitting a wrong-sized
            // RTA_DST alongside `rtm_dst_len = 24` would surface as
            // `0.0.0.0/24`.
            let mut dst_present = false;
            let mut dst_malformed = false;
            let mut gw_malformed = false;
            // Set true when the route carries a cross-family
            // `RTA_VIA`. See the constant's doc comment for why we
            // skip these — the route walker can't represent a
            // mismatched-family gateway with `IpRoute`.
            let mut has_via = false;
            // Linux returns the full table id either inline in
            // `rtm_table` (values 0..=255) or via an RTA_TABLE
            // attribute when the id exceeds 255 — the kernel sets
            // `rtm_table = RT_TABLE_UNSPEC (0)` in that case. Track
            // the effective id so we can drop custom policy tables.
            let mut table_id: u32 = rtm_header.rtm_table as u32;
            // Routes installed via `ip nexthop` carry only an
            // RTA_NH_ID and no top-level RTA_OIF / RTA_MULTIPATH. We
            // capture the id and resolve it against the up-front
            // RTM_GETNEXTHOP dump (`nh_map`) — this lets `route_table`
            // surface default routes installed through nexthop objects
            // (Linux 5.3+) that would otherwise be silently dropped by
            // the `oif == 0` guard.
            let mut nh_id: Option<u32> = None;
            // ECMP routes carry their nexthops inside RTA_MULTIPATH
            // (one or more `struct rtnexthop` each with sub-attrs).
            // We accumulate them and emit them after walking the
            // top-level attribute list, so we know `dst` / `dst_len`
            // before fanning out per-nexthop.
            let mut multipath: Option<&[u8]> = None;

            while rtattr_buf.len() >= RtAttr::SIZE {
              let attr = RtAttr {
                len: u16::from_ne_bytes(rtattr_buf[..2].try_into().unwrap()),
                ty: u16::from_ne_bytes(rtattr_buf[2..4].try_into().unwrap()),
              };
              let attrlen = attr.len as usize;
              if attrlen < RtAttr::SIZE || attrlen > rtattr_buf.len() {
                return Err(rustix::io::Errno::INVAL.into());
              }
              let data = &rtattr_buf[RtAttr::SIZE..attrlen];
              let alen = rta_align_of(attrlen).min(rtattr_buf.len());

              match attr.ty {
                RTA_OIF if data.len() >= 4 => {
                  oif = u32::from_ne_bytes(data[..4].try_into().unwrap());
                }
                RTA_DST => {
                  dst_present = true;
                  dst = parse_rta_ipaddr(rtm_header.rtm_family, data);
                  if dst.is_none() {
                    dst_malformed = true;
                  }
                }
                RTA_GATEWAY => {
                  gw = parse_rta_ipaddr(rtm_header.rtm_family, data);
                  if gw.is_none() {
                    gw_malformed = true;
                  }
                }
                RTA_VIA => {
                  // Cross-family gateway. `IpRoute` can't represent
                  // an IPv4 route with an IPv6 next-hop or vice
                  // versa, and treating the route as on-link
                  // (`gw = None`) would silently misroute. Mark and
                  // skip after the walk.
                  has_via = true;
                }
                RTA_MULTIPATH => {
                  multipath = Some(data);
                }
                RTA_SRC => {
                  // Source constraint present even though `rtm_src_len`
                  // was zero — defence-in-depth flag.
                  has_src_constraint = true;
                }
                RTA_TABLE if data.len() >= 4 => {
                  table_id = u32::from_ne_bytes(data[..4].try_into().unwrap());
                }
                RTA_NH_ID if data.len() >= 4 => {
                  nh_id = Some(u32::from_ne_bytes(data[..4].try_into().unwrap()));
                }
                _ => {}
              }

              rtattr_buf = &rtattr_buf[alen..];
            }

            // Reject malformed routes before any further processing:
            //   - RTA_DST present but unparseable (wrong family / too
            //     short).
            //   - RTA_DST absent but `rtm_dst_len != 0`. The "default
            //     route" encoding is `dst absent + dst_len == 0`;
            //     anything else means the kernel claimed a non-zero
            //     prefix length without supplying the address, which
            //     would synthesize a fake `0.0.0.0/N` / `::/N`.
            //   - RTA_GATEWAY present but unparseable. Treating a
            //     malformed gateway as `None` would silently
            //     downgrade the route to "on-link", which is a
            //     different routing decision.
            if dst_malformed
              || gw_malformed
              || has_via
              || (dst.is_none() && rtm_header.rtm_dst_len != 0)
            {
              received = &received[l..];
              continue;
            }
            // Suppress the "unused" warning for the present flag —
            // `dst_malformed` already encodes the real branch we care
            // about.
            let _ = dst_present;

            // Skip if a source constraint snuck in via RTA_SRC.
            if has_src_constraint {
              received = &received[l..];
              continue;
            }

            // Drop routes from custom policy tables. The three
            // standard RPDB tables consulted by the default rule
            // chain are `local` (255), `main` (254), and `default`
            // (253); together they describe what the kernel would
            // actually do for any outbound packet on a host without
            // custom `ip rule` policy. Anything outside that set is
            // a custom policy table selected by `ip rule` with
            // fwmark / iif / uid / etc., whose constraints aren't
            // representable in `IpRoute`.
            if table_id != RT_TABLE_MAIN as u32
              && table_id != RT_TABLE_LOCAL
              && table_id != RT_TABLE_DEFAULT
            {
              received = &received[l..];
              continue;
            }

            // Resolve nexthop-object references. The route had only an
            // RTA_NH_ID — look up the nexthop in the dump map. Single
            // leaves emit one route; groups fan out to one route per
            // member (similar to RTA_MULTIPATH).
            //
            // Lazy resolution: defer every `RTA_NH_ID` route to the
            // post-walk pass. The pass dumps `RTM_GETNEXTHOP` once
            // and resolves the entire batch — same correctness as
            // dump-up-front, lower cost when no route uses nexthop
            // objects.
            //
            // `resolve_nh_id` outcomes (handled by the post-walk
            // block):
            //   - `None`: id absent from the dump. Surface as
            //     `EINTR` so the caller can retry — kernel state
            //     was changing during enumeration.
            //   - `Some(empty)`: id present but unusable
            //     (blackhole / dead / linkdown / unresolved, or a
            //     group whose members are all filtered). Skip the
            //     route silently.
            //   - `Some(non-empty)`: emit one route per resolved
            //     `(oif, gw)`.
            if let Some(id) = nh_id {
              deferred_nh.push((rtm_header.rtm_family, rtm_header.rtm_dst_len, dst, id));
              received = &received[l..];
              continue;
            }

            // For ECMP routes, decode `RTA_MULTIPATH` and emit one
            // route per nexthop. The wire format of each nexthop is
            // `struct rtnexthop { u16 rtnh_len; u8 rtnh_flags; u8
            // rtnh_hops; s32 rtnh_ifindex; }` followed by RTA-encoded
            // sub-attributes (typically RTA_GATEWAY). On a multi-WAN
            // host where the kernel installs only `default nexthop
            // via A dev e0 nexthop via B dev e1`, the previous "skip
            // ECMP" behaviour caused `route_table_by_filter(|r|
            // r.is_default())` to return *no* default route.
            if let Some(mp) = multipath {
              walk_multipath(
                rtm_header.rtm_family,
                rtm_header.rtm_dst_len,
                dst,
                mp,
                &mut on_route,
              );
              received = &received[l..];
              continue;
            }

            // Skip routes that arrived without RTA_OIF and weren't
            // ECMP — emitting `oif=0` would mislead callers into
            // thinking the route was usable on interface 0.
            if oif == 0 {
              received = &received[l..];
              continue;
            }

            on_route(rtm_header.rtm_family, oif, rtm_header.rtm_dst_len, dst, gw);
          }
          _ => {}
        }

        received = &received[l..];
      }
    }

    // Resolve any deferred `RTA_NH_ID` references in a single batch.
    // Skipping this block when nothing was deferred is the whole
    // point of the lazy-dump optimization — a host with no
    // nexthop-object routes never pays the `RTM_GETNEXTHOP`
    // round-trip. `None` from `resolve_nh_id` means the id wasn't
    // in the dump (kernel state changed during enumeration); we
    // surface that as `EINTR` so the caller can retry rather than
    // silently lose the route. `Some(empty)` means the nexthop is
    // present but unusable (blackhole / down) — skip silently.
    // `Some(non-empty)` emits one route per resolved leaf.
    if !deferred_nh.is_empty() {
      let nh_map = dump_nexthops()?;
      for (rfamily, dst_len, dst, id) in deferred_nh {
        match resolve_nh_id(&nh_map, id) {
          None => return Err(rustix::io::Errno::INTR.into()),
          Some(resolved) => {
            for (nh_oif, nh_gw) in resolved {
              on_route(rfamily, nh_oif, dst_len, dst, nh_gw);
            }
          }
        }
      }
    }

    Ok(())
  }
}

/// Walk the contents of an `RTA_MULTIPATH` attribute payload and call
/// `on_route(family, oif, dst_len, dst, gw)` for each nexthop. Each
/// nexthop is a `struct rtnexthop` followed by RTA-encoded sub-attrs
/// (typically `RTA_GATEWAY`). Aligns advance pointers like the kernel
/// (4-byte `RTA_ALIGNTO`).
fn walk_multipath<F>(
  rtm_family: u8,
  dst_len: u8,
  dst: Option<IpAddr>,
  mut buf: &[u8],
  on_route: &mut F,
) where
  F: FnMut(u8, u32, u8, Option<IpAddr>, Option<IpAddr>),
{
  // sizeof(struct rtnexthop) = 8 (u16 + u8 + u8 + i32).
  const RTNH_SIZE: usize = 8;

  while buf.len() >= RTNH_SIZE {
    let nh_len = u16::from_ne_bytes(buf[..2].try_into().unwrap()) as usize;
    if nh_len < RTNH_SIZE || nh_len > buf.len() {
      // Malformed nexthop; stop rather than risk reading off the end.
      break;
    }
    let nh_flags = buf[2];
    // byte 3 is `rtnh_hops` (weight), not used here.
    let nh_ifindex = i32::from_ne_bytes(buf[4..8].try_into().unwrap()) as u32;

    // Skip nexthops the kernel keeps in the dump but marks unusable
    // (`RTNH_F_DEAD` / `RTNH_F_LINKDOWN` / `RTNH_F_UNRESOLVED`).
    // Surfacing those as ordinary `IpRoute` entries would lie about
    // reachability: e.g. an ECMP default with one nexthop's carrier
    // dropped would still appear as two live routes.
    let unusable = RTNH_F_DEAD | RTNH_F_LINKDOWN | RTNH_F_UNRESOLVED;
    if nh_flags & unusable != 0 {
      let nh_aligned = rta_align_of(nh_len).min(buf.len());
      if nh_aligned == 0 {
        break;
      }
      buf = &buf[nh_aligned..];
      continue;
    }

    // Decode sub-attributes. We track four skip states:
    //   - `nh_gw = Some(addr)`: parsed RTA_GATEWAY → emit with this gw.
    //   - `nh_gw = None`, no skip flag set: no gateway sub-attr at
    //     all → on-link nexthop, emit with `gw = None`.
    //   - `nh_gw_malformed = true`: RTA_GATEWAY sub-attr was present
    //     but parse_rta_ipaddr returned None → skip (treating
    //     malformed as on-link would silently downgrade the route
    //     to direct).
    //   - `nh_has_via = true`: the nexthop carries an `RTA_VIA`
    //     cross-family gateway, which `IpRoute` can't represent →
    //     skip (matches the top-level RTA_VIA rule).
    //   - `nh_truncated = true`: the sub-attribute walk encountered
    //     a length that wouldn't fit the remaining buffer (i.e. the
    //     nexthop's claimed size was inconsistent with its
    //     contents). Without this guard, breaking out of the walk
    //     mid-stream and falling through to `on_route` with whatever
    //     state we'd parsed so far could turn a truncated gateway
    //     into a fake on-link route — strictly worse than a clean
    //     skip, since callers can't distinguish corrupted ECMP data
    //     from a real direct nexthop.
    let mut nh_gw: Option<IpAddr> = None;
    let mut nh_gw_malformed = false;
    let mut nh_has_via = false;
    let mut nh_truncated = false;
    let mut sub = &buf[RTNH_SIZE..nh_len];
    while sub.len() >= RtAttr::SIZE {
      let attr_len = u16::from_ne_bytes(sub[..2].try_into().unwrap()) as usize;
      let attr_ty = u16::from_ne_bytes(sub[2..4].try_into().unwrap());
      if attr_len < RtAttr::SIZE || attr_len > sub.len() {
        nh_truncated = true;
        break;
      }
      if attr_ty == RTA_GATEWAY {
        nh_gw = parse_rta_ipaddr(rtm_family, &sub[RtAttr::SIZE..attr_len]);
        if nh_gw.is_none() {
          nh_gw_malformed = true;
        }
      } else if attr_ty == RTA_VIA {
        nh_has_via = true;
      }
      let alen = rta_align_of(attr_len).min(sub.len());
      sub = &sub[alen..];
    }

    if nh_ifindex != 0 && !nh_gw_malformed && !nh_has_via && !nh_truncated {
      on_route(rtm_family, nh_ifindex, dst_len, dst, nh_gw);
    }

    // Advance to the next nexthop, RTA-aligned.
    let nh_aligned = rta_align_of(nh_len).min(buf.len());
    if nh_aligned == 0 {
      break;
    }
    buf = &buf[nh_aligned..];
  }
}

/// What to do with a netlink `NLMSG_ERROR` reply.
#[derive(Debug)]
enum NlmsgErrOutcome {
  /// `errno == 0`: a plain ack the kernel emitted unsolicited; the
  /// caller should keep iterating.
  Ack,
  /// `errno` indicates the requested address family or subsystem
  /// isn't installed on this host (`EOPNOTSUPP`, `EPROTONOSUPPORT`,
  /// `EAFNOSUPPORT`). The caller should short-circuit and return an
  /// empty result for this dump rather than fail. Keeps single-stack
  /// hosts from turning a populated v4 result into `Err` when the v6
  /// dump fails because there is no v6 stack.
  FamilyUnavailable,
}

/// Decode the `nlmsgerr` body of an `NLMSG_ERROR` reply. The wire
/// format is a 4-byte signed errno (negative on failure, 0 on ack)
/// followed by a copy of the offending request header. Real syscall
/// errors propagate as `Err`; family-unavailable errnos are surfaced
/// to the caller via [`NlmsgErrOutcome::FamilyUnavailable`] so each
/// walker can decide how to represent "this family is empty".
///
/// The "family-unavailable" set (`EOPNOTSUPP`, `EPROTONOSUPPORT`,
/// `EAFNOSUPPORT`) is read from `rustix::io::Errno`. The numeric
/// values for these errnos differ across Linux architectures — x86 /
/// arm have 95 / 93 / 97, MIPS uses 122 / 120 / 124, SPARC uses 45 /
/// 43 / 47 — so a hardcoded literal whitelist would silently fail
/// the recovery path on those targets.
fn decode_nlmsgerr(received: &[u8], hlen: usize) -> io::Result<NlmsgErrOutcome> {
  use rustix::io::Errno;

  if hlen < NLMSG_HDRLEN + 4 {
    return Err(Errno::INVAL.into());
  }
  let errno = i32::from_ne_bytes(received[NLMSG_HDRLEN..NLMSG_HDRLEN + 4].try_into().unwrap());
  if errno == 0 {
    return Ok(NlmsgErrOutcome::Ack);
  }
  // The kernel reports negative errno values in `nlmsgerr.error`.
  let raw = errno.unsigned_abs() as i32;
  if raw == Errno::OPNOTSUPP.raw_os_error()
    || raw == Errno::PROTONOSUPPORT.raw_os_error()
    || raw == Errno::AFNOSUPPORT.raw_os_error()
  {
    return Ok(NlmsgErrOutcome::FamilyUnavailable);
  }
  Err(io::Error::from_raw_os_error(raw))
}

/// Push every usable nexthop's `oif` from an `RTA_MULTIPATH`
/// attribute payload into `out`. Same skip-rules as `walk_multipath`
/// (`RTNH_F_DEAD` / `RTNH_F_LINKDOWN` / `RTNH_F_UNRESOLVED`, and
/// `oif == 0`) but only collects interface indices — best-local
/// doesn't need to decode gateway sub-attrs.
///
/// Used by `netlink_best_local_addrs_into` so an ECMP default with N
/// usable nexthops contributes addresses from all N interfaces, not
/// just the first one the kernel listed.
fn multipath_oifs_into(mut buf: &[u8], out: &mut SmallVec<u32>) {
  const RTNH_SIZE: usize = 8;
  let unusable = RTNH_F_DEAD | RTNH_F_LINKDOWN | RTNH_F_UNRESOLVED;
  while buf.len() >= RTNH_SIZE {
    let nh_len = u16::from_ne_bytes(buf[..2].try_into().unwrap()) as usize;
    if nh_len < RTNH_SIZE || nh_len > buf.len() {
      break;
    }
    let nh_flags = buf[2];
    let nh_ifindex = i32::from_ne_bytes(buf[4..8].try_into().unwrap()) as u32;
    if nh_flags & unusable == 0 && nh_ifindex != 0 {
      out.push(nh_ifindex);
    }
    let nh_aligned = rta_align_of(nh_len).min(buf.len());
    if nh_aligned == 0 {
      break;
    }
    buf = &buf[nh_aligned..];
  }
}

/// Decode an `RTA_DST` / `RTA_GATEWAY` attribute payload as the IP family
/// declared by `rtm_family`. Netlink RTA address payloads are in network
/// byte order regardless of host endianness.
#[inline]
fn parse_rta_ipaddr(rtm_family: u8, data: &[u8]) -> Option<IpAddr> {
  match AddressFamily::from_raw(rtm_family as u16) {
    AddressFamily::INET if data.len() >= 4 => {
      let bytes: [u8; 4] = data[..4].try_into().unwrap();
      Some(IpAddr::V4(bytes.into()))
    }
    AddressFamily::INET6 if data.len() >= 16 => {
      let bytes: [u8; 16] = data[..16].try_into().unwrap();
      Some(IpAddr::V6(bytes.into()))
    }
    _ => None,
  }
}

pub(super) fn rt_generic_addrs<A, F>(
  family: AddressFamily,
  rta: u16,
  rtn: Option<u8>,
  mut f: F,
) -> io::Result<SmallVec<A>>
where
  A: Address + Eq,
  F: FnMut(&IpAddr) -> bool,
{
  unsafe {
    // Lazy nexthop-dump: don't pay the `RTM_GETNEXTHOP` round-trip
    // unless the route walk actually encounters an `RTA_NH_ID`
    // attribute. The vast majority of Linux hosts have no `ip
    // nexthop`-managed routes, so a typical `gateway_addrs()` call
    // benchmarked ~12 µs faster after this change vs. always-dump.
    // Routes that *do* reference a nexthop object collect into
    // `deferred_nh` here and resolve in a single post-walk pass.
    let mut deferred_nh: SmallVec<u32> = SmallVec::new();

    let handle = Handle::new()?;

    // Create and send netlink request for routes
    let req = NetlinkRouteRequest::new(RTM_GETROUTE as u16, 1, family.as_raw() as u8, 0);
    handle.send(&req)?;

    // Get socket name
    let lsa = handle.sock()?;

    // Receive and process messages. `rt_generic_addrs` walks routes
    // with `RTA_MULTIPATH` payloads — see `ROUTE_RECV_BUF_SIZE`.
    let mut rb = vec![0u8; ROUTE_RECV_BUF_SIZE];
    let mut gateways = SmallVec::new();
    // Policy-routing tables and multipath/ECMP entries can surface the
    // same gateway on multiple route messages. Dedup via a HashSet
    // keyed by `(index, IpAddr)`, matching the pattern already used in
    // `src/bsd_like/rt_generic.rs` and `src/windows/gateway.rs`.
    let mut seen: HashSet<(u32, IpAddr)> = HashSet::new();

    'outer: loop {
      let nr = handle.recv(&mut rb)?;

      let mut received = &rb[..nr];

      while received.len() >= NLMSG_HDRLEN {
        let h = decode_nlmsghdr(received);
        let hlen = h.nlmsg_len as usize;
        let l = nlm_align_of(hlen);

        if hlen < NLMSG_HDRLEN || l > received.len() {
          return Err(rustix::io::Errno::INVAL.into());
        }

        if h.nlmsg_seq != 1 || h.nlmsg_pid != lsa.pid() {
          return Err(rustix::io::Errno::INVAL.into());
        }

        match h.nlmsg_type as u32 {
          NLMSG_DONE => {
            // Mirror `netlink_walk_routes` / `netlink_best_local_addrs_into`:
            // surface `EINTR` if the kernel signaled `NLM_F_DUMP_INTR`,
            // because route-table churn during the walk means we
            // returned a partial snapshot. Returning the partial set
            // as `Ok` would silently mislead callers about which
            // gateways actually exist.
            if h.nlmsg_flags as u32 & NLM_F_DUMP_INTR != 0 {
              return Err(rustix::io::Errno::INTR.into());
            }
            break 'outer;
          }
          NLMSG_ERROR => match decode_nlmsgerr(received, hlen)? {
            NlmsgErrOutcome::Ack => {
              received = &received[l..];
              continue;
            }
            // No stack for this family — surface as an empty result
            // instead of `Err`. Lets `gateway_addrs()` keep the
            // populated family on a single-stack host instead of
            // failing the whole call when the other family's dump
            // hits `EAFNOSUPPORT` / `EPROTONOSUPPORT` / `EOPNOTSUPP`.
            NlmsgErrOutcome::FamilyUnavailable => return Ok(SmallVec::new()),
          },
          val if val == RTM_NEWROUTE => {
            // See `netlink_interface` for why this is bounded to `hlen`.
            let rtm = &received[NLMSG_HDRLEN..hlen];
            let rtm_header = RtmMessageHeader::parse(rtm)?;

            // Ensure it's a address we want
            if let Some(rtn) = rtn {
              if rtm_header.rtm_type != rtn {
                received = &received[l..];
                continue;
              }
            }

            let mut rtattr_buf = &rtm[RtmMessageHeader::SIZE..];
            // Top-level `rta` matches all share `current_ifi` from
            // RTA_OIF, so we only need to remember the address — the
            // ifindex is back-filled at emit time. Stays at the
            // smaller `IpAddr` element size (17 bytes vs 24 for the
            // (u32, IpAddr) pair) so the inline buffer doesn't bloat
            // on the hot path. Per-nexthop entries from RTA_MULTIPATH
            // and RTA_NH_ID carry their own ifindex and are emitted
            // straight into `gateways`, bypassing this vec.
            let mut tmp_addrs: SmallVec<IpAddr> = SmallVec::new();
            let mut current_ifi = 0;
            let mut multipath: Option<&[u8]> = None;
            let mut nh_id: Option<u32> = None;
            while rtattr_buf.len() >= RtAttr::SIZE {
              let attr = RtAttr {
                len: u16::from_ne_bytes(rtattr_buf[..2].try_into().unwrap()),
                ty: u16::from_ne_bytes(rtattr_buf[2..4].try_into().unwrap()),
              };

              let attrlen = attr.len as usize;
              if attrlen < RtAttr::SIZE || attrlen > rtattr_buf.len() {
                // Same rationale as in `netlink_best_local_addrs`:
                // a partially-parsed route could emit a bogus address
                // into `gateways`. Fail the whole call instead.
                return Err(rustix::io::Errno::INVAL.into());
              }

              let data = &rtattr_buf[RtAttr::SIZE..attrlen];
              let alen = rta_align_of(attrlen).min(rtattr_buf.len());

              match attr.ty {
                val if val == rta => match (
                  family,
                  AddressFamily::from_raw(rtm_header.rtm_family as u16),
                ) {
                  (AddressFamily::INET, AddressFamily::INET)
                  | (AddressFamily::UNSPEC, AddressFamily::INET)
                    if data.len() >= 4 =>
                  {
                    // Netlink address payloads are already in network
                    // byte order; `Ipv4Addr::from([u8; 4])` is
                    // network-order-by-contract and host-endian-
                    // independent. The previous
                    // `u32::from_ne_bytes(...).swap_bytes()` decode
                    // happened to work on little-endian Linux
                    // (LE-load + swap = BE-load) but produced
                    // byte-reversed addresses on big-endian Linux —
                    // matters now that CI explicitly covers
                    // big-endian targets. Match the canonical
                    // `parse_rta_ipaddr` shape.
                    let bytes: [u8; 4] = data[..4].try_into().unwrap();
                    let addr = IpAddr::V4(bytes.into());

                    if f(&addr) {
                      tmp_addrs.push(addr);
                    }
                  }
                  (AddressFamily::INET6, AddressFamily::INET6)
                  | (AddressFamily::UNSPEC, AddressFamily::INET6)
                    if data.len() >= 16 =>
                  {
                    // `Ipv6Addr::from([u8; 16])` is also
                    // network-order-by-contract — same rationale as
                    // the v4 branch above. The `u128::from_be_bytes`
                    // chain it replaced was already correct, but
                    // sticking to the byte-array form keeps both
                    // arms uniform with `parse_rta_ipaddr`.
                    let bytes: [u8; 16] = data[..16].try_into().unwrap();
                    let addr = IpAddr::V6(bytes.into());

                    if f(&addr) {
                      tmp_addrs.push(addr);
                    }
                  }
                  _ => {}
                },
                RTA_OIF => {
                  if data.len() >= 4 {
                    let idx = u32::from_ne_bytes(data[..4].try_into().unwrap());
                    current_ifi = idx;
                  }
                }
                RTA_MULTIPATH => {
                  multipath = Some(data);
                }
                RTA_NH_ID if data.len() >= 4 => {
                  nh_id = Some(u32::from_ne_bytes(data[..4].try_into().unwrap()));
                }
                _ => {}
              }

              rtattr_buf = &rtattr_buf[alen..];
            }

            // Inline closure for the dedup + try_from + push step.
            // Avoids three duplicate copies across the top-level /
            // multipath / nh_id paths and keeps the per-path code
            // tight.
            //
            // It's a normal local closure — no boxing — so the borrow
            // checker requires we drop the `gateways` / `seen`
            // borrows before the next path runs. Each emit block is
            // a separate statement, which is enough.
            let mut emit = |idx: u32, raw: IpAddr| {
              if let Some(addr) = A::try_from(idx, raw) {
                if seen.insert((addr.index(), addr.addr())) {
                  gateways.push(addr);
                }
              }
            };

            // Top-level matches share `current_ifi`.
            for raw in tmp_addrs.drain(..) {
              emit(current_ifi, raw);
            }

            // ECMP: each `struct rtnexthop` carries its own oif and
            // sub-attrs. Pull the gateway sub-attr per nexthop —
            // important on multi-WAN hosts where the only gateway
            // information lives inside RTA_MULTIPATH and the
            // top-level lookup picks up nothing. Per-nexthop entries
            // emit straight into `gateways` via `emit`, bypassing
            // `tmp_addrs` so we don't pay the size growth of a
            // (u32, IpAddr) inline buffer for them either.
            if rta == RTA_GATEWAY {
              if let Some(mp) = multipath {
                multipath_gateways_into(rtm_header.rtm_family, mp, &mut |idx, gw| {
                  if f(&gw) {
                    emit(idx, gw);
                  }
                });
              }

              // Nexthop-object: defer to the post-walk resolution
              // pass. We collect the bare `nh_id`s here and dump the
              // nexthop map once at the end if any were seen — most
              // hosts have none, in which case we skip the dump
              // entirely.
              if let Some(id) = nh_id {
                deferred_nh.push(id);
              }
            }
          }
          _ => {}
        }

        received = &received[l..];
      }
    }

    // Resolve any deferred `RTA_NH_ID` references in a single batch.
    // Skipping this block when nothing was deferred is the whole
    // point of the lazy-dump optimization.
    if !deferred_nh.is_empty() {
      let nh_map = dump_nexthops()?;
      for id in deferred_nh {
        if let Some(resolved) = resolve_nh_id(&nh_map, id) {
          for (oif, maybe_gw) in resolved {
            if let Some(gw) = maybe_gw {
              if f(&gw) {
                if let Some(addr) = A::try_from(oif, gw) {
                  if seen.insert((addr.index(), addr.addr())) {
                    gateways.push(addr);
                  }
                }
              }
            }
          }
        }
        // `None` (id absent from snapshot) is silently skipped —
        // gateway enumeration is best-effort by design (matches the
        // historical contract of returning `Ok([])` rather than
        // `Err` on transient races) and there's no per-call retry
        // pass like `netlink_walk_routes` has.
      }
    }

    Ok(gateways)
  }
}

/// Walk an `RTA_MULTIPATH` payload and call `sink(oif, gateway)` for
/// each usable nexthop that has an `RTA_GATEWAY` sub-attribute.
/// Skips nexthops with `RTNH_F_DEAD / RTNH_F_LINKDOWN /
/// RTNH_F_UNRESOLVED`, an `oif` of zero, or no gateway sub-attr.
fn multipath_gateways_into<F>(rtm_family: u8, mut buf: &[u8], sink: &mut F)
where
  F: FnMut(u32, IpAddr),
{
  const RTNH_SIZE: usize = 8;
  let unusable = RTNH_F_DEAD | RTNH_F_LINKDOWN | RTNH_F_UNRESOLVED;
  while buf.len() >= RTNH_SIZE {
    let nh_len = u16::from_ne_bytes(buf[..2].try_into().unwrap()) as usize;
    if nh_len < RTNH_SIZE || nh_len > buf.len() {
      break;
    }
    let nh_flags = buf[2];
    let nh_ifindex = i32::from_ne_bytes(buf[4..8].try_into().unwrap()) as u32;

    if nh_flags & unusable == 0 && nh_ifindex != 0 {
      // Walk sub-attributes for RTA_GATEWAY.
      let mut sub = &buf[RTNH_SIZE..nh_len];
      while sub.len() >= RtAttr::SIZE {
        let attr_len = u16::from_ne_bytes(sub[..2].try_into().unwrap()) as usize;
        let attr_ty = u16::from_ne_bytes(sub[2..4].try_into().unwrap());
        if attr_len < RtAttr::SIZE || attr_len > sub.len() {
          break;
        }
        if attr_ty == RTA_GATEWAY {
          if let Some(gw) = parse_rta_ipaddr(rtm_family, &sub[RtAttr::SIZE..attr_len]) {
            sink(nh_ifindex, gw);
          }
        }
        let alen = rta_align_of(attr_len).min(sub.len());
        sub = &sub[alen..];
      }
    }

    let nh_aligned = rta_align_of(nh_len).min(buf.len());
    if nh_aligned == 0 {
      break;
    }
    buf = &buf[nh_aligned..];
  }
}

#[repr(C)]
#[derive(Debug)]
struct RtmMessageHeader {
  rtm_family: u8,
  rtm_dst_len: u8,
  rtm_src_len: u8,
  rtm_tos: u8,
  rtm_table: u8,
  rtm_protocol: u8,
  rtm_scope: u8,
  rtm_type: u8,
  rtm_flags: u32,
}

impl RtmMessageHeader {
  const SIZE: usize = std::mem::size_of::<Self>();

  #[inline]
  fn parse(src: &[u8]) -> io::Result<Self> {
    if src.len() < Self::SIZE {
      return Err(rustix::io::Errno::INVAL.into());
    }

    Ok(Self {
      rtm_family: src[0],
      rtm_dst_len: src[1],
      rtm_src_len: src[2],
      rtm_tos: src[3],
      rtm_table: src[4],
      rtm_protocol: src[5],
      rtm_scope: src[6],
      rtm_type: src[7],
      rtm_flags: u32::from_ne_bytes(src[8..12].try_into().unwrap()),
    })
  }
}

// Round the length of a netlink message up to align it properly.
#[inline]
const fn nlm_align_of(msg_len: usize) -> usize {
  ((msg_len as u32 + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)) as usize
}

// Round the length of a netlink route attribute up to align it
// properly.
#[inline]
const fn rta_align_of(attrlen: usize) -> usize {
  const RTA_ALIGNTO: usize = 0x4;
  (attrlen + RTA_ALIGNTO - 1) & !(RTA_ALIGNTO - 1)
}

/// A pre-serialized RTM_GET* dump request. Stored as a byte array
/// (rather than a `repr(C)` struct with a 16-byte `nlmsghdr` + 1-byte
/// `rtgenmsg`) on purpose: the typed form has 3 trailing padding bytes
/// after `family` for u32 alignment, and reading those padding bytes
/// out via `as_bytes()` is UB by Rust's rules — typed field writes
/// and by-value moves are allowed to leave padding uninitialized even
/// if it was initially zeroed. With a `[u8; N]` body the padding
/// concept doesn't exist; every byte we send is one we explicitly
/// wrote.
struct NetlinkRouteRequest {
  bytes: [u8; Self::SIZE],
}

impl NetlinkRouteRequest {
  /// `nlmsghdr` (16 bytes) + `rtgenmsg` (1 byte) rounded up to
  /// `NLMSG_ALIGNTO` (4 bytes) = 20. Matches what the previous
  /// `repr(C)` typed struct used to serialize, so kernel-side parsing
  /// is unchanged.
  const SIZE: usize = (mem::size_of::<MessageHeader>()
    + mem::size_of::<u8>() // rtgenmsg::family
    + (NLMSG_ALIGNTO as usize - 1))
    & !(NLMSG_ALIGNTO as usize - 1);

  #[inline]
  fn new(proto: u16, seq: u32, family: u8, _ifi: u32) -> Self {
    // TODO(al8n): do not dump when ifi is not 0
    // let flags = if ifi == 0 {
    //   (libc::NLM_F_DUMP | libc::NLM_F_REQUEST) as u16
    // } else {
    //   libc::NLM_F_REQUEST as u16
    // };
    let mut bytes = [0u8; Self::SIZE];
    // `nlmsghdr` (offsets per the C layout):
    //   bytes 0..4   nlmsg_len  : u32
    //   bytes 4..6   nlmsg_type : u16
    //   bytes 6..8   nlmsg_flags: u16
    //   bytes 8..12  nlmsg_seq  : u32
    //   bytes 12..16 nlmsg_pid  : u32
    bytes[0..4].copy_from_slice(&(Self::SIZE as u32).to_ne_bytes());
    bytes[4..6].copy_from_slice(&proto.to_ne_bytes());
    bytes[6..8].copy_from_slice(&((NLM_F_DUMP | NLM_F_REQUEST) as u16).to_ne_bytes());
    bytes[8..12].copy_from_slice(&seq.to_ne_bytes());
    bytes[12..16].copy_from_slice(&std::process::id().to_ne_bytes());
    // `rtgenmsg` body: a single u8 at offset 16. Bytes 17..20 are the
    // NLMSG_ALIGNTO trailer; they were zeroed by the array
    // initializer above and the kernel ignores them past the message
    // body.
    bytes[16] = family;
    Self { bytes }
  }

  #[inline]
  fn as_bytes(&self) -> &[u8] {
    &self.bytes
  }
}

#[repr(C)]
#[derive(Debug)]
struct IfInfoMessageHeader {
  family: u8,
  x_ifi_pad: u8,
  ty: u16,
  index: i32,
  flags: u32,
  change: u32,
}

impl IfInfoMessageHeader {
  const SIZE: usize = mem::size_of::<Self>();

  #[inline]
  fn parse(src: &[u8]) -> io::Result<Self> {
    if src.len() < Self::SIZE {
      return Err(rustix::io::Errno::INVAL.into());
    }

    Ok(Self {
      family: src[0],
      x_ifi_pad: src[1],
      ty: u16::from_ne_bytes(src[2..4].try_into().unwrap()),
      index: i32::from_ne_bytes(src[4..8].try_into().unwrap()),
      flags: u32::from_ne_bytes(src[8..12].try_into().unwrap()),
      change: u32::from_ne_bytes(src[12..16].try_into().unwrap()),
    })
  }
}

#[repr(C)]
struct RtAttr {
  len: u16,
  ty: u16,
}

impl RtAttr {
  const SIZE: usize = mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Debug)]
struct IfNetMessageHeader {
  family: u8,
  prefix_len: u8,
  flags: u8,
  scope: u8,
  index: u32,
}

impl IfNetMessageHeader {
  const SIZE: usize = mem::size_of::<Self>();

  /// Decode an `ifaddrmsg` header from the start of the netlink
  /// message body. Returns `EINVAL` for short buffers — a malformed
  /// `RTM_NEWADDR` with `nlmsg_len == NLMSG_HDRLEN` would otherwise
  /// reach the field reads with an empty `msg_buf` and panic on the
  /// raw index.
  #[inline]
  fn parse(src: &[u8]) -> io::Result<Self> {
    if src.len() < Self::SIZE {
      return Err(rustix::io::Errno::INVAL.into());
    }
    Ok(Self {
      family: src[0],
      prefix_len: src[1],
      flags: src[2],
      scope: src[3],
      index: u32::from_ne_bytes(src[4..8].try_into().unwrap()),
    })
  }
}

#[inline]
fn decode_nlmsghdr(src: &[u8]) -> MessageHeader {
  let hlen = u32::from_ne_bytes(src[..4].try_into().unwrap());
  let hty = u16::from_ne_bytes(src[4..6].try_into().unwrap());
  let hflags = u16::from_ne_bytes(src[6..8].try_into().unwrap());
  let hseq = u32::from_ne_bytes(src[8..12].try_into().unwrap());
  let hpid = u32::from_ne_bytes(src[12..16].try_into().unwrap());
  MessageHeader {
    nlmsg_len: hlen,
    nlmsg_type: hty,
    nlmsg_flags: hflags,
    nlmsg_seq: hseq,
    nlmsg_pid: hpid,
  }
}

#[cfg(test)]
mod netlink_tests {
  use super::*;

  // Regression guard for Android support (issue #4). `Handle::new()`
  // intentionally does NOT bind(): the kernel autobinds a portid on the
  // first send(), and that path bypasses the SELinux `bind` check that
  // Android's untrusted_app domain denies on netlink_route_socket
  // (b/155595000). This pins the invariant the per-message nlmsg_pid
  // filter depends on:
  //   * before the first send the socket is unbound (portid 0), and
  //   * the kernel assigns a non-zero portid on send.
  // If someone reintroduces an eager bind, the first assertion fails
  // (the socket would already be bound before the send).
  #[test]
  fn autobind_assigns_portid_on_send() {
    unsafe {
      let handle = Handle::new().expect("create netlink handle");

      let before = handle.sock().expect("getsockname before send");
      assert_eq!(before.pid(), 0, "socket must be unbound before first send");

      let req =
        NetlinkRouteRequest::new(RTM_GETLINK as u16, 1, AddressFamily::UNSPEC.as_raw() as u8, 0);
      handle.send(&req).expect("send RTM_GETLINK");

      let after = handle.sock().expect("getsockname after send");
      assert_ne!(after.pid(), 0, "kernel must autobind a portid on first send");
    }
  }

  // Codex round 3: an in-band RTM_GETLINK denial arrives as
  // NLMSG_ERROR(-EACCES/-EPERM). `decode_nlmsgerr` must surface the real
  // errno as PermissionDenied (not flatten it to EINVAL) so the Android
  // ioctl fallback in `super::interface_table` actually engages.
  #[test]
  fn nlmsgerr_decodes_eacces_as_permission_denied() {
    use std::io::ErrorKind;

    let eacces = rustix::io::Errno::ACCESS.raw_os_error();
    // The `nlmsgerr` body is a 4-byte signed (negative) errno following the
    // netlink header.
    let mut buf = vec![0u8; NLMSG_HDRLEN + 4];
    buf[NLMSG_HDRLEN..NLMSG_HDRLEN + 4].copy_from_slice(&(-eacces).to_ne_bytes());

    let err =
      decode_nlmsgerr(&buf, NLMSG_HDRLEN + 4).expect_err("a negative errno must be an error");
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
  }
}
