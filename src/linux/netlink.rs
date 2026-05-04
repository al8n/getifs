use linux_raw_sys::{
  if_arp::{self, ARPHRD_IPGRE, ARPHRD_TUNNEL, ARPHRD_TUNNEL6},
  netlink::{self, NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST},
};
use rustix::net::{
  bind, getsockname, netlink::SocketAddrNetlink, recvfrom, sendto, socket, AddressFamily,
  RecvFlags, SendFlags, SocketType,
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
// `route_table` only emits routes from the main and local kernel
// tables. Custom policy tables (selected via `ip rule` with fwmark,
// iif, uid, etc.) carry constraints that aren't representable in
// `IpRoute`, so surfacing them would mislead callers — the
// route would look generally usable when the kernel only consults it
// for matching policy rules.
const RT_TABLE_LOCAL: u32 = netlink::rt_class_t::RT_TABLE_LOCAL as u32;

const IFA_LOCAL: u32 = netlink::IFA_LOCAL as u32;
const IFA_ADDRESS: u32 = netlink::IFA_ADDRESS as u32;

const IFLA_MTU: u32 = if_arp::IFLA_MTU as u32;
const IFLA_IFNAME: u32 = if_arp::IFLA_IFNAME as u32;
const IFLA_ADDRESS: u32 = if_arp::IFLA_ADDRESS as u32;

const RTF_UP: u16 = 0x0001;
const RTF_GATEWAY: u16 = 0x0002;

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
    // Create socket
    let sock = socket(AddressFamily::NETLINK, SocketType::RAW, None)?;

    let sa = SocketAddrNetlink::new(0, 0);
    bind(&sock, &sa)?;

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
          NLMSG_ERROR => return Err(rustix::io::Errno::INVAL.into()),
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

pub(super) fn netlink_addr<N, F>(
  family: AddressFamily,
  ifi: u32,
  mut f: F,
) -> io::Result<SmallVec<N>>
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

    let mut addrs = SmallVec::new();

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
          NLMSG_ERROR => return Err(rustix::io::Errno::INVAL.into()),
          val if val == RTM_NEWADDR => {
            let ifam = IfNetMessageHeader {
              family: msg_buf[0],
              prefix_len: msg_buf[1],
              flags: msg_buf[2],
              scope: msg_buf[3],
              index: u32::from_ne_bytes(msg_buf[4..8].try_into().unwrap()),
            };

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

    Ok(addrs)
  }
}

pub fn netlink_best_local_addrs<N>(family: AddressFamily) -> io::Result<SmallVec<N>>
where
  N: Net,
{
  unsafe {
    let handle = Handle::new()?;

    let req = NetlinkRouteRequest::new(RTM_GETROUTE as u16, 1, family.as_raw() as u8, 0);
    handle.send(&req)?;

    // Snapshot the kernel-assigned address so we can reject any reply
    // that doesn't belong to this socket — same defence the other
    // netlink walkers use.
    let lsa = handle.sock()?;

    let page_size = rustix::param::page_size();
    let mut rb = vec![0u8; page_size];
    let mut best_ifindex = None;
    let mut best_metric = u32::MAX;

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
          NLMSG_DONE => break 'outer,
          NLMSG_ERROR => return Err(rustix::io::Errno::INVAL.into()),
          val if val == RTM_NEWROUTE => {
            // See `netlink_interface` for why this is bounded to `hlen`.
            let rtm = &received[NLMSG_HDRLEN..hlen];
            let rtm_header = RtmMessageHeader::parse(rtm)?;

            // Use the same gateway detection logic as netlink_gateway
            let mut has_gateway = false;
            let old_kernel_gw = (rtm_header.rtm_flags & (RTF_UP as u32 | RTF_GATEWAY as u32))
              == (RTF_UP as u32 | RTF_GATEWAY as u32);
            let new_kernel_gw =
              rtm_header.rtm_dst_len == 0 && rtm_header.rtm_table == RT_TABLE_MAIN as u8;

            if old_kernel_gw || new_kernel_gw {
              has_gateway = true;
            }

            if !has_gateway {
              received = &received[l..];
              continue;
            }

            let mut rtattr_buf = &rtm[RtmMessageHeader::SIZE..];
            let mut current_metric = None;
            let mut current_oif = None;

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
                  current_oif = Some(u32::from_ne_bytes(data[..4].try_into().unwrap()));
                }
                _ => {}
              }

              rtattr_buf = &rtattr_buf[alen..];
            }

            // Update best interface if this route has better metric
            if let (Some(metric), Some(oif)) = (current_metric, current_oif) {
              if metric < best_metric {
                best_metric = metric;
                best_ifindex = Some(oif);
              }
            } else if let Some(oif) = current_oif {
              // If no metric is provided, treat it as best metric
              if best_metric == u32::MAX {
                best_metric = 0;
                best_ifindex = Some(oif);
              }
            }
          }
          _ => {}
        }

        received = &received[l..];
      }
    }

    // Get addresses only from the best interface
    match best_ifindex {
      Some(idx) => netlink_addr(family, idx, local_ip_filter),
      None => Ok(SmallVec::new()),
    }
  }
}

/// One nexthop-object entry from a `RTM_GETNEXTHOP` dump. Either a
/// "leaf" (single `oif` + optional gateway) or a `group` of member ids
/// (each member resolves recursively against the same map). Blackhole
/// nexthops are filtered out before the map is built.
#[derive(Debug, Clone)]
struct NexthopInfo {
  oif: u32,
  gw: Option<IpAddr>,
  /// `Some(member_ids)` for `NHA_GROUP`. Empty list means a malformed
  /// group; we treat those as unusable. Single-leaf nexthops carry
  /// `None`.
  group: Option<SmallVec<u32>>,
}

/// Build the wire bytes for `RTM_GETNEXTHOP` + `NLM_F_DUMP`. The body
/// is `struct nhmsg` (8 bytes); leaving every field zero requests an
/// unfiltered dump of all nexthops the kernel knows about.
fn build_nh_dump_request(seq: u32, family: u8) -> [u8; 24] {
  let mut bytes = [0u8; 24];
  // nlmsghdr (16 bytes)
  bytes[0..4].copy_from_slice(&24u32.to_ne_bytes());
  bytes[4..6].copy_from_slice(&(RTM_GETNEXTHOP as u16).to_ne_bytes());
  bytes[6..8].copy_from_slice(&((NLM_F_DUMP | NLM_F_REQUEST) as u16).to_ne_bytes());
  bytes[8..12].copy_from_slice(&seq.to_ne_bytes());
  bytes[12..16].copy_from_slice(&std::process::id().to_ne_bytes());
  // nhmsg body (8 bytes): nh_family, nh_scope, nh_protocol, resvd, nh_flags
  bytes[16] = family;
  // bytes[17..24] left zero: scope=0, protocol=0, resvd=0, flags=0
  bytes
}

/// Dump every `RTM_NEWNEXTHOP` entry for `family` (use `AF_UNSPEC` to
/// get both v4 and v6) and return them as a map keyed by nexthop id.
/// Used by `netlink_walk_routes` to resolve routes that arrive with an
/// `RTA_NH_ID` reference rather than an inline `RTA_OIF` / `RTA_GATEWAY`.
fn dump_nexthops(family: u8) -> io::Result<std::collections::HashMap<u32, NexthopInfo>> {
  use std::collections::HashMap;
  unsafe {
    let handle = Handle::new()?;

    let req = build_nh_dump_request(1, family);
    handle.send_bytes(&req)?;

    let lsa = handle.sock()?;
    let page_size = rustix::param::page_size();
    let mut rb = vec![0u8; page_size];

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
          NLMSG_ERROR => {
            // `nlmsgerr` body: 4-byte signed errno, then a copy of
            // the failed message header. Only "subsystem not
            // supported" surfaces as "no nexthop objects" — every
            // other errno is a real failure that must propagate.
            // Treating EPERM / ENOBUFS / EINVAL the same as missing
            // subsystem would silently drop every RTA_NH_ID-managed
            // route while `route_table()` still returned `Ok`.
            if hlen < NLMSG_HDRLEN + 4 {
              return Err(rustix::io::Errno::INVAL.into());
            }
            let errno =
              i32::from_ne_bytes(received[NLMSG_HDRLEN..NLMSG_HDRLEN + 4].try_into().unwrap());
            // errno == 0 is a plain ack — we didn't request one, but
            // ignore if the kernel sends one anyway.
            if errno == 0 {
              received = &received[l..];
              continue;
            }
            // Kernel returns negative errno values.
            let raw = errno.unsigned_abs();
            // EOPNOTSUPP (95) / ENOTSUP — pre-5.3 kernels without the
            // nexthop subsystem compiled in. EPROTONOSUPPORT (93) —
            // some build configs.
            const EOPNOTSUPP: u32 = 95;
            const EPROTONOSUPPORT: u32 = 93;
            if raw == EOPNOTSUPP || raw == EPROTONOSUPPORT {
              return Ok(map);
            }
            return Err(io::Error::from_raw_os_error(raw as i32));
          }
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
            let mut group: Option<SmallVec<u32>> = None;
            let mut blackhole = false;

            while attr_buf.len() >= RtAttr::SIZE {
              let attr = RtAttr {
                len: u16::from_ne_bytes(attr_buf[..2].try_into().unwrap()),
                ty: u16::from_ne_bytes(attr_buf[2..4].try_into().unwrap()),
              };
              let attrlen = attr.len as usize;
              if attrlen < RtAttr::SIZE || attrlen > attr_buf.len() {
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

            // Drop nexthops the kernel marks unusable. Inserting them
            // into the map would let `resolve_nh_id` emit them as if
            // they were live; matches `walk_multipath`'s skip logic.
            if id != 0 && !blackhole && !nh_unusable {
              map.insert(id, NexthopInfo { oif, gw, group });
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

/// Resolve an `RTA_NH_ID` reference to a list of `(oif, gw)` tuples.
/// Singletons return one entry. Groups fan out to one entry per member,
/// recursively resolving members that themselves point at single-leaf
/// nexthops. Group-of-groups is rare and out of scope — those are
/// skipped.
fn resolve_nh_id(
  map: &std::collections::HashMap<u32, NexthopInfo>,
  id: u32,
) -> SmallVec<(u32, Option<IpAddr>)> {
  let mut out: SmallVec<(u32, Option<IpAddr>)> = SmallVec::new();
  let Some(nh) = map.get(&id) else {
    return out;
  };
  if let Some(members) = &nh.group {
    for member_id in members {
      if let Some(member) = map.get(member_id) {
        // Skip nested groups — keep the depth bounded.
        if member.group.is_none() && member.oif != 0 {
          out.push((member.oif, member.gw));
        }
      }
    }
  } else if nh.oif != 0 {
    out.push((nh.oif, nh.gw));
  }
  out
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
    // Dump nexthop objects up-front. Routes that arrive with
    // `RTA_NH_ID` (Linux 5.3+ `ip nexthop`-managed indirection) are
    // resolved against this map below. We dump even when the host has
    // no nexthop objects — the dump returns an empty map cheaply, and
    // we still want to call `RTM_GETROUTE` afterward.
    let nh_map = dump_nexthops(family.as_raw() as u8)?;

    // Stale-snapshot recovery: if a route added between the nexthop
    // dump and the route dump references an id our map doesn't know
    // about, we record it here and re-resolve after the route walk
    // completes. `NLM_F_DUMP_INTR` only catches changes *during* the
    // route dump — it can't see the nexthop arriving in the gap
    // between our two requests.
    let mut deferred_nh: Vec<(u8, u8, Option<IpAddr>, u32)> = Vec::new();

    let handle = Handle::new()?;

    let req = NetlinkRouteRequest::new(RTM_GETROUTE as u16, 1, family.as_raw() as u8, 0);
    handle.send(&req)?;

    let lsa = handle.sock()?;
    let page_size = rustix::param::page_size();
    let mut rb = vec![0u8; page_size];

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
          NLMSG_ERROR => return Err(rustix::io::Errno::INVAL.into()),
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
                  dst = parse_rta_ipaddr(rtm_header.rtm_family, data);
                }
                RTA_GATEWAY => {
                  gw = parse_rta_ipaddr(rtm_header.rtm_family, data);
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

            // Skip if a source constraint snuck in via RTA_SRC.
            if has_src_constraint {
              received = &received[l..];
              continue;
            }

            // Drop routes from custom policy tables. `RT_TABLE_MAIN`
            // (254) and `RT_TABLE_LOCAL` (255) cover the unicast / local
            // routes the public API contracts to expose; everything
            // else (RT_TABLE_DEFAULT, custom tables selected by `ip
            // rule`, etc.) carries constraints `IpRoute` can't express.
            if table_id != RT_TABLE_MAIN as u32 && table_id != RT_TABLE_LOCAL {
              received = &received[l..];
              continue;
            }

            // Resolve nexthop-object references. The route had only an
            // RTA_NH_ID — look up the nexthop in the dump map. Single
            // leaves emit one route; groups fan out to one route per
            // member (similar to RTA_MULTIPATH). If the id isn't in
            // `nh_map`, defer the route for a single retry pass after
            // the route walk finishes — covers the race where a
            // nexthop was added between the two dumps.
            if let Some(id) = nh_id {
              let resolved = resolve_nh_id(&nh_map, id);
              if resolved.is_empty() {
                deferred_nh.push((rtm_header.rtm_family, rtm_header.rtm_dst_len, dst, id));
              } else {
                for (nh_oif, nh_gw) in resolved {
                  on_route(
                    rtm_header.rtm_family,
                    nh_oif,
                    rtm_header.rtm_dst_len,
                    dst,
                    nh_gw,
                  );
                }
              }
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

    // Retry pass for routes whose RTA_NH_ID was unresolved against the
    // first nexthop dump. Re-dump and try once more; persistent miss
    // means the kernel state is racing faster than we can snapshot it,
    // and surfacing EINTR is the honest answer (it lets the caller
    // retry instead of silently losing routes).
    if !deferred_nh.is_empty() {
      let nh_map_2 = dump_nexthops(family.as_raw() as u8)?;
      for (rfamily, dst_len, dst, id) in deferred_nh {
        let resolved = resolve_nh_id(&nh_map_2, id);
        if resolved.is_empty() {
          return Err(rustix::io::Errno::INTR.into());
        }
        for (nh_oif, nh_gw) in resolved {
          on_route(rfamily, nh_oif, dst_len, dst, nh_gw);
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

    // Decode sub-attributes (only RTA_GATEWAY is interesting today).
    let mut nh_gw: Option<IpAddr> = None;
    let mut sub = &buf[RTNH_SIZE..nh_len];
    while sub.len() >= RtAttr::SIZE {
      let attr_len = u16::from_ne_bytes(sub[..2].try_into().unwrap()) as usize;
      let attr_ty = u16::from_ne_bytes(sub[2..4].try_into().unwrap());
      if attr_len < RtAttr::SIZE || attr_len > sub.len() {
        break;
      }
      if attr_ty == RTA_GATEWAY {
        nh_gw = parse_rta_ipaddr(rtm_family, &sub[RtAttr::SIZE..attr_len]);
      }
      let alen = rta_align_of(attr_len).min(sub.len());
      sub = &sub[alen..];
    }

    if nh_ifindex != 0 {
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
    let handle = Handle::new()?;

    // Create and send netlink request for routes
    let req = NetlinkRouteRequest::new(RTM_GETROUTE as u16, 1, family.as_raw() as u8, 0);
    handle.send(&req)?;

    // Get socket name
    let lsa = handle.sock()?;

    // Receive and process messages
    let page_size = rustix::param::page_size();
    let mut rb = vec![0u8; page_size];
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
          NLMSG_DONE => break 'outer,
          NLMSG_ERROR => return Err(rustix::io::Errno::INVAL.into()),
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
            let mut tmp_addrs = SmallVec::new();
            let mut current_ifi = 0;
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
                    let addr = IpAddr::V4(std::net::Ipv4Addr::from(
                      u32::from_ne_bytes(data[..4].try_into().unwrap()).swap_bytes(),
                    ));

                    if f(&addr) {
                      tmp_addrs.push(addr);
                    }
                  }
                  (AddressFamily::INET6, AddressFamily::INET6)
                  | (AddressFamily::UNSPEC, AddressFamily::INET6)
                    if data.len() >= 16 =>
                  {
                    let addr = IpAddr::V6(std::net::Ipv6Addr::from(u128::from_be_bytes(
                      data[..16].try_into().unwrap(),
                    )));

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
                _ => {}
              }

              rtattr_buf = &rtattr_buf[alen..];
            }

            for raw in tmp_addrs {
              if let Some(addr) = A::try_from(current_ifi, raw) {
                if seen.insert((addr.index(), addr.addr())) {
                  gateways.push(addr);
                }
              }
            }
          }
          _ => {}
        }

        received = &received[l..];
      }
    }

    Ok(gateways)
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
