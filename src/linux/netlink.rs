use core::slice;

use linux_raw_sys::{
  if_arp::{self, ARPHRD_IPGRE, ARPHRD_TUNNEL, ARPHRD_TUNNEL6},
  netlink::{self, NLM_F_DUMP, NLM_F_REQUEST},
};
use rustix::net::{
  bind, getsockname, netlink::SocketAddrNetlink, recvfrom, sendto, socket, AddressFamily,
  RecvFlags, SendFlags, SocketType,
};

use smallvec_wrapper::{SmallVec, TinyVec};
use std::{ffi::CStr, io, mem, net::IpAddr, os::fd::OwnedFd};

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

const RTA_OIF: u16 = netlink::rtattr_type_t::RTA_OIF as u16;
const RTA_PRIORITY: u16 = netlink::rtattr_type_t::RTA_PRIORITY as u16;

const RT_TABLE_MAIN: u16 = netlink::rt_class_t::RT_TABLE_MAIN as u16;

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
    sendto(&self.fd, req.as_bytes(), SendFlags::empty(), &self.sa).map_err(Into::into)
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

        let msg_buf = &received[NLMSG_HDRLEN..];

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

              let alen = rta_align_of(attrlen);
              let vbuf = &info_data[RtAttr::SIZE..alen];

              match attr.ty as u32 {
                IFLA_MTU => {
                  interface.mtu = u32::from_ne_bytes(vbuf[..4].try_into().unwrap());
                }
                IFLA_IFNAME => {
                  interface.name = CStr::from_ptr(vbuf.as_ptr() as _).to_string_lossy().into();
                }
                IFLA_ADDRESS => match vbuf.len() {
                  // We never return any /32 or /128 IP address
                  // prefix on any IP tunnel interface as the
                  // hardware address.
                  // ipv4
                  4 if info_hdr.ty == ARPHRD_IPGRE as u16
                    || info_hdr.ty == ARPHRD_TUNNEL as u16 =>
                  {
                    continue
                  }
                  // ipv6
                  16 if info_hdr.ty == ARPHRD_TUNNEL6 as u16 || info_hdr.ty == 823 => continue, // 823 is any over GRE over IPv6 tunneling
                  _ => {
                    let mut nonzero = false;
                    for b in vbuf {
                      if *b != 0 {
                        nonzero = true;
                        break;
                      }
                    }
                    if nonzero {
                      let mut data = [0; MAC_ADDRESS_SIZE];
                      let len = vbuf.len().min(MAC_ADDRESS_SIZE);
                      data[..len].copy_from_slice(&vbuf[..len]);
                      interface.mac_addr = Some(MacAddr::new(data));
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

        let msg_buf = &received[NLMSG_HDRLEN..];

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
              let alen = rta_align_of(attrlen);
              let vbuf = &ifa_msg_data[RtAttr::SIZE..alen];

              if ifi == 0 || ifi == ifam.index {
                attrs.push((attr, vbuf));
              }
              ifa_msg_data = &ifa_msg_data[alen..];
            }

            for (attr, _) in attrs.iter() {
              if attr.ty == IFA_LOCAL as u16 {
                point_to_point = true;
                break;
              }
            }

            for (attr, vbuf) in attrs.iter() {
              if point_to_point && attr.ty == IFA_ADDRESS as u16 {
                continue;
              }

              match AddressFamily::from_raw(ifam.family as u16) {
                AddressFamily::INET => {
                  let ip: [u8; 4] = vbuf[..4].try_into().unwrap();
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
                AddressFamily::INET6 if vbuf.len() >= 16 => {
                  let ip: [u8; 16] = vbuf[..16].try_into().unwrap();
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

        match h.nlmsg_type as u32 {
          NLMSG_DONE => break 'outer,
          NLMSG_ERROR => return Err(rustix::io::Errno::INVAL.into()),
          val if val == RTM_NEWROUTE => {
            let rtm = &received[NLMSG_HDRLEN..];
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
              let alen = rta_align_of(attrlen);
              let data = &rtattr_buf[RtAttr::SIZE..attrlen];

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
            let rtm = &received[NLMSG_HDRLEN..];
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
                break;
              }

              let alen = rta_align_of(attrlen);
              let data = &rtattr_buf[RtAttr::SIZE..attrlen];

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

            gateways.extend(
              tmp_addrs
                .into_iter()
                .filter_map(|addr| A::try_from(current_ifi, addr)),
            );
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

#[repr(C)]
struct RtGenMessage {
  family: u8,
}

#[repr(C)]
struct NetlinkRouteRequest {
  header: MessageHeader,
  data: RtGenMessage,
}

impl NetlinkRouteRequest {
  const SIZE: usize = mem::size_of::<Self>();

  #[inline]
  fn new(proto: u16, seq: u32, family: u8, _ifi: u32) -> Self {
    // TODO(al8n): do not dump when ifi is not 0
    // let flags = if ifi == 0 {
    //   (libc::NLM_F_DUMP | libc::NLM_F_REQUEST) as u16
    // } else {
    //   libc::NLM_F_REQUEST as u16
    // };
    Self {
      header: MessageHeader {
        nlmsg_len: Self::SIZE as u32,
        nlmsg_type: proto,
        nlmsg_flags: (NLM_F_DUMP | NLM_F_REQUEST) as u16,
        nlmsg_seq: seq,
        nlmsg_pid: std::process::id(),
      },
      data: RtGenMessage { family },
    }
  }

  #[inline]
  const fn as_bytes(&self) -> &[u8] {
    unsafe { slice::from_raw_parts(self as *const _ as _, Self::SIZE) }
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
