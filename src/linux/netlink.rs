use core::slice;
use libc::{
  bind, close, getsockname, nlmsghdr, recvfrom, sendto, sockaddr_nl, socket, socklen_t, AF_INET,
  AF_INET6, AF_NETLINK, ARPHRD_IPGRE, ARPHRD_TUNNEL, ARPHRD_TUNNEL6, EINVAL, IFA_ADDRESS,
  IFA_LOCAL, IFLA_ADDRESS, IFLA_IFNAME, IFLA_MTU, NETLINK_ROUTE, NLMSG_DONE, NLMSG_ERROR,
  RTM_NEWLINK, SOCK_CLOEXEC, SOCK_RAW,
};
use libc::{RTM_GETADDR, RTM_GETLINK, RTM_NEWADDR};
use smallvec_wrapper::{OneOrMore, SmallVec};
use std::ffi::CStr;
use std::io;
use std::mem;

use super::{Flags, Interface, IpIf, MacAddr, MAC_ADDRESS_SIZE};

const NLMSG_HDRLEN: usize = mem::size_of::<nlmsghdr>();
const NLMSG_ALIGNTO: usize = 4;

// Ensure socket is closed when we're done
struct SocketGuard(i32);

impl Drop for SocketGuard {
  fn drop(&mut self) {
    unsafe { close(self.0) };
  }
}

pub(super) fn netlink_interface(family: i32, ifi: u32) -> io::Result<OneOrMore<Interface>> {
  unsafe {
    // Create socket
    let sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if sock < 0 {
      return Err(io::Error::last_os_error());
    }

    let _guard = SocketGuard(sock);

    // Prepare and bind socket address
    let mut sa: sockaddr_nl = mem::zeroed();
    sa.nl_family = AF_NETLINK as u16;

    if bind(
      sock,
      &sa as *const sockaddr_nl as *const _,
      mem::size_of::<sockaddr_nl>() as socklen_t,
    ) < 0
    {
      return Err(io::Error::last_os_error());
    }

    // Create and send netlink request
    let req = NetlinkRouteRequest::new(RTM_GETLINK, 1, family as u8);
    if sendto(
      sock,
      req.as_bytes().as_ptr() as _,
      NetlinkRouteRequest::SIZE,
      0,
      &sa as *const sockaddr_nl as *const _,
      mem::size_of::<sockaddr_nl>() as socklen_t,
    ) < 0
    {
      return Err(io::Error::last_os_error());
    }

    // Get socket name
    let mut lsa: sockaddr_nl = mem::zeroed();
    let mut lsa_len = mem::size_of::<sockaddr_nl>() as socklen_t;
    if getsockname(sock, &mut lsa as *mut sockaddr_nl as *mut _, &mut lsa_len) < 0 {
      return Err(io::Error::last_os_error());
    }

    // Receive and process messages
    let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
    let mut rb = vec![0u8; page_size];

    let mut interfaces = OneOrMore::new();

    'outer: loop {
      let mut addr: sockaddr_nl = mem::zeroed();
      let mut addr_len = mem::size_of::<sockaddr_nl>() as socklen_t;

      let nr = recvfrom(
        sock,
        rb.as_mut_ptr() as *mut _,
        rb.len(),
        0,
        &mut addr as *mut sockaddr_nl as *mut _,
        &mut addr_len,
      );

      if nr < 0 {
        return Err(io::Error::last_os_error());
      }

      if nr < NLMSG_HDRLEN as isize {
        return Err(io::Error::from_raw_os_error(EINVAL));
      }

      let mut received = &rb[..nr as usize];

      while received.len() >= NLMSG_HDRLEN {
        let h = decode_nlmsghdr(received);
        let hlen = h.nlmsg_len as usize;
        let l = nlm_align_of(hlen);
        if hlen < NLMSG_HDRLEN || l > received.len() {
          return Err(io::Error::from_raw_os_error(EINVAL));
        }

        if h.nlmsg_seq != 1 || h.nlmsg_pid != lsa.nl_pid {
          return Err(io::Error::from_raw_os_error(EINVAL));
        }

        let msg_buf = &received[NLMSG_HDRLEN..];

        match h.nlmsg_type as i32 {
          NLMSG_DONE => break 'outer,
          NLMSG_ERROR => return Err(io::Error::from_raw_os_error(EINVAL)),
          val if val == RTM_NEWLINK as i32 => {
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
                return Err(io::Error::from_raw_os_error(EINVAL));
              }

              let alen = rta_align_of(attrlen);
              let vbuf = &info_data[RtAttr::SIZE..alen];

              match attr.ty {
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
                  4 if info_hdr.ty == ARPHRD_IPGRE || info_hdr.ty == ARPHRD_TUNNEL => continue,
                  // ipv6
                  16 if info_hdr.ty == ARPHRD_TUNNEL6 || info_hdr.ty == 823 => continue, // 823 is any over GRE over IPv6 tunneling
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

pub(super) fn netlink_addr(family: i32, ifi: u32) -> io::Result<SmallVec<IpIf>> {
  unsafe {
    // Create socket
    let sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if sock < 0 {
      return Err(io::Error::last_os_error());
    }

    // Ensure socket is closed when we're done
    let _guard = SocketGuard(sock);

    // Prepare and bind socket address
    let mut sa: sockaddr_nl = mem::zeroed();
    sa.nl_family = AF_NETLINK as u16;

    if bind(
      sock,
      &sa as *const sockaddr_nl as *const _,
      mem::size_of::<sockaddr_nl>() as socklen_t,
    ) < 0
    {
      return Err(io::Error::last_os_error());
    }

    // Create and send netlink request
    let req = NetlinkRouteRequest::new(RTM_GETADDR, 1, family as u8);
    if sendto(
      sock,
      req.as_bytes().as_ptr() as _,
      NetlinkRouteRequest::SIZE,
      0,
      &sa as *const sockaddr_nl as *const _,
      mem::size_of::<sockaddr_nl>() as socklen_t,
    ) < 0
    {
      return Err(io::Error::last_os_error());
    }

    // Get socket name
    let mut lsa: sockaddr_nl = mem::zeroed();
    let mut lsa_len = mem::size_of::<sockaddr_nl>() as socklen_t;
    if getsockname(sock, &mut lsa as *mut sockaddr_nl as *mut _, &mut lsa_len) < 0 {
      return Err(io::Error::last_os_error());
    }

    // Receive and process messages
    let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
    let mut rb = vec![0u8; page_size];

    let mut addrs = SmallVec::new();

    'outer: loop {
      let mut addr: sockaddr_nl = mem::zeroed();
      let mut addr_len = mem::size_of::<sockaddr_nl>() as socklen_t;

      let nr = recvfrom(
        sock,
        rb.as_mut_ptr() as *mut _,
        rb.len(),
        0,
        &mut addr as *mut sockaddr_nl as *mut _,
        &mut addr_len,
      );

      if nr < 0 {
        return Err(io::Error::last_os_error());
      }

      if nr < NLMSG_HDRLEN as isize {
        return Err(io::Error::from_raw_os_error(EINVAL));
      }

      let mut received = &rb[..nr as usize];

      // means auto choose interface for addr fetching
      while received.len() >= NLMSG_HDRLEN {
        let h = decode_nlmsghdr(received);
        let hlen = h.nlmsg_len as usize;
        let l = nlm_align_of(hlen);
        if hlen < NLMSG_HDRLEN || l > received.len() {
          return Err(io::Error::from_raw_os_error(EINVAL));
        }

        if h.nlmsg_seq != 1 || h.nlmsg_pid != lsa.nl_pid {
          return Err(io::Error::from_raw_os_error(EINVAL));
        }

        let msg_buf = &received[NLMSG_HDRLEN..];

        match h.nlmsg_type as i32 {
          NLMSG_DONE => break 'outer,
          NLMSG_ERROR => return Err(io::Error::from_raw_os_error(EINVAL)),
          val if val == RTM_NEWADDR as i32 => {
            let ifam = IfAddrMessageHeader {
              family: msg_buf[0],
              prefix_len: msg_buf[1],
              flags: msg_buf[2],
              scope: msg_buf[3],
              index: u32::from_ne_bytes(msg_buf[4..8].try_into().unwrap()),
            };

            let mut ifa_msg_data = &msg_buf[IfAddrMessageHeader::SIZE..];
            let mut point_to_point = false;
            let mut attrs = SmallVec::new();
            while ifa_msg_data.len() >= RtAttr::SIZE {
              let attr = RtAttr {
                len: u16::from_ne_bytes(ifa_msg_data[..2].try_into().unwrap()),
                ty: u16::from_ne_bytes(ifa_msg_data[2..4].try_into().unwrap()),
              };
              let attrlen = attr.len as usize;
              if attrlen < RtAttr::SIZE || attrlen > ifa_msg_data.len() {
                return Err(io::Error::from_raw_os_error(EINVAL));
              }
              let alen = rta_align_of(attrlen);
              let vbuf = &ifa_msg_data[RtAttr::SIZE..alen];

              if ifi == 0 || ifi == ifam.index {
                attrs.push((attr, vbuf));
              }
              ifa_msg_data = &ifa_msg_data[alen..];
            }

            for (attr, _) in attrs.iter() {
              if attr.ty == IFA_LOCAL {
                point_to_point = true;
                break;
              }
            }

            for (attr, vbuf) in attrs.iter() {
              if point_to_point && attr.ty == IFA_ADDRESS {
                continue;
              }

              match ifam.family as i32 {
                AF_INET => {
                  let ip: [u8; 4] = vbuf[..4].try_into().unwrap();
                  addrs.push(IpIf::with_prefix_len_assert(
                    ifam.index,
                    ip.into(),
                    ifam.prefix_len,
                  ));
                  continue 'outer;
                }
                AF_INET6 if vbuf.len() >= 16 => {
                  let ip: [u8; 16] = vbuf[..16].try_into().unwrap();
                  addrs.push(IpIf::with_prefix_len_assert(
                    ifam.index,
                    ip.into(),
                    ifam.prefix_len,
                  ));
                  continue 'outer;
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

// Round the length of a netlink message up to align it properly.
#[inline]
const fn nlm_align_of(msg_len: usize) -> usize {
  (msg_len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
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
  header: nlmsghdr,
  data: RtGenMessage,
}

impl NetlinkRouteRequest {
  const SIZE: usize = mem::size_of::<Self>();

  #[inline]
  fn new(proto: u16, seq: u32, family: u8) -> Self {
    Self {
      header: nlmsghdr {
        nlmsg_len: Self::SIZE as u32,
        nlmsg_type: proto,
        nlmsg_flags: (libc::NLM_F_DUMP | libc::NLM_F_REQUEST) as u16,
        nlmsg_seq: seq,
        nlmsg_pid: 0,
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
      return Err(io::Error::from_raw_os_error(EINVAL));
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
struct IfAddrMessageHeader {
  family: u8,
  prefix_len: u8,
  flags: u8,
  scope: u8,
  index: u32,
}

impl IfAddrMessageHeader {
  const SIZE: usize = mem::size_of::<Self>();
}

#[inline]
fn decode_nlmsghdr(src: &[u8]) -> nlmsghdr {
  let hlen = u32::from_ne_bytes(src[..4].try_into().unwrap());
  let hty = u16::from_ne_bytes(src[4..6].try_into().unwrap());
  let hflags = u16::from_ne_bytes(src[6..8].try_into().unwrap());
  let hseq = u32::from_ne_bytes(src[8..12].try_into().unwrap());
  let hpid = u32::from_ne_bytes(src[12..16].try_into().unwrap());
  nlmsghdr {
    nlmsg_len: hlen,
    nlmsg_type: hty,
    nlmsg_flags: hflags,
    nlmsg_seq: hseq,
    nlmsg_pid: hpid,
  }
}
