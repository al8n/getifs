use ipnet::ip_mask_to_prefix;
use libc::{
  c_void, if_msghdr, ifa_msghdr, size_t, sysctl, AF_INET, AF_INET6, AF_LINK,
  AF_ROUTE, AF_UNSPEC, CTL_NET, NET_RT_IFLIST, NET_RT_IFLIST2, RTAX_BRD, RTAX_IFA, RTAX_MAX,
  RTAX_NETMASK, RTM_IFINFO, RTM_NEWADDR, RTM_VERSION,
};
use smol_str::SmolStr;
use std::{
  io, mem,
  net::{IpAddr, Ipv6Addr},
  ptr::null_mut,
};

use super::{Interface, IpNet, MacAddr};

#[cfg(any(
  target_os = "macos",
  target_os = "tvos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "visionos",
))]
const KERNAL_ALIGN: usize = 4;

#[cfg(target_os = "dragonfly")]
const KERNAL_ALIGN: usize = core::mem::size_of::<usize>();

#[cfg(target_os = "freebsd")]
const KERNAL_ALIGN: usize = core::mem::size_of::<usize>();

#[cfg(target_os = "netbsd")]
const KERNAL_ALIGN: usize = 8;

#[cfg(target_os = "openbsd")]
const KERNAL_ALIGN: usize = core::mem::size_of::<usize>();

fn invalid_address() -> io::Error {
  io::Error::new(io::ErrorKind::InvalidData, "invalid address")
}

#[inline]
fn invalid_mask(e: ipnet::PrefixLenError) -> io::Error {
  io::Error::new(io::ErrorKind::InvalidData, e)
}

bitflags::bitflags! {
  /// Flags represents the interface flags.
  #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
  pub struct Flags: u32 {
    /// Interface is administratively up
    const UP = 0x1;
    /// Interface supports broadcast access capability
    const BROADCAST = 0x2;
    /// Turn on debugging
    const DEBUG = 0x4;
    /// Interface is a loopback net
    const LOOPBACK = 0x8;
    /// Interface is point-to-point link
    const POINTOPOINT = 0x10;
    /// Obsolete: avoid use of trailers
    const NOTRAILERS = 0x20;
    /// Resources allocated
    const RUNNING = 0x40;
    /// No address resolution protocol
    const NOARP = 0x80;
    /// Receive all packets
    const PROMISC = 0x100;
    /// Receive all multicast packets
    const ALLMULTI = 0x200;
    /// Transmission is in progress
    const OACTIVE = 0x400;
    /// Can't hear own transmissions
    const SIMPLEX = 0x800;
    /// Per link layer defined bit
    const LINK0 = 0x1000;
    /// Per link layer defined bit
    const LINK1 = 0x2000;
    /// Per link layer defined bit
    const LINK2 = 0x4000;
    /// Use alternate physical connection
    const ALTPHYS = 0x4000;
    /// Supports multicast access capability
    const MULTICAST = 0x8000;
  }
}

fn parse(mut b: &[u8]) -> io::Result<(SmolStr, Option<MacAddr>)> {
  if b.len() < 8 {
    return Err(invalid_address());
  }

  b = &b[4..];

  // The encoding looks like the following:
  // +----------------------------+
  // | Type             (1 octet) |
  // +----------------------------+
  // | Name length      (1 octet) |
  // +----------------------------+
  // | Address length   (1 octet) |
  // +----------------------------+
  // | Selector length  (1 octet) |
  // +----------------------------+
  // | Data            (variable) |
  // +----------------------------+
  //
  // On some platforms, all-bit-one of length field means "don't
  // care".

  let (mut nlen, mut alen, mut slen) = (b[1] as usize, b[2] as usize, b[3] as usize);
  if nlen == 0xff {
    nlen = 0
  }
  if alen == 0xff {
    alen = 0
  }
  if slen == 0xff {
    slen = 0
  }

  let l = 4 + nlen + alen + slen;
  if b.len() < l {
    return Err(invalid_address());
  }

  let mut data = &b[4..];
  let name = if nlen > 0 {
    let name = core::str::from_utf8(&data[..nlen])
      .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    data = &data[nlen..];
    SmolStr::from(name)
  } else {
    SmolStr::default()
  };

  let addr = if alen == 6 {
    Some(MacAddr(data[..alen].try_into().unwrap()))
  } else {
    None
  };

  Ok((name, addr))
}

fn parse_kernel_inet_addr(b: &[u8]) -> io::Result<(usize, IpAddr)> {
  // The encoding looks similar to the NLRI encoding.
  // +----------------------------+
  // | Length           (1 octet) |
  // +----------------------------+
  // | Address prefix  (variable) |
  // +----------------------------+
  //
  // The differences between the kernel form and the NLRI
  // encoding are:
  //
  // - The length field of the kernel form indicates the prefix
  //   length in bytes, not in bits
  //
  // - In the kernel form, zero value of the length field
  //   doesn't mean 0.0.0.0/0 or ::/0
  //
  // - The kernel form appends leading bytes to the prefix field
  //   to make the <length, prefix> tuple to be conformed with
  //   the routing message boundary
  // On Darwin, an address in the kernel form is also
  // used as a message filler.
  #[cfg(any(target_os = "macos", target_os = "ios"))]
  let l = {
    let mut l = b[0] as usize;
    if l == 0 || b.len() > roundup(l) {
      l = roundup(l);
    }
    l
  };
  #[cfg(not(any(target_os = "macos", target_os = "ios")))]
  let l = roundup(b[0] as usize);

  if b.len() < l {
    return Err(invalid_address());
  }

  // Don't reorder case expressions.
  // The case expressions for IPv6 must come first.
  const OFF4: usize = 4; // offset of in_addr
  const OFF6: usize = 8; // offset of in6_addr

  match () {
    () if b[0] as usize == size_of::<libc::sockaddr_in>() => {
      let mut ip = [0u8; 4];
      ip.copy_from_slice(&b[OFF4..OFF4 + 4]);
      Ok((b[0] as usize, IpAddr::V4(ip.into())))
    }
    () if b[0] as usize == size_of::<libc::sockaddr_in6>() => {
      let mut ip = [0u8; 16];
      ip.copy_from_slice(&b[OFF6..OFF6 + 16]);
      Ok((b[0] as usize, IpAddr::V6(ip.into())))
    }
    _ => {
      // an old fashion, AF_UNSPEC or unknown means AF_INET
      let mut ip = [0u8; 4];
      let remaining = l - 1;
      if remaining < OFF4 {
        ip[..remaining].copy_from_slice(&b[1..l]);
      } else {
        ip.copy_from_slice(&b[l - OFF4..l]);
      }

      Ok((b[0] as usize, IpAddr::V4(ip.into())))
    }
  }
}

#[inline]
const fn roundup(l: usize) -> usize {
  if l == 0 {
    return KERNAL_ALIGN;
  }

  (l + KERNAL_ALIGN - 1) & !(KERNAL_ALIGN - 1)
}

fn parse_inet_addr(af: i32, b: &[u8]) -> io::Result<(usize, IpAddr)> {
  const SOCK4: usize = size_of::<libc::sockaddr_in>();
  const SOCK6: usize = size_of::<libc::sockaddr_in6>();

  match af {
    AF_INET => {
      if b.len() < SOCK4 {
        return Err(invalid_address());
      }

      let sockaddr = unsafe { &*(b.as_ptr() as *const libc::sockaddr_in) };
      Ok((
        SOCK4,
        IpAddr::V4(sockaddr.sin_addr.s_addr.to_ne_bytes().into()),
      ))
    }
    AF_INET6 => {
      if b.len() < SOCK6 {
        return Err(invalid_address());
      }

      let sockaddr = unsafe { &*(b.as_ptr() as *const libc::sockaddr_in6) };

      let mut ip = sockaddr.sin6_addr.s6_addr;
      // TODO: create own Ipv6Addr
      let _zone_id = sockaddr.sin6_scope_id;
      let mut addr: Ipv6Addr = ip.into();
      if ip[0] == 0xfe && ip[1] & 0xc0 == 0x80
        || ip[0] == 0xff && (ip[1] & 0x0f == 0x01 || ip[1] & 0x0f == 0x02)
      {
        // KAME based IPv6 protocol stack usually
        // embeds the interface index in the
        // interface-local or link-local address as
        // the kernel-internal form.
        let id = u16::from_be_bytes([ip[2], ip[3]]);
        if id != 0 {
          ip[2] = 0;
          ip[3] = 0;
          addr = ip.into();
        }
      }

      Ok((SOCK6, addr.into()))
    }
    _ => Err(invalid_address()),
  }
}

fn parse_addrs(addrs: u32, mut b: &[u8]) -> io::Result<[Option<IpAddr>; RTAX_MAX as usize]> {
  let mut as_ = [None; RTAX_MAX as usize];

  #[allow(clippy::needless_range_loop)]
  for i in 0..RTAX_MAX as usize {
    if b.len() < KERNAL_ALIGN {
      break;
    }

    if addrs & (1 << i) == 0 {
      continue;
    }

    if i <= RTAX_BRD as usize {
      match b[1] as i32 {
        AF_LINK => {
          let l = roundup(b[0] as usize);
          if b.len() < l {
            return Err(io::Error::new(
              io::ErrorKind::InvalidData,
              "message too short",
            ));
          }
          b = &b[l..];
        }
        AF_INET | AF_INET6 => {
          let (_, addr) = parse_inet_addr(b[1] as i32, b)?;
          as_[i] = Some(addr);
          let l = roundup(b[0] as usize);
          if b.len() < l {
            return Err(io::Error::new(
              io::ErrorKind::InvalidData,
              "message too short",
            ));
          }
          b = &b[l..];
        }
        _ => {
          let (l, addr) = parse_kernel_inet_addr(b)?;
          as_[i] = Some(addr);
          let ll = roundup(l);
          if b.len() < ll {
            b = &b[l..];
          } else {
            b = &b[ll..];
          }
        }
      }
    } else {
      let l = roundup(b[0] as usize);
      if b.len() < l {
        return Err(io::Error::new(
          io::ErrorKind::InvalidData,
          "message too short",
        ));
      }
      b = &b[l..];
    }
  }

  Ok(as_)
}

pub(super) fn interface_table(idx: u32) -> io::Result<Vec<Interface>> {
  unsafe {
    let mut mib = [CTL_NET, AF_ROUTE, 0, AF_UNSPEC, NET_RT_IFLIST, idx as i32];

    // Get buffer size
    let mut len: size_t = 0;
    if sysctl(mib.as_mut_ptr(), 6, null_mut(), &mut len, null_mut(), 0) < 0 {
      return Err(io::Error::last_os_error());
    }

    // Allocate buffer
    let mut buf = vec![0u8; len];
    if sysctl(
      mib.as_mut_ptr(),
      6,
      buf.as_mut_ptr() as *mut c_void,
      &mut len,
      null_mut(),
      0,
    ) < 0
    {
      return Err(io::Error::last_os_error());
    }

    let mut results = Vec::new();
    let mut offset = 0;

    while offset < len {
      let ifm = &*(buf.as_ptr().add(offset) as *const if_msghdr);
      if ifm.ifm_type as i32 == RTM_IFINFO {
        let (name, _mac) = parse(&buf[offset + size_of::<if_msghdr>()..])?;
        let interface = Interface {
          index: ifm.ifm_index as u32,
          mtu: ifm.ifm_data.ifi_mtu,
          name,
          mac_addr: _mac,
          flags: Flags::from_bits_truncate(ifm.ifm_flags as u32),
        };
        results.push(interface);
      }
      offset += ifm.ifm_msglen as usize;
    }

    Ok(results)
  }
}

pub(super) fn interface_addr_table(idx: u32) -> io::Result<Vec<IpNet>> {
  const HEADER_SIZE: usize = mem::size_of::<ifa_msghdr>();

  unsafe {
    let mut mib = [CTL_NET, AF_ROUTE, 0, AF_UNSPEC, NET_RT_IFLIST, idx as i32];

    // Get buffer size
    let mut len: size_t = 0;
    if sysctl(mib.as_mut_ptr(), 6, null_mut(), &mut len, null_mut(), 0) < 0 {
      return Err(io::Error::last_os_error());
    }

    // Allocate buffer
    let mut buf = vec![0u8; len];
    if sysctl(
      mib.as_mut_ptr(),
      6,
      buf.as_mut_ptr() as *mut c_void,
      &mut len,
      null_mut(),
      0,
    ) < 0
    {
      return Err(io::Error::last_os_error());
    }

    let mut results = Vec::new();
    let mut b = buf.as_slice();

    while b.len() > HEADER_SIZE {
      let ifam = &*(b.as_ptr() as *const ifa_msghdr);
      let len = ifam.ifam_msglen as usize;

      if ifam.ifam_version as i32 != RTM_VERSION {
        b = &b[len..];
        continue;
      }

      if ifam.ifam_type as i32 == RTM_NEWADDR {
        let addrs = parse_addrs(ifam.ifam_addrs as u32, &b[HEADER_SIZE..len])?;

        let mask = addrs[RTAX_NETMASK as usize]
          .as_ref()
          .map(|ip| ip_mask_to_prefix(*ip));

        let ip: Option<IpAddr> = addrs[RTAX_IFA as usize].as_ref().map(|ip| *ip);

        if let (Some(ip), Some(mask)) = (ip, mask) {
          results.push(IpNet::new_assert(ip, mask.map_err(invalid_mask)?));
        }
      }

      b = &b[len..];
    }

    Ok(results)
  }
}

#[cfg(any(
  target_os = "macos",
  target_os = "tvos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "visionos",
))]
pub(super) fn interface_multiaddr_table(idx: u32) -> io::Result<Vec<IpAddr>> {
  const HEADER_SIZE: usize = mem::size_of::<libc::ifma_msghdr2>();

  unsafe {
    let mut mib = [CTL_NET, AF_ROUTE, 0, AF_UNSPEC, NET_RT_IFLIST2, idx as i32];

    // Get buffer size
    let mut len: size_t = 0;
    if sysctl(mib.as_mut_ptr(), 6, null_mut(), &mut len, null_mut(), 0) < 0 {
      return Err(io::Error::last_os_error());
    }

    // Allocate buffer
    let mut buf = vec![0u8; len];
    if sysctl(
      mib.as_mut_ptr(),
      6,
      buf.as_mut_ptr() as *mut c_void,
      &mut len,
      null_mut(),
      0,
    ) < 0
    {
      return Err(io::Error::last_os_error());
    }

    let mut results = Vec::new();
    let mut b = buf.as_slice();

    while b.len() > HEADER_SIZE {
      let ifam = &*(b.as_ptr() as *const libc::ifma_msghdr2);
      let len = ifam.ifmam_msglen as usize;

      if ifam.ifmam_version as i32 != RTM_VERSION {
        b = &b[len..];
        continue;
      }

      if ifam.ifmam_type as i32 == libc::RTM_NEWMADDR2 {
        let addrs = parse_addrs(ifam.ifmam_addrs as u32, &b[HEADER_SIZE..len])?;

        if let Some(ip) = addrs[RTAX_IFA as usize].as_ref() {
          results.push(*ip);
        }
      }

      b = &b[len..];
    }

    Ok(results)
  }
}

#[cfg(target_os = "freebsd")]
pub(super) fn interface_multiaddr_table(idx: u32) -> io::Result<Vec<IpAddr>> {
  const HEADER_SIZE: usize = mem::size_of::<libc::ifma_msghdr>();

  unsafe {
    let mut mib = [
      CTL_NET,
      AF_ROUTE,
      0,
      AF_UNSPEC,
      libc::NET_RT_IFMALIST,
      idx as i32,
    ];

    // Get buffer size
    let mut len: size_t = 0;
    if sysctl(mib.as_mut_ptr(), 6, null_mut(), &mut len, null_mut(), 0) < 0 {
      return Err(io::Error::last_os_error());
    }

    // Allocate buffer
    let mut buf = vec![0u8; len];
    if sysctl(
      mib.as_mut_ptr(),
      6,
      buf.as_mut_ptr() as *mut c_void,
      &mut len,
      null_mut(),
      0,
    ) < 0
    {
      return Err(io::Error::last_os_error());
    }

    let mut results = Vec::new();
    let mut b = buf.as_slice();

    while b.len() > HEADER_SIZE {
      let ifam = &*(b.as_ptr() as *const libc::ifma_msghdr);
      let len = ifam.ifmam_msglen as usize;

      if ifam.ifmam_version as i32 != RTM_VERSION {
        b = &b[len..];
        continue;
      }

      if ifam.ifmam_type as i32 == libc::RTM_NEWMADDR {
        let addrs = parse_addrs(ifam.ifmam_addrs as u32, &b[HEADER_SIZE..len])?;

        if let Some(ip) = addrs[RTAX_IFA as usize].as_ref() {
          results.push(*ip);
        }
      }

      b = &b[len..];
    }

    Ok(results)
  }
}

#[test]
fn test_interfaces() {
  let interfaces = interface_addr_table(1).unwrap();
  println!("{:?}", interfaces);
  let interfaces = interface_multiaddr_table(1).unwrap();
  println!("{:?}", interfaces);
}
