#[cfg(feature = "mtu")]
use libc::SIOCGIFMTU;
use libc::{ifconf, ifreq, ioctl, sockaddr, socket, AF_INET, RTM_GETLINK, SIOCGIFCONF, SOCK_DGRAM};

#[cfg(feature = "mac_addr")]
use libc::SIOCGIFHWADDR;

#[cfg(feature = "flags")]
use libc::SIOCGIFFLAGS;

use std::{ffi::CStr, io, mem, net::SocketAddr, slice::from_raw_parts};

use crate::MacAddr;

use super::Interface;

#[cfg(feature = "flags")]
bitflags::bitflags! {
  /// Flags represents the interface flags.
  #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
  #[cfg(feature = "flags")]
  #[cfg_attr(docsrs, doc(cfg(feature = "flags")))]
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
    const MASTER = 0x400;
    /// Can't hear own transmissions
    const SLAVE = 0x800;
    /// Per link layer defined bit
    const MULTICAST = 0x1000;
    /// Per link layer defined bit
    const PORTSEL = 0x2000;
    /// Per link layer defined bit
    const AUTOMEDIA = 0x4000;
    /// Supports multicast access capability
    const DYNAMIC = 0x8000;
  }
}

/// Returns a list of the system's network interfaces.
pub fn interfaces() -> io::Result<Vec<Interface>> {
  unsafe {
    let sock = socket(AF_INET, SOCK_DGRAM, 0);
    if sock < 0 {
      return Err(io::Error::last_os_error());
    }

    // First call with null buffer to get required size
    let mut ifc: ifconf = mem::zeroed();
    if ioctl(sock, SIOCGIFCONF, &mut ifc) < 0 {
      let _ = libc::close(sock);
      return Err(io::Error::last_os_error());
    }

    // Allocate exact buffer size needed
    let mut buffer = vec![0u8; ifc.ifc_len as usize];
    ifc.ifc_ifcu.ifcu_buf = buffer.as_mut_ptr() as *mut _;

    // Second call to get actual interface data
    if ioctl(sock, SIOCGIFCONF, &mut ifc) < 0 {
      let _ = libc::close(sock);
      return Err(io::Error::last_os_error());
    }

    let ifreqs = from_raw_parts(
      ifc.ifc_ifcu.ifcu_req as *const ifreq,
      ifc.ifc_len as usize / mem::size_of::<ifreq>(),
    );

    let mut results = Vec::with_capacity(ifreqs.len());

    for ifreq in ifreqs {
      let name = CStr::from_ptr(ifreq.ifr_name.as_ptr()).to_string_lossy();

      let mut ifr = *ifreq;

      // Get interface index
      let index = libc::if_nametoindex(ifreq.ifr_name.as_ptr());

      // Get flags
      #[cfg(feature = "flags")]
      let flags = if ioctl(sock, SIOCGIFFLAGS, &mut ifr) < 0 {
        let _ = libc::close(sock);
        return Err(io::Error::last_os_error());
      } else {
        ifr.ifr_ifru.ifru_flags as u32
      };

      // Get MTU
      #[cfg(feature = "mtu")]
      let mtu = if ioctl(sock, SIOCGIFMTU, &mut ifr) < 0 {
        let _ = libc::close(sock);
        return Err(io::Error::last_os_error());
      } else {
        ifr.ifr_ifru.ifru_mtu as u32
      };

      // Get hardware address (this one can fail as not all interfaces have MAC)
      #[cfg(feature = "mac_addr")]
      let mac_addr = if ioctl(sock, SIOCGIFHWADDR, &mut ifr) >= 0 {
        let sa = &ifr.ifr_ifru.ifru_hwaddr as *const sockaddr;
        let data = (*sa).sa_data;
        let addr: [u8; 6] = data[..6].try_into().unwrap();
        if addr == [0; 6] {
          None
        } else {
          Some(MacAddr(addr))
        }
      } else {
        return Err(io::Error::last_os_error());
      };

      results.push(Interface {
        index: index as u32,
        name: name.into(),
        #[cfg(feature = "mtu")]
        mtu,
        #[cfg(feature = "mac_addr")]
        mac_addr,
        #[cfg(feature = "flags")]
        flags: Flags::from_bits_retain(flags),
      });
    }

    let _ = libc::close(sock);
    Ok(results)
  }
}

#[test]
fn test_interfaces() {
  let interfaces = interfaces().unwrap();
  for interface in interfaces {
    println!("{:?}", interface);
  }
}
