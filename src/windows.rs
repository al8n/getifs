use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use smallvec_wrapper::{OneOrMore, SmallVec};
use smol_str::SmolStr;
use windows::{
  core::*,
  Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR},
  Win32::NetworkManagement::{IpHelper::*, Ndis::*},
  Win32::Networking::WinSock::*,
};

use super::{Interface, IpIf, MacAddr, MAC_ADDRESS_SIZE};

bitflags::bitflags! {
  /// Flags represents the interface flags.
  #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
  pub struct Flags: u32 {
    /// Interface is administratively up
    const UP = 0x1;
    /// Interface supports broadcast access capability
    const BROADCAST = 0x2;
    /// Interface is a loopback net
    const LOOPBACK = 0x4;
    /// Interface is point-to-point link
    const POINTOPOINT = 0x8;
    /// Supports multicast access capability
    const MULTICAST = 0x10;
    /// Resources allocated
    const RUNNING = 0x20;
  }
}

fn get_adapter_addresses() -> Result<SmallVec<IP_ADAPTER_ADDRESSES_LH>> {
  let mut size = 15000u32; // recommended initial size

  let mut buffer = vec![0; size as usize];
  loop {
    let result = unsafe {
      GetAdaptersAddresses(
        AF_UNSPEC.0 as u32,
        GAA_FLAG_INCLUDE_PREFIX,
        None,
        Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
        &mut size,
      )
    };

    if result == NO_ERROR.0 {
      if size == 0 {
        return Ok(SmallVec::new());
      }
      break;
    }

    if result != ERROR_BUFFER_OVERFLOW.0 {
      return Err(Error::from_win32());
    }

    if size <= buffer.len() as u32 {
      return Err(Error::from_win32());
    }
    buffer.resize(size as usize, 0);
  }

  let mut adapters = SmallVec::new();
  let mut current = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;

  // Safety: current is guaranteed to be valid as we just allocated it
  while !current.is_null() {
    unsafe {
      let curr = &*current;
      adapters.push(*curr);
      current = curr.Next;
    }
  }

  Ok(adapters)
}

pub(super) fn interface_table(idx: u32) -> io::Result<OneOrMore<Interface>> {
  let adapters = get_adapter_addresses()?;
  let mut interfaces = OneOrMore::new();

  for adapter in adapters {
    let mut index = 0;
    let res = unsafe { ConvertInterfaceLuidToIndex(&adapter.Luid, &mut index) };
    if res == NO_ERROR {
      index = adapter.Ipv6IfIndex;
    }

    if idx == 0 || idx == index {
      let mut name_buf = [0u8; 256];
      let name = {
        let hname = unsafe { if_indextoname(index, &mut name_buf) };
        let osname = unsafe { hname.as_bytes() };
        let osname_str = core::str::from_utf8(osname)
          .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        SmolStr::new(osname_str)
      };

      let mut flags = Flags::empty();
      if adapter.OperStatus == IfOperStatusUp {
        flags |= Flags::UP | Flags::RUNNING;
      }

      match adapter.IfType {
        IF_TYPE_ETHERNET_CSMACD
        | IF_TYPE_IEEE80211
        | IF_TYPE_IEEE1394
        | IF_TYPE_ISO88025_TOKENRING => {
          flags |= Flags::BROADCAST | Flags::MULTICAST;
        }
        IF_TYPE_PPP | IF_TYPE_TUNNEL => {
          flags |= Flags::POINTOPOINT | Flags::MULTICAST;
        }
        IF_TYPE_SOFTWARE_LOOPBACK => {
          flags |= Flags::LOOPBACK | Flags::MULTICAST;
        }
        IF_TYPE_ATM => {
          flags |= Flags::BROADCAST | Flags::POINTOPOINT | Flags::MULTICAST;
        }
        _ => {}
      }

      let mtu = if adapter.Mtu == 0xffffffff {
        0
      } else {
        adapter.Mtu
      };

      let hardware_addr = if adapter.PhysicalAddressLength > 0 {
        let mut buf = [0u8; MAC_ADDRESS_SIZE];
        let max_addr_len = (adapter.PhysicalAddressLength as usize).min(MAC_ADDRESS_SIZE);
        let addr = &adapter.PhysicalAddress[..max_addr_len];
        buf[..max_addr_len].copy_from_slice(addr);
        Some(MacAddr::new(buf))
      } else {
        None
      };

      let interface = Interface {
        index,
        name,
        flags,
        mtu,
        mac_addr: hardware_addr,
        addrs: Default::default(),
      };

      let ifindex = interface.index;
      interfaces.push(interface);

      if idx == ifindex {
        break;
      }
    }
  }

  Ok(interfaces)
}

pub(super) fn interface_addr_table(ifi: u32) -> io::Result<SmallVec<IpIf>> {
  let adapters = get_adapter_addresses()?;
  let mut addresses = SmallVec::new();

  for adapter in adapters {
    let mut index = 0;
    let res = unsafe { ConvertInterfaceLuidToIndex(&adapter.Luid, &mut index) };
    if res == NO_ERROR {
      index = adapter.Ipv6IfIndex;
    }

    if ifi == 0 || ifi == index {
      let mut unicast = adapter.FirstUnicastAddress;
      while !unicast.is_null() {
        let addr = unsafe { &*unicast };
        if let Some(ip) = sockaddr_to_ipaddr(addr.Address.lpSockaddr) {
          let ip = IpIf::with_prefix_len_assert(index, ip, addr.OnLinkPrefixLength);
          addresses.push(ip);
        }
        unicast = addr.Next;
      }

      let mut anycast = adapter.FirstAnycastAddress;
      while !anycast.is_null() {
        let addr = unsafe { &*anycast };
        if let Some(ip) = sockaddr_to_ipaddr(addr.Address.lpSockaddr) {
          let ip = IpIf::new(index, ip);
          addresses.push(ip);
        }
        anycast = addr.Next;
      }
    }
  }

  Ok(addresses)
}

pub(super) fn interface_multiaddr_table(ifi: Option<&Interface>) -> io::Result<SmallVec<IpAddr>> {
  let adapters = get_adapter_addresses()?;
  let mut addresses = SmallVec::new();

  for adapter in adapters {
    let mut index = 0;
    let res = unsafe { ConvertInterfaceLuidToIndex(&adapter.Luid, &mut index) };
    if res == NO_ERROR {
      index = adapter.Ipv6IfIndex;
    }

    let ifi = ifi.map_or(0, |i| i.index);
    if ifi == 0 || ifi == index {
      let mut multicast = adapter.FirstMulticastAddress;
      while !multicast.is_null() {
        let addr = unsafe { &*multicast };
        if let Some(ip) = sockaddr_to_ipaddr(addr.Address.lpSockaddr) {
          addresses.push(ip);
        }
        multicast = addr.Next;
      }
    }
  }

  Ok(addresses)
}

fn sockaddr_to_ipaddr(sockaddr: *const SOCKADDR) -> Option<IpAddr> {
  if sockaddr.is_null() {
    return None;
  }

  unsafe {
    match (*sockaddr).sa_family {
      AF_INET => {
        // let addr = sockaddr as *const SOCKADDR_IN;
        // let bytes = unsafe { (*addr).sin_addr.S_un.S_addr.to_ne_bytes() };
        // Some(IpAddr::V4(bytes.into()))
        None
      }
      AF_INET6 => {
        // let addr = sockaddr as *const SOCKADDR_IN6;
        // let bytes = unsafe { (*addr).sin6_addr.u.Byte };
        // Some(IpAddr::V6(bytes.into()))
        None
      }
      _ => None,
    }
  }
}
