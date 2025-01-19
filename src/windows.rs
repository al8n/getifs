use std::{
  io::{self, Error, Result},
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use smallvec_wrapper::{SmallVec, TinyVec};
use smol_str::SmolStr;
use windows_sys::{
  core::*,
  Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR},
  Win32::NetworkManagement::{IpHelper::*, Ndis::*},
  Win32::Networking::WinSock::*,
};

use super::{
  Address, IfAddr, IfNet, Ifv4Addr, Ifv4Net, Ifv6Addr, Ifv6Net, Interface, MacAddr, Net,
  MAC_ADDRESS_SIZE,
};

pub(super) use local_addr::*;
pub(super) use gateway::*;

#[path = "windows/local_addr.rs"]
mod local_addr;

#[path = "windows/gateway.rs"]
mod gateway;

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

struct Information {
  buffer: Vec<u8>,
  adapters: SmallVec<IP_ADAPTER_ADDRESSES_LH>,
}

impl Information {
  fn fetch() -> Result<Self> {
    let mut size = 15000u32; // recommended initial size

    let mut buffer = vec![0; size as usize];
    loop {
      let result = unsafe {
        GetAdaptersAddresses(
          AF_UNSPEC as u32,
          GAA_FLAG_INCLUDE_PREFIX,
          std::ptr::null() as _,
          buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
          &mut size,
        )
      };

      if result == NO_ERROR {
        if size == 0 {
          return Ok(Self {
            buffer: Vec::new(),
            adapters: SmallVec::new(),
          });
        }
        break;
      }

      if result != ERROR_BUFFER_OVERFLOW {
        return Err(Error::last_os_error());
      }

      if size <= buffer.len() as u32 {
        return Err(Error::last_os_error());
      }
      buffer.resize(size as usize, 0);
    }

    let mut adapters = SmallVec::new();
    let mut current = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;

    // Safety: current is guaranteed to be valid as we just allocated it
    unsafe {
      while let Some(curr) = current.as_ref() {
        adapters.push(*curr);
        current = curr.Next;
      }
    }

    Ok(Self { buffer, adapters })
  }
}

pub(super) fn interface_table(idx: u32) -> io::Result<TinyVec<Interface>> {
  let info = Information::fetch()?;
  let mut interfaces = TinyVec::new();

  for adapter in info.adapters.iter() {
    let mut index = 0;
    let res = unsafe { ConvertInterfaceLuidToIndex(&adapter.Luid, &mut index) };
    if res == NO_ERROR {
      index = adapter.Ipv6IfIndex;
    }

    if idx == 0 || idx == index {
      let name = match crate::utils::friendly_name(adapter.FriendlyName) {
        Some(name) => name,
        None => {
          let mut name_buf = [0u8; 256];
          let hname = unsafe { if_indextoname(index, name_buf.as_mut_ptr()) };
          unsafe {
            std::ffi::CStr::from_ptr(hname as _)
              .to_string_lossy()
              .into()
          }
        }
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

pub(super) fn interface_ipv4_addresses<F>(idx: u32, f: F) -> io::Result<SmallVec<Ifv4Net>>
where
  F: FnMut(&IpAddr) -> bool,
{
  interface_addr_table(AF_INET, idx, f)
}

pub(super) fn interface_ipv6_addresses<F>(idx: u32, f: F) -> io::Result<SmallVec<Ifv6Net>>
where
  F: FnMut(&IpAddr) -> bool,
{
  interface_addr_table(AF_INET6, idx, f)
}

pub(super) fn interface_addresses<F>(idx: u32, f: F) -> io::Result<SmallVec<IfNet>>
where
  F: FnMut(&IpAddr) -> bool,
{
  interface_addr_table(AF_UNSPEC, idx, f)
}

pub(super) fn interface_addr_table<T, F>(family: u16, ifi: u32, mut f: F) -> io::Result<SmallVec<T>>
where
  T: Net,
  F: FnMut(&IpAddr) -> bool,
{
  let info = Information::fetch()?;
  let mut addresses = SmallVec::new();

  for adapter in info.adapters.iter() {
    let mut index = 0;
    let res = unsafe { ConvertInterfaceLuidToIndex(&adapter.Luid, &mut index) };
    if res == NO_ERROR {
      index = adapter.Ipv6IfIndex;
    }

    if ifi == 0 || ifi == index {
      unsafe {
        let mut unicast = adapter.FirstUnicastAddress;
        while let Some(addr) = unicast.as_ref() {
          if let Some(ip) = sockaddr_to_ipaddr(family, addr.Address.lpSockaddr) {
            if let Some(ip) = T::try_from_with_filter(index, ip, addr.OnLinkPrefixLength, &mut f) {
              addresses.push(ip);
            }
          }
          unicast = addr.Next;
        }

        // TODO(al8n): Should we include anycast addresses?
        // let mut anycast = adapter.FirstAnycastAddress;
        // while let Some(addr) = anycast.as_ref() {
        //   if let Some(ip) = sockaddr_to_ipaddr(addr.Address.lpSockaddr) {
        //     let ip = IfNet::new(index, ip);
        //     addresses.push(ip);
        //   }
        //   anycast = addr.Next;
        // }
      }
    }
  }

  Ok(addresses)
}

pub(super) fn interface_multicast_ipv4_addresses<F>(
  idx: u32,
  mut f: F,
) -> io::Result<SmallVec<Ifv4Addr>>
where
  F: FnMut(&std::net::Ipv4Addr) -> bool,
{
  interface_multiaddr_table(AF_INET, idx, |addr| match addr {
    IpAddr::V4(ip) => f(ip),
    _ => false,
  })
}

pub(super) fn interface_multicast_ipv6_addresses<F>(
  idx: u32,
  mut f: F,
) -> io::Result<SmallVec<Ifv6Addr>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  interface_multiaddr_table(AF_INET6, idx, |addr| match addr {
    IpAddr::V6(ip) => f(ip),
    _ => false,
  })
}

pub(super) fn interface_multicast_addresses<F>(idx: u32, f: F) -> io::Result<SmallVec<IfAddr>>
where
  F: FnMut(&IpAddr) -> bool,
{
  interface_multiaddr_table(AF_UNSPEC, idx, f)
}

pub(super) fn interface_multiaddr_table<T, F>(
  family: u16,
  ifi: u32,
  mut f: F,
) -> io::Result<SmallVec<T>>
where
  T: Address,
  F: FnMut(&IpAddr) -> bool,
{
  let info = Information::fetch()?;
  let mut addresses = SmallVec::new();

  for adapter in info.adapters.iter() {
    let mut index = 0;
    let res = unsafe { ConvertInterfaceLuidToIndex(&adapter.Luid, &mut index) };
    if res == NO_ERROR {
      index = adapter.Ipv6IfIndex;
    }

    if ifi == 0 || ifi == index {
      let mut multicast = adapter.FirstMulticastAddress;
      unsafe {
        while let Some(addr) = multicast.as_ref() {
          if let Some(ip) = sockaddr_to_ipaddr(family, addr.Address.lpSockaddr) {
            if let Some(ip) = T::try_from_with_filter(index, ip, &mut f) {
              addresses.push(ip);
            }
          }
          multicast = addr.Next;
        }
      }
    }
  }

  Ok(addresses)
}

fn sockaddr_to_ipaddr(family: u16, sockaddr: *const SOCKADDR) -> Option<IpAddr> {
  if sockaddr.is_null() {
    return None;
  }

  unsafe {
    match (family, (*sockaddr).sa_family) {
      (AF_INET, AF_INET) | (AF_UNSPEC, AF_INET) => {
        let addr = sockaddr as *const SOCKADDR_IN;
        if addr.is_null() {
          return None;
        }
        let bytes = (*addr).sin_addr.S_un.S_addr.to_ne_bytes();
        Some(IpAddr::V4(bytes.into()))
      }
      (AF_INET6, AF_INET6) | (AF_UNSPEC, AF_INET6) => {
        let addr = sockaddr as *const SOCKADDR_IN6;
        if addr.is_null() {
          return None;
        }
        let bytes = (*addr).sin6_addr.u.Byte;
        Some(IpAddr::V6(bytes.into()))
      }
      _ => None,
    }
  }
}
