use std::{
  io::{self, Error, Result},
  marker::PhantomData,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use smallvec_wrapper::{SmallVec, TinyVec};
use windows_sys::{
  Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR},
  Win32::NetworkManagement::{IpHelper::*, Ndis::*},
  Win32::Networking::WinSock::*,
};

use super::{
  Address, IfAddr, IfNet, Ifv4Addr, Ifv4Net, Ifv6Addr, Ifv6Net, Interface, MacAddr, Net,
  MAC_ADDRESS_SIZE,
};

pub(super) use gateway::*;
pub(super) use local_addr::*;

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
  // The kernel writes a null-terminated singly-linked list of
  // `IP_ADAPTER_ADDRESSES_LH` records into this buffer, with every
  // `Next`/`FirstUnicastAddress`/`FriendlyName`/… pointer aimed back
  // into it. We keep the buffer alive and walk the list via an
  // iterator — no per-adapter copy.
  //
  // Backing type is `Vec<u64>` rather than `Vec<u8>` so that the
  // pointer cast to `*mut IP_ADAPTER_ADDRESSES_LH` is guaranteed
  // 8-byte aligned. `Vec<u8>` only guarantees 1-byte alignment, and
  // dereferencing a misaligned `IP_ADAPTER_ADDRESSES_LH` is UB in
  // Rust — even though every real-world allocator happens to return
  // a 16-byte-aligned block for small Vecs, Rust's safety model
  // doesn't let us rely on that.
  buffer: Vec<u64>,
}

/// Bytes per `u64` element in the backing buffer.
const BYTES_PER_U64: usize = core::mem::size_of::<u64>();

/// Round a byte count up to a whole number of `u64` elements.
#[inline]
fn u64_len(size_bytes: u32) -> usize {
  (size_bytes as usize + BYTES_PER_U64 - 1) / BYTES_PER_U64
}

impl Information {
  fn fetch() -> Result<Self> {
    let mut size = 15000u32; // recommended initial size

    let mut buffer: Vec<u64> = vec![0; u64_len(size)];
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
          return Ok(Self { buffer: Vec::new() });
        }
        break;
      }

      if result != ERROR_BUFFER_OVERFLOW {
        return Err(Error::last_os_error());
      }

      // `size` is in bytes; compare against the byte capacity of
      // the u64-backed buffer.
      if (size as usize) <= buffer.len() * BYTES_PER_U64 {
        return Err(Error::last_os_error());
      }
      buffer.resize(u64_len(size), 0);
    }

    Ok(Self { buffer })
  }

  /// Iterate over the native adapter linked list in-place, without
  /// copying the (~400-byte) `IP_ADAPTER_ADDRESSES_LH` records.
  ///
  /// Each yielded reference borrows from `self.buffer`, so the iterator
  /// (and any pointer fields read from its items) must not outlive
  /// this `Information`.
  fn iter(&self) -> AdapterIter<'_> {
    let head = if self.buffer.is_empty() {
      std::ptr::null()
    } else {
      self.buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH
    };
    AdapterIter {
      current: head,
      _marker: PhantomData,
    }
  }
}

struct AdapterIter<'a> {
  current: *const IP_ADAPTER_ADDRESSES_LH,
  _marker: PhantomData<&'a IP_ADAPTER_ADDRESSES_LH>,
}

impl<'a> Iterator for AdapterIter<'a> {
  type Item = &'a IP_ADAPTER_ADDRESSES_LH;

  fn next(&mut self) -> Option<Self::Item> {
    // SAFETY: `current` is either null, or a pointer into the buffer
    // of the `Information` whose lifetime this iterator borrows. The
    // kernel produced a null-terminated singly-linked list of these
    // structs in that buffer.
    unsafe {
      let curr = self.current.as_ref()?;
      self.current = curr.Next;
      Some(curr)
    }
  }
}

/// Resolves the interface index for a Windows adapter.
///
/// Mirrors Go's `net/interface_windows.go`: prefer the LUID-derived
/// index, fall back to `Ipv6IfIndex` only when the conversion fails.
fn adapter_index(adapter: &IP_ADAPTER_ADDRESSES_LH) -> u32 {
  let mut index = 0u32;
  // SAFETY: `adapter.Luid` is a kernel-populated LUID; `index` is a
  // writable local `u32`.
  let res = unsafe { ConvertInterfaceLuidToIndex(&adapter.Luid, &mut index) };
  if res != NO_ERROR {
    index = adapter.Ipv6IfIndex;
  }
  index
}

pub(super) fn interface_table(idx: Option<u32>) -> io::Result<TinyVec<Interface>> {
  let info = Information::fetch()?;
  let mut interfaces = TinyVec::new();

  for adapter in info.iter() {
    let index = adapter_index(adapter);

    if let Some(idx) = idx {
      if idx == index {
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
          Some(MacAddr::from_raw(buf))
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

        interfaces.push(interface);
        break;
      }
    } else {
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
        Some(MacAddr::from_raw(buf))
      } else {
        None
      };

      interfaces.push(Interface {
        index,
        name,
        flags,
        mtu,
        mac_addr: hardware_addr,
      });
    }
  }

  Ok(interfaces)
}

pub(super) fn interface_ipv4_addresses<F>(idx: Option<u32>, f: F) -> io::Result<SmallVec<Ifv4Net>>
where
  F: FnMut(&IpAddr) -> bool,
{
  interface_addr_table(AF_INET, idx, f)
}

pub(super) fn interface_ipv6_addresses<F>(idx: Option<u32>, f: F) -> io::Result<SmallVec<Ifv6Net>>
where
  F: FnMut(&IpAddr) -> bool,
{
  interface_addr_table(AF_INET6, idx, f)
}

pub(super) fn interface_addresses<F>(idx: Option<u32>, f: F) -> io::Result<SmallVec<IfNet>>
where
  F: FnMut(&IpAddr) -> bool,
{
  interface_addr_table(AF_UNSPEC, idx, f)
}

pub(super) fn interface_addr_table<T, F>(
  family: u16,
  ifi: Option<u32>,
  mut f: F,
) -> io::Result<SmallVec<T>>
where
  T: Net,
  F: FnMut(&IpAddr) -> bool,
{
  let info = Information::fetch()?;
  let mut addresses = SmallVec::new();

  for adapter in info.iter() {
    let index = adapter_index(adapter);

    if let Some(ifi) = ifi {
      if ifi == index {
        unsafe {
          let mut unicast = adapter.FirstUnicastAddress;
          while let Some(addr) = unicast.as_ref() {
            if let Some(ip) = sockaddr_to_ipaddr(family, addr.Address.lpSockaddr) {
              if let Some(ip) = T::try_from_with_filter(index, ip, addr.OnLinkPrefixLength, &mut f)
              {
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
    } else {
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
  idx: Option<u32>,
  mut f: F,
) -> io::Result<SmallVec<Ifv4Addr>>
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  interface_multiaddr_table(AF_INET, idx, |addr| match addr {
    IpAddr::V4(ip) => f(ip),
    _ => false,
  })
}

pub(super) fn interface_multicast_ipv6_addresses<F>(
  idx: Option<u32>,
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

pub(super) fn interface_multicast_addresses<F>(
  idx: Option<u32>,
  f: F,
) -> io::Result<SmallVec<IfAddr>>
where
  F: FnMut(&IpAddr) -> bool,
{
  interface_multiaddr_table(AF_UNSPEC, idx, f)
}

pub(super) fn interface_multiaddr_table<T, F>(
  family: u16,
  ifi: Option<u32>,
  mut f: F,
) -> io::Result<SmallVec<T>>
where
  T: Address,
  F: FnMut(&IpAddr) -> bool,
{
  let info = Information::fetch()?;
  let mut addresses = SmallVec::new();

  for adapter in info.iter() {
    let index = adapter_index(adapter);

    if let Some(ifi) = ifi {
      if ifi == index {
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
    } else {
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
