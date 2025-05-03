use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use smallvec_wrapper::SmallVec;

use super::{
  super::{ipv4_filter_to_ip_filter, ipv6_filter_to_ip_filter, local_ip_filter},
  interface_addresses, interface_ipv4_addresses, interface_ipv6_addresses, sockaddr_to_ipaddr,
  IfNet, IfOperStatusUp, Ifv4Net, Ifv6Net, Information, Net, NO_ERROR,
};

use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::*;

fn best_local_addrs_in<T: Net>(family: u16) -> io::Result<SmallVec<T>> {
  let info = Information::fetch()?;

  let mut addresses = SmallVec::new();

  // Iterate through adapters
  for adapter in info.adapters.iter() {
    // Only consider operational adapters
    if adapter.OperStatus == IfOperStatusUp {
      let mut index = 0;
      let res = unsafe { ConvertInterfaceLuidToIndex(&adapter.Luid, &mut index) };
      if res == NO_ERROR {
        index = adapter.Ipv6IfIndex;
      }

      // Check if this interface has a default route
      let has_default_route = unsafe {
        let table;
        let mut num_entries = 0u32;
        let result = GetIpForwardTable(std::ptr::null_mut(), &mut num_entries, 0);
        if result == ERROR_INSUFFICIENT_BUFFER {
          let mut buffer = vec![0u8; num_entries as usize];
          table = buffer.as_mut_ptr() as *mut MIB_IPFORWARDTABLE;
          if GetIpForwardTable(table, &mut num_entries, 0) == NO_ERROR {
            let table_ref = &*table;
            let rows = core::slice::from_raw_parts(
              &table_ref.table as *const _ as *const MIB_IPFORWARDROW,
              table_ref.dwNumEntries as usize,
            );
            // Look for a default route (0.0.0.0) on this interface
            rows
              .iter()
              .any(|route| route.dwForwardDest == 0 && route.dwForwardIfIndex == index)
          } else {
            false
          }
        } else {
          false
        }
      };

      if has_default_route {
        let mut unicast_address = adapter.FirstUnicastAddress;

        while !unicast_address.is_null() {
          let addr = unsafe { &*unicast_address };

          if let Some(ip) = sockaddr_to_ipaddr(family, addr.Address.lpSockaddr) {
            if let Some(ip) = T::try_from(index, ip, addr.OnLinkPrefixLength) {
              addresses.push(ip);
            }
          }

          unicast_address = addr.Next;
        }
      }
    }
  }

  Ok(addresses)
}

pub(crate) fn best_local_ipv4_addrs() -> io::Result<SmallVec<Ifv4Net>> {
  best_local_addrs_in(AF_INET)
}

pub(crate) fn best_local_ipv6_addrs() -> io::Result<SmallVec<Ifv6Net>> {
  best_local_addrs_in(AF_INET6)
}

pub(crate) fn best_local_addrs() -> io::Result<SmallVec<IfNet>> {
  best_local_addrs_in(AF_UNSPEC)
}

pub(crate) fn local_ipv4_addrs() -> io::Result<SmallVec<Ifv4Net>> {
  interface_ipv4_addresses(None, local_ip_filter)
}

pub(crate) fn local_ipv6_addrs() -> io::Result<SmallVec<Ifv6Net>> {
  interface_ipv6_addresses(None, local_ip_filter)
}

pub(crate) fn local_addrs() -> io::Result<SmallVec<IfNet>> {
  interface_addresses(None, local_ip_filter)
}

pub(crate) fn local_ipv4_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv4Net>>
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  let mut f = ipv4_filter_to_ip_filter(f);
  interface_ipv4_addresses(None, move |addr| f(addr) && local_ip_filter(addr))
}

pub(crate) fn local_ipv6_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv6Net>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  let mut f = ipv6_filter_to_ip_filter(f);
  interface_ipv6_addresses(None, move |addr| f(addr) && local_ip_filter(addr))
}

pub(crate) fn local_addrs_by_filter<F>(mut f: F) -> io::Result<SmallVec<IfNet>>
where
  F: FnMut(&IpAddr) -> bool,
{
  interface_addresses(None, |addr| f(addr) && local_ip_filter(addr))
}
