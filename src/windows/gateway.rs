use smallvec_wrapper::SmallVec;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::*;

use crate::{ipv4_filter_to_ip_filter, ipv6_filter_to_ip_filter};

use super::{sockaddr_to_ipaddr, Address, IfAddr, Ifv4Addr, Ifv6Addr, NO_ERROR};

pub(crate) fn gateway_addrs() -> io::Result<SmallVec<IfAddr>> {
  gateway_addrs_in(AF_UNSPEC, |_| true)
}

pub(crate) fn gateway_ipv4_addrs() -> io::Result<SmallVec<Ifv4Addr>> {
  gateway_addrs_in(AF_INET, |_| true)
}

pub(crate) fn gateway_ipv6_addrs() -> io::Result<SmallVec<Ifv6Addr>> {
  gateway_addrs_in(AF_INET6, |_| true)
}

pub(crate) fn gateway_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<IfAddr>>
where
  F: FnMut(&IpAddr) -> bool,
{
  gateway_addrs_in(AF_UNSPEC, f)
}

pub(crate) fn gateway_ipv4_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv4Addr>>
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  gateway_addrs_in(AF_INET, ipv4_filter_to_ip_filter(f))
}

pub(crate) fn gateway_ipv6_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv6Addr>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  gateway_addrs_in(AF_INET6, ipv6_filter_to_ip_filter(f))
}

pub(crate) fn gateway_addrs_in<A, F>(family: u16, mut f: F) -> io::Result<SmallVec<A>>
where
  A: Address + Eq,
  F: FnMut(&IpAddr) -> bool,
{
  let mut results = SmallVec::new();

  unsafe {
    // Get the forward table for both IPv4 and IPv6
    let mut table_v4 = std::ptr::null_mut();
    let mut table_v6 = std::ptr::null_mut();

    // Initialize the tables based on the requested address family
    if family == AF_INET || family == AF_UNSPEC {
      if GetIpForwardTable2(AF_INET as u16, &mut table_v4) != NO_ERROR {
        return Err(io::Error::last_os_error());
      }
    }

    if family == AF_INET6 || family == AF_UNSPEC {
      if GetIpForwardTable2(AF_INET6 as u16, &mut table_v6) != NO_ERROR {
        if !table_v4.is_null() {
          FreeMibTable(table_v4 as _);
        }
        return Err(io::Error::last_os_error());
      }
    }

    // Cleanup guard using defer pattern
    struct TableGuard(*const MIB_IPFORWARD_TABLE2);

    impl Drop for TableGuard {
      fn drop(&mut self) {
        if !self.0.is_null() {
          unsafe {
            FreeMibTable(self.0 as *mut _);
          }
        }
      }
    }

    let _guard_v4 = TableGuard(table_v4);
    let _guard_v6 = TableGuard(table_v6);

    // Process IPv4 routes
    if !table_v4.is_null() {
      let table = &*table_v4;
      for i in 0..table.NumEntries {
        let route = &table.Table[i as usize];

        // Check if route is up and has a gateway
        if route.Route.State == IF_OPER_STATUS_OPERATIONAL as u32 {
          if let Some(gateway) = sockaddr_to_ipaddr(family, (&route.NextHop) as _) {
            // Skip default gateway (0.0.0.0)
            if let IpAddr::V4(addr) = gateway {
              if addr.octets() == [0, 0, 0, 0] {
                continue;
              }
            }

            // Apply filter and add to results if it passes
            if let Some(addr) =
              A::try_from_with_filter(route.InterfaceIndex, gateway, |addr| f(addr))
            {
              if !results.contains(&addr) {
                results.push(addr);
              }
            }
          }
        }
      }
    }

    // Process IPv6 routes
    if !table_v6.is_null() {
      let table = &*table_v6;
      for i in 0..table.NumEntries {
        let route = &table.Table[i as usize];

        // Check if route is up and has a gateway
        if route.Route.State == IF_OPER_STATUS_OPERATIONAL as u32 {
          if let Some(gateway) = sockaddr_to_ipaddr(family, (&route.NextHop) as _) {
            // Skip default gateway (::)
            if let IpAddr::V6(addr) = gateway {
              if addr.octets() == [0; 16] {
                continue;
              }
            }

            // Apply filter and add to results if it passes
            if let Some(addr) =
              A::try_from_with_filter(route.InterfaceIndex, gateway, |addr| f(addr))
            {
              if !results.contains(&addr) {
                results.push(addr);
              }
            }
          }
        }
      }
    }
  }

  Ok(results)
}
