use smallvec_wrapper::SmallVec;
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_NOT_SUPPORTED};
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::*;

use crate::{ipv4_filter_to_ip_filter, ipv6_filter_to_ip_filter};

use super::{sockaddr_to_ipaddr, Address, IfAddr, Ifv4Addr, Ifv6Addr, NO_ERROR};

struct ForwardTable(*mut MIB_IPFORWARD_TABLE2);

impl ForwardTable {
  fn rows(&self) -> &[MIB_IPFORWARD_ROW2] {
    if self.0.is_null() {
      return &[];
    }
    // SAFETY: `GetIpForwardTable2` allocated this table, which remains
    // owned by `self` for the lifetime of the returned slice.
    unsafe {
      let table = &*self.0;
      core::slice::from_raw_parts(
        &table.Table as *const _ as *const MIB_IPFORWARD_ROW2,
        table.NumEntries as usize,
      )
    }
  }
}

impl Drop for ForwardTable {
  fn drop(&mut self) {
    if !self.0.is_null() {
      // SAFETY: this pointer came from a successful `GetIpForwardTable2`
      // call and this guard is its sole owner.
      unsafe { FreeMibTable(self.0 as _) };
    }
  }
}

#[inline]
fn family_status(status: u32) -> io::Result<bool> {
  match status {
    NO_ERROR => Ok(true),
    ERROR_NOT_FOUND | ERROR_NOT_SUPPORTED => Ok(false),
    status => Err(io::Error::from_raw_os_error(status as i32)),
  }
}

fn fetch_family(family: u16) -> io::Result<Option<ForwardTable>> {
  let mut table = std::ptr::null_mut();
  // SAFETY: `table` is a valid out-pointer. A successful allocation is
  // immediately transferred to the `ForwardTable` guard below.
  let status = unsafe { GetIpForwardTable2(family, &mut table) };
  if family_status(status)? {
    Ok(Some(ForwardTable(table)))
  } else {
    Ok(None)
  }
}

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
  // Multi-homed or multi-path Windows hosts can surface the same
  // gateway via several routes in the forwarding table. The previous
  // `!results.contains(&addr)` check was O(n²); dedup via a HashSet
  // keyed by `(index, IpAddr)` makes it O(1) per candidate, matching
  // the pattern already used on BSD (`src/bsd_like/rt_generic.rs`).
  let mut seen: HashSet<(u32, IpAddr)> = HashSet::new();

  // Query each requested family independently. `ERROR_NOT_FOUND` and
  // `ERROR_NOT_SUPPORTED` mean that family is empty/unavailable, so an
  // AF_UNSPEC query can still return the other stack's gateways.
  let table_v4 = if family == AF_INET || family == AF_UNSPEC {
    fetch_family(AF_INET)?
  } else {
    None
  };
  let table_v6 = if family == AF_INET6 || family == AF_UNSPEC {
    fetch_family(AF_INET6)?
  } else {
    None
  };

  if let Some(table) = table_v4.as_ref() {
    for route in table.rows() {
      // Check if route is up and has a gateway
      if route.ValidLifetime > 0 && !route.Loopback {
        if let Some(gateway) =
          sockaddr_to_ipaddr(family, &route.NextHop as *const _ as *const SOCKADDR)
        {
          // Skip default gateway (0.0.0.0)
          if let IpAddr::V4(addr) = gateway {
            if addr.octets() == [0, 0, 0, 0] {
              continue;
            }
          }

          // Apply filter and add to results if it passes
          if let Some(addr) = A::try_from_with_filter(route.InterfaceIndex, gateway, |addr| f(addr))
          {
            if seen.insert((addr.index(), addr.addr())) {
              results.push(addr);
            }
          }
        }
      }
    }
  }

  if let Some(table) = table_v6.as_ref() {
    for route in table.rows() {
      // Check if route is up and has a gateway
      if route.ValidLifetime > 0 && !route.Loopback {
        if let Some(gateway) =
          sockaddr_to_ipaddr(family, &route.NextHop as *const _ as *const SOCKADDR)
        {
          // Skip default gateway (::)
          if let IpAddr::V6(addr) = gateway {
            if addr.octets() == [0; 16] {
              continue;
            }
          }

          // Apply filter and add to results if it passes
          if let Some(addr) = A::try_from_with_filter(route.InterfaceIndex, gateway, |addr| f(addr))
          {
            if seen.insert((addr.index(), addr.addr())) {
              results.push(addr);
            }
          }
        }
      }
    }
  }

  Ok(results)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn unavailable_family_is_empty_without_hiding_the_other_stack() {
    let v4_available = family_status(NO_ERROR).unwrap();
    let v6_available = family_status(ERROR_NOT_SUPPORTED).unwrap();
    assert!(v4_available);
    assert!(!v6_available);

    assert!(!family_status(ERROR_NOT_FOUND).unwrap());
  }

  #[test]
  fn unexpected_family_status_preserves_the_returned_code() {
    let error = family_status(8).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(8));
  }
}
