use smallvec_wrapper::SmallVec;
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows_sys::Win32::Networking::WinSock::*;

use crate::{ipv4_filter_to_ip_filter, ipv6_filter_to_ip_filter};

use super::{mib::forward_table, sockaddr_to_ipaddr, Address, IfAddr, Ifv4Addr, Ifv6Addr};

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
  // gateway via several routes in the forwarding table. Dedup via a
  // HashSet keyed by `(index, IpAddr)` is an O(1) check per candidate,
  // where scanning `results` would be O(n²). The BSD walker
  // (`src/bsd_like/rt_generic.rs`) dedups the same way.
  let mut seen: HashSet<(u32, IpAddr)> = HashSet::new();

  // Query each requested family independently. `forward_table` reports
  // an empty or absent stack as `None`, so an AF_UNSPEC query can still
  // return the other stack's gateways.
  let table_v4 = if family == AF_INET || family == AF_UNSPEC {
    forward_table(AF_INET)?
  } else {
    None
  };
  let table_v6 = if family == AF_INET6 || family == AF_UNSPEC {
    forward_table(AF_INET6)?
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
