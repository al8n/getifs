use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use smallvec_wrapper::SmallVec;

use super::{
  super::{ipv4_filter_to_ip_filter, ipv6_filter_to_ip_filter, local_ip_filter},
  interface_addresses, interface_ipv4_addresses, interface_ipv6_addresses, IfNet, Ifv4Net, Ifv6Net,
  NO_ERROR,
};

use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::*;

/// Finds the `InterfaceIndex` of the default-route adapter with the
/// lowest `Metric` for the requested family, or `None` if no default
/// route exists for that family.
///
/// This replaces the previous `best_local_addrs_in` loop, which:
///   1. Only ever called `GetIpForwardTable` (IPv4-only), so
///      `best_local_ipv6_addrs` was driven by IPv4 routing state.
///   2. Re-read the forwarding table inside the adapter loop, causing
///      O(#adapters) redundant table fetches.
///   3. Accepted *any* `0.0.0.0` route without comparing metrics, so a
///      multi-homed host would emit addresses from every adapter that
///      had any default route — not "the best" as the docs promise.
fn best_default_route_interface(family: u16) -> io::Result<Option<u32>> {
  // SAFETY: `GetIpForwardTable2` writes a valid `*mut MIB_IPFORWARD_TABLE2`
  // into `table` on success; `FreeMibTable` is called via the guard below.
  unsafe {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let result = GetIpForwardTable2(family, &mut table);
    if result != NO_ERROR {
      return Err(io::Error::last_os_error());
    }

    // Defer the `FreeMibTable` call so we don't leak on any early
    // return below.
    struct TableGuard(*mut MIB_IPFORWARD_TABLE2);
    impl Drop for TableGuard {
      fn drop(&mut self) {
        if !self.0.is_null() {
          unsafe { FreeMibTable(self.0 as *mut _) }
        }
      }
    }
    let _guard = TableGuard(table);

    if table.is_null() {
      return Ok(None);
    }

    let t = &*table;
    let rows = core::slice::from_raw_parts(
      &t.Table as *const _ as *const MIB_IPFORWARD_ROW2,
      t.NumEntries as usize,
    );

    // Scan once, tracking the lowest-metric default route.
    // `PrefixLength == 0` on a `MIB_IPFORWARD_ROW2` identifies a
    // default route (0.0.0.0/0 or ::/0) regardless of family.
    let mut best: Option<(u32, u32)> = None; // (metric, interface_index)
    for route in rows {
      if route.DestinationPrefix.PrefixLength != 0 {
        continue;
      }
      match best {
        None => best = Some((route.Metric, route.InterfaceIndex)),
        Some((best_metric, _)) if route.Metric < best_metric => {
          best = Some((route.Metric, route.InterfaceIndex));
        }
        _ => {}
      }
    }
    Ok(best.map(|(_, idx)| idx))
  }
}

pub(crate) fn best_local_ipv4_addrs() -> io::Result<SmallVec<Ifv4Net>> {
  match best_default_route_interface(AF_INET)? {
    Some(idx) => interface_ipv4_addresses(Some(idx), local_ip_filter),
    None => Ok(SmallVec::new()),
  }
}

pub(crate) fn best_local_ipv6_addrs() -> io::Result<SmallVec<Ifv6Net>> {
  match best_default_route_interface(AF_INET6)? {
    Some(idx) => interface_ipv6_addresses(Some(idx), local_ip_filter),
    None => Ok(SmallVec::new()),
  }
}

pub(crate) fn best_local_addrs() -> io::Result<SmallVec<IfNet>> {
  // For the any-family variant, independently pick the best v4 and
  // best v6 default-route interface. This lets a dual-stack host with
  // different WAN/VPN egress per family surface the right addresses
  // for each — collapsing both into a single "best interface" would
  // arbitrarily drop one family's usable addresses.
  let mut result: SmallVec<IfNet> = SmallVec::new();
  if let Some(idx) = best_default_route_interface(AF_INET)? {
    let v4 = interface_ipv4_addresses(Some(idx), local_ip_filter)?;
    for a in v4 {
      result.push(a.into());
    }
  }
  if let Some(idx) = best_default_route_interface(AF_INET6)? {
    let v6 = interface_ipv6_addresses(Some(idx), local_ip_filter)?;
    for a in v6 {
      result.push(a.into());
    }
  }
  Ok(result)
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
