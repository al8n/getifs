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

/// Finds the `InterfaceIndex` of the adapter that the kernel would use
/// to reach the unspecified address of the requested family, or `None`
/// if no route is available for that family.
///
/// Defers to `GetBestRoute2` rather than scanning `MIB_IPFORWARD_TABLE2`
/// ourselves: the kernel's selection is the **effective** metric (route
/// metric + interface metric — not just `MIB_IPFORWARD_ROW2.Metric`)
/// and also rejects unusable rows (loopback / dead / disabled), which
/// matches Windows' own outbound interface selection. Querying the
/// table and comparing only `route.Metric` would mis-order multi-homed
/// hosts where a low-route-metric route lives on a high-cost interface.
///
/// History: an earlier revision scanned `MIB_IPFORWARD_TABLE2` and
/// picked the lowest `route.Metric`; before that, `best_local_addrs_in`
/// fetched the legacy IPv4-only `GetIpForwardTable` *per adapter* and
/// accepted any default route. This is the version that actually models
/// what Windows does.
fn best_default_route_interface(family: u16) -> io::Result<Option<u32>> {
  // SAFETY: We hand `GetBestRoute2` a zero-initialised `SOCKADDR_INET`
  // with `si_family` set to the requested family, which the kernel
  // reads as `0.0.0.0:0` or `[::]:0` — the canonical "default-route"
  // destination. All output buffers are kernel-writable locals.
  unsafe {
    let mut destination: SOCKADDR_INET = std::mem::zeroed();
    destination.si_family = family;

    let mut best_route: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
    let mut best_source: SOCKADDR_INET = std::mem::zeroed();

    let result = GetBestRoute2(
      std::ptr::null(), // InterfaceLuid: let kernel choose
      0,                // InterfaceIndex: let kernel choose
      std::ptr::null(), // SourceAddress: let kernel choose
      &destination,
      0, // AddressSortOptions
      &mut best_route,
      &mut best_source,
    );

    if result != NO_ERROR {
      // ERROR_NETWORK_UNREACHABLE / ERROR_NOT_FOUND etc. — there's no
      // route to the unspecified destination, e.g. no IPv6 default
      // route on a v4-only host. Treat as "no best interface" rather
      // than surfacing as an `io::Error` to callers.
      return Ok(None);
    }

    Ok(Some(best_route.InterfaceIndex))
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
