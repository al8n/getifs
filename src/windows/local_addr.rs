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
/// Uses [`GetBestInterfaceEx`], which takes only a destination address
/// and returns the best interface index directly. We previously called
/// `GetBestRoute2(NULL, 0, NULL, &dest, ...)` and let the kernel pick
/// — that worked in practice on shipping Windows but the documented
/// contract for `GetBestRoute2` is "DestinationAddress must be
/// initialized AND at least one of InterfaceLuid or InterfaceIndex
/// must be initialized" (see
/// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getbestroute2).
/// `GetBestInterfaceEx` is the right shape for "given a destination,
/// which interface would route there?" — no required interface
/// selector, no source address, no `MIB_IPFORWARD_ROW2` we don't use.
///
/// The kernel still applies effective metric (route metric + interface
/// metric) and rejects unusable rows (loopback / dead / disabled),
/// which is what Windows itself does for outbound traffic.
///
/// History: earlier revisions scanned `MIB_IPFORWARD_TABLE2` and
/// compared only `route.Metric` (mis-ordered multi-homed hosts with a
/// low-route-metric route on a high-cost interface). Then we moved to
/// `GetBestRoute2`. Now we use `GetBestInterfaceEx` to satisfy the
/// documented input contract without losing the metric correctness.
fn best_default_route_interface(family: u16) -> io::Result<Option<u32>> {
  // SAFETY: We zero-initialise a `SOCKADDR_INET`, set its family, and
  // hand its address as a `*const SOCKADDR` (matching the standard
  // Windows pattern of treating `SOCKADDR_INET` as a tagged union of
  // `sockaddr_in` / `sockaddr_in6`). `GetBestInterfaceEx` writes
  // back the best interface index into a stack u32.
  unsafe {
    let mut destination: SOCKADDR_INET = std::mem::zeroed();
    destination.si_family = family;

    let mut best_ifindex: u32 = 0;
    let result = GetBestInterfaceEx(
      &destination as *const SOCKADDR_INET as *const SOCKADDR,
      &mut best_ifindex,
    );

    if result != NO_ERROR {
      // Whitelist the "no route to that destination on this host"
      // codes as legitimate `Ok(None)`. Anything else (allocation
      // failure, invalid parameter, network-stack failure) is a real
      // syscall error the caller deserves to see; collapsing it
      // would make `best_local_*` indistinguishable from "host has
      // no default route" and mask real platform failures.
      //
      //   - `ERROR_NOT_FOUND` (1168): no default route for the
      //     requested family on this host.
      //   - `ERROR_NETWORK_UNREACHABLE` (1231): destination
      //     unreachable through any installed route.
      //   - `ERROR_NOT_SUPPORTED` (50): the IP stack for the
      //     requested family isn't installed at all. Without this
      //     whitelist, `best_local_addrs()` would discard a
      //     perfectly-good IPv4 result if the v6 probe failed
      //     because there's no v6 stack — the union API has to
      //     accept that absence.
      const ERROR_NOT_SUPPORTED: i32 = 50;
      const ERROR_NOT_FOUND: i32 = 1168;
      const ERROR_NETWORK_UNREACHABLE: i32 = 1231;
      let code = result as i32;
      if code == ERROR_NOT_FOUND || code == ERROR_NETWORK_UNREACHABLE || code == ERROR_NOT_SUPPORTED
      {
        return Ok(None);
      }
      return Err(io::Error::from_raw_os_error(code));
    }

    Ok(Some(best_ifindex))
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
