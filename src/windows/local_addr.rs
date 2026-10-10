use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use smallvec_wrapper::SmallVec;

use super::{
  super::{ipv4_filter_to_ip_filter, ipv6_filter_to_ip_filter, local_ip_filter},
  interface_addresses, interface_ipv4_addresses, interface_ipv6_addresses,
  mib::OwnedMibTable,
  IfNet, Ifv4Net, Ifv6Net,
};

use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::*;

/// Finds every `InterfaceIndex` that ties at the best (smallest)
/// effective metric for the requested family's default route, or an
/// empty `SmallVec` if no usable default exists. Plural return is
/// deliberate: Windows does install equal-cost defaults (multi-homed
/// hosts, ECMP-style WAN bonding), and a single-`Option` return would
/// silently drop every interface past the first one in
/// `GetIpForwardTable2` order. Mirrors the Linux/BSD `best_oifs`
/// pattern so all three platforms behave consistently when a metric
/// tie exists.
///
/// Walks `GetIpForwardTable2` for `PrefixLength == 0` rows with
/// `ValidLifetime > 0 && !Loopback`, then picks the row with the
/// smallest *effective* metric (route metric + interface metric — the
/// sum the Windows TCP/IP stack itself uses for routing decisions).
/// Joining the interface metric matters on multi-homed hosts where a
/// low-route-metric default sits on a high-cost interface (Wi-Fi
/// behind a cellular fallback, for example) — comparing on
/// `route.Metric` alone would silently misorder them. Rows on an
/// interface that is not `Connected` (or is absent from
/// `GetIpInterfaceTable`) are skipped.
///
/// This walks the forwarding table instead of asking `GetBestRoute2`
/// or `GetBestInterfaceEx` for the best route to the unspecified
/// address, which is outside the documented contracts of both APIs:
/// `GetBestRoute2` requires both the destination AND at least one
/// interface selector to be initialized
/// (https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getbestroute2),
/// and `GetBestInterfaceEx` is documented as "interface with the best
/// route to the *specified* IPv4 or IPv6 address"
/// (https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getbestinterfaceex)
/// — `0.0.0.0` / `::` is an unspecified address, not a documented
/// "give me the default" sentinel. Both calls happen to work on
/// shipping Windows, but neither is guaranteed by its API contract.
/// The forwarding-table walk asks the only question Windows answers
/// unambiguously — "which routes have `/0`?" — and applies the same
/// effective-metric tie-break the kernel uses.
fn best_default_route_interfaces(family: u16) -> io::Result<SmallVec<u32>> {
  // SAFETY: `GetIpForwardTable2` is an IP Helper table getter.
  let forward = match unsafe { OwnedMibTable::fetch(|table| GetIpForwardTable2(family, table)) } {
    Ok(table) => table,
    Err(status) => return classify_table_error(status),
  };

  // SAFETY: `GetIpInterfaceTable` is an IP Helper table getter.
  let interfaces = match unsafe { OwnedMibTable::fetch(|table| GetIpInterfaceTable(family, table)) }
  {
    Ok(table) => table,
    Err(status) => return classify_table_error(status),
  };

  Ok(select_best_default_route_interfaces(
    forward.rows(),
    interfaces.rows(),
  ))
}

fn select_best_default_route_interfaces(
  forward: &[MIB_IPFORWARD_ROW2],
  interfaces: &[MIB_IPINTERFACE_ROW],
) -> SmallVec<u32> {
  // Per-interface state: `(metric, connected)`. We need both —
  // metric for effective-route ranking, `Connected` to drop routes
  // pinned to admin-down / unplugged adapters that the Windows
  // forwarding table can still hold (a static default for a VPN
  // interface that's currently disconnected, for example). Without
  // this filter, such a stale route can win the metric race and
  // make `best_local_*` return addresses on an interface the
  // kernel won't use for outbound traffic.
  let mut iface_state: std::collections::HashMap<u32, (u32, bool)> =
    std::collections::HashMap::new();
  for r in interfaces {
    if r.InterfaceIndex != 0 {
      iface_state.insert(r.InterfaceIndex, (r.Metric, r.Connected));
    }
  }

  let mut best_eff: u64 = u64::MAX;
  let mut best_oifs: SmallVec<u32> = SmallVec::new();
  for row in forward {
    if row.InterfaceIndex == 0 || row.DestinationPrefix.PrefixLength != 0 {
      continue;
    }
    if row.ValidLifetime == 0 || row.Loopback {
      continue;
    }
    // Drop candidates whose interface is either absent from the
    // IP-interface table (kernel state divergence) or marked
    // `Connected = FALSE` (link down / admin disabled). The
    // kernel won't use such a route for outbound traffic, so
    // selecting it here would hand back addresses on an
    // unusable adapter.
    let if_m = match iface_state.get(&row.InterfaceIndex) {
      Some(&(metric, connected)) if connected => metric as u64,
      _ => continue,
    };
    // Effective metric per Microsoft's documented routing model:
    // the kernel sums route metric + interface metric and picks
    // the row with the smallest sum. Promote to u64 so the
    // addition can't wrap on a pathological u32+u32.
    let eff = row.Metric as u64 + if_m;
    // Strict-less wins resets the candidate set; an equal eff
    // extends it (multi-homed Windows hosts can install
    // equal-cost defaults across two adapters). Same `<` / `==`
    // shape as the Linux / BSD walkers.
    if eff < best_eff {
      best_eff = eff;
      best_oifs.clear();
      best_oifs.push(row.InterfaceIndex);
    } else if eff == best_eff {
      best_oifs.push(row.InterfaceIndex);
    }
  }

  // Sort + dedup so two default routes on one interface (equal-cost next
  // hops, or duplicate kernel rows during a churn window) don't make us walk
  // the address table twice for the same ifindex.
  best_oifs.sort_unstable();
  best_oifs.dedup();

  best_oifs
}

pub(crate) fn default_ipv4_interface_indices() -> io::Result<SmallVec<u32>> {
  best_default_route_interfaces(AF_INET)
}

pub(crate) fn default_ipv6_interface_indices() -> io::Result<SmallVec<u32>> {
  best_default_route_interfaces(AF_INET6)
}

/// Map a `MIB`-table fetch failure: known "no stack / no entries"
/// codes collapse to `Ok(empty)`, anything else propagates as the
/// concrete syscall error, so single-stack hosts surface their
/// populated family instead of `Err`. This is a superset of
/// `mib::forward_table`'s empty-family statuses: it also treats
/// `ERROR_NETWORK_UNREACHABLE` as empty.
#[inline]
fn classify_table_error(code: u32) -> io::Result<SmallVec<u32>> {
  // ERROR_NOT_SUPPORTED (50): IP stack for this family not installed.
  // ERROR_NOT_FOUND (1168): no entries for this family.
  // ERROR_NETWORK_UNREACHABLE (1231): destination unreachable.
  const ERROR_NOT_SUPPORTED: u32 = 50;
  const ERROR_NOT_FOUND: u32 = 1168;
  const ERROR_NETWORK_UNREACHABLE: u32 = 1231;
  match code {
    ERROR_NOT_SUPPORTED | ERROR_NOT_FOUND | ERROR_NETWORK_UNREACHABLE => Ok(SmallVec::new()),
    _ => Err(io::Error::from_raw_os_error(code as i32)),
  }
}

pub(crate) fn best_local_ipv4_addrs() -> io::Result<SmallVec<Ifv4Net>> {
  let mut out: SmallVec<Ifv4Net> = SmallVec::new();
  for idx in best_default_route_interfaces(AF_INET)? {
    let v4 = interface_ipv4_addresses(Some(idx), local_ip_filter)?;
    for a in v4 {
      out.push(a);
    }
  }
  Ok(out)
}

pub(crate) fn best_local_ipv6_addrs() -> io::Result<SmallVec<Ifv6Net>> {
  let mut out: SmallVec<Ifv6Net> = SmallVec::new();
  for idx in best_default_route_interfaces(AF_INET6)? {
    let v6 = interface_ipv6_addresses(Some(idx), local_ip_filter)?;
    for a in v6 {
      out.push(a);
    }
  }
  Ok(out)
}

pub(crate) fn best_local_addrs() -> io::Result<SmallVec<IfNet>> {
  // For the any-family variant, independently pick the best v4 and
  // best v6 default-route interfaces. This lets a dual-stack host
  // with different WAN/VPN egress per family surface the right
  // addresses for each — collapsing both into a single "best
  // interface" would arbitrarily drop one family's usable addresses.
  let mut result: SmallVec<IfNet> = SmallVec::new();
  for idx in best_default_route_interfaces(AF_INET)? {
    let v4 = interface_ipv4_addresses(Some(idx), local_ip_filter)?;
    for a in v4 {
      result.push(a.into());
    }
  }
  for idx in best_default_route_interfaces(AF_INET6)? {
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

#[cfg(test)]
mod tests {
  use super::*;

  fn interface(index: u32, metric: u32, connected: bool) -> MIB_IPINTERFACE_ROW {
    MIB_IPINTERFACE_ROW {
      InterfaceIndex: index,
      Metric: metric,
      Connected: connected,
      ..Default::default()
    }
  }

  fn route(
    index: u32,
    metric: u32,
    prefix_len: u8,
    valid_lifetime: u32,
    loopback: bool,
  ) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2 {
      InterfaceIndex: index,
      Metric: metric,
      ValidLifetime: valid_lifetime,
      Loopback: loopback,
      ..Default::default()
    };
    row.DestinationPrefix.PrefixLength = prefix_len;
    row
  }

  #[test]
  fn selector_keeps_every_equal_best_nonzero_interface() {
    let interfaces = [
      interface(4, 10, true),
      interface(2, 20, true),
      interface(0, 0, true),
      interface(9, 0, false),
    ];
    let routes = [
      route(4, 20, 0, 1, false),
      route(2, 10, 0, 1, false),
      route(4, 20, 0, 1, false),
      route(0, 0, 0, 1, false),
      route(9, 0, 0, 1, false),
      route(8, 0, 0, 1, false),
      route(4, 0, 24, 1, false),
      route(4, 0, 0, 0, false),
      route(4, 0, 0, 1, true),
    ];

    assert_eq!(
      select_best_default_route_interfaces(&routes, &interfaces).as_slice(),
      &[2, 4]
    );
  }

  #[test]
  fn selector_returns_empty_without_a_usable_route() {
    assert!(select_best_default_route_interfaces(&[], &[]).is_empty());
    assert!(select_best_default_route_interfaces(
      &[route(7, 0, 0, 1, false)],
      &[interface(7, 0, false)]
    )
    .is_empty());
  }

  // Pure-function unit test for `classify_table_error`. Covers
  // every arm of the whitelist match plus the catch-all error
  // path, which a live run reaches only when a Win32 table API
  // actually fails on the host.
  #[test]
  fn classify_table_error_whitelist_returns_empty() {
    for code in [50u32, 1168u32, 1231u32] {
      let r = classify_table_error(code).unwrap();
      assert!(r.is_empty(), "expected empty result for whitelisted {code}");
    }
  }

  #[test]
  fn classify_table_error_unknown_propagates() {
    let r = classify_table_error(0xDEAD);
    assert!(r.is_err());
    assert_eq!(r.unwrap_err().raw_os_error(), Some(0xDEAD));
  }
}
