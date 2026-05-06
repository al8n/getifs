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

/// Finds every `InterfaceIndex` that ties at the best (smallest)
/// effective metric for the requested family's default route, or an
/// empty `SmallVec` if no usable default exists. Plural return is
/// deliberate: Windows does install equal-cost defaults (multi-homed
/// hosts, ECMP-style WAN bonding), and the previous single-`Option`
/// shape silently dropped every interface past the first one in
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
/// `route.Metric` alone would silently misorder them.
///
/// History: earlier revisions of this code used `GetBestRoute2(NULL,
/// 0, NULL, &dest, ...)` and then `GetBestInterfaceEx(&zero_dest,
/// ...)`. Both queries — passing the unspecified address as a
/// destination — are outside the documented contracts of those APIs:
/// `GetBestRoute2` requires both the destination AND at least one
/// interface selector to be initialized
/// (https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getbestroute2),
/// and `GetBestInterfaceEx` is documented as "interface with the best
/// route to the *specified* IPv4 or IPv6 address"
/// (https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getbestinterfaceex)
/// — `0.0.0.0` / `::` is an unspecified address, not a documented
/// "give me the default" sentinel. Both happened to work on shipping
/// Windows, but neither is guaranteed by the API contract. The
/// forwarding-table walk is the right shape: it asks the only
/// question Windows answers unambiguously — "which routes have
/// `/0`?" — and applies the same effective-metric tie-break the
/// kernel uses.
fn best_default_route_interface(family: u16) -> io::Result<SmallVec<u32>> {
  // SAFETY: All three calls below allocate kernel-side tables that we
  // free via `FreeMibTable` in `Drop`. We treat each row through a
  // `&MIB_IPFORWARD_ROW2` / `&MIB_IPINTERFACE_ROW` reference into the
  // table's storage; the table lives until the guard drops at end of
  // scope, so no row reference outlives its backing memory.
  unsafe {
    let mut forward_ptr: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let r = GetIpForwardTable2(family, &mut forward_ptr);
    if r != NO_ERROR {
      return classify_table_error(r);
    }
    struct ForwardGuard(*mut MIB_IPFORWARD_TABLE2);
    impl Drop for ForwardGuard {
      fn drop(&mut self) {
        if !self.0.is_null() {
          unsafe { FreeMibTable(self.0 as *mut _) };
        }
      }
    }
    let _g1 = ForwardGuard(forward_ptr);

    // Build (InterfaceIndex -> Metric) for `family` so we can fold
    // the per-interface metric into each candidate row's effective
    // metric. Missing rows fall back to 0 — that matches what the
    // kernel does on interfaces without an explicit metric.
    let mut iface_ptr: *mut MIB_IPINTERFACE_TABLE = std::ptr::null_mut();
    let r2 = GetIpInterfaceTable(family, &mut iface_ptr);
    if r2 != NO_ERROR {
      return classify_table_error(r2);
    }
    struct IfaceGuard(*mut MIB_IPINTERFACE_TABLE);
    impl Drop for IfaceGuard {
      fn drop(&mut self) {
        if !self.0.is_null() {
          unsafe { FreeMibTable(self.0 as *mut _) };
        }
      }
    }
    let _g2 = IfaceGuard(iface_ptr);

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
    if !iface_ptr.is_null() {
      let it = &*iface_ptr;
      let rows = core::slice::from_raw_parts(
        &it.Table as *const _ as *const MIB_IPINTERFACE_ROW,
        it.NumEntries as usize,
      );
      for r in rows {
        iface_state.insert(r.InterfaceIndex, (r.Metric, r.Connected));
      }
    }

    let mut best_eff: u64 = u64::MAX;
    let mut best_oifs: SmallVec<u32> = SmallVec::new();
    if !forward_ptr.is_null() {
      let ft = &*forward_ptr;
      let rows = core::slice::from_raw_parts(
        &ft.Table as *const _ as *const MIB_IPFORWARD_ROW2,
        ft.NumEntries as usize,
      );
      for row in rows {
        if row.DestinationPrefix.PrefixLength != 0 {
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
    }

    // Sort + dedup so two route rows that share an interface index
    // (e.g. one v4 and one v6 default both pinned to the same
    // adapter, or duplicate kernel rows during a churn window) don't
    // make us walk the address table twice for the same ifindex.
    best_oifs.sort_unstable();
    best_oifs.dedup();

    Ok(best_oifs)
  }
}

/// Map a `MIB`-table fetch failure: known "no stack / no entries"
/// codes collapse to `Ok(empty)`, anything else propagates as the
/// concrete syscall error. Same whitelist `windows/route.rs` and
/// `windows/gateway.rs` use so single-stack hosts surface their
/// populated family instead of `Err`.
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
  for idx in best_default_route_interface(AF_INET)? {
    let v4 = interface_ipv4_addresses(Some(idx), local_ip_filter)?;
    for a in v4 {
      out.push(a);
    }
  }
  Ok(out)
}

pub(crate) fn best_local_ipv6_addrs() -> io::Result<SmallVec<Ifv6Net>> {
  let mut out: SmallVec<Ifv6Net> = SmallVec::new();
  for idx in best_default_route_interface(AF_INET6)? {
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
  for idx in best_default_route_interface(AF_INET)? {
    let v4 = interface_ipv4_addresses(Some(idx), local_ip_filter)?;
    for a in v4 {
      result.push(a.into());
    }
  }
  for idx in best_default_route_interface(AF_INET6)? {
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

  // Pure-function unit test for `classify_table_error`. Covers
  // every arm of the whitelist match plus the catch-all error
  // path. Live tarpaulin runs only ever hit this when a Win32
  // table API actually fails on the host, so the branches stayed
  // uncovered.
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
