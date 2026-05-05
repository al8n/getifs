use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};
use smallvec_wrapper::SmallVec;
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::*;

use super::{sockaddr_to_ipaddr, IpRoute, Ipv4Route, Ipv6Route, NO_ERROR};

/// `GetIpForwardTable2` returns this when the requested family has no
/// route entries (e.g. IPv6 stack present but no IPv6 routes
/// installed, or a single-stack v4 host). It's the only error code we
/// treat as "this family is just empty" in the union API; everything
/// else propagates so allocation/parameter failures aren't masked.
const ERROR_NOT_FOUND: i32 = 1168;
// `GetIpForwardTable2` returns `ERROR_NOT_SUPPORTED` (50) when the
// requested IPv4 / IPv6 stack isn't installed on the host — a v4-only
// box configured without an IPv6 stack, for example. Per Microsoft
// docs that's the same "no entries for this family" state we already
// surface for `ERROR_NOT_FOUND`, just signalled differently. Without
// this whitelist, `route_ipv6_table()` would return a hard error and
// the union `route_table()` would lose the populated v4 routes.
const ERROR_NOT_SUPPORTED: i32 = 50;

/// Owned wrapper around `MIB_IPFORWARD_TABLE2` that frees the table on
/// drop. `GetIpForwardTable2` allocates the buffer; the caller must
/// release it with `FreeMibTable`.
struct ForwardTable {
  ptr: *const MIB_IPFORWARD_TABLE2,
}

impl ForwardTable {
  fn fetch(family: u16) -> io::Result<Self> {
    let mut ptr = std::ptr::null_mut();
    let result = unsafe { GetIpForwardTable2(family, &mut ptr) };
    if result != NO_ERROR {
      // The `NETIO_STATUS` returned by `GetIpForwardTable2` *is* the
      // Win32 error code for this call — relying on `last_os_error()`
      // would read a thread-local that this API doesn't reliably set.
      // Preserve the actual code so callers can match on
      // `ERROR_NOT_FOUND` etc.
      return Err(io::Error::from_raw_os_error(result as i32));
    }
    Ok(Self { ptr })
  }

  fn rows(&self) -> &[MIB_IPFORWARD_ROW2] {
    if self.ptr.is_null() {
      return &[];
    }
    unsafe {
      let table = &*self.ptr;
      core::slice::from_raw_parts(
        &table.Table as *const _ as *const MIB_IPFORWARD_ROW2,
        table.NumEntries as usize,
      )
    }
  }
}

impl Drop for ForwardTable {
  fn drop(&mut self) {
    if !self.ptr.is_null() {
      unsafe { FreeMibTable(self.ptr as *mut _) };
    }
  }
}

#[inline]
fn build_routev4(row: &MIB_IPFORWARD_ROW2) -> Option<Ipv4Route> {
  let prefix = row.DestinationPrefix.Prefix;
  let dst_ip = sockaddr_to_ipaddr(AF_UNSPEC, &prefix as *const _ as *const SOCKADDR)?;
  let dst_v4 = match dst_ip {
    IpAddr::V4(ip) => ip,
    _ => return None,
  };
  // Match the public `route_table` contract (unicast/local routes).
  // Windows' `GetIpForwardTable2` includes the on-link multicast cone
  // `224.0.0.0/4` and the limited-broadcast row `255.255.255.255/32`
  // alongside ordinary unicast routes; same filter as
  // `bsd_like::build_routev4` so cross-platform behavior is consistent.
  if dst_v4.is_multicast() || dst_v4.is_broadcast() {
    return None;
  }
  let net = Ipv4Net::new(dst_v4, row.DestinationPrefix.PrefixLength).ok()?;

  let gw_ip = sockaddr_to_ipaddr(AF_UNSPEC, &row.NextHop as *const _ as *const SOCKADDR);
  let gw = match gw_ip {
    Some(IpAddr::V4(g)) if g != Ipv4Addr::UNSPECIFIED => Some(g),
    _ => None,
  };

  Some(Ipv4Route::new(row.InterfaceIndex, net, gw))
}

#[inline]
fn build_routev6(row: &MIB_IPFORWARD_ROW2) -> Option<Ipv6Route> {
  let prefix = row.DestinationPrefix.Prefix;
  let dst_ip = sockaddr_to_ipaddr(AF_UNSPEC, &prefix as *const _ as *const SOCKADDR)?;
  let dst_v6 = match dst_ip {
    IpAddr::V6(ip) => ip,
    _ => return None,
  };
  // Drop `ff00::/8` for the same reason `build_routev4` drops
  // multicast/broadcast — keep `route_table` consistent with the
  // documented unicast/local contract on Windows.
  if dst_v6.is_multicast() {
    return None;
  }
  let net = Ipv6Net::new(dst_v6, row.DestinationPrefix.PrefixLength).ok()?;

  let gw_ip = sockaddr_to_ipaddr(AF_UNSPEC, &row.NextHop as *const _ as *const SOCKADDR);
  let gw = match gw_ip {
    Some(IpAddr::V6(g)) if g != Ipv6Addr::UNSPECIFIED => Some(g),
    _ => None,
  };

  Some(Ipv6Route::new(row.InterfaceIndex, net, gw))
}

/// `Ok(Some(table))` for a populated family, `Ok(None)` for "no
/// entries for this family" (kernel returned `ERROR_NOT_FOUND` —
/// stack present but empty — or `ERROR_NOT_SUPPORTED` — stack absent
/// entirely, e.g. an IPv6-disabled host). `Err(_)` for any other
/// failure (allocation, invalid parameter, etc.) — those propagate so
/// the union API can't silently turn genuine syscall failures into
/// empty results.
fn fetch_family(family: u16) -> io::Result<Option<ForwardTable>> {
  match ForwardTable::fetch(family) {
    Ok(table) => Ok(Some(table)),
    Err(e)
      if matches!(
        e.raw_os_error(),
        Some(ERROR_NOT_FOUND) | Some(ERROR_NOT_SUPPORTED)
      ) =>
    {
      Ok(None)
    }
    Err(e) => Err(e),
  }
}

pub(crate) fn route_table_by_filter<F>(mut f: F) -> io::Result<SmallVec<IpRoute>>
where
  F: FnMut(&IpRoute) -> bool,
{
  let mut out: SmallVec<IpRoute> = SmallVec::new();

  // Fetch each family independently. Suppress *only* `ERROR_NOT_FOUND`
  // (interpreted as "this family has no routes installed", e.g. on a
  // single-stack host) so the union API can return whichever family
  // is populated. Any other Win32 error — allocation failure, invalid
  // parameter, network-stack issue — propagates with its actual code,
  // so callers reasoning about connectivity can distinguish "no
  // routes" from "the table syscall failed."
  if let Some(table_v4) = fetch_family(AF_INET)? {
    for row in table_v4.rows() {
      if let Some(r) = build_routev4(row) {
        let r = IpRoute::V4(r);
        if f(&r) {
          out.push(r);
        }
      }
    }
  }
  if let Some(table_v6) = fetch_family(AF_INET6)? {
    for row in table_v6.rows() {
      if let Some(r) = build_routev6(row) {
        let r = IpRoute::V6(r);
        if f(&r) {
          out.push(r);
        }
      }
    }
  }
  Ok(out)
}

pub(crate) fn route_ipv4_table_by_filter<F>(mut f: F) -> io::Result<SmallVec<Ipv4Route>>
where
  F: FnMut(&Ipv4Route) -> bool,
{
  // Use `fetch_family` rather than `ForwardTable::fetch` directly so
  // `ERROR_NOT_FOUND` (the kernel's "this family has no route entries"
  // signal — common on a single-stack host) maps to an empty
  // `SmallVec` rather than `Err`. Real syscall failures still
  // propagate.
  let mut out: SmallVec<Ipv4Route> = SmallVec::new();
  if let Some(table) = fetch_family(AF_INET)? {
    for row in table.rows() {
      if let Some(r) = build_routev4(row) {
        if f(&r) {
          out.push(r);
        }
      }
    }
  }
  Ok(out)
}

pub(crate) fn route_ipv6_table_by_filter<F>(mut f: F) -> io::Result<SmallVec<Ipv6Route>>
where
  F: FnMut(&Ipv6Route) -> bool,
{
  // Same rationale as `route_ipv4_table_by_filter`: empty IPv6 route
  // table on a v4-only host is `Ok([])`, not `Err(ERROR_NOT_FOUND)`.
  let mut out: SmallVec<Ipv6Route> = SmallVec::new();
  if let Some(table) = fetch_family(AF_INET6)? {
    for row in table.rows() {
      if let Some(r) = build_routev6(row) {
        if f(&r) {
          out.push(r);
        }
      }
    }
  }
  Ok(out)
}
