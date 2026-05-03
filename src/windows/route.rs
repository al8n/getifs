use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};
use smallvec_wrapper::SmallVec;
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::*;

use super::{sockaddr_to_ipaddr, Route, Routev4, Routev6, NO_ERROR};

/// `GetIpForwardTable2` returns this when the requested family has no
/// route entries (e.g. IPv6 stack present but no IPv6 routes
/// installed, or a single-stack v4 host). It's the only error code we
/// treat as "this family is just empty" in the union API; everything
/// else propagates so allocation/parameter failures aren't masked.
const ERROR_NOT_FOUND: i32 = 1168;

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
fn build_routev4(row: &MIB_IPFORWARD_ROW2) -> Option<Routev4> {
  let prefix = row.DestinationPrefix.Prefix;
  let dst_ip = sockaddr_to_ipaddr(AF_UNSPEC, &prefix as *const _ as *const SOCKADDR)?;
  let dst_v4 = match dst_ip {
    IpAddr::V4(ip) => ip,
    _ => return None,
  };
  let net = Ipv4Net::new(dst_v4, row.DestinationPrefix.PrefixLength).ok()?;

  let gw_ip = sockaddr_to_ipaddr(AF_UNSPEC, &row.NextHop as *const _ as *const SOCKADDR);
  let gw = match gw_ip {
    Some(IpAddr::V4(g)) if g != Ipv4Addr::UNSPECIFIED => Some(g),
    _ => None,
  };

  Some(Routev4::new(row.InterfaceIndex, net, gw))
}

#[inline]
fn build_routev6(row: &MIB_IPFORWARD_ROW2) -> Option<Routev6> {
  let prefix = row.DestinationPrefix.Prefix;
  let dst_ip = sockaddr_to_ipaddr(AF_UNSPEC, &prefix as *const _ as *const SOCKADDR)?;
  let dst_v6 = match dst_ip {
    IpAddr::V6(ip) => ip,
    _ => return None,
  };
  let net = Ipv6Net::new(dst_v6, row.DestinationPrefix.PrefixLength).ok()?;

  let gw_ip = sockaddr_to_ipaddr(AF_UNSPEC, &row.NextHop as *const _ as *const SOCKADDR);
  let gw = match gw_ip {
    Some(IpAddr::V6(g)) if g != Ipv6Addr::UNSPECIFIED => Some(g),
    _ => None,
  };

  Some(Routev6::new(row.InterfaceIndex, net, gw))
}

/// `Ok(Some(table))` for a populated family, `Ok(None)` for "no
/// entries for this family" (kernel returned `ERROR_NOT_FOUND`),
/// `Err(_)` for any other failure (allocation, invalid parameter,
/// etc.) — those propagate so the union API can't silently turn
/// genuine syscall failures into empty results.
fn fetch_family(family: u16) -> io::Result<Option<ForwardTable>> {
  match ForwardTable::fetch(family) {
    Ok(table) => Ok(Some(table)),
    Err(e) if e.raw_os_error() == Some(ERROR_NOT_FOUND) => Ok(None),
    Err(e) => Err(e),
  }
}

pub(crate) fn route_table_by_filter<F>(mut f: F) -> io::Result<SmallVec<Route>>
where
  F: FnMut(&Route) -> bool,
{
  let mut out: SmallVec<Route> = SmallVec::new();

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
        let r = Route::V4(r);
        if f(&r) {
          out.push(r);
        }
      }
    }
  }
  if let Some(table_v6) = fetch_family(AF_INET6)? {
    for row in table_v6.rows() {
      if let Some(r) = build_routev6(row) {
        let r = Route::V6(r);
        if f(&r) {
          out.push(r);
        }
      }
    }
  }
  Ok(out)
}

pub(crate) fn route_ipv4_table_by_filter<F>(mut f: F) -> io::Result<SmallVec<Routev4>>
where
  F: FnMut(&Routev4) -> bool,
{
  let mut out: SmallVec<Routev4> = SmallVec::new();
  let table = ForwardTable::fetch(AF_INET)?;
  for row in table.rows() {
    if let Some(r) = build_routev4(row) {
      if f(&r) {
        out.push(r);
      }
    }
  }
  Ok(out)
}

pub(crate) fn route_ipv6_table_by_filter<F>(mut f: F) -> io::Result<SmallVec<Routev6>>
where
  F: FnMut(&Routev6) -> bool,
{
  let mut out: SmallVec<Routev6> = SmallVec::new();
  let table = ForwardTable::fetch(AF_INET6)?;
  for row in table.rows() {
    if let Some(r) = build_routev6(row) {
      if f(&r) {
        out.push(r);
      }
    }
  }
  Ok(out)
}
