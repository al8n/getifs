use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};
use smallvec_wrapper::SmallVec;
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::*;

use super::{sockaddr_to_ipaddr, Route, Routev4, Routev6, NO_ERROR};

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
      return Err(io::Error::last_os_error());
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

pub(crate) fn route_table_by_filter<F>(mut f: F) -> io::Result<SmallVec<Route>>
where
  F: FnMut(&Route) -> bool,
{
  let mut out: SmallVec<Route> = SmallVec::new();

  // Fetch each family independently. If either family's table is
  // unavailable (e.g. IPv6 disabled on the host) preserve whatever the
  // other family returned rather than failing the union API. Callers
  // that want the per-family error semantics should use
  // `route_ipv4_table_by_filter` / `route_ipv6_table_by_filter`.
  if let Ok(table_v4) = ForwardTable::fetch(AF_INET) {
    for row in table_v4.rows() {
      if let Some(r) = build_routev4(row) {
        let r = Route::V4(r);
        if f(&r) {
          out.push(r);
        }
      }
    }
  }
  if let Ok(table_v6) = ForwardTable::fetch(AF_INET6) {
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
