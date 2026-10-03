use core::net::IpAddr;
use std::{
  io,
  net::{Ipv4Addr, Ipv6Addr},
};

use super::{interface_addrs, interface_ipv4_addrs, interface_ipv6_addrs, interfaces, IfAddr};

#[inline]
fn interface_not_found() -> io::Error {
  io::Error::new(io::ErrorKind::NotFound, "interface not found")
}

#[inline]
fn interface_not_found_for_ip() -> io::Error {
  io::Error::new(
    io::ErrorKind::NotFound,
    "no local interface has the requested IP address",
  )
}

#[inline]
fn ambiguous_interface_for_ip() -> io::Error {
  io::Error::new(
    io::ErrorKind::InvalidInput,
    "the requested IP address belongs to multiple local interfaces",
  )
}

fn mtu_from_interface_snapshot<I>(index: u32, interfaces: I) -> io::Result<u32>
where
  I: IntoIterator<Item = (u32, u32)>,
{
  interfaces
    .into_iter()
    .find_map(|(candidate_index, mtu)| (candidate_index == index).then_some(mtu))
    .ok_or_else(interface_not_found)
}

fn mtu_from_ip_snapshots<T, I, A>(ip: T, interfaces: I, addrs: A) -> io::Result<u32>
where
  T: Into<IpAddr>,
  I: IntoIterator<Item = (u32, u32)>,
  A: IntoIterator<Item = (u32, IpAddr)>,
{
  let ip = ip.into();
  let mut matching_index = None;

  for (index, addr) in addrs {
    if addr != ip {
      continue;
    }

    match matching_index {
      Some(previous_index) if previous_index != index => return Err(ambiguous_interface_for_ip()),
      Some(_) => {}
      None => matching_index = Some(index),
    }
  }

  let index = matching_index.ok_or_else(interface_not_found_for_ip)?;
  mtu_from_interface_snapshot(index, interfaces)
}

fn query_ip_mtu<T, I, A, LoadInterfaces, LoadAddrs>(
  ip: T,
  load_interfaces: LoadInterfaces,
  load_addrs: LoadAddrs,
) -> io::Result<u32>
where
  T: Into<IpAddr>,
  I: IntoIterator<Item = (u32, u32)>,
  A: IntoIterator<Item = (u32, IpAddr)>,
  LoadInterfaces: FnOnce() -> io::Result<I>,
  LoadAddrs: FnOnce() -> io::Result<A>,
{
  let interfaces = load_interfaces()?;
  let addrs = load_addrs()?;
  mtu_from_ip_snapshots(ip, interfaces, addrs)
}

fn interface_mtu_snapshot() -> io::Result<impl Iterator<Item = (u32, u32)>> {
  interfaces().map(|snapshot| {
    snapshot
      .into_iter()
      .map(|interface| (interface.index(), interface.mtu()))
  })
}

fn ip_address_snapshot() -> io::Result<impl Iterator<Item = (u32, IpAddr)>> {
  interface_addrs().map(|snapshot| snapshot.into_iter().map(|addr| (addr.index(), addr.addr())))
}

fn ipv4_address_snapshot() -> io::Result<impl Iterator<Item = (u32, IpAddr)>> {
  interface_ipv4_addrs().map(|snapshot| {
    snapshot
      .into_iter()
      .map(|addr| (addr.index(), IpAddr::V4(addr.addr())))
  })
}

fn ipv6_address_snapshot() -> io::Result<impl Iterator<Item = (u32, IpAddr)>> {
  interface_ipv6_addrs().map(|snapshot| {
    snapshot
      .into_iter()
      .map(|addr| (addr.index(), IpAddr::V6(addr.addr())))
  })
}

fn get_mtu<T, A, LoadAddrs>(ip: T, load_addrs: LoadAddrs) -> io::Result<u32>
where
  T: Into<IpAddr>,
  A: IntoIterator<Item = (u32, IpAddr)>,
  LoadAddrs: FnOnce() -> io::Result<A>,
{
  query_ip_mtu(ip, interface_mtu_snapshot, load_addrs)
}

/// Gets the local link MTU for an interface index.
///
/// This is the interface's configured local MTU, not a remote path MTU.
/// It is read through the same per-index lookup as
/// [`crate::interface_by_index`]; use [`crate::Interface::mtu`] when you
/// already hold a [`crate::Interface`] snapshot. Returns
/// [`io::ErrorKind::NotFound`] when no interface has that index, and
/// propagates other lookup errors.
///
/// ## Example
///
/// ```no_run
/// use getifs::{get_interface_mtu, interfaces};
///
/// # fn main() -> std::io::Result<()> {
/// if let Some(interface) = interfaces()?.into_iter().next() {
///   println!("{}", get_interface_mtu(interface.index())?);
/// }
/// # Ok(())
/// # }
/// ```
pub fn get_interface_mtu(index: u32) -> io::Result<u32> {
  crate::interface_by_index(index)?
    .map(|interface| interface.mtu())
    .ok_or_else(interface_not_found)
}

/// Gets the local link MTU for the interface named by an [`IfAddr`].
///
/// This resolves the address's interface index and does not re-enumerate or
/// validate that the address is still assigned. Interface snapshots are weak:
/// an interface can disappear or be recreated between calls. For an IPv6
/// link-local address, prefer this scoped form over [`get_ip_mtu`], because
/// the same address can legitimately occur on more than one interface.
///
/// ## Example
///
/// ```no_run
/// use getifs::{get_ifaddr_mtu, interfaces, IfAddr};
///
/// # fn main() -> std::io::Result<()> {
/// if let Some(interface) = interfaces()?.into_iter().next() {
///   if let Some(address) = interface.addrs()?.into_iter().next() {
///     let scoped = IfAddr::new(address.index(), address.addr());
///     println!("{}", get_ifaddr_mtu(scoped)?);
///   }
/// }
/// # Ok(())
/// # }
/// ```
pub fn get_ifaddr_mtu(addr: IfAddr) -> io::Result<u32> {
  get_interface_mtu(addr.index())
}

/// Gets the local link MTU for a local [`IpAddr`].
///
/// This is not a remote path-MTU probe. The interface and address tables are
/// separate weak snapshots, so address-enumeration errors are propagated and a
/// matching address whose interface disappears between snapshots returns
/// [`io::ErrorKind::NotFound`]. If no local interface has `ip`, this returns
/// [`io::ErrorKind::NotFound`]. If the same IP occurs on distinct interfaces,
/// this returns [`io::ErrorKind::InvalidInput`] rather than choosing one
/// arbitrarily. That ambiguity is common for IPv6 link-local addresses; use
/// [`get_ifaddr_mtu`] with an interface-scoped [`IfAddr`] instead.
///
/// ## Example
///
/// ```no_run
/// use getifs::{get_ip_mtu, interfaces};
///
/// # fn main() -> std::io::Result<()> {
/// if let Some(interface) = interfaces()?.into_iter().next() {
///   if let Some(address) = interface.addrs()?.into_iter().next() {
///     println!("{}", get_ip_mtu(address.addr())?);
///   }
/// }
/// # Ok(())
/// # }
/// ```
pub fn get_ip_mtu(ip: IpAddr) -> io::Result<u32> {
  get_mtu(ip, ip_address_snapshot)
}

/// Gets the local link MTU for a local [`Ipv4Addr`].
///
/// This has the same snapshot and error semantics as [`get_ip_mtu`].
/// It enumerates only local IPv4 interface addresses.
///
/// ## Example
///
/// ```no_run
/// use getifs::{get_ipv4_mtu, interfaces};
///
/// # fn main() -> std::io::Result<()> {
/// for interface in interfaces()? {
///   if let Some(address) = interface.ipv4_addrs()?.into_iter().next() {
///     println!("{}", get_ipv4_mtu(address.addr())?);
///     break;
///   }
/// }
/// # Ok(())
/// # }
/// ```
pub fn get_ipv4_mtu(ip: Ipv4Addr) -> io::Result<u32> {
  get_mtu(ip, ipv4_address_snapshot)
}

/// Gets the local link MTU for a local [`Ipv6Addr`].
///
/// This has the same snapshot and error semantics as [`get_ip_mtu`]. For a
/// link-local address, use [`get_ifaddr_mtu`] when its interface is known. It
/// enumerates only local IPv6 interface addresses.
///
/// ## Example
///
/// ```no_run
/// use getifs::{get_ipv6_mtu, interfaces};
///
/// # fn main() -> std::io::Result<()> {
/// for interface in interfaces()? {
///   if let Some(address) = interface.ipv6_addrs()?.into_iter().next() {
///     println!("{}", get_ipv6_mtu(address.addr())?);
///     break;
///   }
/// }
/// # Ok(())
/// # }
/// ```
pub fn get_ipv6_mtu(ip: Ipv6Addr) -> io::Result<u32> {
  get_mtu(ip, ipv6_address_snapshot)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn assert_error_kind<T>(result: io::Result<T>, expected: io::ErrorKind) {
    match result {
      Err(error) => assert_eq!(error.kind(), expected),
      Ok(_) => panic!("expected {expected:?} error"),
    }
  }

  #[test]
  fn interface_mtu_fixture_handles_zero_one_and_missing_indices() {
    assert_error_kind(
      mtu_from_interface_snapshot(7, std::iter::empty::<(u32, u32)>()),
      io::ErrorKind::NotFound,
    );
    assert_eq!(mtu_from_interface_snapshot(7, [(7, 1_500)]).unwrap(), 1_500);
    assert_error_kind(
      mtu_from_interface_snapshot(9, [(7, 1_500), (8, 9_000)]),
      io::ErrorKind::NotFound,
    );
  }

  #[test]
  fn ip_mtu_fixture_handles_zero_one_multiple_and_missing_indices() {
    let ip = Ipv4Addr::new(192, 0, 2, 1);

    assert_error_kind(
      mtu_from_ip_snapshots(
        ip,
        std::iter::empty::<(u32, u32)>(),
        std::iter::empty::<(u32, IpAddr)>(),
      ),
      io::ErrorKind::NotFound,
    );
    assert_eq!(
      mtu_from_ip_snapshots(ip, [(7, 1_500)], [(7, IpAddr::V4(ip))]).unwrap(),
      1_500
    );
    assert_eq!(
      mtu_from_ip_snapshots(
        ip,
        [(7, 1_500), (8, 9_000)],
        [(7, IpAddr::V4(ip)), (7, IpAddr::V4(ip))],
      )
      .unwrap(),
      1_500
    );
    assert_error_kind(
      mtu_from_ip_snapshots(
        ip,
        [(7, 1_500), (8, 9_000)],
        [(7, IpAddr::V4(ip)), (8, IpAddr::V4(ip))],
      ),
      io::ErrorKind::InvalidInput,
    );
    assert_error_kind(
      mtu_from_ip_snapshots(ip, [(7, 1_500)], [(8, IpAddr::V4(ip))]),
      io::ErrorKind::NotFound,
    );
  }

  #[test]
  fn ip_mtu_fixture_propagates_snapshot_errors() {
    let ip = Ipv4Addr::new(192, 0, 2, 1);
    assert_error_kind(
      query_ip_mtu(
        ip,
        || Err::<[(u32, u32); 0], _>(io::Error::new(io::ErrorKind::PermissionDenied, "fixture")),
        || -> io::Result<[(u32, IpAddr); 0]> { panic!("address query must not run") },
      ),
      io::ErrorKind::PermissionDenied,
    );
    assert_error_kind(
      query_ip_mtu(
        ip,
        || Ok([(7, 1_500)]),
        || Err::<[(u32, IpAddr); 0], _>(io::Error::new(io::ErrorKind::InvalidData, "fixture")),
      ),
      io::ErrorKind::InvalidData,
    );
  }

  #[test]
  fn query_ip_mtu_rejects_ambiguous_address_before_selecting_an_mtu() {
    let ip = Ipv6Addr::LOCALHOST;
    assert_error_kind(
      query_ip_mtu(
        ip,
        || Ok([(7, 1_500), (8, 9_000)]),
        || Ok([(7, IpAddr::V6(ip)), (8, IpAddr::V6(ip))]),
      ),
      io::ErrorKind::InvalidInput,
    );
  }
}
