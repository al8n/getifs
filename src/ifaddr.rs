use std::{io, net::{IpAddr, Ipv4Addr, Ipv6Addr}};

use ipnet::IpNet;
use smallvec_wrapper::SmallVec;
use iprfc::{RFC6890, FORWARDING_BLACK_LIST};

use super::{interfaces, Interface};

/// Returns a single IP address that is part of [RFC 6890](RFC6890)
/// and has a default route. If the system can't determine its IP address
/// or find an [RFC 6890](RFC6890) IP address, a `None` will be returned instead.
pub fn get_private_ip() -> io::Result<Option<IpAddr>> {
  // let ifs = interfaces()?;

  // for inf in ifs.iter() {
  //   let mut addr = inf.addrs()?;
  //   addr.retain(|ipi| {
      
  //   });
  // }

  todo!()
}

/// Returns a bunch of IP addresses that are part of [RFC 6890](RFC6890) and have a default route. If the system can't determine its IP address or find an [RFC 6890](RFC6890) IP address, an empty `SmallVec` will be returned instead.
pub fn get_private_ips() -> io::Result<SmallVec<IpAddr>> {
  todo!()
}

/// Returns a bunch of [`IfAddr`](super::IfAddr) that are part of [RFC 6890](RFC6890) and have a
/// default route.  If the system can't determine its IP address or find an [RFC 6890](RFC6890) IP address,
/// an empty IfAddrs will be returned instead.
pub fn get_private_interfaces() -> io::Result<SmallVec<Interface>> {
  todo!()
}
