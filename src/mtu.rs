use core::net::IpAddr;
use std::{
  io,
  net::{Ipv4Addr, Ipv6Addr},
};

use super::interfaces;

fn interface_not_found_for_ip() -> io::Error {
  io::Error::new(io::ErrorKind::Other, "interface not found")
}

/// Get the MTU of the given [`IpAddr`].
///
/// ## Example
///
/// ```rust
/// use getifs::get_ip_mtu;
///
/// let mtu = get_ip_mtu("127.0.0.1".parse().unwrap()).unwrap();
/// println!("MTU: {}", mtu);
/// ```
pub fn get_ip_mtu(ip: IpAddr) -> io::Result<u32> {
  interfaces().and_then(|ifis| {
    for iface in ifis {
      match iface.addrs_by_filter(|addr| ip.eq(addr)) {
        Ok(addrs) => {
          if !addrs.is_empty() {
            return Ok(iface.mtu());
          }
        }
        Err(_) => continue,
      }
    }

    Err(interface_not_found_for_ip())
  })
}

/// Get the MTU of the given [`Ipv4Addr`].
///
/// ## Example
///
/// ```rust
/// use std::net::Ipv4Addr;
/// use getifs::get_ipv4_mtu;
///
/// let mtu = get_ipv4_mtu(Ipv4Addr::LOCALHOST).unwrap();
/// println!("MTU: {}", mtu);
/// ```
pub fn get_ipv4_mtu(ip: Ipv4Addr) -> io::Result<u32> {
  interfaces().and_then(|ifis| {
    for iface in ifis {
      match iface.ipv4_addrs_by_filter(|addr| ip.eq(addr)) {
        Ok(addrs) => {
          if !addrs.is_empty() {
            return Ok(iface.mtu());
          }
        }
        Err(_) => continue,
      }
    }

    Err(interface_not_found_for_ip())
  })
}

/// Get the MTU of the given [`Ipv6Addr`].
///
/// ## Example
///
/// ```rust
/// use std::net::Ipv6Addr;
/// use getifs::get_ipv6_mtu;
///
/// let mtu = get_ipv6_mtu(Ipv6Addr::LOCALHOST).unwrap();
/// println!("MTU: {}", mtu);
/// ```
pub fn get_ipv6_mtu(ip: Ipv6Addr) -> io::Result<u32> {
  interfaces().and_then(|ifis| {
    for iface in ifis {
      match iface.ipv6_addrs_by_filter(|addr| ip.eq(addr)) {
        Ok(addrs) => {
          if !addrs.is_empty() {
            return Ok(iface.mtu());
          }
        }
        Err(_) => continue,
      }
    }

    Err(interface_not_found_for_ip())
  })
}
