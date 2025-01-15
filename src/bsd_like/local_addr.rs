use std::{io, net::IpAddr};

use libc::{AF_INET, AF_INET6, AF_UNSPEC, NET_RT_DUMP, RTA_DST, RTF_UP};
use smallvec_wrapper::SmallVec;

use crate::Ipv6AddrExt;

use super::{fetch, invalid_message, message_too_short, IfNet, Ifv4Net, Ifv6Net, Net};

/// Returns the IPv4 addresses from the interface with the best default route.
/// The "best" interface is determined by the routing metrics of default routes (`0.0.0.0`).
///
/// See also [`local_ipv4_addrs`].
///
/// ## Example
///
/// ```rust
/// use getifs::best_local_ipv4_addrs;
///
/// let ipv4_addrs = best_local_ipv4_addrs()?;
/// for addr in ipv4_addrs {
///   println!("IPv4: {} on interface {}", addr.addr, addr.ifindex);
/// }
/// ```
pub fn best_local_ipv4_addrs() -> io::Result<SmallVec<Ifv4Net>> {
  bast_local_ip_addrs_in(AF_INET)
}

/// Returns the IPv6 addresses from the interface with the best default route.
/// The "best" interface is determined by the routing metrics of default routes (`::`).
///
/// See also [`local_ipv6_addrs`].
///
/// ## Example
///
/// ```rust
/// use getifs::best_local_ipv6_addrs;
///
/// let ipv6_addrs = best_local_ipv6_addrs()?;
/// // Will only contain addresses from the interface with best default route
/// for addr in ipv6_addrs {
///   println!("IPv6: {} on interface {}", addr.addr, addr.ifindex);
/// }
/// ```
pub fn best_local_ipv6_addrs() -> io::Result<SmallVec<Ifv6Net>> {
  bast_local_ip_addrs_in(AF_INET6)
}

/// Returns both IPv4 and IPv6 addresses from the interfaces with the best default routes.
/// The "best" interfaces are determined by the routing metrics of default routes.
///
/// See also [`local_ip_addrs`].
///
/// ## Example
///
/// ```rust
/// use getifs::best_local_ip_addrs;
///
/// let all_addrs = best_local_ip_addrs()?;
/// // Will only contain addresses from interfaces with best default routes
/// for addr in all_addrs {
///   println!("IP: {} on interface {}", addr.addr, addr.ifindex);
/// }
/// ```
pub fn best_local_ip_addrs() -> io::Result<SmallVec<IfNet>> {
  bast_local_ip_addrs_in(AF_UNSPEC)
}

fn bast_local_ip_addrs_in<T: Net>(family: i32) -> io::Result<SmallVec<T>> {
  // First get the default route to find the interface index
  let routes = fetch(family, NET_RT_DUMP, 0)?;
  let mut best_ifindex = None;
  let mut best_metric = u32::MAX;

  unsafe {
    let mut src = routes.as_slice();
    while src.len() > 4 {
      let l = u16::from_ne_bytes(src[..2].try_into().unwrap()) as usize;
      if l == 0 {
        return Err(invalid_message());
      }
      if src.len() < l {
        return Err(message_too_short());
      }
      if src[2] as i32 != libc::RTM_VERSION {
        src = &src[l..];
        continue;
      }

      let rtm = &*(src.as_ptr() as *const libc::rt_msghdr);

      // Only consider UP routes
      if (rtm.rtm_flags & RTF_UP) == 0 {
        src = &src[l..];
        continue;
      }

      let mut addr_ptr = src.as_ptr().add(std::mem::size_of::<libc::rt_msghdr>());
      let mut addrs = rtm.rtm_addrs;
      let mut i = 1;
      let mut is_default = false;

      while addrs != 0 {
        if (addrs & 1) != 0 {
          let sa = &*(addr_ptr as *const libc::sockaddr);
          match (family, sa.sa_family as i32, i) {
            (AF_INET, AF_INET, RTA_DST) | (AF_UNSPEC, AF_INET, RTA_DST) => {
              let sa_in = &*(addr_ptr as *const libc::sockaddr_in);
              if sa_in.sin_addr.s_addr == 0 {
                is_default = true;
              }
            }
            (AF_INET6, AF_INET6, RTA_DST) | (AF_UNSPEC, AF_INET6, RTA_DST) => {
              let sa_in6 = &*(addr_ptr as *const libc::sockaddr_in6);
              if sa_in6.sin6_addr.s6_addr.iter().all(|&x| x == 0) {
                is_default = true;
              }
            }
            _ => {}
          }

          let sa_len = if sa.sa_len == 0 {
            std::mem::size_of::<libc::sockaddr>()
          } else {
            sa.sa_len as usize
          };
          addr_ptr = addr_ptr.add((sa_len + 7) & !7);
        }
        i += 1;
        addrs >>= 1;
      }

      // If this is a default route and has better metric, update best_ifindex
      if is_default && rtm.rtm_rmx.rmx_recvpipe < best_metric {
        best_metric = rtm.rtm_rmx.rmx_recvpipe;
        best_ifindex = Some(rtm.rtm_index);
      }

      src = &src[l..];
    }
  }

  // Only pass the interface index if we found a valid default route
  match best_ifindex {
    Some(idx) => super::interface_addr_table(family, idx as u32, local_ip_filter),
    None => Ok(SmallVec::new()),
  }
}

/// Returns all IPv4 addresses from interfaces that have valid routes (excluding loopback).
/// This ensures we only return addresses that can be used for communication.
///
/// See also [`best_local_ipv4_addrs`] and [`local_ipv4_addrs_by_filter`].
///
/// ## Example
///
/// ```rust
/// use getifs::local_ipv4_addrs;
///
/// let ipv4_addrs = local_ipv4_addrs()?;
/// for addr in ipv4_addrs {
///   println!("IPv4: {}", addr);
/// }
/// ```
pub fn local_ipv4_addrs() -> io::Result<SmallVec<Ifv4Net>> {
  all_local_ip_addrs_in(AF_INET, local_ip_filter)
}

/// Returns all IPv6 addresses from interfaces that have valid routes (excluding loopback).
/// This ensures we only return addresses that can be used for communication.
///
/// See also [`best_local_ipv6_addrs`] and [`local_ipv6_addrs_by_filter`].
///
/// ## Example
///
/// ```rust
/// use getifs::local_ipv6_addrs;
///
/// let ipv6_addrs = local_ipv6_addrs()?;
/// for addr in ipv6_addrs {
///   println!("IPv6: {}", addr);
/// }
/// ```
pub fn local_ipv6_addrs() -> io::Result<SmallVec<Ifv6Net>> {
  all_local_ip_addrs_in(AF_INET6, local_ip_filter)
}

/// Returns all IP addresses (both IPv4 and IPv6) from interfaces that have valid routes (excluding loopback).
/// This ensures we only return addresses that can be used for communication.
///
/// See also [`best_local_ip_addrs`] and [`local_ip_addrs_by_filter`].
///
/// ## Example
///
/// ```rust
/// use getifs::local_ip_addrs;
///
/// let all_addrs = local_ip_addrs()?;
/// for addr in all_addrs {
///     println!("IP: {}", addr);
/// }
/// ```
pub fn local_ip_addrs() -> io::Result<SmallVec<IfNet>> {
  all_local_ip_addrs_in(AF_UNSPEC, local_ip_filter)
}

/// Returns all local IP addresses from interfaces that have valid routes (excluding loopback).
/// This ensures we only get addresses that can be used for communication.
fn all_local_ip_addrs_in<T, F>(family: i32, f: F) -> io::Result<SmallVec<T>>
where
  T: Net,
  F: FnMut(&IpAddr) -> bool,
{
  // First get all routes to find valid interface indices
  let routes = fetch(family, NET_RT_DUMP, 0)?;
  let mut valid_ifindices = SmallVec::new();

  unsafe {
    let mut src = routes.as_slice();
    while src.len() > 4 {
      let l = u16::from_ne_bytes(src[..2].try_into().unwrap()) as usize;
      if l == 0 {
        return Err(invalid_message());
      }
      if src.len() < l {
        return Err(message_too_short());
      }
      if src[2] as i32 != libc::RTM_VERSION {
        src = &src[l..];
        continue;
      }

      let rtm = &*(src.as_ptr() as *const libc::rt_msghdr);
      // Only consider UP routes
      if (rtm.rtm_flags & RTF_UP) == 0 {
        src = &src[l..];
        continue;
      }

      // Add interface index to valid set
      valid_ifindices.push(rtm.rtm_index as u32);
      src = &src[l..];
    }
  }

  valid_ifindices.dedup();

  match valid_ifindices.len() {
    0 => Ok(SmallVec::new()),
    1 if valid_ifindices[0] != 0 => {
      // If only one valid interface, return its addresses
      super::interface_addr_table(family, valid_ifindices[0], f)
    }
    _ => {
      // Get addresses only from interfaces that have valid routes
      let all_addrs = super::interface_addr_table(family, 0, f)?;
      Ok(
        all_addrs
          .into_iter()
          .filter(|i: &T| !i.addr().is_loopback() && valid_ifindices.contains(&i.index()))
          .collect(),
      )
    }
  }
}

/// Returns all IPv4 addresses from interfaces that have valid routes.
///
/// Use the provided filter to further refine the results.
///
/// ## Example
///
/// ```rust
/// use getifs::local_ipv4_addrs_by_filter;
///
/// let addrs = local_ipv4_addrs_by_filter(|addr| !addr.is_loopback())?;
/// for addr in addrs {
///   println!("IPv4: {}", addr);
/// }
/// ```
pub fn local_ipv4_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv4Net>>
where
  F: FnMut(&IpAddr) -> bool,
{
  all_local_ip_addrs_in(AF_INET, f)
}

/// Returns all IPv6 addresses from interfaces that have valid routes.
///
/// Use the provided filter to further refine the results.
///
/// ## Example
///
/// ```rust
/// use getifs::local_ipv6_addrs_by_filter;
///
/// let addrs = local_ipv6_addrs_by_filter(|addr| !addr.is_loopback())?;
/// for addr in addrs {
///   println!("IPv6: {}", addr);
/// }
/// ```
pub fn local_ipv6_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv6Net>>
where
  F: FnMut(&IpAddr) -> bool,
{
  all_local_ip_addrs_in(AF_INET6, f)
}

/// Returns all IP addresses (both IPv4 and IPv6) from interfaces that have valid routes.
///
/// Use the provided filter to further refine the results.
///
/// ## Example
///
/// ```rust
/// use getifs::local_ip_addrs_by_filter;
///
///
/// let addrs = local_ip_addrs_by_filter(|addr| !addr.is_loopback())?;
/// for addr in addrs {
///   println!("IP: {}", addr);
/// }
/// ```
pub fn local_ip_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<IfNet>>
where
  F: FnMut(&IpAddr) -> bool,
{
  all_local_ip_addrs_in(AF_UNSPEC, f)
}

#[inline]
fn local_ip_filter(addr: &IpAddr) -> bool {
  match addr {
    IpAddr::V4(addr) => !(addr.is_loopback() || addr.is_link_local()),
    IpAddr::V6(addr) => !(addr.is_loopback() || Ipv6AddrExt::is_unicast_link_local(addr)),
  }
}
