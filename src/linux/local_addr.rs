use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use rustix::net::AddressFamily;
use smallvec_wrapper::SmallVec;

use crate::{
  ipv4_filter_to_ip_filter, ipv6_filter_to_ip_filter, local_ip_filter, IfNet, Ifv4Net, Ifv6Net,
};

use super::netlink::{netlink_addr, netlink_best_local_addrs};

pub(crate) fn best_local_ipv4_addrs() -> io::Result<SmallVec<Ifv4Net>> {
  netlink_best_local_addrs(AddressFamily::INET)
}

pub(crate) fn best_local_ipv6_addrs() -> io::Result<SmallVec<Ifv6Net>> {
  netlink_best_local_addrs(AddressFamily::INET6)
}

pub(crate) fn best_local_addrs() -> io::Result<SmallVec<IfNet>> {
  netlink_best_local_addrs(AddressFamily::UNSPEC)
}

pub(crate) fn local_ipv4_addrs() -> io::Result<SmallVec<Ifv4Net>> {
  netlink_addr(AddressFamily::INET, 0, local_ip_filter)
}

pub(crate) fn local_ipv6_addrs() -> io::Result<SmallVec<Ifv6Net>> {
  netlink_addr(AddressFamily::INET6, 0, local_ip_filter)
}

pub(crate) fn local_addrs() -> io::Result<SmallVec<IfNet>> {
  netlink_addr(AddressFamily::UNSPEC, 0, local_ip_filter)
}

pub(crate) fn local_ipv4_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv4Net>>
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  let mut f = ipv4_filter_to_ip_filter(f);
  netlink_addr(AddressFamily::INET, 0, |addr| {
    f(addr) && local_ip_filter(addr)
  })
}

pub(crate) fn local_ipv6_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv6Net>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  let mut f = ipv6_filter_to_ip_filter(f);
  netlink_addr(AddressFamily::INET6, 0, |addr| {
    f(addr) && local_ip_filter(addr)
  })
}

pub(crate) fn local_addrs_by_filter<F>(mut f: F) -> io::Result<SmallVec<IfNet>>
where
  F: FnMut(&IpAddr) -> bool,
{
  netlink_addr(AddressFamily::UNSPEC, 0, |addr| {
    f(addr) && local_ip_filter(addr)
  })
}
