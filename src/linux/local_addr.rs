use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use libc::{AF_INET, AF_INET6, AF_UNSPEC};
use smallvec_wrapper::SmallVec;

use crate::{
  ipv4_filter_to_ip_filter, ipv6_filter_to_ip_filter, local_ip_filter, IfNet, Ifv4Net, Ifv6Net,
};

use super::netlink::{netlink_addr, netlink_best_local_ip_addrs};

pub(crate) fn best_local_ipv4_addrs() -> io::Result<SmallVec<Ifv4Net>> {
  netlink_best_local_ip_addrs(AF_INET)
}

pub(crate) fn best_local_ipv6_addrs() -> io::Result<SmallVec<Ifv6Net>> {
  netlink_best_local_ip_addrs(AF_INET6)
}

pub(crate) fn best_local_ip_addrs() -> io::Result<SmallVec<IfNet>> {
  netlink_best_local_ip_addrs(AF_UNSPEC)
}

pub(crate) fn local_ipv4_addrs() -> io::Result<SmallVec<Ifv4Net>> {
  netlink_addr(AF_INET, 0, local_ip_filter)
}

pub(crate) fn local_ipv6_addrs() -> io::Result<SmallVec<Ifv6Net>> {
  netlink_addr(AF_INET6, 0, local_ip_filter)
}

pub(crate) fn local_ip_addrs() -> io::Result<SmallVec<IfNet>> {
  netlink_addr(AF_UNSPEC, 0, local_ip_filter)
}

pub(crate) fn local_ipv4_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv4Net>>
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  let mut f = ipv4_filter_to_ip_filter(f);
  netlink_addr(AF_INET, 0, |addr| f(addr) && local_ip_filter(addr))
}

pub(crate) fn local_ipv6_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv6Net>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  let mut f = ipv6_filter_to_ip_filter(f);
  netlink_addr(AF_INET6, 0, |addr| f(addr) && local_ip_filter(addr))
}

pub(crate) fn local_ip_addrs_by_filter<F>(mut f: F) -> io::Result<SmallVec<IfNet>>
where
  F: FnMut(&IpAddr) -> bool,
{
  netlink_addr(AF_UNSPEC, 0, |addr| f(addr) && local_ip_filter(addr))
}
