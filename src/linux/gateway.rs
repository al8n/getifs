use libc::{AF_INET, AF_INET6, AF_UNSPEC};
use smallvec_wrapper::SmallVec;
use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::{ipv4_filter_to_ip_filter, ipv6_filter_to_ip_filter};

use super::{
  super::{IfAddr, Ifv4Addr, Ifv6Addr},
  netlink::netlink_gateway,
};

pub(crate) fn rt_gateway_addrs() -> io::Result<SmallVec<IfAddr>> {
  netlink_gateway(AF_UNSPEC, |_| true)
}

pub(crate) fn rt_gateway_ipv4_addrs() -> io::Result<SmallVec<Ifv4Addr>> {
  netlink_gateway(AF_INET, |_| true)
}

pub(crate) fn rt_gateway_ipv6_addrs() -> io::Result<SmallVec<Ifv6Addr>> {
  netlink_gateway(AF_INET6, |_| true)
}

pub(crate) fn rt_gateway_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<IfAddr>>
where
  F: FnMut(&IpAddr) -> bool,
{
  netlink_gateway(AF_UNSPEC, f)
}

pub(crate) fn rt_gateway_ipv4_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv4Addr>>
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  netlink_gateway(AF_INET, ipv4_filter_to_ip_filter(f))
}

pub(crate) fn rt_gateway_ipv6_addrs_by_filter<F>(f: F) -> io::Result<SmallVec<Ifv6Addr>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  netlink_gateway(AF_INET6, ipv6_filter_to_ip_filter(f))
}
