use libc::{AF_INET, AF_INET6, AF_UNSPEC};
use smallvec_wrapper::SmallVec;
use std::io;

use super::{
  super::{IfAddr, Ifv4Addr, Ifv6Addr},
  netlink::netlink_gateway,
};

pub(crate) fn gateway_ip_addrs() -> io::Result<SmallVec<IfAddr>> {
  netlink_gateway(AF_UNSPEC, |_| true)
}

pub(crate) fn gateway_ipv4_addrs() -> io::Result<SmallVec<Ifv4Addr>> {
  netlink_gateway(AF_INET, |_| true)
}

pub(crate) fn gateway_ipv6_addrs() -> io::Result<SmallVec<Ifv6Addr>> {
  netlink_gateway(AF_INET6, |_| true)
}
