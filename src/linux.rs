use std::io;

use ipnet::IpNet;
use libc::{
  AF_UNSPEC, RTM_GETADDR, RTM_GETLINK
};

use crate::MacAddr;

use super::Interface;

#[path = "linux/netlink.rs"]
mod netlink;

use netlink::netlink_rib;

bitflags::bitflags! {
  /// Flags represents the interface flags.
  #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
  pub struct Flags: u32 {
    /// Interface is administratively up
    const UP = 0x1;
    /// Interface supports broadcast access capability
    const BROADCAST = 0x2;
    /// Turn on debugging
    const DEBUG = 0x4;
    /// Interface is a loopback net
    const LOOPBACK = 0x8;
    /// Interface is point-to-point link
    const POINTOPOINT = 0x10;
    /// Obsolete: avoid use of trailers
    const NOTRAILERS = 0x20;
    /// Resources allocated
    const RUNNING = 0x40;
    /// No address resolution protocol
    const NOARP = 0x80;
    /// Receive all packets
    const PROMISC = 0x100;
    /// Receive all multicast packets
    const ALLMULTI = 0x200;
    /// Transmission is in progress
    const MASTER = 0x400;
    /// Can't hear own transmissions
    const SLAVE = 0x800;
    /// Per link layer defined bit
    const MULTICAST = 0x1000;
    /// Per link layer defined bit
    const PORTSEL = 0x2000;
    /// Per link layer defined bit
    const AUTOMEDIA = 0x4000;
    /// Supports multicast access capability
    const DYNAMIC = 0x8000;
  }
}


pub(super) fn interface_table(ifi: u32) -> io::Result<Vec<Interface>> {
  netlink_rib(RTM_GETLINK as i32, AF_UNSPEC).map(|res| res.expect_left("must be interfaces when query type is GETLINK"))
}

pub(super) fn interface_addr_table(idx: u32) -> io::Result<Vec<IpNet>> {
  netlink_rib(RTM_GETADDR as i32, AF_UNSPEC).map(|res| res.expect_right("must be ipnets when query type is GETADDR"))
}

#[test]
fn test_interfaces() {
  let interfaces = interface_table(0).unwrap();
  for interface in interfaces {
    println!("{:?}", interface);
  }
}
