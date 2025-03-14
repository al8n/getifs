use std::{
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use hardware_address::xtoi2;
use rustix::net::AddressFamily;
use smallvec_wrapper::{SmallVec, TinyVec};
use smol_str::SmolStr;

use super::{
  IfAddr, IfNet, Ifv4Addr, Ifv4Net, Ifv6Addr, Ifv6Net, Interface, MacAddr, Net, MAC_ADDRESS_SIZE,
};

pub(super) use local_addr::*;

#[path = "linux/netlink.rs"]
mod netlink;

#[path = "linux/local_addr.rs"]
mod local_addr;

use netlink::{netlink_addr, netlink_interface};

macro_rules! rt_generic_mod {
  ($($name:ident($rta:expr, $rtn:expr)), +$(,)?) => {
    $(
      paste::paste! {
        pub(super) use [< rt_ $name >]::*;

        mod [< rt_ $name >] {
          use rustix::net::AddressFamily;
          use smallvec_wrapper::SmallVec;
          use std::{
            io,
            net::{IpAddr, Ipv4Addr, Ipv6Addr},
          };

          use crate::{ipv4_filter_to_ip_filter, ipv6_filter_to_ip_filter};

          use super::{
            super::{IfAddr, Ifv4Addr, Ifv6Addr},
            netlink::rt_generic_addrs,
          };

          pub(crate) fn [< $name _addrs >]() -> io::Result<SmallVec<IfAddr>> {
            rt_generic_addrs(AddressFamily::UNSPEC, $rta, $rtn, |_| true)
          }

          pub(crate) fn [< $name _ipv4_addrs >]() -> io::Result<SmallVec<Ifv4Addr>> {
            rt_generic_addrs(AddressFamily::INET, $rta, $rtn, |_| true)
          }

          pub(crate) fn [< $name _ipv6_addrs >]() -> io::Result<SmallVec<Ifv6Addr>> {
            rt_generic_addrs(AddressFamily::INET6, $rta, $rtn, |_| true)
          }

          pub(crate) fn [< $name _addrs_by_filter >]<F>(f: F) -> io::Result<SmallVec<IfAddr>>
          where
            F: FnMut(&IpAddr) -> bool,
          {
            rt_generic_addrs(AddressFamily::UNSPEC, $rta, $rtn, f)
          }

          pub(crate) fn [< $name _ipv4_addrs_by_filter >]<F>(f: F) -> io::Result<SmallVec<Ifv4Addr>>
          where
            F: FnMut(&Ipv4Addr) -> bool,
          {
            rt_generic_addrs(AddressFamily::INET, $rta, $rtn, ipv4_filter_to_ip_filter(f))
          }

          pub(crate) fn [< $name _ipv6_addrs_by_filter >]<F>(f: F) -> io::Result<SmallVec<Ifv6Addr>>
          where
            F: FnMut(&Ipv6Addr) -> bool,
          {
            rt_generic_addrs(AddressFamily::INET6, $rta, $rtn, ipv6_filter_to_ip_filter(f))
          }
        }
      }
    )*
  };
}

rt_generic_mod!(gateway(
  linux_raw_sys::netlink::rtattr_type_t::RTA_GATEWAY as u16,
  None
),);

impl Interface {
  #[inline]
  fn new(index: u32, flags: Flags) -> Self {
    Self {
      index,
      mtu: 0,
      name: SmolStr::default(),
      mac_addr: None,
      flags,
    }
  }
}

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

pub(super) fn interface_table(index: u32) -> io::Result<TinyVec<Interface>> {
  netlink_interface(AddressFamily::UNSPEC, index)
}

pub(super) fn interface_ipv4_addresses<F>(index: u32, f: F) -> io::Result<SmallVec<Ifv4Net>>
where
  F: FnMut(&IpAddr) -> bool,
{
  netlink_addr(AddressFamily::INET, index, f)
}

pub(super) fn interface_ipv6_addresses<F>(index: u32, f: F) -> io::Result<SmallVec<Ifv6Net>>
where
  F: FnMut(&IpAddr) -> bool,
{
  netlink_addr(AddressFamily::INET6, index, f)
}

pub(super) fn interface_addresses<F>(index: u32, f: F) -> io::Result<SmallVec<IfNet>>
where
  F: FnMut(&IpAddr) -> bool,
{
  netlink_addr(AddressFamily::UNSPEC, index, f)
}

const IGMP_PATH: &str = "/proc/net/igmp";
const IGMP6_PATH: &str = "/proc/net/igmp6";

pub(super) fn interface_multicast_ipv4_addresses<F>(
  ifi: u32,
  f: F,
) -> io::Result<SmallVec<Ifv4Addr>>
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  parse_proc_net_igmp(IGMP_PATH, ifi, f)
}

pub(super) fn interface_multicast_ipv6_addresses<F>(
  ifi: u32,
  f: F,
) -> io::Result<SmallVec<Ifv6Addr>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  parse_proc_net_igmp6(IGMP6_PATH, ifi, f)
}

pub(super) fn interface_multicast_addresses<F>(ifi: u32, mut f: F) -> io::Result<SmallVec<IfAddr>>
where
  F: FnMut(&IpAddr) -> bool,
{
  // Parse IPv4 multicast addrs
  let ifmat4 = parse_proc_net_igmp("/proc/net/igmp", ifi, |addr| f(&(*addr).into()))?;

  // Parse IPv6 multicast addrs
  let ifmat6 = parse_proc_net_igmp6("/proc/net/igmp6", ifi, |addr| f(&(*addr).into()))?;

  Ok(
    ifmat4
      .into_iter()
      .map(From::from)
      .chain(ifmat6.into_iter().map(From::from))
      .collect(),
  )
}

fn parse_proc_net_igmp<F>(path: &str, ifi: u32, mut f: F) -> std::io::Result<SmallVec<Ifv4Addr>>
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  use std::io::BufRead;

  let file = std::fs::File::open(path)?;
  let reader = std::io::BufReader::new(file);
  let mut ifmat = SmallVec::new();
  let mut idx = 0;
  let mut lines = reader.lines();

  // Skip first line
  lines.next();

  for line in lines {
    let line = line?;
    let fields: smallvec_wrapper::MediumVec<&str> = line
      .split([' ', ':', '\r', '\t', '\n'])
      .filter(|s| !s.is_empty())
      .collect();

    if fields.len() < 4 {
      continue;
    }

    match () {
      () if !line.starts_with(' ') && !line.starts_with('\t') => {
        // New interface line
        match fields[0].parse() {
          Ok(res) => idx = res,
          Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
        }
      }
      () if fields[0].len() == 8 => {
        if ifi == 0 || ifi == idx {
          // The Linux kernel puts the IP
          // address in /proc/net/igmp in native
          // endianness.
          let src = fields[0];
          let mut b = [0u8; 4];
          for i in (0..src.len()).step_by(2) {
            b[i / 2] = xtoi2(&src[i..i + 2], 0).unwrap_or(0);
          }

          b.reverse();
          let ip = b.into();
          if f(&ip) {
            ifmat.push(Ifv4Addr::new(idx, ip));
          }
        }
      }
      _ => {}
    }
  }

  Ok(ifmat)
}

fn parse_proc_net_igmp6<F>(path: &str, ifi: u32, mut f: F) -> io::Result<SmallVec<Ifv6Addr>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  use std::io::BufRead;

  let file = std::fs::File::open(path)?;
  let reader = std::io::BufReader::new(file);
  let mut ifmat = SmallVec::new();

  for line in reader.lines() {
    let line = line?;
    let fields: smallvec_wrapper::MediumVec<&str> = line
      .split([' ', '\r', '\t', '\n'])
      .filter(|s| !s.is_empty())
      .collect();

    if fields.len() < 6 {
      continue;
    }

    let idx = match fields[0].parse() {
      Ok(res) => res,
      Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
    };

    if ifi == 0 || ifi == idx {
      let mut i = 0;
      let src = fields[2];
      let mut data = [0u8; 16];
      while i + 1 < src.len() {
        data[i / 2] = xtoi2(&src[i..i + 2], 0).unwrap_or(0);
        i += 2;
      }

      let ip = data.into();
      if f(&ip) {
        ifmat.push(Ifv6Addr::new(idx, ip));
      }
    }
  }

  Ok(ifmat)
}
