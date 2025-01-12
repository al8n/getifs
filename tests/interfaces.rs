use std::net::IpAddr;

use getifs::{
  interface_addrs, interface_by_index, interface_by_name, interfaces, Flags, Interface, IpIf,
};

use iprobe::{ipv4, ipv6};

#[derive(Debug)]
struct IfStats {
  loopback: u32, // # of active loopback interfaces
  other: u32,    // # of active other interfaces
}

impl IfStats {
  fn stats(ift: &[Interface]) -> Self {
    let mut loopback = 0;
    let mut other = 0;
    for ifi in ift {
      if ifi.flags().contains(Flags::UP) {
        if ifi.flags().contains(Flags::LOOPBACK) {
          loopback += 1;
        } else {
          other += 1;
        }
      }
    }

    Self { loopback, other }
  }
}

#[derive(Default, Debug)]
struct RouteStats {
  ipv4: u32, // # of active connected unicast or multicast addrs
  ipv6: u32, // # of active connected unicast or multicast addrs
}

fn validate_interface_unicast_addrs(ifat: &[IpIf]) -> std::io::Result<RouteStats> {
  // Note: BSD variants allow assigning any IPv4/IPv6 address
  // prefix to IP interface. For example,
  //   - 0.0.0.0/0 through 255.255.255.255/32
  //   - ::/0 through ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128
  // In other words, there is no tightly-coupled combination of
  // interface address prefixes and connected routes.
  let mut stats = RouteStats::default();
  for ifa in ifat {
    if ifa.addr().is_multicast() {
      return Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("unexpected multicast address: {ifa:?}"),
      ));
    }

    let prefix_len = ifa.prefix_len().unwrap();
    let max_prefix_len = ifa.max_prefix_len().unwrap();
    match ifa.addr() {
      IpAddr::V4(addr) => {
        if prefix_len == 0 || prefix_len > 8 * 4 || max_prefix_len != 8 * 4 {
          return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected prefix length {ifa:?}"),
          ));
        }

        if addr.is_loopback() && prefix_len < 8 {
          // see RFC 1122
          return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected prefix length",
          ));
        }

        stats.ipv4 += 1;
      }
      IpAddr::V6(addr) => {
        if prefix_len == 0 || prefix_len > 8 * 16 || max_prefix_len != 8 * 16 {
          return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected prefix length {ifa:?}"),
          ));
        }

        if addr.is_loopback() && prefix_len < 8 {
          // see RFC 1122
          return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected prefix length",
          ));
        }

        stats.ipv6 += 1;
      }
    }
  }

  Ok(stats)
}

fn check_unicast_stats(ifstats: &IfStats, uni_stats: &RouteStats) -> std::io::Result<()> {
  // Test the existence of connected unicast routes for IPv4.
  if ipv4() && ifstats.loopback + ifstats.other > 0 && uni_stats.ipv4 == 0 {
    return Err(std::io::Error::new(
      std::io::ErrorKind::InvalidData,
      "num Ipv4 unicast routes = 0; want>0; summary:{ifstats:?}, {uni_stats:?}",
    ));
  }

  // Test the existence of connected unicast routes for IPv6.
  // We can assume the existence of ::1/128 when at least one
  // loopback interface is installed.
  if ipv6() && ifstats.loopback > 0 && uni_stats.ipv6 == 0 {
    return Err(std::io::Error::new(
      std::io::ErrorKind::InvalidData,
      format!("num Ipv6 unicast routes = 0; want>0; summary:{ifstats:?}, {uni_stats:?}"),
    ));
  }

  Ok(())
}

fn validate_interface_multicast_addrs(ifmat: &[IpAddr]) -> std::io::Result<RouteStats> {
  let mut stats = RouteStats::default();
  for ifa in ifmat {
    if ifa.is_unspecified() || !ifa.is_multicast() {
      return Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("unexpected unicast address: {ifa}"),
      ));
    }

    match ifa {
      IpAddr::V4(addr) => {
        if addr.is_multicast() {
          stats.ipv4 += 1;
        }
      }
      IpAddr::V6(addr) => {
        if addr.is_multicast() {
          stats.ipv6 += 1;
        }
      }
    }
  }

  Ok(stats)
}

fn check_multicast_stats(
  ifstats: &IfStats,
  uni_stats: &RouteStats,
  multi_stats: &RouteStats,
) -> std::io::Result<()> {
  // Test the existence of connected multicast route
  // clones for IPv4. Unlike IPv6, IPv4 multicast
  // capability is not a mandatory feature, and so IPv4
  // multicast validation is ignored and we only check
  // IPv6 below.
  //
  // Test the existence of connected multicast route
  // clones for IPv6. Some platform never uses loopback
  // interface as the nexthop for multicast routing.
  // We can assume the existence of connected multicast
  // route clones when at least two connected unicast
  // routes, ::1/128 and other, are installed.
  if ipv6() && ifstats.loopback > 0 && uni_stats.ipv6 > 1 && multi_stats.ipv6 == 0 {
    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("num Ipv6 multicast routes = 0; want>0; summary:{ifstats:?}, {uni_stats:?}, {multi_stats:?}")));
  }

  Ok(())
}

#[test]
fn ifis() {
  let ift = interfaces().unwrap();

  for ifi in ift {
    println!(
      "{}: flags={:?} index={} mtu={} hwaddr={:?}",
      ifi.name(),
      ifi.flags(),
      ifi.index(),
      ifi.mtu(),
      ifi.mac_addr()
    );

    let ifxi = interface_by_index(ifi.index()).unwrap().unwrap();
    assert_eq!(ifi, ifxi);

    let ifxn = interface_by_name(ifi.name()).unwrap().unwrap();

    assert_eq!(ifi, ifxn);
  }
}

#[test]
fn if_addrs() {
  let ift = interfaces().unwrap();
  let stats = IfStats::stats(&ift);
  let ifat = interface_addrs().unwrap();
  for ifa in &ifat {
    println!("{:?}", ifa);
  }

  let uni_stats = validate_interface_unicast_addrs(&ifat).unwrap();

  check_unicast_stats(&stats, &uni_stats).unwrap();
}

#[test]
#[cfg(not(windows))]
fn if_unicast_addrs() {
  let ift = interfaces().unwrap();
  let if_stats = IfStats::stats(&ift);

  let mut uni_stats = RouteStats::default();
  for ifi in ift {
    let ifat = ifi.addrs();

    let stats = validate_interface_unicast_addrs(ifat).unwrap();

    uni_stats.ipv4 += stats.ipv4;
    uni_stats.ipv6 += stats.ipv6;
  }

  check_unicast_stats(&if_stats, &uni_stats).unwrap();
}

#[test]
#[cfg(not(windows))]
fn if_multicast_addrs() {
  let ift = interfaces().unwrap();
  let if_stats = IfStats::stats(&ift);
  let ifat = interface_addrs().unwrap();

  let uni_stats = validate_interface_unicast_addrs(&ifat).unwrap();

  let mut multi_stats = RouteStats::default();

  for ifi in ift {
    let ifmat = ifi.multicast_addrs().unwrap();

    let stats = validate_interface_multicast_addrs(&ifmat).unwrap();

    multi_stats.ipv4 += stats.ipv4;
    multi_stats.ipv6 += stats.ipv6;
  }

  check_multicast_stats(&if_stats, &uni_stats, &multi_stats).unwrap();
}
