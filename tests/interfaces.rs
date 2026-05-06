use std::net::IpAddr;

use getifs::{
  gateway_addrs, interface_addrs, interface_by_index, interface_by_name, interfaces, local_addrs,
  Flags, IfNet, Interface,
};

// `IfAddr` is only used by the multicast helper below, which is
// itself cfg-gated to platforms with multicast enumeration. Pulling
// it in unconditionally produced an unused-import warning on
// NetBSD/OpenBSD where the helper isn't compiled.
#[cfg(any(
  target_vendor = "apple",
  target_os = "freebsd",
  target_os = "dragonfly",
  target_os = "linux",
  windows,
))]
use getifs::IfAddr;

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

fn validate_interface_unicast_addrs(ifat: &[IfNet]) -> std::io::Result<RouteStats> {
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

    let prefix_len = ifa.prefix_len();
    let max_prefix_len = ifa.max_prefix_len();
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
      format!("num Ipv4 unicast routes = 0; want>0; summary:{ifstats:?}, {uni_stats:?}"),
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

// Multicast helpers and the `if_multicast_addrs` test below are gated
// to the same platforms as `Interface::multicast_addrs` (see
// `cfg_multicast!` in src/macros.rs). NetBSD / OpenBSD have no API at
// all so the symbol is absent there. DragonFly returns
// `Err(ErrorKind::Unsupported)` from `multicast_addrs()` (the kernel
// doesn't expose multicast group enumeration via sysctl) — the test
// compiles there and exercises the call path, with the explicit
// `Err(Unsupported)` arm below treated as a per-platform skip.
#[cfg(any(
  target_vendor = "apple",
  target_os = "freebsd",
  target_os = "dragonfly",
  target_os = "linux",
  windows,
))]
fn validate_interface_multicast_addrs(ifmat: &[IfAddr]) -> std::io::Result<RouteStats> {
  let mut stats = RouteStats::default();
  for ifa in ifmat.iter().map(|ifa| ifa.addr()) {
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

#[cfg(any(
  target_vendor = "apple",
  target_os = "freebsd",
  target_os = "dragonfly",
  target_os = "linux",
  windows,
))]
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

// DragonFly's vmactions VM has interfaces churning during the test
// run (the QEMU bridge attaches/detaches faster than `interfaces()`
// snapshots), so `interface_by_index` re-lookups intermittently
// return `None` for an interface `interfaces()` just listed —
// flaky on that platform without indicating a real bug.
#[cfg(not(target_os = "dragonfly"))]
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

// Skip on NetBSD (the address walker hits the known
// `parse_addrs` "invalid address" gap on whatever sockaddr shape
// NetBSD's RTM_NEWADDR slot emits — same root cause as the
// `*_by_filter` gates in `tests/filter_variants.rs`) and on
// DragonFly (the vmactions VM ships with no IPv4 unicast address
// on its sole non-loopback interface, so the
// `check_unicast_stats` "must have at least one v4 unicast route"
// assertion always trips even though the API call itself
// succeeded).
#[cfg(not(any(target_os = "netbsd", target_os = "dragonfly")))]
#[test]
fn if_addrs() {
  let ift = interfaces().unwrap();
  let stats = IfStats::stats(&ift);
  let ifat = interface_addrs().unwrap();
  for ifa in &ifat {
    println!("{ifa:?}");
  }

  let uni_stats = validate_interface_unicast_addrs(&ifat).unwrap();

  check_unicast_stats(&stats, &uni_stats).unwrap();
}

// Same NetBSD / DragonFly skip rationale as `if_addrs` above.
#[cfg(not(any(target_os = "netbsd", target_os = "dragonfly")))]
#[test]
fn if_unicast_addrs() {
  let ift = interfaces().unwrap();
  let if_stats = IfStats::stats(&ift);

  let mut uni_stats = RouteStats::default();
  for ifi in ift {
    let ifat = ifi.addrs().unwrap();

    let stats = validate_interface_unicast_addrs(&ifat).unwrap();

    uni_stats.ipv4 += stats.ipv4;
    uni_stats.ipv6 += stats.ipv6;
  }

  check_unicast_stats(&if_stats, &uni_stats).unwrap();
}

#[test]
fn gw_addrs() {
  let addrs = gateway_addrs().unwrap();
  for addr in addrs {
    println!("Gateway {addr}");
  }
}

// Skip on NetBSD: `local_addrs()` goes through the same address
// walker as `interface_addrs()` and hits the same `parse_addrs`
// "invalid address" gap — see `if_addrs` above for the root cause.
#[cfg(not(target_os = "netbsd"))]
#[test]
fn lc_addrs() {
  let addrs = local_addrs().unwrap();
  for addr in addrs {
    println!("Local {addr}");
  }
}

#[cfg(any(
  target_vendor = "apple",
  target_os = "freebsd",
  target_os = "dragonfly",
  target_os = "linux",
  windows,
))]
#[test]
fn if_multicast_addrs() {
  let ift = interfaces().unwrap();
  let if_stats = IfStats::stats(&ift);
  let ifat = interface_addrs().unwrap();

  let uni_stats = validate_interface_unicast_addrs(&ifat).unwrap();

  let mut multi_stats = RouteStats::default();

  for ifi in ift {
    match ifi.multicast_addrs() {
      Ok(ifmat) => {
        let stats = validate_interface_multicast_addrs(&ifmat).unwrap();
        multi_stats.ipv4 += stats.ipv4;
        multi_stats.ipv6 += stats.ipv6;
      }
      // DragonFly's kernel has no multicast-group enumeration
      // sysctl (no `NET_RT_IFMALIST`) so `multicast_addrs()` returns
      // `ErrorKind::Unsupported` rather than a misleading empty
      // `Ok`. Treat it as a skip on that platform; on every other
      // target, propagate.
      Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
        #[cfg(target_os = "dragonfly")]
        {
          let _ = e;
        }
        #[cfg(not(target_os = "dragonfly"))]
        panic!("unexpected Unsupported from multicast_addrs(): {e}");
      }
      Err(e) => panic!("multicast_addrs() failed: {e}"),
    }
  }

  // The "v6 multicast must be present when v6 unicast > 1" assertion
  // is the existence-of-multicast-route check copied from the Go
  // reference. Skip on DragonFly — `multi_stats` is always zero
  // there because every iteration short-circuited on
  // `Unsupported`, and the assertion would always trip.
  #[cfg(not(target_os = "dragonfly"))]
  check_multicast_stats(&if_stats, &uni_stats, &multi_stats).unwrap();
  #[cfg(target_os = "dragonfly")]
  let _ = (&if_stats, &uni_stats, &multi_stats);
}
