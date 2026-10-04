//! Smoke tests for every public `*_by_filter` variant.
//!
//! The functions are generic wrappers around an `os::*` implementation. These
//! tests exercise the call and closure paths without assuming a public IP,
//! default route, or any particular address family is configured on the host.

use std::io;

use common::interface_disappeared;
use getifs::{
  gateway_addrs_by_filter, gateway_ipv4_addrs_by_filter, gateway_ipv6_addrs_by_filter,
  interface_addrs_by_filter, interface_ipv4_addrs_by_filter, interface_ipv6_addrs_by_filter,
  interfaces, local_addrs_by_filter, local_ipv4_addrs_by_filter, local_ipv6_addrs_by_filter,
  private_addrs_by_filter, private_ipv4_addrs_by_filter, private_ipv6_addrs_by_filter,
  public_addrs_by_filter, public_ipv4_addrs_by_filter, public_ipv6_addrs_by_filter,
};

mod common;

#[cfg(any(
  target_vendor = "apple",
  target_os = "freebsd",
  target_os = "dragonfly",
  target_os = "netbsd",
  target_os = "openbsd",
  target_os = "linux",
  target_os = "android",
  windows,
))]
fn assert_multicast_result<T>(result: io::Result<T>) {
  #[cfg(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
  ))]
  match result {
    Err(error) => assert_eq!(error.kind(), io::ErrorKind::Unsupported),
    Ok(_) => panic!("multicast enumeration unexpectedly succeeded"),
  }

  #[cfg(not(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
  )))]
  if let Err(error) = result {
    panic!("multicast enumeration failed: {error}");
  }
}

#[test]
fn private_ipv4_addrs_by_filter_runs() {
  let mut seen = 0usize;
  private_ipv4_addrs_by_filter(|_| {
    seen += 1;
    true
  })
  .expect("private_ipv4_addrs_by_filter");
  let _ = seen;
}

#[test]
fn private_ipv6_addrs_by_filter_runs() {
  let mut seen = 0usize;
  private_ipv6_addrs_by_filter(|_| {
    seen += 1;
    true
  })
  .expect("private_ipv6_addrs_by_filter");
  let _ = seen;
}

#[test]
fn private_addrs_by_filter_runs() {
  let mut seen = 0usize;
  private_addrs_by_filter(|_| {
    seen += 1;
    true
  })
  .expect("private_addrs_by_filter");
  let _ = seen;
}

#[test]
fn public_ipv4_addrs_by_filter_runs() {
  let mut seen = 0usize;
  public_ipv4_addrs_by_filter(|_| {
    seen += 1;
    true
  })
  .expect("public_ipv4_addrs_by_filter");
  let _ = seen;
}

#[test]
fn public_ipv6_addrs_by_filter_runs() {
  let mut seen = 0usize;
  public_ipv6_addrs_by_filter(|_| {
    seen += 1;
    true
  })
  .expect("public_ipv6_addrs_by_filter");
  let _ = seen;
}

#[test]
fn public_addrs_by_filter_runs() {
  let mut seen = 0usize;
  public_addrs_by_filter(|_| {
    seen += 1;
    true
  })
  .expect("public_addrs_by_filter");
  let _ = seen;
}

#[test]
fn local_ipv4_addrs_by_filter_runs() {
  let mut seen = 0usize;
  local_ipv4_addrs_by_filter(|_| {
    seen += 1;
    true
  })
  .expect("local_ipv4_addrs_by_filter");
  let _ = seen;
}

#[test]
fn local_ipv6_addrs_by_filter_runs() {
  let mut seen = 0usize;
  local_ipv6_addrs_by_filter(|_| {
    seen += 1;
    true
  })
  .expect("local_ipv6_addrs_by_filter");
  let _ = seen;
}

#[test]
fn local_addrs_by_filter_runs() {
  let mut seen = 0usize;
  local_addrs_by_filter(|_| {
    seen += 1;
    true
  })
  .expect("local_addrs_by_filter");
  let _ = seen;
}

#[test]
fn gateway_addrs_by_filter_runs() {
  let mut seen = 0usize;
  gateway_addrs_by_filter(|_| {
    seen += 1;
    true
  })
  .expect("gateway_addrs_by_filter");
  let _ = seen;
}

#[test]
fn gateway_ipv4_addrs_by_filter_runs() {
  let mut seen = 0usize;
  gateway_ipv4_addrs_by_filter(|_| {
    seen += 1;
    true
  })
  .expect("gateway_ipv4_addrs_by_filter");
  let _ = seen;
}

#[test]
fn gateway_ipv6_addrs_by_filter_runs() {
  let mut seen = 0usize;
  gateway_ipv6_addrs_by_filter(|_| {
    seen += 1;
    true
  })
  .expect("gateway_ipv6_addrs_by_filter");
  let _ = seen;
}

#[test]
fn interface_addrs_by_filter_runs() {
  let mut seen = 0usize;
  interface_addrs_by_filter(|_| {
    seen += 1;
    true
  })
  .expect("interface_addrs_by_filter");
  let _ = seen;
}

#[test]
fn interface_ipv4_addrs_by_filter_runs() {
  let mut seen = 0usize;
  interface_ipv4_addrs_by_filter(|_| {
    seen += 1;
    true
  })
  .expect("interface_ipv4_addrs_by_filter");
  let _ = seen;
}

#[test]
fn interface_ipv6_addrs_by_filter_runs() {
  let mut seen = 0usize;
  interface_ipv6_addrs_by_filter(|_| {
    seen += 1;
    true
  })
  .expect("interface_ipv6_addrs_by_filter");
  let _ = seen;
}

#[cfg(any(
  target_vendor = "apple",
  target_os = "freebsd",
  target_os = "dragonfly",
  target_os = "netbsd",
  target_os = "openbsd",
  target_os = "linux",
  target_os = "android",
  windows,
))]
mod multicast {
  use super::assert_multicast_result;
  use getifs::{
    interface_multicast_addrs_by_filter, interface_multicast_ipv4_addrs_by_filter,
    interface_multicast_ipv6_addrs_by_filter,
  };

  #[test]
  fn interface_multicast_addrs_by_filter_runs() {
    assert_multicast_result(interface_multicast_addrs_by_filter(|_| true));
  }

  #[test]
  fn interface_multicast_ipv4_addrs_by_filter_runs() {
    assert_multicast_result(interface_multicast_ipv4_addrs_by_filter(|_| true));
  }

  #[test]
  fn interface_multicast_ipv6_addrs_by_filter_runs() {
    assert_multicast_result(interface_multicast_ipv6_addrs_by_filter(|_| true));
  }
}

#[test]
fn interface_method_addrs_by_filter_runs() {
  let snapshot = interfaces().expect("interfaces()");
  assert!(
    !snapshot.is_empty(),
    "at least the loopback interface should exist"
  );

  for interface in snapshot {
    let index = interface.index();
    let name = interface.name().to_string();
    if let Err(error) = interface.addrs_by_filter(|_| true) {
      if interface_disappeared(index, &name) {
        continue;
      }
      panic!("{name} addrs_by_filter failed: {error}");
    }
    if let Err(error) = interface.ipv4_addrs_by_filter(|_| true) {
      if interface_disappeared(index, &name) {
        continue;
      }
      panic!("{name} ipv4_addrs_by_filter failed: {error}");
    }
    if let Err(error) = interface.ipv6_addrs_by_filter(|_| true) {
      if interface_disappeared(index, &name) {
        continue;
      }
      panic!("{name} ipv6_addrs_by_filter failed: {error}");
    }
  }
}

#[cfg(any(
  target_vendor = "apple",
  target_os = "freebsd",
  target_os = "dragonfly",
  target_os = "netbsd",
  target_os = "openbsd",
  target_os = "linux",
  target_os = "android",
  windows,
))]
#[test]
fn interface_method_multicast_addrs_by_filter_runs() {
  let snapshot = interfaces().expect("interfaces()");
  assert!(
    !snapshot.is_empty(),
    "at least the loopback interface should exist"
  );

  for interface in snapshot {
    assert_multicast_result(interface.multicast_addrs_by_filter(|_| true));
    assert_multicast_result(interface.ipv4_multicast_addrs_by_filter(|_| true));
    assert_multicast_result(interface.ipv6_multicast_addrs_by_filter(|_| true));
  }
}
