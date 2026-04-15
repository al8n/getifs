//! Smoke tests for every public `*_by_filter` variant.
//!
//! Each `*_by_filter` function is a generic wrapper around an
//! `os::*`-dispatched implementation. Without an explicit caller, the
//! only coverage they get is through doctests — and tarpaulin's
//! attribution for monomorphized generic functions is unreliable, so
//! that coverage doesn't show up in the CI report. These tests invoke
//! every variant with a trivial `|_| true` closure so the CI tarpaulin
//! run can record real instrumented line-hits against them.
//!
//! The tests don't assert on *what* the filter saw — the address set
//! of a GitHub-Actions runner isn't fixed — only that:
//!   1. the outer call returned `Ok`, and
//!   2. the filter closure was reachable (the function actually
//!      entered the per-address loop).
//!
//! Point (2) is tracked via an invocation counter. We deliberately do
//! not assert `counter > 0` because a minimally-configured sandbox
//! could legitimately have zero addresses of a given family.

use getifs::{
  gateway_addrs_by_filter, gateway_ipv4_addrs_by_filter, gateway_ipv6_addrs_by_filter,
  interface_addrs_by_filter, interface_ipv4_addrs_by_filter, interface_ipv6_addrs_by_filter,
  interfaces, local_addrs_by_filter, local_ipv4_addrs_by_filter, local_ipv6_addrs_by_filter,
  private_addrs_by_filter, private_ipv4_addrs_by_filter, private_ipv6_addrs_by_filter,
  public_addrs_by_filter, public_ipv4_addrs_by_filter, public_ipv6_addrs_by_filter,
};

// ---------------------------------------------------------------------
// Free `*_by_filter` functions — private / public / local / gateway /
// interface address enumeration.
// ---------------------------------------------------------------------

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

// ---------------------------------------------------------------------
// Multicast free functions — gated to the same platforms as the
// `cfg_multicast!` macro (Apple, FreeBSD, Linux, Windows).
// ---------------------------------------------------------------------

#[cfg(any(
  target_vendor = "apple",
  target_os = "freebsd",
  target_os = "linux",
  windows
))]
mod multicast {
  use getifs::{
    interface_multicast_addrs_by_filter, interface_multicast_ipv4_addrs_by_filter,
    interface_multicast_ipv6_addrs_by_filter,
  };

  #[test]
  fn interface_multicast_addrs_by_filter_runs() {
    let mut seen = 0usize;
    interface_multicast_addrs_by_filter(|_| {
      seen += 1;
      true
    })
    .expect("interface_multicast_addrs_by_filter");
    let _ = seen;
  }

  #[test]
  fn interface_multicast_ipv4_addrs_by_filter_runs() {
    let mut seen = 0usize;
    interface_multicast_ipv4_addrs_by_filter(|_| {
      seen += 1;
      true
    })
    .expect("interface_multicast_ipv4_addrs_by_filter");
    let _ = seen;
  }

  #[test]
  fn interface_multicast_ipv6_addrs_by_filter_runs() {
    let mut seen = 0usize;
    interface_multicast_ipv6_addrs_by_filter(|_| {
      seen += 1;
      true
    })
    .expect("interface_multicast_ipv6_addrs_by_filter");
    let _ = seen;
  }
}

// ---------------------------------------------------------------------
// Methods on `Interface`. These are generic too, and are only reached
// when the caller iterates `interfaces()` and invokes them per-entry.
// The loopback interface is guaranteed to exist on every reasonable
// runner, so these tests will always have at least one Interface to
// exercise.
// ---------------------------------------------------------------------

#[test]
fn interface_method_addrs_by_filter_runs() {
  let ift = interfaces().expect("interfaces()");
  assert!(
    !ift.is_empty(),
    "at least the loopback interface should exist"
  );
  for ifi in ift {
    let _ = ifi.addrs_by_filter(|_| true).expect("addrs_by_filter");
    let _ = ifi
      .ipv4_addrs_by_filter(|_| true)
      .expect("ipv4_addrs_by_filter");
    let _ = ifi
      .ipv6_addrs_by_filter(|_| true)
      .expect("ipv6_addrs_by_filter");
  }
}

#[cfg(any(
  target_vendor = "apple",
  target_os = "freebsd",
  target_os = "linux",
  windows
))]
#[test]
fn interface_method_multicast_addrs_by_filter_runs() {
  let ift = interfaces().expect("interfaces()");
  assert!(
    !ift.is_empty(),
    "at least the loopback interface should exist"
  );
  for ifi in ift {
    let _ = ifi
      .multicast_addrs_by_filter(|_| true)
      .expect("multicast_addrs_by_filter");
    let _ = ifi
      .ipv4_multicast_addrs_by_filter(|_| true)
      .expect("ipv4_multicast_addrs_by_filter");
    let _ = ifi
      .ipv6_multicast_addrs_by_filter(|_| true)
      .expect("ipv6_multicast_addrs_by_filter");
  }
}
