//! Structural smoke coverage for the 0.8 Rust-native query APIs.
//!
//! These calls intentionally make no assumptions about a WAN address or a
//! default route. `None` and empty family slices are valid host states.

use std::io;

use getifs::rfc::{FORWARDING_BLACKLIST, RFC6890};
use getifs::{
  default_interfaces, order, predicate, preferred_private_addr, preferred_private_addr_by,
  preferred_private_ipv4_addr, preferred_private_ipv4_addr_by, preferred_private_ipv6_addr,
  preferred_private_ipv6_addr_by, preferred_public_addr, preferred_public_addr_by,
  preferred_public_ipv4_addr, preferred_public_ipv4_addr_by, preferred_public_ipv6_addr,
  preferred_public_ipv6_addr_by, Flags, IfNet, Interface, InterfaceSnapshot,
};

fn assert_default_slice(interfaces: &[Interface]) {
  for pair in interfaces.windows(2) {
    assert!(pair[0].index() < pair[1].index());
  }
  assert!(interfaces.iter().all(|interface| interface.index() != 0));
}

fn assert_public(candidate: Option<IfNet>) {
  if let Some(candidate) = candidate {
    assert!(!RFC6890.contains(&candidate.addr()));
    assert!(!FORWARDING_BLACKLIST.contains(&candidate.addr()));
  }
}

fn assert_private(candidate: Option<IfNet>) {
  if let Some(candidate) = candidate {
    assert!(RFC6890.contains(&candidate.addr()));
    assert!(!FORWARDING_BLACKLIST.contains(&candidate.addr()));
  }
}

#[test]
fn rust_native_snapshot_default_and_preferred_apis_smoke() -> io::Result<()> {
  let snapshot = InterfaceSnapshot::capture()?;
  for record in snapshot.iter() {
    assert_eq!(record.index(), record.interface().index());
    assert_eq!(record.index(), record.network().index());
  }
  assert!(snapshot
    .matching(predicate::flags(Flags::UP))
    .all(|record| record.interface().flags().contains(Flags::UP)));

  let defaults = default_interfaces()?;
  assert_default_slice(defaults.ipv4());
  assert_default_slice(defaults.ipv6());

  assert_public(preferred_public_addr()?);
  assert_public(preferred_public_ipv4_addr()?.map(IfNet::from));
  assert_public(preferred_public_ipv6_addr()?.map(IfNet::from));
  assert_private(preferred_private_addr()?);
  assert_private(preferred_private_ipv4_addr()?.map(IfNet::from));
  assert_private(preferred_private_ipv6_addr()?.map(IfNet::from));

  assert_public(preferred_public_addr_by(order::by_interface_index())?);
  assert_public(preferred_public_ipv4_addr_by(order::by_interface_index())?.map(IfNet::from));
  assert_public(preferred_public_ipv6_addr_by(order::by_interface_index())?.map(IfNet::from));
  assert_private(preferred_private_addr_by(order::by_interface_index())?);
  assert_private(preferred_private_ipv4_addr_by(order::by_interface_index())?.map(IfNet::from));
  assert_private(preferred_private_ipv6_addr_by(order::by_interface_index())?.map(IfNet::from));

  Ok(())
}
