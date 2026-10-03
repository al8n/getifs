use std::io;

use getifs::{
  gateway_addrs, interface_addrs, interface_by_index, interface_by_name, interfaces, local_addrs,
  Flags, IfNet, Interface,
};

#[cfg(any(
  target_vendor = "apple",
  target_os = "freebsd",
  target_os = "linux",
  windows,
))]
use getifs::IfAddr;

fn assert_meaningful_snapshot(interfaces: &[Interface]) {
  assert!(
    !interfaces.is_empty(),
    "interfaces() must include at least the loopback interface"
  );
  assert!(
    interfaces
      .iter()
      .any(|interface| interface.flags().contains(Flags::LOOPBACK)),
    "interfaces() must include a loopback fixture"
  );
}

fn interface_disappeared(index: u32, name: &str) -> bool {
  !interfaces()
    .expect("refresh interface snapshot after lookup race")
    .iter()
    .any(|interface| interface.index() == index && interface.name().as_str() == name)
}

fn validate_interface_unicast_addrs(addrs: &[IfNet]) -> io::Result<()> {
  for addr in addrs {
    if addr.addr().is_multicast() {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unexpected multicast address: {addr:?}"),
      ));
    }

    if addr.prefix_len() > addr.max_prefix_len() {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unexpected prefix length: {addr:?}"),
      ));
    }
  }

  Ok(())
}

#[cfg(any(
  target_vendor = "apple",
  target_os = "freebsd",
  target_os = "linux",
  windows,
))]
fn validate_interface_multicast_addrs(addrs: &[IfAddr]) -> io::Result<()> {
  for addr in addrs.iter().map(IfAddr::addr) {
    if addr.is_unspecified() || !addr.is_multicast() {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unexpected non-multicast address: {addr}"),
      ));
    }
  }

  Ok(())
}

#[test]
fn ifis() {
  let snapshot = interfaces().unwrap();
  assert_meaningful_snapshot(&snapshot);

  for interface in snapshot {
    let index = interface.index();
    let name = interface.name().to_string();
    println!(
      "{}: flags={:?} index={} mtu={} hwaddr={:?}",
      name,
      interface.flags(),
      index,
      interface.mtu(),
      interface.mac_addr()
    );

    match interface_by_index(index) {
      Ok(Some(found)) => {
        assert_eq!(found.index(), index);
        assert_eq!(found.name().as_str(), name);
      }
      Ok(None) if interface_disappeared(index, &name) => continue,
      Ok(None) => panic!("interface_by_index({index}) lost a still-present {name}"),
      Err(_) if interface_disappeared(index, &name) => continue,
      Err(error) => panic!("interface_by_index({index}) failed for {name}: {error}"),
    }

    match interface_by_name(&name) {
      Ok(Some(found)) => {
        assert_eq!(found.index(), index);
        assert_eq!(found.name().as_str(), name);
      }
      Ok(None) if interface_disappeared(index, &name) => continue,
      Ok(None) => panic!("interface_by_name({name}) lost a still-present interface"),
      Err(_) if interface_disappeared(index, &name) => continue,
      Err(error) => panic!("interface_by_name({name}) failed: {error}"),
    }
  }
}

#[test]
fn if_addrs() {
  let snapshot = interfaces().unwrap();
  assert_meaningful_snapshot(&snapshot);

  let addrs = interface_addrs().unwrap();
  for addr in &addrs {
    println!("{addr:?}");
  }
  validate_interface_unicast_addrs(&addrs).unwrap();
  assert!(
    addrs.iter().any(|addr| addr.addr().is_loopback()),
    "interface_addrs() must retain a loopback address fixture"
  );
}

#[test]
fn if_unicast_addrs() {
  let snapshot = interfaces().unwrap();
  assert_meaningful_snapshot(&snapshot);

  let mut saw_loopback = false;
  for interface in snapshot {
    let index = interface.index();
    let name = interface.name().to_string();
    let addrs = match interface.addrs() {
      Ok(addrs) => addrs,
      Err(_) if interface_disappeared(index, &name) => continue,
      Err(error) => panic!("{} addrs failed: {error}", name),
    };

    validate_interface_unicast_addrs(&addrs).unwrap();
    assert!(
      addrs.iter().all(|addr| addr.index() == index),
      "{} returned an address for another interface",
      name
    );
    if interface.flags().contains(Flags::LOOPBACK) {
      saw_loopback |= addrs.iter().any(|addr| addr.addr().is_loopback());
    }
  }

  assert!(
    saw_loopback,
    "loopback interface must retain a loopback address"
  );
}

#[test]
fn gw_addrs() {
  let addrs = gateway_addrs().unwrap();
  for addr in addrs {
    println!("Gateway {addr}");
  }
}

#[test]
fn lc_addrs() {
  let addrs = local_addrs().unwrap();
  for addr in addrs {
    assert!(
      !addr.addr().is_multicast(),
      "unexpected multicast local address: {addr:?}"
    );
    println!("Local {addr}");
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
fn if_multicast_addrs() {
  let snapshot = interfaces().unwrap();
  assert_meaningful_snapshot(&snapshot);

  for interface in snapshot {
    let result = interface.multicast_addrs();

    #[cfg(any(
      target_os = "android",
      target_os = "dragonfly",
      target_os = "netbsd",
      target_os = "openbsd",
    ))]
    match result {
      Err(error) => assert_eq!(error.kind(), io::ErrorKind::Unsupported),
      Ok(addrs) => panic!(
        "{} unexpectedly enumerated {} multicast addresses",
        interface.name(),
        addrs.len()
      ),
    }

    #[cfg(not(any(
      target_os = "android",
      target_os = "dragonfly",
      target_os = "netbsd",
      target_os = "openbsd",
    )))]
    validate_interface_multicast_addrs(&result.unwrap()).unwrap();
  }
}
