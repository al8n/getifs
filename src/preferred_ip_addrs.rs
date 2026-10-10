use std::io;

use iprfc::{FORWARDING_BLACKLIST, RFC6890};
use smallvec_wrapper::SmallVec;

use super::{
  default_interfaces::join_default_interfaces, order, os, AddressComparator, DefaultInterfaces,
  Flags, IfNet, Ifv4Net, Ifv6Net, Interface, InterfaceAddress, InterfaceSnapshot,
};

/// Returns the preferred forwardable public IPv4 or IPv6 interface address.
///
/// A candidate must be on an administratively-up interface, outside RFC 6890,
/// and outside the forwarding blacklist. Default-route membership is a
/// preference, not a requirement. The default ranking is, in order:
///
/// 1. An interface selected by that address family's default route.
/// 2. IPv4 before IPv6.
/// 3. A larger network (smaller prefix length).
/// 4. A lower interface index.
/// 5. A numerically smaller address.
/// 6. A lexicographically smaller cached interface name.
///
/// The first captured candidate wins a complete tie. An IPv6 default-route
/// candidate therefore outranks a nondefault IPv4 candidate; IPv4-before-IPv6
/// applies only after family-default membership ties. `Ok(None)` means no
/// eligible joined record was captured, including when no default route exists.
/// I/O, permission, and route-parse failures are returned as `Err`.
pub fn preferred_public_addr() -> io::Result<Option<IfNet>> {
  preferred_default(Class::Public, Family::Any)
}

/// Returns the preferred forwardable public IPv4 interface address.
///
/// Only IPv4 candidates and IPv4 default-route membership participate, so the
/// mixed-family IPv4-before-IPv6 tie-break does not apply.
pub fn preferred_public_ipv4_addr() -> io::Result<Option<Ifv4Net>> {
  preferred_default(Class::Public, Family::V4).map(as_v4)
}

/// Returns the preferred forwardable public IPv6 interface address.
///
/// Only IPv6 candidates and IPv6 default-route membership participate, so the
/// mixed-family IPv4-before-IPv6 tie-break does not apply.
pub fn preferred_public_ipv6_addr() -> io::Result<Option<Ifv6Net>> {
  preferred_default(Class::Public, Family::V6).map(as_v6)
}

/// Returns the preferred forwardable private IPv4 or IPv6 interface address.
///
/// Private uses the crate's RFC 6890 classification: the address must be in
/// RFC 6890 and outside the forwarding blacklist, and its interface must be
/// administratively up. Its ranking and `Ok(None)`/`Err` behavior are the same
/// as [`preferred_public_addr`].
pub fn preferred_private_addr() -> io::Result<Option<IfNet>> {
  preferred_default(Class::Private, Family::Any)
}

/// Returns the preferred forwardable private IPv4 interface address.
pub fn preferred_private_ipv4_addr() -> io::Result<Option<Ifv4Net>> {
  preferred_default(Class::Private, Family::V4).map(as_v4)
}

/// Returns the preferred forwardable private IPv6 interface address.
pub fn preferred_private_ipv6_addr() -> io::Result<Option<Ifv6Net>> {
  preferred_default(Class::Private, Family::V6).map(as_v6)
}

/// Returns the preferred eligible public address using `order` instead of the
/// complete default ranking.
///
/// `order` cannot make down, forwarding-blacklisted, or RFC-misclassified
/// addresses eligible. A complete tie still keeps the first captured candidate.
pub fn preferred_public_addr_by<C>(order: C) -> io::Result<Option<IfNet>>
where
  C: AddressComparator,
{
  preferred_by(Class::Public, Family::Any, order)
}

/// Returns the preferred eligible public IPv4 address using `order`.
pub fn preferred_public_ipv4_addr_by<C>(order: C) -> io::Result<Option<Ifv4Net>>
where
  C: AddressComparator,
{
  preferred_by(Class::Public, Family::V4, order).map(as_v4)
}

/// Returns the preferred eligible public IPv6 address using `order`.
pub fn preferred_public_ipv6_addr_by<C>(order: C) -> io::Result<Option<Ifv6Net>>
where
  C: AddressComparator,
{
  preferred_by(Class::Public, Family::V6, order).map(as_v6)
}

/// Returns the preferred eligible private address using `order` instead of the
/// complete default ranking.
pub fn preferred_private_addr_by<C>(order: C) -> io::Result<Option<IfNet>>
where
  C: AddressComparator,
{
  preferred_by(Class::Private, Family::Any, order)
}

/// Returns the preferred eligible private IPv4 address using `order`.
pub fn preferred_private_ipv4_addr_by<C>(order: C) -> io::Result<Option<Ifv4Net>>
where
  C: AddressComparator,
{
  preferred_by(Class::Private, Family::V4, order).map(as_v4)
}

/// Returns the preferred eligible private IPv6 address using `order`.
pub fn preferred_private_ipv6_addr_by<C>(order: C) -> io::Result<Option<Ifv6Net>>
where
  C: AddressComparator,
{
  preferred_by(Class::Private, Family::V6, order).map(as_v6)
}

#[derive(Copy, Clone)]
enum Class {
  Public,
  Private,
}

#[derive(Copy, Clone)]
enum Family {
  Any,
  V4,
  V6,
}

fn preferred_default(class: Class, family: Family) -> io::Result<Option<IfNet>> {
  let snapshot = InterfaceSnapshot::capture()?;
  let defaults = default_interfaces_for_family_with(
    family,
    snapshot.interfaces(),
    os::default_ipv4_interface_indices,
    os::default_ipv6_interface_indices,
  )?;
  let comparator = default_order(&defaults);
  Ok(select(&snapshot, class, family, &comparator).map(|address| *address.network()))
}

fn default_interfaces_for_family_with<IPv4, IPv6>(
  family: Family,
  interfaces: &[Interface],
  ipv4_indices: IPv4,
  ipv6_indices: IPv6,
) -> io::Result<DefaultInterfaces>
where
  IPv4: FnOnce() -> io::Result<SmallVec<u32>>,
  IPv6: FnOnce() -> io::Result<SmallVec<u32>>,
{
  match family {
    Family::V4 => Ok(join_default_interfaces(
      interfaces,
      ipv4_indices()?,
      SmallVec::new(),
    )),
    Family::V6 => Ok(join_default_interfaces(
      interfaces,
      SmallVec::new(),
      ipv6_indices()?,
    )),
    Family::Any => {
      let ipv4_indices = ipv4_indices()?;
      let ipv6_indices = ipv6_indices()?;
      Ok(join_default_interfaces(
        interfaces,
        ipv4_indices,
        ipv6_indices,
      ))
    }
  }
}

fn preferred_by<C>(class: Class, family: Family, order: C) -> io::Result<Option<IfNet>>
where
  C: AddressComparator,
{
  let snapshot = InterfaceSnapshot::capture()?;
  Ok(select(&snapshot, class, family, &order).map(|address| *address.network()))
}

fn default_order(defaults: &DefaultInterfaces) -> impl AddressComparator + '_ {
  order::default_first(defaults)
    .then(order::ipv4_first())
    .then(order::larger_network_first())
    .then(order::by_interface_index())
    .then(order::by_address())
    .then(order::by_interface_name())
}

fn select<'a, C>(
  snapshot: &'a InterfaceSnapshot,
  class: Class,
  family: Family,
  order: &C,
) -> Option<InterfaceAddress<'a>>
where
  C: AddressComparator,
{
  snapshot.preferred(
    move |address: InterfaceAddress<'_>| eligible(address, class, family),
    order,
  )
}

fn eligible(address: InterfaceAddress<'_>, class: Class, family: Family) -> bool {
  if !address.interface().flags().contains(Flags::UP) {
    return false;
  }

  let ip = address.addr();
  if FORWARDING_BLACKLIST.contains(&ip) {
    return false;
  }

  let family_matches = matches!(
    (family, ip),
    (Family::Any, _)
      | (Family::V4, std::net::IpAddr::V4(_))
      | (Family::V6, std::net::IpAddr::V6(_))
  );
  if !family_matches {
    return false;
  }

  match class {
    Class::Public => !RFC6890.contains(&ip),
    Class::Private => RFC6890.contains(&ip),
  }
}

fn as_v4(candidate: Option<IfNet>) -> Option<Ifv4Net> {
  match candidate {
    Some(IfNet::V4(network)) => Some(network),
    Some(IfNet::V6(_)) | None => None,
  }
}

fn as_v6(candidate: Option<IfNet>) -> Option<Ifv6Net> {
  match candidate {
    Some(IfNet::V6(network)) => Some(network),
    Some(IfNet::V4(_)) | None => None,
  }
}

#[cfg(test)]
mod tests {
  use std::{
    cell::Cell,
    cmp::Ordering,
    io,
    net::{Ipv4Addr, Ipv6Addr},
  };

  use smallvec_wrapper::{SmallVec, TinyVec};

  use crate::{
    DefaultInterfaces, Flags, HardwareAddr, IfNet, Ifv4Net, Ifv6Net, Interface, InterfaceSnapshot,
    SmolStr,
  };

  use super::{
    as_v4, as_v6, default_interfaces_for_family_with, default_order, select, Class, Family,
  };

  fn interface(index: u32, name: &str, flags: Flags) -> Interface {
    Interface {
      index,
      mtu: 1500,
      name: SmolStr::new(name),
      hardware_addr: HardwareAddr::from_bytes(&[index as u8; 6]),
      flags,
    }
  }

  fn provider<'a>(
    calls: &'a Cell<usize>,
    result: io::Result<SmallVec<u32>>,
  ) -> impl FnOnce() -> io::Result<SmallVec<u32>> + 'a {
    move || {
      calls.set(calls.get() + 1);
      result
    }
  }

  fn snapshot() -> InterfaceSnapshot {
    let interfaces: TinyVec<Interface> = vec![
      interface(1, "down-default", Flags::empty()),
      interface(2, "up", Flags::UP),
      interface(3, "private", Flags::UP),
      interface(4, "blacklisted", Flags::UP),
      interface(5, "v6", Flags::UP),
      interface(6, "private-blacklisted", Flags::UP),
    ]
    .into();
    let networks: SmallVec<IfNet> = vec![
      IfNet::with_prefix_len_assert(1, "8.8.8.8".parse().unwrap(), 24),
      IfNet::with_prefix_len_assert(2, "1.1.1.1".parse().unwrap(), 16),
      IfNet::with_prefix_len_assert(3, "10.0.0.1".parse().unwrap(), 8),
      IfNet::with_prefix_len_assert(4, "192.0.2.1".parse().unwrap(), 24),
      IfNet::with_prefix_len_assert(5, "2606:4700:4700::1111".parse().unwrap(), 64),
      IfNet::with_prefix_len_assert(6, "127.0.0.1".parse().unwrap(), 8),
    ]
    .into();
    InterfaceSnapshot::from_parts(interfaces, networks)
  }

  fn defaults(snapshot: &InterfaceSnapshot) -> DefaultInterfaces {
    DefaultInterfaces {
      ipv4: vec![snapshot.interfaces()[0].clone()].into(),
      ipv6: TinyVec::new(),
    }
  }

  #[test]
  fn fixed_eligibility_excludes_down_and_nonforwardable_candidates() {
    let snapshot = snapshot();
    let defaults = defaults(&snapshot);
    let order = default_order(&defaults);

    let public = select(&snapshot, Class::Public, Family::Any, &order).unwrap();
    assert_eq!(public.index(), 2);
    assert_eq!(public.addr().to_string(), "1.1.1.1");
    assert_eq!(
      select(&snapshot, Class::Public, Family::V6, &order)
        .unwrap()
        .index(),
      5
    );
  }

  #[test]
  fn no_default_route_and_custom_order_keep_fixed_eligibility() {
    let snapshot = snapshot();
    let no_defaults = DefaultInterfaces::default();
    let order = default_order(&no_defaults);
    assert_eq!(
      select(&snapshot, Class::Public, Family::V4, &order)
        .unwrap()
        .index(),
      2
    );

    let reverse_index = |left: crate::InterfaceAddress<'_>, right: crate::InterfaceAddress<'_>| {
      right.index().cmp(&left.index())
    };
    let candidate = select(&snapshot, Class::Public, Family::Any, &reverse_index).unwrap();
    assert_eq!(candidate.index(), 5);
    assert_eq!(
      select(&snapshot, Class::Public, Family::V4, &reverse_index)
        .unwrap()
        .index(),
      2
    );
    assert_eq!(
      select(&snapshot, Class::Private, Family::V4, &reverse_index)
        .unwrap()
        .index(),
      3
    );

    let all_down = InterfaceSnapshot::from_parts(
      vec![
        interface(9, "down-v4-public", Flags::empty()),
        interface(10, "down-v6-public", Flags::empty()),
        interface(11, "down-private", Flags::empty()),
      ]
      .into(),
      vec![
        IfNet::with_prefix_len_assert(9, "9.9.9.9".parse().unwrap(), 24),
        IfNet::with_prefix_len_assert(10, "2606:4700:4700::1001".parse().unwrap(), 64),
        IfNet::with_prefix_len_assert(11, "10.0.0.2".parse().unwrap(), 8),
      ]
      .into(),
    );
    for (class, family) in [
      (Class::Public, Family::Any),
      (Class::Public, Family::V4),
      (Class::Public, Family::V6),
      (Class::Private, Family::Any),
      (Class::Private, Family::V4),
      (Class::Private, Family::V6),
    ] {
      assert!(select(&all_down, class, family, &reverse_index).is_none());
    }
  }

  #[test]
  fn eligible_default_routes_are_preferred_and_equal_defaults_use_tiebreaks() {
    let interfaces: TinyVec<Interface> = vec![
      interface(2, "two", Flags::UP),
      interface(3, "three", Flags::UP),
    ]
    .into();
    let networks: SmallVec<IfNet> = vec![
      IfNet::with_prefix_len_assert(2, "8.8.8.8".parse().unwrap(), 24),
      IfNet::with_prefix_len_assert(3, "1.1.1.1".parse().unwrap(), 24),
    ]
    .into();
    let snapshot = InterfaceSnapshot::from_parts(interfaces, networks);

    let one_default = DefaultInterfaces {
      ipv4: vec![snapshot.interfaces()[1].clone()].into(),
      ipv6: TinyVec::new(),
    };
    assert_eq!(
      select(
        &snapshot,
        Class::Public,
        Family::V4,
        &default_order(&one_default)
      )
      .unwrap()
      .index(),
      3
    );

    let equal_defaults = DefaultInterfaces {
      ipv4: vec![
        snapshot.interfaces()[0].clone(),
        snapshot.interfaces()[1].clone(),
      ]
      .into(),
      ipv6: TinyVec::new(),
    };
    assert_eq!(
      select(
        &snapshot,
        Class::Public,
        Family::V4,
        &default_order(&equal_defaults)
      )
      .unwrap()
      .index(),
      2
    );
  }

  #[test]
  fn any_family_default_membership_precedes_ipv4_preference() {
    let interfaces: TinyVec<Interface> = vec![
      interface(2, "v4-nondefault", Flags::UP),
      interface(3, "v6-default", Flags::UP),
    ]
    .into();
    let networks: SmallVec<IfNet> = vec![
      IfNet::with_prefix_len_assert(2, "8.8.8.8".parse().unwrap(), 24),
      IfNet::with_prefix_len_assert(3, "2606:4700:4700::1111".parse().unwrap(), 64),
    ]
    .into();
    let snapshot = InterfaceSnapshot::from_parts(interfaces, networks);

    let ipv6_default = DefaultInterfaces {
      ipv4: TinyVec::new(),
      ipv6: vec![snapshot.interfaces()[1].clone()].into(),
    };
    assert_eq!(
      select(
        &snapshot,
        Class::Public,
        Family::Any,
        &default_order(&ipv6_default)
      )
      .unwrap()
      .index(),
      3
    );

    let ipv4_default = DefaultInterfaces {
      ipv4: vec![snapshot.interfaces()[0].clone()].into(),
      ipv6: TinyVec::new(),
    };
    assert_eq!(
      select(
        &snapshot,
        Class::Public,
        Family::Any,
        &default_order(&ipv4_default)
      )
      .unwrap()
      .index(),
      2
    );
  }

  #[test]
  fn typed_result_conversions_only_keep_the_requested_family() {
    let v4 = Ifv4Net::with_prefix_len_assert(2, Ipv4Addr::new(8, 8, 8, 8), 24);
    let v6 =
      Ifv6Net::with_prefix_len_assert(3, "2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap(), 64);

    assert_eq!(as_v4(Some(v4.into())), Some(v4));
    assert_eq!(as_v4(Some(v6.into())), None);
    assert_eq!(as_v4(None), None);
    assert_eq!(as_v6(Some(v6.into())), Some(v6));
    assert_eq!(as_v6(Some(v4.into())), None);
    assert_eq!(as_v6(None), None);
  }

  #[test]
  fn family_default_dispatch_isolated_and_joins_only_requested_family() {
    let interfaces: TinyVec<Interface> =
      vec![interface(2, "v4", Flags::UP), interface(3, "v6", Flags::UP)].into();
    let v4_calls = Cell::new(0);
    let v6_calls = Cell::new(0);
    let defaults = default_interfaces_for_family_with(
      Family::V4,
      &interfaces,
      provider(&v4_calls, Ok(vec![2].into())),
      provider(&v6_calls, Err(io::Error::from_raw_os_error(701))),
    )
    .unwrap();
    assert_eq!(v4_calls.get(), 1);
    assert_eq!(v6_calls.get(), 0);
    assert_eq!(defaults.ipv4()[0].index(), 2);
    assert!(defaults.ipv6().is_empty());

    let v4_calls = Cell::new(0);
    let v6_calls = Cell::new(0);
    let defaults = default_interfaces_for_family_with(
      Family::V6,
      &interfaces,
      provider(&v4_calls, Err(io::Error::from_raw_os_error(702))),
      provider(&v6_calls, Ok(vec![3].into())),
    )
    .unwrap();
    assert_eq!(v4_calls.get(), 0);
    assert_eq!(v6_calls.get(), 1);
    assert!(defaults.ipv4().is_empty());
    assert_eq!(defaults.ipv6()[0].index(), 3);
  }

  #[test]
  fn family_default_dispatch_propagates_selected_family_errors() {
    let interfaces: TinyVec<Interface> = vec![interface(2, "v4", Flags::UP)].into();
    let v4_calls = Cell::new(0);
    let v6_calls = Cell::new(0);
    let error = default_interfaces_for_family_with(
      Family::V4,
      &interfaces,
      provider(&v4_calls, Err(io::Error::from_raw_os_error(703))),
      provider(&v6_calls, Ok(SmallVec::new())),
    )
    .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(703));
    assert_eq!(v4_calls.get(), 1);
    assert_eq!(v6_calls.get(), 0);

    let v4_calls = Cell::new(0);
    let v6_calls = Cell::new(0);
    let error = default_interfaces_for_family_with(
      Family::V6,
      &interfaces,
      provider(&v4_calls, Ok(SmallVec::new())),
      provider(&v6_calls, Err(io::Error::from_raw_os_error(704))),
    )
    .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(704));
    assert_eq!(v4_calls.get(), 0);
    assert_eq!(v6_calls.get(), 1);
  }

  #[test]
  fn any_family_default_dispatch_calls_both_and_short_circuits_errors() {
    let interfaces: TinyVec<Interface> =
      vec![interface(2, "v4", Flags::UP), interface(3, "v6", Flags::UP)].into();
    let v4_calls = Cell::new(0);
    let v6_calls = Cell::new(0);
    let defaults = default_interfaces_for_family_with(
      Family::Any,
      &interfaces,
      provider(&v4_calls, Ok(vec![2].into())),
      provider(&v6_calls, Ok(vec![3].into())),
    )
    .unwrap();
    assert_eq!(v4_calls.get(), 1);
    assert_eq!(v6_calls.get(), 1);
    assert_eq!(defaults.ipv4()[0].index(), 2);
    assert_eq!(defaults.ipv6()[0].index(), 3);

    let v4_calls = Cell::new(0);
    let v6_calls = Cell::new(0);
    let error = default_interfaces_for_family_with(
      Family::Any,
      &interfaces,
      provider(&v4_calls, Err(io::Error::from_raw_os_error(705))),
      provider(&v6_calls, Ok(SmallVec::new())),
    )
    .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(705));
    assert_eq!(v4_calls.get(), 1);
    assert_eq!(v6_calls.get(), 0);

    let v4_calls = Cell::new(0);
    let v6_calls = Cell::new(0);
    let error = default_interfaces_for_family_with(
      Family::Any,
      &interfaces,
      provider(&v4_calls, Ok(SmallVec::new())),
      provider(&v6_calls, Err(io::Error::from_raw_os_error(706))),
    )
    .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(706));
    assert_eq!(v4_calls.get(), 1);
    assert_eq!(v6_calls.get(), 1);

    let v4_calls = Cell::new(0);
    let v6_calls = Cell::new(0);
    let empty = default_interfaces_for_family_with(
      Family::Any,
      &interfaces,
      provider(&v4_calls, Ok(SmallVec::new())),
      provider(&v6_calls, Ok(SmallVec::new())),
    )
    .unwrap();
    assert!(empty.is_empty());
    assert_eq!(v4_calls.get(), 1);
    assert_eq!(v6_calls.get(), 1);
  }

  #[test]
  fn complete_ties_keep_the_first_captured_record() {
    let snapshot = snapshot();
    let equal = |_: crate::InterfaceAddress<'_>, _: crate::InterfaceAddress<'_>| Ordering::Equal;
    assert_eq!(
      select(&snapshot, Class::Public, Family::Any, &equal)
        .unwrap()
        .index(),
      2
    );
  }
}
