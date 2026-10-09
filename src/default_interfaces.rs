use std::io;

use smallvec_wrapper::{SmallVec, TinyVec};

use super::{interfaces, os, Interface};

/// The interfaces selected by the best usable default route for each family.
///
/// An interface can appear in both slices. A slice is empty when its address
/// family has no usable default route or when the corresponding interface is
/// absent from the interface capture.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct DefaultInterfaces {
  pub(crate) ipv4: TinyVec<Interface>,
  pub(crate) ipv6: TinyVec<Interface>,
}

impl DefaultInterfaces {
  /// Returns every IPv4 interface tied at the best usable default route.
  #[inline]
  pub fn ipv4(&self) -> &[Interface] {
    &self.ipv4
  }

  /// Returns every IPv6 interface tied at the best usable default route.
  #[inline]
  pub fn ipv6(&self) -> &[Interface] {
    &self.ipv6
  }

  /// Returns `true` when neither family has a captured default interface.
  #[inline]
  pub fn is_empty(&self) -> bool {
    self.ipv4.is_empty() && self.ipv6.is_empty()
  }
}

/// Captures the interfaces selected by the best usable default route for each
/// address family.
///
/// This makes a weak snapshot: routes and interfaces are captured separately.
/// A selected index that is absent from the unfiltered interface capture is
/// omitted. Interfaces with only link-local or otherwise filtered addresses
/// are retained because this query does not derive its result from
/// `best_local_*` addresses.
///
/// A family with no usable default route, or with no available address-family
/// stack, has an empty slice. Permission, malformed-response, and persistent
/// interruption errors are returned. Linux considers the standard `local`,
/// `main`, and `default` RPDB tables in their normal precedence order; custom
/// `ip rule` policy tables are not modeled. On OpenBSD a lower route priority
/// wins; other BSD targets do not expose a comparable priority, so every
/// usable default route is retained as an equal-best result.
pub fn default_interfaces() -> io::Result<DefaultInterfaces> {
  let (ipv4_indices, ipv6_indices) = default_interface_indices()?;
  let interfaces = interfaces()?;

  Ok(join_default_interfaces(
    &interfaces,
    ipv4_indices,
    ipv6_indices,
  ))
}

pub(crate) fn default_interfaces_from_captured(
  interfaces: &[Interface],
) -> io::Result<DefaultInterfaces> {
  let (ipv4_indices, ipv6_indices) = default_interface_indices()?;
  Ok(join_default_interfaces(
    interfaces,
    ipv4_indices,
    ipv6_indices,
  ))
}

fn default_interface_indices() -> io::Result<(SmallVec<u32>, SmallVec<u32>)> {
  Ok((
    os::default_ipv4_interface_indices()?,
    os::default_ipv6_interface_indices()?,
  ))
}

fn join_default_interfaces(
  interfaces: &[Interface],
  ipv4_indices: SmallVec<u32>,
  ipv6_indices: SmallVec<u32>,
) -> DefaultInterfaces {
  DefaultInterfaces {
    ipv4: join_interfaces(interfaces, ipv4_indices),
    ipv6: join_interfaces(interfaces, ipv6_indices),
  }
}

fn join_interfaces(interfaces: &[Interface], mut indices: SmallVec<u32>) -> TinyVec<Interface> {
  indices.sort_unstable();
  indices.dedup();

  let mut joined = TinyVec::new();
  for index in indices {
    if index == 0 {
      continue;
    }
    if let Some(interface) = interfaces
      .iter()
      .find(|interface| interface.index() == index)
    {
      joined.push(interface.clone());
    }
  }
  joined
}

#[cfg(test)]
mod tests {
  use smallvec_wrapper::{SmallVec, TinyVec};

  use crate::{Flags, HardwareAddr, Interface, SmolStr};

  use super::{join_default_interfaces, join_interfaces, DefaultInterfaces};

  fn interface(index: u32, name: &str) -> Interface {
    Interface {
      index,
      mtu: 1500,
      name: SmolStr::new(name),
      hardware_addr: HardwareAddr::from_bytes(&[index as u8; 6]),
      flags: Flags::UP,
    }
  }

  #[test]
  fn joins_sorted_indices_to_the_first_matching_capture() {
    let first = interface(2, "first");
    let duplicate = interface(2, "later");
    let third = interface(3, "third");
    let interfaces: TinyVec<Interface> = vec![first, duplicate, third].into();
    let indices: SmallVec<u32> = vec![3, 2, 0, 2, 99].into();

    let joined = join_interfaces(&interfaces, indices);
    assert_eq!(joined.len(), 2);
    assert_eq!(joined[0].index(), 2);
    assert_eq!(joined[0].name().as_str(), "first");
    assert_eq!(joined[1].index(), 3);
  }

  #[test]
  fn empty_default_interfaces_are_empty() {
    assert!(DefaultInterfaces::default().is_empty());
  }

  #[test]
  fn dual_family_defaults_keep_an_interface_without_any_address_records() {
    let interfaces: TinyVec<Interface> = vec![interface(7, "link-only")].into();
    let defaults = DefaultInterfaces {
      ipv4: join_interfaces(&interfaces, vec![7].into()),
      ipv6: join_interfaces(&interfaces, vec![7].into()),
    };

    assert_eq!(defaults.ipv4()[0].index(), 7);
    assert_eq!(defaults.ipv6()[0].index(), 7);
  }

  #[test]
  fn joined_defaults_keep_each_family_sorted_and_independent() {
    let interfaces: TinyVec<Interface> = vec![interface(2, "two"), interface(3, "three")].into();
    let defaults = join_default_interfaces(&interfaces, vec![3, 2, 3].into(), vec![3].into());

    assert_eq!(
      defaults
        .ipv4()
        .iter()
        .map(Interface::index)
        .collect::<Vec<_>>(),
      [2, 3]
    );
    assert_eq!(defaults.ipv6()[0].index(), 3);
    assert!(!defaults.is_empty());
  }
}
