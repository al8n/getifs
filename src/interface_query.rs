use std::{cmp::Ordering, io, net::IpAddr};

use ipnet::IpNet;
use iprfc::RFC;
use smallvec_wrapper::{SmallVec, TinyVec};
use smol_str::SmolStr;

use super::{interface_addrs, interfaces, DefaultInterfaces, IfNet, Interface};

/// A single in-memory capture of interfaces and their unicast addresses.
///
/// Reusing a snapshot avoids repeated OS queries while filtering or ranking.
/// Addresses whose indices are not present in the interface capture remain in
/// [`InterfaceSnapshot::networks`] but are omitted from joined iteration.
#[derive(Clone, Debug)]
pub struct InterfaceSnapshot {
  interfaces: TinyVec<Interface>,
  networks: SmallVec<IfNet>,
}

/// A borrowed, joined interface and address record from an
/// [`InterfaceSnapshot`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct InterfaceAddress<'a> {
  interface: &'a Interface,
  network: &'a IfNet,
}

impl InterfaceSnapshot {
  /// Captures all interfaces and unicast interface addresses.
  ///
  /// The collections are captured separately, so this is a weak snapshot.
  pub fn capture() -> io::Result<Self> {
    Ok(Self::from_parts(interfaces()?, interface_addrs()?))
  }

  /// Creates a snapshot from already captured interface and address collections.
  #[inline]
  pub fn from_parts(interfaces: TinyVec<Interface>, networks: SmallVec<IfNet>) -> Self {
    Self {
      interfaces,
      networks,
    }
  }

  /// Returns the captured interface collection, including interfaces without
  /// addresses.
  #[inline]
  pub fn interfaces(&self) -> &[Interface] {
    &self.interfaces
  }

  /// Returns the captured address collection, including addresses whose index
  /// could not be joined to a captured interface.
  #[inline]
  pub fn networks(&self) -> &[IfNet] {
    &self.networks
  }

  /// Iterates over addresses joined to the first captured interface with the
  /// same index.
  pub fn iter(&self) -> impl Iterator<Item = InterfaceAddress<'_>> + '_ {
    self.networks.iter().filter_map(|network| {
      self
        .interfaces
        .iter()
        .find(|interface| interface.index() == network.index())
        .map(|interface| InterfaceAddress { interface, network })
    })
  }

  /// Iterates over joined records accepted by `predicate`.
  pub fn matching<'a, P>(&'a self, predicate: P) -> impl Iterator<Item = InterfaceAddress<'a>> + 'a
  where
    P: InterfacePredicate + 'a,
  {
    self
      .iter()
      .filter(move |address| predicate.matches(*address))
  }

  /// Returns the preferred joined record accepted by `predicate`.
  ///
  /// A complete comparator tie keeps the first captured candidate.
  pub fn preferred<'a, P, C>(&'a self, predicate: P, order: &C) -> Option<InterfaceAddress<'a>>
  where
    P: InterfacePredicate,
    C: AddressComparator,
  {
    let mut addresses = self
      .iter()
      .filter(move |address| predicate.matches(*address));
    let mut best = addresses.next()?;
    for candidate in addresses {
      if order.compare(candidate, best) == Ordering::Less {
        best = candidate;
      }
    }
    Some(best)
  }
}

impl<'a> InterfaceAddress<'a> {
  /// Returns the captured interface.
  #[inline]
  pub const fn interface(self) -> &'a Interface {
    self.interface
  }

  /// Returns the captured interface network.
  #[inline]
  pub const fn network(self) -> &'a IfNet {
    self.network
  }

  /// Returns the cached host address.
  #[inline]
  pub const fn addr(self) -> IpAddr {
    self.network.addr()
  }

  /// Returns the joined interface index.
  #[inline]
  pub const fn index(self) -> u32 {
    self.interface.index()
  }

  /// Returns the cached UTF-8 interface name.
  #[inline]
  pub const fn name(self) -> &'a SmolStr {
    self.interface.name()
  }
}

/// A predicate over a borrowed [`InterfaceAddress`].
///
/// Closures with the signature `Fn(InterfaceAddress<'_>) -> bool` implement
/// this trait directly. Combinators preserve short-circuiting behavior.
pub trait InterfacePredicate {
  /// Returns whether `address` is accepted.
  fn matches(&self, address: InterfaceAddress<'_>) -> bool;

  /// Requires both predicates to accept an address.
  #[inline]
  fn and<P>(self, next: P) -> AndPredicate<Self, P>
  where
    Self: Sized,
    P: InterfacePredicate,
  {
    AndPredicate { first: self, next }
  }

  /// Requires either predicate to accept an address.
  #[inline]
  fn or<P>(self, next: P) -> OrPredicate<Self, P>
  where
    Self: Sized,
    P: InterfacePredicate,
  {
    OrPredicate { first: self, next }
  }

  /// Inverts this predicate.
  #[inline]
  fn not(self) -> NotPredicate<Self>
  where
    Self: Sized,
  {
    NotPredicate { predicate: self }
  }
}

impl<F> InterfacePredicate for F
where
  F: for<'a> Fn(InterfaceAddress<'a>) -> bool,
{
  #[inline]
  fn matches(&self, address: InterfaceAddress<'_>) -> bool {
    self(address)
  }
}

/// The conjunction of two [`InterfacePredicate`] values.
pub struct AndPredicate<P, Q> {
  first: P,
  next: Q,
}

impl<P, Q> InterfacePredicate for AndPredicate<P, Q>
where
  P: InterfacePredicate,
  Q: InterfacePredicate,
{
  #[inline]
  fn matches(&self, address: InterfaceAddress<'_>) -> bool {
    self.first.matches(address) && self.next.matches(address)
  }
}

/// The disjunction of two [`InterfacePredicate`] values.
pub struct OrPredicate<P, Q> {
  first: P,
  next: Q,
}

impl<P, Q> InterfacePredicate for OrPredicate<P, Q>
where
  P: InterfacePredicate,
  Q: InterfacePredicate,
{
  #[inline]
  fn matches(&self, address: InterfaceAddress<'_>) -> bool {
    self.first.matches(address) || self.next.matches(address)
  }
}

/// The negation of an [`InterfacePredicate`].
pub struct NotPredicate<P> {
  predicate: P,
}

impl<P> InterfacePredicate for NotPredicate<P>
where
  P: InterfacePredicate,
{
  #[inline]
  fn matches(&self, address: InterfaceAddress<'_>) -> bool {
    !self.predicate.matches(address)
  }
}

/// Common typed [`InterfacePredicate`] constructors.
pub mod predicate {
  use super::{InterfaceAddress, InterfacePredicate, IpNet, RFC};
  use crate::Flags;

  /// Matches a cached UTF-8 interface name.
  pub fn name<F>(predicate: F) -> impl InterfacePredicate
  where
    F: Fn(&str) -> bool,
  {
    move |address: InterfaceAddress<'_>| predicate(address.name().as_str())
  }

  /// Matches a record whose host address lies within `cidr`.
  pub fn cidr(cidr: IpNet) -> impl InterfacePredicate {
    move |address: InterfaceAddress<'_>| cidr.contains(&address.addr())
  }

  /// Matches a record whose host address belongs to `rfc`.
  pub fn rfc(rfc: RFC) -> impl InterfacePredicate {
    move |address: InterfaceAddress<'_>| rfc.contains(&address.addr())
  }

  /// Matches an interface containing every bit in `flags`.
  pub fn flags(flags: Flags) -> impl InterfacePredicate {
    move |address: InterfaceAddress<'_>| address.interface().flags().contains(flags)
  }
}

/// A cached ordering over two [`InterfaceAddress`] values.
///
/// Comparators must only inspect their two captured records and any data
/// captured when the comparator was constructed. They must not perform I/O.
pub trait AddressComparator {
  /// Compares `left` with `right` using preference order.
  fn compare(&self, left: InterfaceAddress<'_>, right: InterfaceAddress<'_>) -> Ordering;

  /// Uses `next` to break ties from this comparator.
  #[inline]
  fn then<C>(self, next: C) -> Then<Self, C>
  where
    Self: Sized,
    C: AddressComparator,
  {
    Then { first: self, next }
  }

  /// Reverses this comparator's preference order.
  #[inline]
  fn reverse(self) -> ReverseComparator<Self>
  where
    Self: Sized,
  {
    ReverseComparator { comparator: self }
  }
}

impl<F> AddressComparator for F
where
  F: for<'a> Fn(InterfaceAddress<'a>, InterfaceAddress<'a>) -> Ordering,
{
  #[inline]
  fn compare(&self, left: InterfaceAddress<'_>, right: InterfaceAddress<'_>) -> Ordering {
    self(left, right)
  }
}

/// A comparator that breaks ties from `first` with `next`.
pub struct Then<C, D> {
  first: C,
  next: D,
}

impl<C, D> AddressComparator for Then<C, D>
where
  C: AddressComparator,
  D: AddressComparator,
{
  #[inline]
  fn compare(&self, left: InterfaceAddress<'_>, right: InterfaceAddress<'_>) -> Ordering {
    match self.first.compare(left, right) {
      Ordering::Equal => self.next.compare(left, right),
      order => order,
    }
  }
}

/// A comparator with the reverse of another comparator's order.
pub struct ReverseComparator<C> {
  comparator: C,
}

impl<C> AddressComparator for ReverseComparator<C>
where
  C: AddressComparator,
{
  #[inline]
  fn compare(&self, left: InterfaceAddress<'_>, right: InterfaceAddress<'_>) -> Ordering {
    self.comparator.compare(right, left)
  }
}

/// Common cached [`AddressComparator`] constructors.
pub mod order {
  use super::{AddressComparator, DefaultInterfaces, InterfaceAddress};

  /// Prefers records whose interface is selected by the corresponding
  /// family-specific default route.
  pub fn default_first(defaults: &DefaultInterfaces) -> impl AddressComparator + '_ {
    move |left: InterfaceAddress<'_>, right: InterfaceAddress<'_>| {
      (!is_default(defaults, left)).cmp(&!is_default(defaults, right))
    }
  }

  /// Prefers administratively-up interfaces.
  pub fn up_first() -> impl AddressComparator {
    |left: InterfaceAddress<'_>, right: InterfaceAddress<'_>| {
      (!left.interface().flags().contains(crate::Flags::UP))
        .cmp(&!right.interface().flags().contains(crate::Flags::UP))
    }
  }

  /// Prefers IPv4 records over IPv6 records.
  pub fn ipv4_first() -> impl AddressComparator {
    |left: InterfaceAddress<'_>, right: InterfaceAddress<'_>| {
      let left_is_v6 = matches!(left.addr(), std::net::IpAddr::V6(_));
      let right_is_v6 = matches!(right.addr(), std::net::IpAddr::V6(_));
      left_is_v6.cmp(&right_is_v6)
    }
  }

  /// Prefers the larger network, represented by the smaller prefix length.
  pub fn larger_network_first() -> impl AddressComparator {
    |left: InterfaceAddress<'_>, right: InterfaceAddress<'_>| {
      left
        .network()
        .prefix_len()
        .cmp(&right.network().prefix_len())
    }
  }

  /// Prefers lower interface indices.
  pub fn by_interface_index() -> impl AddressComparator {
    |left: InterfaceAddress<'_>, right: InterfaceAddress<'_>| left.index().cmp(&right.index())
  }

  /// Prefers numerically smaller addresses.
  pub fn by_address() -> impl AddressComparator {
    |left: InterfaceAddress<'_>, right: InterfaceAddress<'_>| left.addr().cmp(&right.addr())
  }

  /// Prefers lexicographically smaller cached interface names.
  pub fn by_interface_name() -> impl AddressComparator {
    |left: InterfaceAddress<'_>, right: InterfaceAddress<'_>| {
      left.interface.name.cmp(&right.interface.name)
    }
  }

  fn is_default(defaults: &DefaultInterfaces, address: InterfaceAddress<'_>) -> bool {
    let interfaces = match address.addr() {
      std::net::IpAddr::V4(_) => defaults.ipv4(),
      std::net::IpAddr::V6(_) => defaults.ipv6(),
    };
    interfaces
      .iter()
      .any(|interface| interface.index() == address.index())
  }
}

/// Stable sorting support for slices of [`InterfaceAddress`] values.
pub trait InterfaceAddressSliceExt<'a> {
  /// Stably sorts records using `comparator`.
  fn sort_with<C>(&mut self, comparator: &C)
  where
    C: AddressComparator;
}

impl<'a> InterfaceAddressSliceExt<'a> for [InterfaceAddress<'a>] {
  #[inline]
  fn sort_with<C>(&mut self, comparator: &C)
  where
    C: AddressComparator,
  {
    self.sort_by(|left, right| comparator.compare(*left, *right));
  }
}

/// Sorting and minimum support for iterators of [`InterfaceAddress`] values.
pub trait InterfaceAddressIteratorExt<'a>: Iterator<Item = InterfaceAddress<'a>> + Sized {
  /// Collects records into a stably sorted vector.
  fn sorted_with<C>(self, comparator: &C) -> Vec<InterfaceAddress<'a>>
  where
    C: AddressComparator;

  /// Returns the minimum record, retaining the first record for complete ties.
  fn min_with<C>(self, comparator: &C) -> Option<InterfaceAddress<'a>>
  where
    C: AddressComparator;
}

impl<'a, I> InterfaceAddressIteratorExt<'a> for I
where
  I: Iterator<Item = InterfaceAddress<'a>>,
{
  fn sorted_with<C>(self, comparator: &C) -> Vec<InterfaceAddress<'a>>
  where
    C: AddressComparator,
  {
    let mut records: Vec<_> = self.collect();
    InterfaceAddressSliceExt::sort_with(records.as_mut_slice(), comparator);
    records
  }

  fn min_with<C>(mut self, comparator: &C) -> Option<InterfaceAddress<'a>>
  where
    C: AddressComparator,
  {
    let mut best = self.next()?;
    for candidate in self {
      if comparator.compare(candidate, best) == Ordering::Less {
        best = candidate;
      }
    }
    Some(best)
  }
}

#[cfg(test)]
mod tests {
  use std::{cell::Cell, cmp::Ordering};

  use ipnet::{IpNet, Ipv4Net};
  use smallvec_wrapper::{SmallVec, TinyVec};

  use crate::{
    order, predicate, AddressComparator, DefaultInterfaces, Flags, HardwareAddr, IfNet, Interface,
    InterfaceAddressIteratorExt, InterfaceAddressSliceExt, InterfacePredicate, InterfaceSnapshot,
    SmolStr,
  };

  fn interface(index: u32, name: &str, flags: Flags, hardware: &[u8]) -> Interface {
    Interface {
      index,
      mtu: 1500,
      name: SmolStr::new(name),
      hardware_addr: HardwareAddr::from_bytes(hardware),
      flags,
    }
  }

  fn snapshot() -> InterfaceSnapshot {
    let interfaces: TinyVec<Interface> = vec![
      interface(1, "en0", Flags::UP, &[1; 6]),
      interface(2, "down", Flags::empty(), &[2; 8]),
      interface(2, "duplicate", Flags::UP, &[3; 20]),
      interface(3, "v6", Flags::UP, &[4; 5]),
    ]
    .into();
    let networks: SmallVec<IfNet> = vec![
      IfNet::with_prefix_len_assert(1, "10.0.0.1".parse().unwrap(), 8),
      IfNet::with_prefix_len_assert(2, "192.0.2.1".parse().unwrap(), 24),
      IfNet::with_prefix_len_assert(3, "2001:db8::1".parse().unwrap(), 64),
      IfNet::with_prefix_len_assert(99, "198.51.100.1".parse().unwrap(), 24),
    ]
    .into();
    InterfaceSnapshot::from_parts(interfaces, networks)
  }

  #[test]
  fn joins_first_duplicate_and_leaves_unjoined_networks_visible() {
    let snapshot = snapshot();
    assert_eq!(snapshot.networks().len(), 4);
    let joined: Vec<_> = snapshot.iter().collect();
    assert_eq!(joined.len(), 3);
    assert_eq!(joined[1].name().as_str(), "down");
  }

  #[test]
  fn typed_predicates_compose_and_short_circuit() {
    let snapshot = snapshot();
    let cidr = IpNet::V4(Ipv4Net::new("10.0.0.0".parse().unwrap(), 8).unwrap());
    let records: Vec<_> = snapshot
      .matching(
        predicate::name(|name| name.starts_with("en"))
          .and(predicate::cidr(cidr))
          .and(predicate::flags(Flags::UP))
          .and(predicate::rfc(crate::rfc::RFC1918)),
      )
      .collect();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].index(), 1);

    let calls = Cell::new(0);
    let first = |_: crate::InterfaceAddress<'_>| true;
    let second = |_: crate::InterfaceAddress<'_>| {
      calls.set(calls.get() + 1);
      false
    };
    assert!(first.or(second).matches(records[0]));
    assert_eq!(calls.get(), 0);

    let calls = Cell::new(0);
    let first_false = |_: crate::InterfaceAddress<'_>| false;
    let second = |_: crate::InterfaceAddress<'_>| {
      calls.set(calls.get() + 1);
      true
    };
    assert!(first_false.or(second).matches(records[0]));
    assert_eq!(calls.get(), 1);

    let and_calls = Cell::new(0);
    let first_false = |_: crate::InterfaceAddress<'_>| false;
    let second = |_: crate::InterfaceAddress<'_>| {
      and_calls.set(and_calls.get() + 1);
      true
    };
    assert!(!first_false.and(second).matches(records[0]));
    assert_eq!(and_calls.get(), 0);

    let and_calls = Cell::new(0);
    let first_true = |_: crate::InterfaceAddress<'_>| true;
    let second = |_: crate::InterfaceAddress<'_>| {
      and_calls.set(and_calls.get() + 1);
      true
    };
    assert!(first_true.and(second).matches(records[0]));
    assert_eq!(and_calls.get(), 1);
    assert!(first.not().not().matches(records[0]));
  }

  #[test]
  fn comparators_sort_stably_and_keep_first_minimum_on_ties() {
    let snapshot = snapshot();
    let mut records: Vec<_> = snapshot.iter().collect();
    let defaults = DefaultInterfaces {
      ipv4: vec![snapshot.interfaces()[1].clone()].into(),
      ipv6: TinyVec::new(),
    };
    let comparator = order::default_first(&defaults)
      .then(order::ipv4_first())
      .then(order::larger_network_first())
      .then(order::by_interface_index())
      .then(order::by_address())
      .then(order::by_interface_name());
    records.as_mut_slice().sort_with(&comparator);
    assert_eq!(records[0].index(), 2);
    assert_eq!(records[1].index(), 1);

    let equal = |_: crate::InterfaceAddress<'_>, _: crate::InterfaceAddress<'_>| Ordering::Equal;
    assert_eq!(snapshot.iter().min_with(&equal).unwrap().index(), 1);
    assert_eq!(snapshot.iter().sorted_with(&equal)[0].index(), 1);

    let reverse_index = |left: crate::InterfaceAddress<'_>, right: crate::InterfaceAddress<'_>| {
      right.index().cmp(&left.index())
    };
    assert_eq!(snapshot.iter().min_with(&reverse_index).unwrap().index(), 3);
  }

  #[test]
  fn typed_comparators_cover_each_ranking_key_without_io() {
    let snapshot = snapshot();
    let records: Vec<_> = snapshot.iter().collect();
    let defaults = DefaultInterfaces {
      ipv4: vec![snapshot.interfaces()[1].clone()].into(),
      ipv6: TinyVec::new(),
    };

    assert_eq!(
      order::default_first(&defaults).compare(records[1], records[0]),
      Ordering::Less
    );
    assert_eq!(
      order::up_first().compare(records[0], records[1]),
      Ordering::Less
    );
    assert_eq!(
      order::ipv4_first().compare(records[0], records[2]),
      Ordering::Less
    );
    assert_eq!(
      order::larger_network_first().compare(records[0], records[1]),
      Ordering::Less
    );
    assert_eq!(
      order::by_interface_index().compare(records[0], records[1]),
      Ordering::Less
    );
    assert_eq!(
      order::by_address().compare(records[0], records[1]),
      Ordering::Less
    );
    assert_eq!(
      order::by_interface_name().compare(records[1], records[0]),
      Ordering::Less
    );
    assert_eq!(
      order::by_interface_index()
        .reverse()
        .compare(records[0], records[1]),
      Ordering::Greater
    );
  }
}
