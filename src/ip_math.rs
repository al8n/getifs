use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// Checked address arithmetic for standard-library IP address types.
pub trait CheckedIpAddrExt: Sized {
  /// The unsigned address-offset type for this address family.
  type Offset;

  /// Adds individual addresses without wrapping.
  fn checked_add(self, offset: Self::Offset) -> Option<Self>;

  /// Subtracts individual addresses without wrapping.
  fn checked_sub(self, offset: Self::Offset) -> Option<Self>;
}

impl CheckedIpAddrExt for Ipv4Addr {
  type Offset = u32;

  #[inline]
  fn checked_add(self, offset: Self::Offset) -> Option<Self> {
    u32::from(self).checked_add(offset).map(Ipv4Addr::from)
  }

  #[inline]
  fn checked_sub(self, offset: Self::Offset) -> Option<Self> {
    u32::from(self).checked_sub(offset).map(Ipv4Addr::from)
  }
}

impl CheckedIpAddrExt for Ipv6Addr {
  type Offset = u128;

  #[inline]
  fn checked_add(self, offset: Self::Offset) -> Option<Self> {
    u128::from(self).checked_add(offset).map(Ipv6Addr::from)
  }

  #[inline]
  fn checked_sub(self, offset: Self::Offset) -> Option<Self> {
    u128::from(self).checked_sub(offset).map(Ipv6Addr::from)
  }
}

impl CheckedIpAddrExt for IpAddr {
  type Offset = u128;

  #[inline]
  fn checked_add(self, offset: Self::Offset) -> Option<Self> {
    match self {
      Self::V4(addr) => u32::try_from(offset)
        .ok()
        .and_then(|offset| CheckedIpAddrExt::checked_add(addr, offset).map(Self::V4)),
      Self::V6(addr) => CheckedIpAddrExt::checked_add(addr, offset).map(Self::V6),
    }
  }

  #[inline]
  fn checked_sub(self, offset: Self::Offset) -> Option<Self> {
    match self {
      Self::V4(addr) => u32::try_from(offset)
        .ok()
        .and_then(|offset| CheckedIpAddrExt::checked_sub(addr, offset).map(Self::V4)),
      Self::V6(addr) => CheckedIpAddrExt::checked_sub(addr, offset).map(Self::V6),
    }
  }
}

/// Usable-host accessors that stay within an IP network's prefix.
pub trait UsableIpNetExt {
  /// The address type for this network family.
  type Addr;
  /// The unsigned host-offset type for this network family.
  type Offset;

  /// Returns the first usable host address.
  fn first_usable(&self) -> Self::Addr;

  /// Returns the last usable host address.
  fn last_usable(&self) -> Self::Addr;

  /// Returns the `offset`th usable host address from the front.
  fn nth_usable(&self, offset: Self::Offset) -> Option<Self::Addr>;

  /// Returns the `offset`th usable host address from the back.
  fn nth_usable_back(&self, offset: Self::Offset) -> Option<Self::Addr>;
}

impl UsableIpNetExt for Ipv4Net {
  type Addr = Ipv4Addr;
  type Offset = u32;

  #[inline]
  fn first_usable(&self) -> Self::Addr {
    ipv4_usable_bounds(self).0
  }

  #[inline]
  fn last_usable(&self) -> Self::Addr {
    ipv4_usable_bounds(self).1
  }

  #[inline]
  fn nth_usable(&self, offset: Self::Offset) -> Option<Self::Addr> {
    let (first, last) = ipv4_usable_bounds(self);
    CheckedIpAddrExt::checked_add(first, offset).filter(|candidate| *candidate <= last)
  }

  #[inline]
  fn nth_usable_back(&self, offset: Self::Offset) -> Option<Self::Addr> {
    let (first, last) = ipv4_usable_bounds(self);
    CheckedIpAddrExt::checked_sub(last, offset).filter(|candidate| *candidate >= first)
  }
}

impl UsableIpNetExt for Ipv6Net {
  type Addr = Ipv6Addr;
  type Offset = u128;

  #[inline]
  fn first_usable(&self) -> Self::Addr {
    self.network()
  }

  #[inline]
  fn last_usable(&self) -> Self::Addr {
    self.broadcast()
  }

  #[inline]
  fn nth_usable(&self, offset: Self::Offset) -> Option<Self::Addr> {
    CheckedIpAddrExt::checked_add(self.first_usable(), offset)
      .filter(|candidate| *candidate <= self.last_usable())
  }

  #[inline]
  fn nth_usable_back(&self, offset: Self::Offset) -> Option<Self::Addr> {
    CheckedIpAddrExt::checked_sub(self.last_usable(), offset)
      .filter(|candidate| *candidate >= self.first_usable())
  }
}

impl UsableIpNetExt for IpNet {
  type Addr = IpAddr;
  type Offset = u128;

  #[inline]
  fn first_usable(&self) -> Self::Addr {
    match self {
      Self::V4(net) => IpAddr::V4(net.first_usable()),
      Self::V6(net) => IpAddr::V6(net.first_usable()),
    }
  }

  #[inline]
  fn last_usable(&self) -> Self::Addr {
    match self {
      Self::V4(net) => IpAddr::V4(net.last_usable()),
      Self::V6(net) => IpAddr::V6(net.last_usable()),
    }
  }

  #[inline]
  fn nth_usable(&self, offset: Self::Offset) -> Option<Self::Addr> {
    match self {
      Self::V4(net) => u32::try_from(offset)
        .ok()
        .and_then(|offset| net.nth_usable(offset).map(IpAddr::V4)),
      Self::V6(net) => net.nth_usable(offset).map(IpAddr::V6),
    }
  }

  #[inline]
  fn nth_usable_back(&self, offset: Self::Offset) -> Option<Self::Addr> {
    match self {
      Self::V4(net) => u32::try_from(offset)
        .ok()
        .and_then(|offset| net.nth_usable_back(offset).map(IpAddr::V4)),
      Self::V6(net) => net.nth_usable_back(offset).map(IpAddr::V6),
    }
  }
}

/// Checked arithmetic over `ipnet` values that preserves their prefix and
/// stored host bits.
pub trait CheckedIpNetExt: Sized {
  /// The unsigned address or subnet-offset type for this network family.
  type Offset;

  /// Offsets the stored address by individual addresses without changing the
  /// prefix. The address may cross the original subnet.
  fn checked_add_address(self, offset: Self::Offset) -> Option<Self>;

  /// Offsets the stored address backwards by individual addresses without
  /// changing the prefix. The address may cross the original subnet.
  fn checked_sub_address(self, offset: Self::Offset) -> Option<Self>;

  /// Offsets by whole prefix-sized subnets without changing the prefix or the
  /// original stored host bits.
  fn checked_add_subnets(self, count: Self::Offset) -> Option<Self>;

  /// Offsets backwards by whole prefix-sized subnets without changing the
  /// prefix or the original stored host bits.
  fn checked_sub_subnets(self, count: Self::Offset) -> Option<Self>;
}

impl CheckedIpNetExt for Ipv4Net {
  type Offset = u32;

  #[inline]
  fn checked_add_address(self, offset: Self::Offset) -> Option<Self> {
    Ipv4Net::new(
      CheckedIpAddrExt::checked_add(self.addr(), offset)?,
      self.prefix_len(),
    )
    .ok()
  }

  #[inline]
  fn checked_sub_address(self, offset: Self::Offset) -> Option<Self> {
    Ipv4Net::new(
      CheckedIpAddrExt::checked_sub(self.addr(), offset)?,
      self.prefix_len(),
    )
    .ok()
  }

  #[inline]
  fn checked_add_subnets(self, count: Self::Offset) -> Option<Self> {
    checked_ipv4_subnets(self, count, true)
  }

  #[inline]
  fn checked_sub_subnets(self, count: Self::Offset) -> Option<Self> {
    checked_ipv4_subnets(self, count, false)
  }
}

impl CheckedIpNetExt for Ipv6Net {
  type Offset = u128;

  #[inline]
  fn checked_add_address(self, offset: Self::Offset) -> Option<Self> {
    Ipv6Net::new(
      CheckedIpAddrExt::checked_add(self.addr(), offset)?,
      self.prefix_len(),
    )
    .ok()
  }

  #[inline]
  fn checked_sub_address(self, offset: Self::Offset) -> Option<Self> {
    Ipv6Net::new(
      CheckedIpAddrExt::checked_sub(self.addr(), offset)?,
      self.prefix_len(),
    )
    .ok()
  }

  #[inline]
  fn checked_add_subnets(self, count: Self::Offset) -> Option<Self> {
    checked_ipv6_subnets(self, count, true)
  }

  #[inline]
  fn checked_sub_subnets(self, count: Self::Offset) -> Option<Self> {
    checked_ipv6_subnets(self, count, false)
  }
}

impl CheckedIpNetExt for IpNet {
  type Offset = u128;

  #[inline]
  fn checked_add_address(self, offset: Self::Offset) -> Option<Self> {
    match self {
      Self::V4(net) => u32::try_from(offset)
        .ok()
        .and_then(|offset| net.checked_add_address(offset).map(Self::V4)),
      Self::V6(net) => net.checked_add_address(offset).map(Self::V6),
    }
  }

  #[inline]
  fn checked_sub_address(self, offset: Self::Offset) -> Option<Self> {
    match self {
      Self::V4(net) => u32::try_from(offset)
        .ok()
        .and_then(|offset| net.checked_sub_address(offset).map(Self::V4)),
      Self::V6(net) => net.checked_sub_address(offset).map(Self::V6),
    }
  }

  #[inline]
  fn checked_add_subnets(self, count: Self::Offset) -> Option<Self> {
    match self {
      Self::V4(net) => u32::try_from(count)
        .ok()
        .and_then(|count| net.checked_add_subnets(count).map(Self::V4)),
      Self::V6(net) => net.checked_add_subnets(count).map(Self::V6),
    }
  }

  #[inline]
  fn checked_sub_subnets(self, count: Self::Offset) -> Option<Self> {
    match self {
      Self::V4(net) => u32::try_from(count)
        .ok()
        .and_then(|count| net.checked_sub_subnets(count).map(Self::V4)),
      Self::V6(net) => net.checked_sub_subnets(count).map(Self::V6),
    }
  }
}

#[inline]
fn ipv4_usable_bounds(net: &Ipv4Net) -> (Ipv4Addr, Ipv4Addr) {
  let first = u32::from(net.network());
  let last = u32::from(net.broadcast());
  if net.prefix_len() <= 30 {
    (Ipv4Addr::from(first + 1), Ipv4Addr::from(last - 1))
  } else {
    (Ipv4Addr::from(first), Ipv4Addr::from(last))
  }
}

#[inline]
fn checked_ipv4_subnets(net: Ipv4Net, count: u32, add: bool) -> Option<Ipv4Net> {
  if count == 0 {
    return Some(net);
  }
  let host_bits = 32 - u32::from(net.prefix_len());
  if host_bits == 32 {
    return None;
  }
  let stride = 1u32.checked_shl(host_bits)?;
  let offset = count.checked_mul(stride)?;
  if add {
    net.checked_add_address(offset)
  } else {
    net.checked_sub_address(offset)
  }
}

#[inline]
fn checked_ipv6_subnets(net: Ipv6Net, count: u128, add: bool) -> Option<Ipv6Net> {
  if count == 0 {
    return Some(net);
  }
  let host_bits = 128 - u32::from(net.prefix_len());
  if host_bits == 128 {
    return None;
  }
  let stride = 1u128.checked_shl(host_bits)?;
  let offset = count.checked_mul(stride)?;
  if add {
    net.checked_add_address(offset)
  } else {
    net.checked_sub_address(offset)
  }
}

#[cfg(test)]
mod tests {
  use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

  use ipnet::{IpNet, Ipv4Net, Ipv6Net};

  use super::{CheckedIpAddrExt, CheckedIpNetExt, UsableIpNetExt};

  #[test]
  fn address_offsets_are_checked_per_family() {
    assert_eq!(
      Ipv4Addr::new(192, 0, 2, 1).checked_add(1),
      Some(Ipv4Addr::new(192, 0, 2, 2))
    );
    assert!(Ipv4Addr::BROADCAST.checked_add(1).is_none());
    assert!(Ipv4Addr::UNSPECIFIED.checked_sub(1).is_none());
    assert!(Ipv6Addr::from(u128::MAX).checked_add(1).is_none());
    assert!(Ipv6Addr::UNSPECIFIED.checked_sub(1).is_none());
    assert!(IpAddr::V4(Ipv4Addr::LOCALHOST)
      .checked_add(u128::from(u32::MAX) + 1)
      .is_none());
  }

  #[test]
  fn usable_hosts_cover_ipv4_boundary_prefixes() {
    let slash_30 = Ipv4Net::new("192.0.2.0".parse::<Ipv4Addr>().unwrap(), 30).unwrap();
    assert_eq!(
      slash_30.first_usable(),
      "192.0.2.1".parse::<Ipv4Addr>().unwrap()
    );
    assert_eq!(
      slash_30.last_usable(),
      "192.0.2.2".parse::<Ipv4Addr>().unwrap()
    );
    assert_eq!(
      slash_30.nth_usable(1),
      Some("192.0.2.2".parse::<Ipv4Addr>().unwrap())
    );
    assert!(slash_30.nth_usable(2).is_none());

    let slash_31 = Ipv4Net::new("192.0.2.0".parse::<Ipv4Addr>().unwrap(), 31).unwrap();
    assert_eq!(
      slash_31.first_usable(),
      "192.0.2.0".parse::<Ipv4Addr>().unwrap()
    );
    assert_eq!(
      slash_31.last_usable(),
      "192.0.2.1".parse::<Ipv4Addr>().unwrap()
    );

    let slash_32 = Ipv4Net::new("192.0.2.42".parse::<Ipv4Addr>().unwrap(), 32).unwrap();
    assert_eq!(
      slash_32.first_usable(),
      "192.0.2.42".parse::<Ipv4Addr>().unwrap()
    );
    assert_eq!(
      slash_32.nth_usable_back(0),
      Some("192.0.2.42".parse::<Ipv4Addr>().unwrap())
    );
    assert!(slash_32.nth_usable_back(1).is_none());
  }

  #[test]
  fn usable_hosts_cover_ipv6_boundaries() {
    let slash_126 = Ipv6Net::new("2001:db8::".parse::<Ipv6Addr>().unwrap(), 126).unwrap();
    assert_eq!(
      slash_126.first_usable(),
      "2001:db8::".parse::<Ipv6Addr>().unwrap()
    );
    assert_eq!(
      slash_126.last_usable(),
      "2001:db8::3".parse::<Ipv6Addr>().unwrap()
    );
    assert_eq!(
      slash_126.nth_usable_back(3),
      Some("2001:db8::".parse::<Ipv6Addr>().unwrap())
    );
    assert!(slash_126.nth_usable(4).is_none());

    let slash_128 = Ipv6Net::new("2001:db8::1".parse::<Ipv6Addr>().unwrap(), 128).unwrap();
    assert_eq!(
      slash_128.first_usable(),
      "2001:db8::1".parse::<Ipv6Addr>().unwrap()
    );
    assert!(slash_128.nth_usable(1).is_none());
  }

  #[test]
  fn network_offsets_preserve_prefix_and_host_bits() {
    let v4 = Ipv4Net::new("192.0.2.42".parse::<Ipv4Addr>().unwrap(), 24).unwrap();
    assert_eq!(
      v4.checked_add_address(214).unwrap().addr(),
      "192.0.3.0".parse::<Ipv4Addr>().unwrap()
    );
    assert_eq!(
      v4.checked_add_subnets(1).unwrap().addr(),
      "192.0.3.42".parse::<Ipv4Addr>().unwrap()
    );
    assert_eq!(v4.checked_add_subnets(1).unwrap().prefix_len(), 24);
    assert_eq!(
      v4.checked_sub_subnets(1).unwrap().addr(),
      "192.0.1.42".parse::<Ipv4Addr>().unwrap()
    );
    assert_eq!(v4.checked_add_address(0), Some(v4));
    assert_eq!(v4.checked_add_subnets(0), Some(v4));

    let v6 = Ipv6Net::new("2001:db8::42".parse::<Ipv6Addr>().unwrap(), 64).unwrap();
    assert_eq!(
      v6.checked_add_subnets(1).unwrap().addr(),
      "2001:db8:0:1::42".parse::<Ipv6Addr>().unwrap()
    );
  }

  #[test]
  fn subnet_offsets_guard_full_width_and_overflow() {
    let v4_zero = Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 1), 0).unwrap();
    assert_eq!(v4_zero.checked_add_subnets(0), Some(v4_zero));
    assert!(v4_zero.checked_add_subnets(1).is_none());

    let v4_overflow = Ipv4Net::new(Ipv4Addr::new(192, 0, 2, 42), 24).unwrap();
    assert!(v4_overflow.checked_add_subnets(u32::MAX).is_none());

    let v6_zero = Ipv6Net::new("2001:db8::1".parse::<Ipv6Addr>().unwrap(), 0).unwrap();
    assert_eq!(v6_zero.checked_sub_subnets(0), Some(v6_zero));
    assert!(v6_zero.checked_sub_subnets(1).is_none());

    let v6_overflow = Ipv6Net::new("2001:db8::42".parse::<Ipv6Addr>().unwrap(), 64).unwrap();
    assert!(v6_overflow.checked_add_subnets(u128::MAX).is_none());

    let v4_single = Ipv4Net::new(Ipv4Addr::BROADCAST, 32).unwrap();
    assert!(v4_single.checked_add_subnets(1).is_none());
    assert_eq!(
      v4_single.checked_sub_subnets(1).unwrap().addr(),
      "255.255.255.254".parse::<Ipv4Addr>().unwrap()
    );

    let v6_single = Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 128).unwrap();
    assert!(v6_single.checked_sub_subnets(1).is_none());
    assert_eq!(
      v6_single.checked_add_subnets(1).unwrap().addr(),
      "::1".parse::<Ipv6Addr>().unwrap()
    );
  }

  #[test]
  fn enum_network_offsets_reject_unrepresentable_ipv4_counts() {
    let net = IpNet::V4(Ipv4Net::new("192.0.2.42".parse::<Ipv4Addr>().unwrap(), 24).unwrap());
    assert!(net.checked_add_address(u128::from(u32::MAX) + 1).is_none());
    assert!(net.checked_add_subnets(u128::from(u32::MAX) + 1).is_none());
    assert_eq!(
      net.nth_usable(0),
      Some(IpAddr::V4("192.0.2.1".parse::<Ipv4Addr>().unwrap()))
    );
  }
}
