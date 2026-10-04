use std::{io, net::Ipv4Addr};

/// Returns a non-link-local IPv4 address for the interface named `name`.
///
/// `Ok(None)` means the named interface was found but has no matching IPv4
/// address. A missing name remains an error from [`super::ifname_to_index`].
///
/// ## Example
///
/// ```rust
/// use getifs::{ifname_to_v4_iface, interfaces};
///
/// let interface = interfaces().unwrap().into_iter().next().unwrap();
/// let iface = ifname_to_v4_iface(interface.name()).unwrap().unwrap();
///
/// let addrs = interface.ipv4_addrs().unwrap().into_iter().map(|net| net.addr()).collect::<Vec<_>>();
/// assert!(addrs.contains(&iface));
/// ```
pub fn ifname_to_v4_iface(name: &str) -> io::Result<Option<Ipv4Addr>> {
  let idx = super::name_to_idx::ifname_to_index(name)?;
  let iface = super::interface_by_index(idx)?;

  match iface {
    Some(iface) => {
      let addrs = iface.ipv4_addrs_by_filter(|ip| !ip.is_link_local())?;

      Ok(addrs.into_iter().next().map(|net| net.addr()))
    }
    None => Ok(None),
  }
}

/// Returns the interface index for the interface named `name`.
///
/// `Ok(Some(index))` is the normal result. `Ok(None)` preserves the historic
/// zero-index mapping and is not a missing-name signal; a missing name remains
/// an error from [`super::ifname_to_index`].
///
/// ## Example
///
/// ```rust
/// use getifs::{ifname_to_v6_iface, interfaces};
///
/// let interface = interfaces().unwrap().into_iter().next().unwrap();
/// let iface = ifname_to_v6_iface(interface.name()).unwrap();
///
/// assert_eq!(interface.index(), iface.unwrap());
/// ```
pub fn ifname_to_v6_iface(name: &str) -> io::Result<Option<u32>> {
  super::name_to_idx::ifname_to_index(name).map(|idx| (idx != 0).then_some(idx))
}

/// Returns the historic IPv4-address and interface-index tuple for `name`.
///
/// The first `Option` is `None` when the interface has no non-link-local IPv4
/// address (or disappears before its addresses are read). The second is
/// `None` only for the historic zero-index mapping; it is not a missing-name
/// signal. A missing name remains an error from [`super::ifname_to_index`].
///
/// ## Example
///
/// ```rust
/// use getifs::{ifname_to_iface, interfaces};
///
/// let interface = interfaces().unwrap().into_iter().next().unwrap();
/// let (v4_iface, v6_iface) = ifname_to_iface(interface.name()).unwrap();
///
/// assert_eq!(interface.index(), v6_iface.unwrap());
///
/// let addrs = interface.ipv4_addrs().unwrap().into_iter().map(|net| net.addr()).collect::<Vec<_>>();
/// assert!(addrs.contains(&v4_iface.unwrap()));
/// ```
pub fn ifname_to_iface(name: &str) -> io::Result<(Option<Ipv4Addr>, Option<u32>)> {
  let idx = super::name_to_idx::ifname_to_index(name)?;
  let v6_iface = (idx != 0).then_some(idx);
  let iface = super::interface_by_index(idx)?;

  match iface {
    Some(iface) => {
      let addrs = iface.ipv4_addrs_by_filter(|ip| !ip.is_link_local())?;
      let v4_iface = addrs.into_iter().next().map(|net| net.addr());
      Ok((v4_iface, v6_iface))
    }
    None => Ok((None, v6_iface)),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  // Round-trip every public function against the first interface
  // returned by `interfaces()`. Hits the success arm, the
  // `iface.ipv4_addrs_by_filter` call, and the
  // `Some(iface) => ...` match arm of each entry point.
  //
  // Skipped on DragonFly: vmactions interface churn means `interface_by_index`
  // intermittently returns `None` for an interface `interfaces()` just listed.
  #[cfg(not(target_os = "dragonfly"))]
  #[test]
  fn ifname_to_v4_iface_first_interface() {
    let ift = crate::interfaces().unwrap();
    let first = ift.iter().next().unwrap();
    // Result may be None (the first interface can lack a
    // non-link-local v4 address), but the call itself must succeed.
    let _ = ifname_to_v4_iface(first.name()).unwrap();
  }

  #[cfg(not(target_os = "dragonfly"))]
  #[test]
  fn ifname_to_v6_iface_round_trips() {
    let ift = crate::interfaces().unwrap();
    let first = ift.iter().next().unwrap();
    let v6 = ifname_to_v6_iface(first.name()).unwrap();
    assert_eq!(v6, Some(first.index()));
  }

  #[cfg(not(target_os = "dragonfly"))]
  #[test]
  fn ifname_to_iface_round_trips() {
    let ift = crate::interfaces().unwrap();
    let first = ift.iter().next().unwrap();
    let (_, v6) = ifname_to_iface(first.name()).unwrap();
    assert_eq!(v6, Some(first.index()));
  }

  // Error path: non-existent name surfaces from the
  // `ifname_to_index` lookup with `?` and never reaches the match
  // arms.
  #[test]
  fn ifname_to_v4_iface_unknown_name_errors() {
    assert!(ifname_to_v4_iface("nonexistent_iface_xyz_12345").is_err());
  }

  #[test]
  fn ifname_to_v6_iface_unknown_name_errors() {
    assert!(ifname_to_v6_iface("nonexistent_iface_xyz_12345").is_err());
  }

  #[test]
  fn ifname_to_iface_unknown_name_errors() {
    assert!(ifname_to_iface("nonexistent_iface_xyz_12345").is_err());
  }
}
