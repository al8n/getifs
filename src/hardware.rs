use std::hash::{Hash, Hasher};

use hardware_address::{Eui64Addr, InfiniBandAddr, MacAddr};

/// A captured link-layer hardware address.
///
/// Known fixed-width encodings use their typed `hardware-address` values.
/// Other nonzero encodings retain their complete raw byte sequence. Empty and
/// all-zero values are represented as absent by [`HardwareAddr::from_bytes`].
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum HardwareAddr {
  /// A six-octet EUI-48 (MAC) address.
  Mac(MacAddr),
  /// An eight-octet EUI-64 address.
  Eui64(Eui64Addr),
  /// A twenty-octet InfiniBand address.
  InfiniBand(InfiniBandAddr),
  /// A nonempty hardware address with an otherwise unknown width.
  Raw(Box<[u8]>),
}

impl HardwareAddr {
  /// Decodes a hardware address while preserving its complete byte sequence.
  ///
  /// Empty values and values consisting only of zero octets return `None`.
  /// Six-, eight-, and twenty-octet values use the corresponding typed
  /// variant; all other nonzero values use [`HardwareAddr::Raw`].
  #[inline]
  pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
    if bytes.is_empty() || bytes.iter().all(|&byte| byte == 0) {
      return None;
    }

    match bytes.len() {
      MacAddr::SIZE => Some(Self::Mac(MacAddr::from_raw(bytes.try_into().ok()?))),
      Eui64Addr::SIZE => Some(Self::Eui64(Eui64Addr::from_raw(bytes.try_into().ok()?))),
      InfiniBandAddr::SIZE => Some(Self::InfiniBand(InfiniBandAddr::from_raw(
        bytes.try_into().ok()?,
      ))),
      _ => Some(Self::Raw(Box::from(bytes))),
    }
  }

  /// Returns the complete captured hardware-address bytes.
  #[inline]
  pub fn as_bytes(&self) -> &[u8] {
    match self {
      Self::Mac(addr) => addr.as_bytes(),
      Self::Eui64(addr) => addr.as_bytes(),
      Self::InfiniBand(addr) => addr.as_bytes(),
      Self::Raw(bytes) => bytes,
    }
  }
}

impl PartialEq for HardwareAddr {
  #[inline]
  fn eq(&self, other: &Self) -> bool {
    self.as_bytes() == other.as_bytes()
  }
}

impl Eq for HardwareAddr {}

impl Hash for HardwareAddr {
  #[inline]
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.as_bytes().len().hash(state);
    self.as_bytes().hash(state);
  }
}

#[cfg(test)]
mod tests {
  use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
  };

  use hardware_address::{Eui64Addr, InfiniBandAddr, MacAddr};

  use super::HardwareAddr;

  fn hash(addr: &HardwareAddr) -> u64 {
    let mut hasher = DefaultHasher::new();
    addr.hash(&mut hasher);
    hasher.finish()
  }

  #[test]
  fn canonical_widths_and_zero_normalization() {
    assert!(matches!(
      HardwareAddr::from_bytes(&[1; 6]),
      Some(HardwareAddr::Mac(_))
    ));
    assert!(matches!(
      HardwareAddr::from_bytes(&[1; 8]),
      Some(HardwareAddr::Eui64(_))
    ));
    assert!(matches!(
      HardwareAddr::from_bytes(&[1; 20]),
      Some(HardwareAddr::InfiniBand(_))
    ));
    assert_eq!(
      HardwareAddr::from_bytes(&[1; 5]).unwrap().as_bytes(),
      &[1; 5]
    );
    assert!(HardwareAddr::from_bytes(&[]).is_none());
    assert!(HardwareAddr::from_bytes(&[0; 5]).is_none());
    assert!(HardwareAddr::from_bytes(&[0; 6]).is_none());
    assert!(HardwareAddr::from_bytes(&[0; 8]).is_none());
    assert!(HardwareAddr::from_bytes(&[0; 20]).is_none());
  }

  #[test]
  fn equality_and_hash_ignore_the_representation() {
    let raw6 = HardwareAddr::Raw(Box::from([1, 2, 3, 4, 5, 6].as_slice()));
    let mac = HardwareAddr::Mac(MacAddr::from_raw([1, 2, 3, 4, 5, 6]));
    assert_eq!(raw6, mac);
    assert_eq!(hash(&raw6), hash(&mac));

    let raw8 = HardwareAddr::Raw(Box::from([1, 2, 3, 4, 5, 6, 7, 8].as_slice()));
    let eui64 = HardwareAddr::Eui64(Eui64Addr::from_raw([1, 2, 3, 4, 5, 6, 7, 8]));
    assert_eq!(raw8, eui64);
    assert_eq!(hash(&raw8), hash(&eui64));

    let infiniband = HardwareAddr::InfiniBand(InfiniBandAddr::from_raw([1; 20]));
    assert_ne!(mac, infiniband);
    assert_ne!(
      HardwareAddr::Raw(Box::from([1; 5].as_slice())),
      HardwareAddr::Raw(Box::from([1; 6].as_slice()))
    );
    assert_ne!(
      raw6,
      HardwareAddr::Raw(Box::from([1, 2, 3, 4, 5, 7].as_slice()))
    );
  }
}
