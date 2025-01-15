use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

macro_rules! if_addr {
  ($kind:literal) => {
    paste::paste! {
      #[doc = "An interface IP" $kind " address."]
      #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
      pub struct [<If $kind Addr>] {
        index: u32,
        addr: [<Ip $kind Addr>],
      }

      impl core::fmt::Display for [<If $kind Addr>] {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
          write!(f, "{} ({})", self.addr, self.index)
        }
      }

      impl core::ops::Deref for [<If $kind Addr>] {
        type Target = [<Ip $kind Addr>];

        #[inline]
        fn deref(&self) -> &Self::Target {
          &self.addr
        }
      }

      impl [<If $kind Addr>] {
        #[doc = "Creates a new `If" $kind "Addr` from an [`Ip" $kind "Addr`]."]
        #[inline]
        pub const fn new(index: u32, addr: [<Ip $kind Addr>]) -> Self {
          Self {
            index,
            addr,
          }
        }

        /// Returns the index of the interface.
        #[inline]
        pub const fn index(&self) -> u32 {
          self.index
        }

        /// Returns the name of the interface.
        ///
        /// This method will invoke the `if_indextoname` function to get the name of the interface internally.
        pub fn name(&self) -> std::io::Result<smol_str::SmolStr> {
          crate::idx_to_name::ifindex_to_name(self.index)
        }

        /// Returns the address of the interface.
        #[inline]
        pub const fn addr(&self) -> [<Ip $kind Addr>] {
          self.addr
        }
      }
    }
  };
}

if_addr!("v4");
if_addr!("v6");

/// An interface address.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum IfAddr {
  /// An IPv4 interface address.
  V4(Ifv4Addr),
  /// An IPv6 interface address.
  V6(Ifv6Addr),
}

impl core::fmt::Display for IfAddr {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::V4(addr) => write!(f, "{addr}"),
      Self::V6(addr) => write!(f, "{addr}"),
    }
  }
}

impl From<Ifv4Addr> for IfAddr {
  fn from(value: Ifv4Addr) -> Self {
    Self::V4(value)
  }
}

impl From<Ifv6Addr> for IfAddr {
  fn from(value: Ifv6Addr) -> Self {
    Self::V6(value)
  }
}

impl IfAddr {
  /// Creates a new `IfAddr` from an [`IpAddr`].
  #[inline]
  pub const fn new(index: u32, addr: IpAddr) -> Self {
    match addr {
      IpAddr::V4(addr) => Self::V4(Ifv4Addr::new(index, addr)),
      IpAddr::V6(addr) => Self::V6(Ifv6Addr::new(index, addr)),
    }
  }

  /// Returns the index of the interface.
  #[inline]
  pub const fn index(&self) -> u32 {
    match self {
      Self::V4(addr) => addr.index(),
      Self::V6(addr) => addr.index(),
    }
  }

  /// Returns the name of the interface.
  ///
  /// This method will invoke the `if_indextoname` function to get the name of the interface internally.
  pub fn name(&self) -> std::io::Result<smol_str::SmolStr> {
    crate::idx_to_name::ifindex_to_name(self.index())
  }

  /// Returns the address of the interface.
  #[inline]
  pub const fn addr(&self) -> IpAddr {
    match self {
      Self::V4(addr) => IpAddr::V4(addr.addr()),
      Self::V6(addr) => IpAddr::V6(addr.addr()),
    }
  }
}
