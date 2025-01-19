use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net, PrefixLenError};

macro_rules! if_net {
  ($kind:literal) => {
    paste::paste! {
      #[doc = "An interface IP" $kind " network."]
      #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
      pub struct [<If $kind Net>] {
        index: u32,
        addr: [<Ip $kind Net>],
      }

      impl core::fmt::Display for [<If $kind Net>] {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
          write!(f, "{} ({})", self.addr, self.index)
        }
      }

      impl core::ops::Deref for [<If $kind Net>] {
        type Target = [<Ip $kind Net>];

        #[inline]
        fn deref(&self) -> &Self::Target {
          &self.addr
        }
      }

      impl [<If $kind Net>] {
        #[doc = "Creates a new `If" $kind "Net` from an [`Ip" $kind "Net`]."]
        #[inline]
        pub const fn new(index: u32, addr: [<Ip $kind Net>]) -> Self {
          Self {
            index,
            addr,
          }
        }

        #[doc = "Creates a new IP" $kind "interface address from an index, [`Ip" $kind "Addr`] and prefix length."]
        #[inline]
        pub const fn with_prefix_len(index: u32, addr: [<Ip $kind Addr>], prefix_len: u8) -> Result<Self, PrefixLenError> {
          match [<Ip $kind Net>]::new(addr, prefix_len) {
            Ok(net) => Ok(Self::new(index, net)),
            Err(err) => Err(err),
          }
        }

        #[doc = "Creates a new IP" $kind " interface address from an index, [`Ip" $kind "Addr`] and prefix length."]
        /// If called from a const context it will verify prefix length at compile time.
        /// Otherwise it will panic at runtime if prefix length is not less then or equal to 32.
        #[inline]
        pub const fn with_prefix_len_assert(index: u32, addr: [<Ip $kind Addr>], prefix_len: u8) -> Self {
          Self { index, addr: [<Ip $kind Net>]::new_assert(addr, prefix_len) }
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
          self.addr.addr()
        }

        /// Returns the net of the interface.
        #[inline]
        pub const fn net(&self) -> &[<Ip $kind Net>] {
          &self.addr
        }

        /// Returns the prefix length of the interface address.
        #[inline]
        pub const fn prefix_len(&self) -> u8 {
          self.addr.prefix_len()
        }

        /// Returns the maximum prefix length of the interface address.
        #[inline]
        pub const fn max_prefix_len(&self) -> u8 {
          self.addr.max_prefix_len()
        }
      }
    }
  };
}

if_net!("v4");
if_net!("v6");

/// An interface network.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum IfNet {
  /// An IPv4 interface address.
  V4(Ifv4Net),
  /// An IPv6 interface address.
  V6(Ifv6Net),
}

impl core::fmt::Display for IfNet {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::V4(addr) => write!(f, "{addr}"),
      Self::V6(addr) => write!(f, "{addr}"),
    }
  }
}

impl From<Ifv4Net> for IfNet {
  fn from(value: Ifv4Net) -> Self {
    Self::V4(value)
  }
}

impl From<Ifv6Net> for IfNet {
  fn from(value: Ifv6Net) -> Self {
    Self::V6(value)
  }
}

impl IfNet {
  /// Creates a new `IfNet` from an [`IpNet`].
  #[inline]
  pub const fn from_net(index: u32, addr: IpNet) -> Self {
    match addr {
      IpNet::V4(addr) => Self::V4(Ifv4Net::new(index, addr)),
      IpNet::V6(addr) => Self::V6(Ifv6Net::new(index, addr)),
    }
  }

  /// Creates a new IP interface address from an index, [`IpAddr`] and prefix length.
  #[inline]
  pub const fn with_prefix_len(
    index: u32,
    addr: IpAddr,
    prefix_len: u8,
  ) -> Result<Self, PrefixLenError> {
    match addr {
      IpAddr::V4(addr) => match Ifv4Net::with_prefix_len(index, addr, prefix_len) {
        Ok(addr) => Ok(Self::V4(addr)),
        Err(err) => Err(err),
      },
      IpAddr::V6(addr) => match Ifv6Net::with_prefix_len(index, addr, prefix_len) {
        Ok(addr) => Ok(Self::V6(addr)),
        Err(err) => Err(err),
      },
    }
  }

  /// Creates a new IP interface address from an index, [`IpAddr`] and prefix length.
  /// If called from a const context it will verify prefix length at compile time.
  /// Otherwise it will panic at runtime if prefix length is not less then or equal to 32.
  #[inline]
  pub const fn with_prefix_len_assert(index: u32, addr: IpAddr, prefix_len: u8) -> Self {
    match addr {
      IpAddr::V4(addr) => Self::V4(Ifv4Net::with_prefix_len_assert(index, addr, prefix_len)),
      IpAddr::V6(addr) => Self::V6(Ifv6Net::with_prefix_len_assert(index, addr, prefix_len)),
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

  /// Returns the prefix length of the interface address.
  #[inline]
  pub const fn prefix_len(&self) -> u8 {
    match self {
      Self::V4(addr) => addr.addr.prefix_len(),
      Self::V6(addr) => addr.addr.prefix_len(),
    }
  }

  /// Returns the maximum prefix length of the interface address.
  #[inline]
  pub const fn max_prefix_len(&self) -> u8 {
    match self {
      Self::V4(addr) => addr.addr.max_prefix_len(),
      Self::V6(addr) => addr.addr.max_prefix_len(),
    }
  }
}
