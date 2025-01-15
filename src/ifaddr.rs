use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use either::Either;
use ipnet::{IpNet, Ipv4Net, Ipv6Net, PrefixLenError};

macro_rules! if_addr {
  ($kind:literal) => {
    paste::paste! {
      #[doc = "An interface IP" $kind " address."]
      #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
      pub struct [<If $kind Addr>] {
        index: u32,
        addr: Either<[<Ip $kind Net>], [<Ip $kind Addr>]>,
      }

      impl core::fmt::Display for [<If $kind Addr>] {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
          match self.addr {
            Either::Left(net) => write!(f, "{} ({})", net, self.index),
            Either::Right(addr) => write!(f, "{} ({})", addr, self.index),
          }
        }
      }

      impl [<If $kind Addr>] {
        #[doc = "Creates a new `Ifv4Addr` from an [`Ip" $kind "Addr`]."]
        #[inline]
        pub const fn from_addr(index: u32, addr: [<Ip $kind Addr>]) -> Self {
          Self {
            index,
            addr: Either::Right(addr),
          }
        }

        #[doc = "Creates a new `Ifv4Addr` from an [`Ip" $kind "Net`]."]
        #[inline]
        pub const fn from_net(index: u32, addr: [<Ip $kind Net>]) -> Self {
          Self {
            index,
            addr: Either::Left(addr),
          }
        }

        #[doc = "Creates a new IP" $kind "interface address from an index, [`Ip" $kind "Addr`] and prefix length."]
        #[inline]
        pub const fn with_prefix_len(index: u32, addr: [<Ip $kind Addr>], prefix_len: u8) -> Result<Self, PrefixLenError> {
          match [<Ip $kind Net>]::new(addr, prefix_len) {
            Ok(net) => Ok(Self::from_net(index, net)),
            Err(err) => Err(err),
          }
        }

        #[doc = "Creates a new IP" $kind " interface address from an index, [`Ip" $kind "Addr`] and prefix length."]
        /// If called from a const context it will verify prefix length at compile time.
        /// Otherwise it will panic at runtime if prefix length is not less then or equal to 32.
        #[inline]
        pub const fn with_prefix_len_assert(index: u32, addr: [<Ip $kind Addr>], prefix_len: u8) -> Self {
          Self { index, addr: Either::Left([<Ip $kind Net>]::new_assert(addr, prefix_len)) }
        }

        /// Returns the index of the interface.
        #[inline]
        pub const fn index(&self) -> u32 {
          self.index
        }

        /// Returns the address of the interface.
        #[inline]
        pub const fn addr(&self) -> [<Ip $kind Addr>] {
          match self.addr {
            Either::Left(ref net) => net.addr(),
            Either::Right(addr) => addr,
          }
        }

        /// Returns the IP of the interface.
        #[inline]
        pub const fn ip(&self) -> Either<&[<Ip $kind Net>], &[<Ip $kind Addr>]> {
          match self.addr {
            Either::Left(ref net) => Either::Left(net),
            Either::Right(ref addr) => Either::Right(addr),
          }
        }

        /// Returns the prefix length of the interface address.
        #[inline]
        pub const fn prefix_len(&self) -> Option<u8> {
          match self.addr {
            Either::Left(ref net) => Some(net.prefix_len()),
            Either::Right(_) => None,
          }
        }

        /// Returns the maximum prefix length of the interface address.
        #[inline]
        pub const fn max_prefix_len(&self) -> Option<u8> {
          match self.addr {
            Either::Left(ref net) => Some(net.max_prefix_len()),
            Either::Right(_) => None,
          }
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
  pub const fn from_addr(index: u32, addr: IpAddr) -> Self {
    match addr {
      IpAddr::V4(addr) => Self::V4(Ifv4Addr::from_addr(index, addr)),
      IpAddr::V6(addr) => Self::V6(Ifv6Addr::from_addr(index, addr)),
    }
  }

  /// Creates a new `IfAddr` from an [`IpNet`].
  #[inline]
  pub const fn from_net(index: u32, addr: IpNet) -> Self {
    match addr {
      IpNet::V4(addr) => Self::V4(Ifv4Addr::from_net(index, addr)),
      IpNet::V6(addr) => Self::V6(Ifv6Addr::from_net(index, addr)),
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
      IpAddr::V4(addr) => match Ifv4Addr::with_prefix_len(index, addr, prefix_len) {
        Ok(addr) => Ok(Self::V4(addr)),
        Err(err) => Err(err),
      },
      IpAddr::V6(addr) => match Ifv6Addr::with_prefix_len(index, addr, prefix_len) {
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
      IpAddr::V4(addr) => Self::V4(Ifv4Addr::with_prefix_len_assert(index, addr, prefix_len)),
      IpAddr::V6(addr) => Self::V6(Ifv6Addr::with_prefix_len_assert(index, addr, prefix_len)),
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
  pub const fn prefix_len(&self) -> Option<u8> {
    match self {
      Self::V4(addr) => addr.prefix_len(),
      Self::V6(addr) => addr.prefix_len(),
    }
  }

  /// Returns the maximum prefix length of the interface address.
  #[inline]
  pub const fn max_prefix_len(&self) -> Option<u8> {
    match self {
      Self::V4(addr) => addr.max_prefix_len(),
      Self::V6(addr) => addr.max_prefix_len(),
    }
  }
}
