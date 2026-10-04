use std::{
  io::{self, Error, Result},
  marker::PhantomData,
  mem::MaybeUninit,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use smallvec_wrapper::{SmallVec, TinyVec};
use windows_sys::{
  Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, NO_ERROR},
  Win32::NetworkManagement::{IpHelper::*, Ndis::*},
  Win32::Networking::WinSock::*,
};

use super::{
  Address, IfAddr, IfNet, Ifv4Addr, Ifv4Net, Ifv6Addr, Ifv6Net, Interface, IpRoute, Ipv4Route,
  Ipv6Route, MacAddr, Net, MAC_ADDRESS_SIZE,
};

pub(super) use gateway::*;
pub(super) use local_addr::*;
pub(super) use route::*;

#[path = "windows/local_addr.rs"]
mod local_addr;

#[path = "windows/gateway.rs"]
mod gateway;

#[path = "windows/route.rs"]
mod route;

#[path = "windows/mib.rs"]
mod mib;

bitflags::bitflags! {
  /// Flags represents the interface flags.
  #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
  pub struct Flags: u32 {
    /// Interface is administratively up
    const UP = 0x1;
    /// Interface supports broadcast access capability
    const BROADCAST = 0x2;
    /// Interface is a loopback net
    const LOOPBACK = 0x4;
    /// Interface is point-to-point link
    const POINTOPOINT = 0x8;
    /// Supports multicast access capability
    const MULTICAST = 0x10;
    /// Resources allocated
    const RUNNING = 0x20;
  }
}

struct Information {
  // The kernel writes a null-terminated singly-linked list of
  // `IP_ADAPTER_ADDRESSES_LH` records into this buffer, with every
  // `Next`/`FirstUnicastAddress`/`FriendlyName`/… pointer aimed back
  // into it. We keep the buffer alive and walk the list via an
  // iterator — no per-adapter copy.
  //
  // Backing type is `Vec<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>>` so
  // the allocation is aligned for `IP_ADAPTER_ADDRESSES_LH` itself —
  // `MaybeUninit<T>` is documented to have the same size, alignment,
  // and ABI as `T`. `Vec<u8>` would only guarantee 1-byte alignment,
  // and `Vec<u64>` only `align_of::<u64>()`, neither of which is a
  // sound proxy for the struct's alignment across all targets.
  // Dereferencing a misaligned `IP_ADAPTER_ADDRESSES_LH` is UB in
  // Rust, so the backing allocation must carry the correct alignment
  // by construction.
  buffer: Vec<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>>,
}

/// Compile-time assertion that `MaybeUninit<IP_ADAPTER_ADDRESSES_LH>`
/// inherits the struct's alignment. Guaranteed by the standard library,
/// but the explicit check makes the invariant load-bearing if anyone
/// ever changes the backing element type.
const _: () = assert!(
  core::mem::align_of::<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>>()
    == core::mem::align_of::<IP_ADAPTER_ADDRESSES_LH>()
);

/// Bytes per backing slot — one whole `IP_ADAPTER_ADDRESSES_LH` worth
/// of storage. Rounding the requested byte count up to whole slots
/// wastes at most `size_of - 1` bytes per fetch and keeps the
/// struct-aligned guarantee.
const SLOT_SIZE: usize = core::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>();
const INITIAL_BUFFER_SIZE: u32 = 15_000;
const MAX_TRIES: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdapterQueryStatus {
  Success,
  Empty,
  Retry,
}

#[inline]
fn classify_adapter_status(status: u32) -> Result<AdapterQueryStatus> {
  match status {
    NO_ERROR => Ok(AdapterQueryStatus::Success),
    ERROR_NO_DATA => Ok(AdapterQueryStatus::Empty),
    ERROR_BUFFER_OVERFLOW => Ok(AdapterQueryStatus::Retry),
    status => Err(Error::from_raw_os_error(status as i32)),
  }
}

/// Round a byte count up to a whole number of backing slots.
#[inline]
fn slots_for(size_bytes: u32) -> Option<usize> {
  let size_bytes = usize::try_from(size_bytes).ok()?;
  size_bytes
    .checked_add(SLOT_SIZE - 1)
    .map(|rounded| rounded / SLOT_SIZE)
}

/// Return the slot count and the exact byte length that can be safely
/// advertised to `GetAdaptersAddresses` for a requested byte count.
#[inline]
fn buffer_layout(size_bytes: u32) -> Option<(usize, u32)> {
  let slots = slots_for(size_bytes)?;
  let bytes = slots.checked_mul(SLOT_SIZE)?;
  Some((slots, u32::try_from(bytes).ok()?))
}

fn resize_buffer(
  buffer: &mut Vec<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>>,
  requested_bytes: u32,
) -> Result<u32> {
  let (slots, _) = buffer_layout(requested_bytes).ok_or_else(|| {
    Error::new(
      io::ErrorKind::InvalidData,
      "GetAdaptersAddresses reported an unrepresentable buffer size",
    )
  })?;

  if slots > buffer.len() {
    buffer
      .try_reserve_exact(slots - buffer.len())
      .map_err(|_| {
        Error::new(
          io::ErrorKind::OutOfMemory,
          "failed to allocate the GetAdaptersAddresses buffer",
        )
      })?;
    buffer.resize_with(slots, MaybeUninit::uninit);
  }

  buffer
    .len()
    .checked_mul(SLOT_SIZE)
    .and_then(|bytes| u32::try_from(bytes).ok())
    .ok_or_else(|| {
      Error::new(
        io::ErrorKind::InvalidData,
        "GetAdaptersAddresses buffer length cannot be represented as u32",
      )
    })
}

#[inline]
fn retry_size(reported_bytes: u32, allocated_bytes: u32, attempt: usize) -> Result<u32> {
  if attempt + 1 == MAX_TRIES || reported_bytes <= allocated_bytes {
    Err(Error::from_raw_os_error(ERROR_BUFFER_OVERFLOW as i32))
  } else {
    Ok(reported_bytes)
  }
}

impl Information {
  fn fetch() -> Result<Self> {
    let mut buffer: Vec<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>> = Vec::new();
    // `MaybeUninit::uninit` skips a 15KB zero-fill. Windows initializes the
    // records and strings it returns; readers below never form references
    // over the unwritten tail of this allocation.
    let mut buffer_bytes = resize_buffer(&mut buffer, INITIAL_BUFFER_SIZE)?;
    for attempt in 0..MAX_TRIES {
      // `SizePointer` describes the allocation passed to the kernel, not
      // merely the byte count that originally caused us to allocate it.
      let mut size = buffer_bytes;
      let result = unsafe {
        GetAdaptersAddresses(
          AF_UNSPEC as u32,
          GAA_FLAG_INCLUDE_PREFIX,
          std::ptr::null() as _,
          buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
          &mut size,
        )
      };

      match classify_adapter_status(result)? {
        AdapterQueryStatus::Success if size == 0 => {
          return Ok(Self { buffer: Vec::new() });
        }
        AdapterQueryStatus::Success => return Ok(Self { buffer }),
        // No addresses is a valid empty snapshot, not a stale thread-local
        // last-error. This occurs on hosts with no configured IP adapters.
        AdapterQueryStatus::Empty => return Ok(Self { buffer: Vec::new() }),
        AdapterQueryStatus::Retry => {}
      }

      // A concurrent adapter change can make the required size grow
      // between calls. Bound that race exactly as Microsoft's sample
      // does, and reject a non-growing overflow response rather than
      // spinning forever.
      let required_bytes = retry_size(size, buffer_bytes, attempt)?;
      buffer_bytes = resize_buffer(&mut buffer, required_bytes)?;
    }

    Err(Error::from_raw_os_error(ERROR_BUFFER_OVERFLOW as i32))
  }

  /// Iterate over the native adapter linked list in-place, without
  /// copying the (~400-byte) `IP_ADAPTER_ADDRESSES_LH` records.
  ///
  /// Each yielded reference borrows from `self.buffer`, so the iterator
  /// (and any pointer fields read from its items) must not outlive
  /// this `Information`.
  fn iter(&self) -> AdapterIter<'_> {
    let head = if self.buffer.is_empty() {
      std::ptr::null()
    } else {
      self.buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH
    };
    AdapterIter {
      current: head,
      _marker: PhantomData,
    }
  }

  /// Resolve a UTF-16 string returned inside the adapter buffer without
  /// ever scanning beyond that allocation.
  fn friendly_name(&self, name: windows_sys::core::PWSTR) -> Option<smol_str::SmolStr> {
    if name.is_null() {
      return None;
    }

    let start = self.buffer.as_ptr() as usize;
    let byte_len = self.buffer.len().checked_mul(SLOT_SIZE)?;
    let end = start.checked_add(byte_len)?;
    let name_addr = name as usize;
    if name_addr < start || name_addr >= end || name_addr % core::mem::align_of::<u16>() != 0 {
      return None;
    }

    let available_units =
      ((end - name_addr) / core::mem::size_of::<u16>()).min(IF_MAX_STRING_SIZE as usize + 1);
    let name = name.cast_const();
    for len in 0..available_units {
      // SAFETY: `name.add(len)` stays inside the allocation by construction.
      // `GetAdaptersAddresses` guarantees that `FriendlyName` points to an
      // initialized, NUL-terminated UTF-16 string in the returned buffer, so
      // every unit through the first NUL is initialized. Reading one unit at a
      // time avoids creating a reference over the unwritten tail of the
      // `MaybeUninit` allocation.
      if unsafe { name.add(len).read() } == 0 {
        // SAFETY: only the initialized string prefix through its NUL is made
        // into a slice, and that range was checked against the allocation.
        let initialized = unsafe { core::slice::from_raw_parts(name, len + 1) };
        return crate::utils::friendly_name(initialized);
      }
    }
    None
  }
}

struct AdapterIter<'a> {
  current: *const IP_ADAPTER_ADDRESSES_LH,
  _marker: PhantomData<&'a IP_ADAPTER_ADDRESSES_LH>,
}

impl<'a> Iterator for AdapterIter<'a> {
  type Item = &'a IP_ADAPTER_ADDRESSES_LH;

  fn next(&mut self) -> Option<Self::Item> {
    // SAFETY: `current` is either null, or a pointer into the buffer
    // of the `Information` whose lifetime this iterator borrows. The
    // kernel produced a null-terminated singly-linked list of these
    // structs in that buffer.
    unsafe {
      let curr = self.current.as_ref()?;
      self.current = curr.Next;
      Some(curr)
    }
  }
}

/// Resolves an adapter name when its `FriendlyName` is unavailable.
///
/// Returns `None` when `if_indextoname` fails or yields an empty or
/// non-UTF-8 name: such a name could not be passed back to
/// `ifname_to_index`.
pub(super) fn interface_name_fallback(index: u32) -> Option<smol_str::SmolStr> {
  let mut name_buf = [0u8; IF_MAX_STRING_SIZE as usize + 1];
  // SAFETY: `if_indextoname` writes into `name_buf` (which is >= IF_NAMESIZE)
  // and returns either a pointer into that buffer or null.
  let hname = unsafe { if_indextoname(index, name_buf.as_mut_ptr()) };
  if hname.is_null() {
    return None;
  }
  std::ffi::CStr::from_bytes_until_nul(&name_buf)
    .ok()
    .and_then(|name| name.to_str().ok())
    .filter(|name| !name.is_empty())
    .map(smol_str::SmolStr::new)
}

#[inline]
pub(super) fn win32_status_error(status: u32) -> io::Error {
  io::Error::from_raw_os_error(status as i32)
}

#[inline]
fn adapter_mac_address(adapter: &IP_ADAPTER_ADDRESSES_LH) -> Option<MacAddr> {
  if adapter.PhysicalAddressLength as usize != MAC_ADDRESS_SIZE {
    return None;
  }

  let mut bytes = [0; MAC_ADDRESS_SIZE];
  bytes.copy_from_slice(&adapter.PhysicalAddress[..MAC_ADDRESS_SIZE]);
  Some(MacAddr::from_raw(bytes))
}

/// Resolves the interface index for a Windows adapter.
///
/// Mirrors Go's `net/interface_windows.go`: prefer the LUID-derived
/// index, fall back to `Ipv6IfIndex` only when the conversion fails.
fn adapter_index(adapter: &IP_ADAPTER_ADDRESSES_LH) -> u32 {
  let mut index = 0u32;
  // SAFETY: `adapter.Luid` is a kernel-populated LUID; `index` is a
  // writable local `u32`.
  let res = unsafe { ConvertInterfaceLuidToIndex(&adapter.Luid, &mut index) };
  if res != NO_ERROR {
    index = adapter.Ipv6IfIndex;
  }
  index
}

pub(super) fn interface_table(idx: Option<u32>) -> io::Result<TinyVec<Interface>> {
  let info = Information::fetch()?;
  let mut interfaces = TinyVec::new();

  for adapter in info.iter() {
    let index = adapter_index(adapter);
    if idx.is_some_and(|i| i != index) {
      continue;
    }

    let Some(name) = info
      .friendly_name(adapter.FriendlyName)
      .or_else(|| interface_name_fallback(index))
    else {
      continue;
    };

    let mut flags = Flags::empty();
    if adapter.OperStatus == IfOperStatusUp {
      flags |= Flags::UP | Flags::RUNNING;
    }

    match adapter.IfType {
      IF_TYPE_ETHERNET_CSMACD
      | IF_TYPE_IEEE80211
      | IF_TYPE_IEEE1394
      | IF_TYPE_ISO88025_TOKENRING => {
        flags |= Flags::BROADCAST | Flags::MULTICAST;
      }
      IF_TYPE_PPP | IF_TYPE_TUNNEL => {
        flags |= Flags::POINTOPOINT | Flags::MULTICAST;
      }
      IF_TYPE_SOFTWARE_LOOPBACK => {
        flags |= Flags::LOOPBACK | Flags::MULTICAST;
      }
      IF_TYPE_ATM => {
        flags |= Flags::BROADCAST | Flags::POINTOPOINT | Flags::MULTICAST;
      }
      _ => {}
    }

    let mtu = if adapter.Mtu == 0xffffffff {
      0
    } else {
      adapter.Mtu
    };

    let hardware_addr = adapter_mac_address(adapter);

    interfaces.push(Interface {
      index,
      name,
      flags,
      mtu,
      mac_addr: hardware_addr,
    });

    if idx.is_some() {
      break;
    }
  }

  Ok(interfaces)
}

pub(super) fn interface_ipv4_addresses<F>(idx: Option<u32>, f: F) -> io::Result<SmallVec<Ifv4Net>>
where
  F: FnMut(&IpAddr) -> bool,
{
  interface_addr_table(AF_INET, idx, f)
}

pub(super) fn interface_ipv6_addresses<F>(idx: Option<u32>, f: F) -> io::Result<SmallVec<Ifv6Net>>
where
  F: FnMut(&IpAddr) -> bool,
{
  interface_addr_table(AF_INET6, idx, f)
}

pub(super) fn interface_addresses<F>(idx: Option<u32>, f: F) -> io::Result<SmallVec<IfNet>>
where
  F: FnMut(&IpAddr) -> bool,
{
  interface_addr_table(AF_UNSPEC, idx, f)
}

pub(super) fn interface_addr_table<T, F>(
  family: u16,
  ifi: Option<u32>,
  mut f: F,
) -> io::Result<SmallVec<T>>
where
  T: Net,
  F: FnMut(&IpAddr) -> bool,
{
  let info = Information::fetch()?;
  let mut addresses = SmallVec::new();

  for adapter in info.iter() {
    let index = adapter_index(adapter);
    if ifi.is_some_and(|i| i != index) {
      continue;
    }

    unsafe {
      let mut unicast = adapter.FirstUnicastAddress;
      while let Some(addr) = unicast.as_ref() {
        if let Some(ip) = sockaddr_to_ipaddr(family, addr.Address.lpSockaddr) {
          if let Some(ip) = T::try_from_with_filter(index, ip, addr.OnLinkPrefixLength, &mut f) {
            addresses.push(ip);
          }
        }
        unicast = addr.Next;
      }

      // TODO(al8n): Should we include anycast addresses?
    }
  }

  Ok(addresses)
}

pub(super) fn interface_multicast_ipv4_addresses<F>(
  idx: Option<u32>,
  mut f: F,
) -> io::Result<SmallVec<Ifv4Addr>>
where
  F: FnMut(&Ipv4Addr) -> bool,
{
  interface_multiaddr_table(AF_INET, idx, |addr| match addr {
    IpAddr::V4(ip) => f(ip),
    _ => false,
  })
}

pub(super) fn interface_multicast_ipv6_addresses<F>(
  idx: Option<u32>,
  mut f: F,
) -> io::Result<SmallVec<Ifv6Addr>>
where
  F: FnMut(&Ipv6Addr) -> bool,
{
  interface_multiaddr_table(AF_INET6, idx, |addr| match addr {
    IpAddr::V6(ip) => f(ip),
    _ => false,
  })
}

pub(super) fn interface_multicast_addresses<F>(
  idx: Option<u32>,
  f: F,
) -> io::Result<SmallVec<IfAddr>>
where
  F: FnMut(&IpAddr) -> bool,
{
  interface_multiaddr_table(AF_UNSPEC, idx, f)
}

pub(super) fn interface_multiaddr_table<T, F>(
  family: u16,
  ifi: Option<u32>,
  mut f: F,
) -> io::Result<SmallVec<T>>
where
  T: Address,
  F: FnMut(&IpAddr) -> bool,
{
  let info = Information::fetch()?;
  let mut addresses = SmallVec::new();

  for adapter in info.iter() {
    let index = adapter_index(adapter);
    if ifi.is_some_and(|i| i != index) {
      continue;
    }

    let mut multicast = adapter.FirstMulticastAddress;
    unsafe {
      while let Some(addr) = multicast.as_ref() {
        if let Some(ip) = sockaddr_to_ipaddr(family, addr.Address.lpSockaddr) {
          if let Some(ip) = T::try_from_with_filter(index, ip, &mut f) {
            addresses.push(ip);
          }
        }
        multicast = addr.Next;
      }
    }
  }

  Ok(addresses)
}

fn sockaddr_to_ipaddr(family: u16, sockaddr: *const SOCKADDR) -> Option<IpAddr> {
  if sockaddr.is_null() {
    return None;
  }

  unsafe {
    match (family, (*sockaddr).sa_family) {
      (AF_INET, AF_INET) | (AF_UNSPEC, AF_INET) => {
        let addr = sockaddr as *const SOCKADDR_IN;
        if addr.is_null() {
          return None;
        }
        let bytes = (*addr).sin_addr.S_un.S_addr.to_ne_bytes();
        Some(IpAddr::V4(bytes.into()))
      }
      (AF_INET6, AF_INET6) | (AF_UNSPEC, AF_INET6) => {
        let addr = sockaddr as *const SOCKADDR_IN6;
        if addr.is_null() {
          return None;
        }
        let bytes = (*addr).sin6_addr.u.Byte;
        Some(IpAddr::V6(bytes.into()))
      }
      _ => None,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn adapter_status_preserves_empty_and_error_outcomes() {
    assert_eq!(
      classify_adapter_status(NO_ERROR).unwrap(),
      AdapterQueryStatus::Success
    );
    assert_eq!(
      classify_adapter_status(ERROR_NO_DATA).unwrap(),
      AdapterQueryStatus::Empty
    );
    assert_eq!(
      classify_adapter_status(ERROR_BUFFER_OVERFLOW).unwrap(),
      AdapterQueryStatus::Retry
    );
    assert_eq!(
      classify_adapter_status(87).unwrap_err().raw_os_error(),
      Some(87)
    );
  }

  #[test]
  fn adapter_buffer_layout_rounds_up_and_reports_allocated_bytes() {
    let (one_slot, one_slot_bytes) = buffer_layout(1).unwrap();
    assert_eq!(one_slot, 1);
    assert_eq!(one_slot_bytes as usize, SLOT_SIZE);

    let requested = u32::try_from(SLOT_SIZE + 1).unwrap();
    let (two_slots, two_slot_bytes) = buffer_layout(requested).unwrap();
    assert_eq!(two_slots, 2);
    assert_eq!(two_slot_bytes as usize, 2 * SLOT_SIZE);
  }

  #[test]
  fn adapter_buffer_layout_rejects_unrepresentable_maximum() {
    assert!(buffer_layout(u32::MAX).is_none());
    #[cfg(target_pointer_width = "32")]
    assert!(slots_for(u32::MAX).is_none());
  }

  #[test]
  fn adapter_buffer_retry_is_bounded_and_requires_growth() {
    assert_eq!(retry_size(32_000, 16_000, 0).unwrap(), 32_000);

    for error in [
      retry_size(16_000, 16_000, 0),
      retry_size(32_000, 16_000, MAX_TRIES - 1),
    ] {
      assert_eq!(
        error.unwrap_err().raw_os_error(),
        Some(ERROR_BUFFER_OVERFLOW as i32)
      );
    }
  }

  #[test]
  fn adapter_mac_requires_exactly_six_bytes() {
    let mut adapter = IP_ADAPTER_ADDRESSES_LH::default();
    adapter.PhysicalAddress[..MAC_ADDRESS_SIZE].copy_from_slice(&[0, 1, 2, 3, 4, 5]);

    for length in [0, 5, 7, 8] {
      adapter.PhysicalAddressLength = length;
      assert!(adapter_mac_address(&adapter).is_none());
    }

    adapter.PhysicalAddressLength = MAC_ADDRESS_SIZE as u32;
    assert_eq!(
      adapter_mac_address(&adapter).unwrap().octets(),
      [0, 1, 2, 3, 4, 5]
    );
  }

  #[test]
  fn win32_status_error_preserves_the_returned_code() {
    assert_eq!(win32_status_error(87).raw_os_error(), Some(87));
  }
}
