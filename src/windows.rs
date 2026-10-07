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
/// Flags for the address queries. They omit `GAA_FLAG_INCLUDE_ALL_INTERFACES`:
/// an adapter that is not bound to IPv4 or IPv6 has no addresses to report,
/// and the flag makes every query markedly slower. Interfaces, bound or not,
/// come from the interface table instead; see [`interface_table`].
const ADDRESS_QUERY_FLAGS: GET_ADAPTERS_ADDRESSES_FLAGS = GAA_FLAG_INCLUDE_PREFIX;

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
          ADDRESS_QUERY_FLAGS,
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

/// Resolves an interface name when its alias is unavailable.
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

/// Returns the hardware address of `length` bytes from `address` when it is a
/// 6-byte (EUI-48) MAC address.
#[inline]
fn physical_mac(length: u32, address: &[u8]) -> Option<MacAddr> {
  if length as usize != MAC_ADDRESS_SIZE {
    return None;
  }

  let bytes: [u8; MAC_ADDRESS_SIZE] = address.get(..MAC_ADDRESS_SIZE)?.try_into().ok()?;
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

/// The `FilterInterface` bit of `MIB_IF_ROW2::InterfaceAndOperStatusFlags`,
/// the second member of that BOOLEAN bitfield (`HardwareInterface` is 0x01).
/// Such a row is an NDIS filter module layered on a miniport, such as a QoS
/// or WFP lightweight filter or a Hyper-V switch extension. It reports its
/// miniport's MAC address and is not an interface of its own.
const FILTER_INTERFACE: u8 = 0x02;

fn interface_flags(
  if_type: u32,
  admin_status: NET_IF_ADMIN_STATUS,
  oper_status: IF_OPER_STATUS,
) -> Flags {
  let mut flags = Flags::empty();
  if admin_status == NET_IF_ADMIN_STATUS_UP {
    flags |= Flags::UP;
  }
  if oper_status == IfOperStatusUp {
    flags |= Flags::RUNNING;
  }

  match if_type {
    IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211 | IF_TYPE_IEEE1394 | IF_TYPE_ISO88025_TOKENRING => {
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

  flags
}

/// Builds the [`Interface`] of one interface-table row. Returns `None` for an
/// NDIS filter module, for the unspecified index 0, and for a row whose name
/// cannot be represented.
///
/// The name is the interface alias, which `GetAdaptersAddresses` reports as
/// the friendly name and `ifname_to_index` resolves. `Mtu` is the link MTU;
/// the unbounded `u32::MAX` of a loopback interface is reported as 0.
fn interface_from_row(row: &MIB_IF_ROW2) -> Option<Interface> {
  if row.InterfaceAndOperStatusFlags._bitfield & FILTER_INTERFACE != 0 || row.InterfaceIndex == 0 {
    return None;
  }

  let index = row.InterfaceIndex;
  let name = crate::utils::friendly_name(&row.Alias).or_else(|| interface_name_fallback(index))?;
  Some(Interface {
    index,
    name,
    flags: interface_flags(row.Type, row.AdminStatus, row.OperStatus),
    mtu: if row.Mtu == u32::MAX { 0 } else { row.Mtu },
    mac_addr: physical_mac(row.PhysicalAddressLength, &row.PhysicalAddress),
  })
}

/// Lists the interfaces from the IP Helper interface table: every NDIS
/// interface except filter modules, whether or not it is bound to IPv4 or
/// IPv6. A lookup of one index reads only that interface's row.
pub(super) fn interface_table(idx: Option<u32>) -> io::Result<TinyVec<Interface>> {
  let mut interfaces = TinyVec::new();
  match idx {
    Some(index) => interfaces.extend(
      mib::interface_row(index)?
        .as_ref()
        .and_then(interface_from_row),
    ),
    None => interfaces.extend(
      mib::interface_table()?
        .rows()
        .iter()
        .filter_map(interface_from_row),
    ),
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

  /// An interface-table row for index 42 named `alias`: an Ethernet adapter
  /// that is administratively up but has no link.
  fn row(alias: &str) -> MIB_IF_ROW2 {
    let mut row = MIB_IF_ROW2 {
      InterfaceIndex: 42,
      Type: IF_TYPE_ETHERNET_CSMACD,
      Mtu: 9_000,
      AdminStatus: NET_IF_ADMIN_STATUS_UP,
      OperStatus: IfOperStatusDown,
      PhysicalAddressLength: MAC_ADDRESS_SIZE as u32,
      ..Default::default()
    };
    row.PhysicalAddress[..MAC_ADDRESS_SIZE].copy_from_slice(&[0, 1, 2, 3, 4, 5]);
    for (unit, encoded) in row.Alias.iter_mut().zip(alias.encode_utf16()) {
      *unit = encoded;
    }
    row
  }

  #[test]
  fn administrative_and_operational_flags_are_independent() {
    let flags = |admin, oper| interface_flags(0, admin, oper);
    assert_eq!(
      flags(NET_IF_ADMIN_STATUS_UP, IfOperStatusUp),
      Flags::UP | Flags::RUNNING
    );
    assert_eq!(flags(NET_IF_ADMIN_STATUS_UP, IfOperStatusDown), Flags::UP);
    assert_eq!(
      flags(NET_IF_ADMIN_STATUS_DOWN, IfOperStatusUp),
      Flags::RUNNING
    );
    assert_eq!(
      flags(NET_IF_ADMIN_STATUS_DOWN, IfOperStatusDown),
      Flags::empty()
    );
    assert_eq!(
      flags(NET_IF_ADMIN_STATUS_UP, IfOperStatusUnknown),
      Flags::UP
    );
    assert_eq!(
      flags(NET_IF_ADMIN_STATUS_TESTING, IfOperStatusUp),
      Flags::RUNNING
    );
    assert_eq!(flags(99, IfOperStatusTesting), Flags::empty());
  }

  #[test]
  fn unbound_row_keeps_its_metadata_and_capabilities() {
    let interface = interface_from_row(&row("unbound")).unwrap();
    assert_eq!(interface.index(), 42);
    assert_eq!(interface.name(), "unbound");
    assert_eq!(interface.mtu(), 9_000);
    assert_eq!(interface.mac_addr().unwrap().octets(), [0, 1, 2, 3, 4, 5]);
    assert_eq!(
      interface.flags(),
      Flags::UP | Flags::BROADCAST | Flags::MULTICAST
    );
  }

  #[test]
  fn filter_modules_and_index_zero_are_not_interfaces() {
    let mut filter = row("Ethernet-QoS Packet Scheduler-0000");
    filter.InterfaceAndOperStatusFlags._bitfield = FILTER_INTERFACE;
    assert!(interface_from_row(&filter).is_none());

    // Every other flag, `HardwareInterface` included, keeps the row.
    for bits in [0x01, !FILTER_INTERFACE] {
      let mut other = row("Ethernet");
      other.InterfaceAndOperStatusFlags._bitfield = bits;
      assert!(interface_from_row(&other).is_some(), "{bits:#04x}");
    }

    let mut unspecified = row("Ethernet");
    unspecified.InterfaceIndex = 0;
    assert!(interface_from_row(&unspecified).is_none());
  }

  #[test]
  fn unknown_mtu_and_a_non_eui48_address_are_not_reported() {
    let mut row = row("Loopback Pseudo-Interface 1");
    row.Mtu = u32::MAX;
    row.PhysicalAddressLength = 0;
    let interface = interface_from_row(&row).unwrap();
    assert_eq!(interface.mtu(), 0);
    assert_eq!(interface.mac_addr(), None);
  }

  #[test]
  fn row_without_a_usable_name_is_skipped() {
    // An empty alias falls back to `if_indextoname`, which knows no such index.
    let mut row = row("");
    row.InterfaceIndex = u32::MAX - 1;
    assert!(interface_from_row(&row).is_none());
  }

  // The loopback interface is administratively and operationally up on every
  // Windows host, so both the table and the single-row lookup must report its
  // state, which the statistics-free table level still returns.
  #[test]
  fn loopback_state_is_reported_by_both_lookups() {
    let interfaces = interface_table(None).unwrap();
    let loopback = interfaces
      .iter()
      .find(|interface| interface.flags().contains(Flags::LOOPBACK))
      .expect("a loopback interface");
    assert_eq!(
      loopback.flags(),
      Flags::UP | Flags::RUNNING | Flags::LOOPBACK | Flags::MULTICAST
    );
    assert_eq!(loopback.mtu(), 0);

    let by_index = interface_table(Some(loopback.index())).unwrap();
    assert_eq!(by_index.as_slice(), core::slice::from_ref(loopback));
  }

  // The adapter list and the interface table are separate snapshots, so an
  // adapter removed between the two is tolerated.
  #[test]
  fn every_bound_adapter_is_an_interface() {
    use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;

    let adapters = Information::fetch().unwrap();
    let interfaces = interface_table(None).unwrap();
    for adapter in adapters.iter() {
      let index = adapter_index(adapter);
      if interfaces
        .iter()
        .any(|interface| interface.index() == index)
      {
        continue;
      }
      match mib::interface_row(index) {
        Ok(Some(row)) => assert!(
          interface_from_row(&row).is_none(),
          "adapter {index} is missing from interface_table"
        ),
        Ok(None) => {}
        Err(error) if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => {}
        Err(error) => panic!("adapter {index}: {error}"),
      }
    }
  }

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
  fn physical_mac_requires_exactly_six_bytes() {
    let address = [0, 1, 2, 3, 4, 5, 6, 7];
    for length in [0, 5, 7, 8] {
      assert!(physical_mac(length, &address).is_none());
    }

    let length = MAC_ADDRESS_SIZE as u32;
    assert_eq!(
      physical_mac(length, &address).unwrap().octets(),
      [0, 1, 2, 3, 4, 5]
    );
    assert!(physical_mac(length, &address[..4]).is_none());
  }

  #[test]
  fn win32_status_error_preserves_the_returned_code() {
    assert_eq!(win32_status_error(87).raw_os_error(), Some(87));
  }
}
