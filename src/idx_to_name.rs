use smol_str::SmolStr;
use std::io;

/// Returns the name of the interface by the given index.
///
/// ## Example
///
/// ```rust
/// use getifs::{ifindex_to_name, interfaces};
///
/// let interface = interfaces().unwrap().into_iter().next().unwrap();
/// let name = ifindex_to_name(interface.index()).unwrap();
///
/// assert_eq!(interface.name(), &name);
/// ```
pub fn ifindex_to_name(idx: u32) -> io::Result<SmolStr> {
  ifindex_to_name_in(idx)
}

#[cfg(bsd_like)]
fn ifindex_to_name_in(idx: u32) -> io::Result<SmolStr> {
  use std::ffi::CStr;

  let mut ifname = [0u8; libc::IF_NAMESIZE + 1];
  let res = unsafe { libc::if_indextoname(idx as _, ifname.as_mut_ptr() as *mut libc::c_char) };

  if res.is_null() {
    return Err(io::Error::last_os_error());
  }

  // Use CStr to handle null-terminated string
  let name = unsafe { CStr::from_ptr(ifname.as_ptr() as *const libc::c_char) };

  // Convert to string and then to SmolStr
  name
    .to_str()
    .map(SmolStr::new)
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(linux_like)]
fn ifindex_to_name_in(idx: u32) -> io::Result<SmolStr> {
  use rustix::net::{
    netdevice::index_to_name_inlined, socket_with, AddressFamily, SocketFlags, SocketType,
  };

  let socket_fd = socket_with(
    AddressFamily::INET,
    SocketType::DGRAM,
    SocketFlags::CLOEXEC,
    None,
  )?;

  // `index_to_name_inlined` (rustix 1.1) returns a stack-allocated
  // `InlinedName` — no intermediate `String` on the heap. Interface
  // names are bounded by `IF_NAMESIZE` (16), which fits within
  // `SmolStr`'s inline capacity (23), so this stays allocation-free.
  index_to_name_inlined(socket_fd, idx)
    .map(|name| SmolStr::new(name.as_str()))
    .map_err(Into::into)
}

/// Returns the name of the interface by the given index.
#[cfg(windows)]
fn ifindex_to_name_in(idx: u32) -> io::Result<SmolStr> {
  use windows_sys::Win32::Foundation::NO_ERROR;
  use windows_sys::Win32::NetworkManagement::{
    IpHelper::{ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToAlias},
    Ndis::{IF_MAX_STRING_SIZE, NET_LUID_LH},
  };

  use crate::os::{interface_name_fallback, win32_status_error};

  let mut luid = NET_LUID_LH { Value: 0 };

  // Convert index to LUID. ConvertInterface* returns the error code
  // directly and does not promise to update the thread's last error.
  let result = unsafe { ConvertInterfaceIndexToLuid(idx, &mut luid) };
  if result != NO_ERROR {
    return Err(win32_status_error(result));
  }

  // The documented maximum excludes the terminating NUL.
  let mut name_buf = [0u16; IF_MAX_STRING_SIZE as usize + 1];
  let result = unsafe { ConvertInterfaceLuidToAlias(&luid, name_buf.as_mut_ptr(), name_buf.len()) };
  if result == NO_ERROR {
    if let Some(name) = crate::utils::friendly_name(&name_buf) {
      return Ok(name);
    }

    return interface_name_fallback(idx).ok_or_else(|| {
      io::Error::new(
        io::ErrorKind::InvalidData,
        "Windows returned an invalid interface alias and no raw name",
      )
    });
  }

  // `if_indextoname` deliberately exposes no error code. If that fallback
  // also fails, preserve the actionable ConvertInterface status rather than
  // reading unrelated last-error state.
  interface_name_fallback(idx).ok_or_else(|| win32_status_error(result))
}

#[cfg(test)]
mod tests {
  use super::*;

  // Covers the `Err(...)` arm — a wildly out-of-range index has no
  // matching interface on any platform, so `if_indextoname` /
  // `ConvertInterfaceIndexToLuid` returns null/non-zero and we
  // surface the OS error.
  #[test]
  fn out_of_range_index_returns_err() {
    // 0xFFFE_FFFE is far above any real interface index on any host.
    assert!(ifindex_to_name(0xFFFE_FFFE).is_err());
  }

  // Covers the success arm by round-tripping the first interface
  // returned by `interfaces()`. Skipped on DragonFly because of
  // vmactions interface churn — see the matching gate on
  // `name_to_idx::tests::round_trip_first_interface`.
  #[cfg(not(target_os = "dragonfly"))]
  #[test]
  fn round_trip_first_interface() {
    let ift = crate::interfaces().unwrap();
    let first = ift.iter().next().unwrap();
    let name = ifindex_to_name(first.index()).unwrap();
    assert_eq!(first.name(), &name);
  }
}
