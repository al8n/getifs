use std::io;

/// Returns the index of the interface by the given name.
///
/// ## Example
///
/// ```rust
/// use getifs::{ifname_to_index, interfaces};
///
/// let interface = interfaces().unwrap().into_iter().next().unwrap();
/// let index = ifname_to_index(interface.name()).unwrap();
///
/// assert_eq!(interface.index(), index);
/// ```
pub fn ifname_to_index(name: &str) -> io::Result<u32> {
  ifname_to_index_in(name)
}

#[cfg(bsd_like)]
fn ifname_to_index_in(name: &str) -> io::Result<u32> {
  use std::ffi::CString;

  // Convert to CString for C interface
  let name_cstr = CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

  let res = unsafe { libc::if_nametoindex(name_cstr.as_ptr()) };

  if res == 0 {
    Err(io::Error::last_os_error())
  } else {
    Ok(res)
  }
}

#[cfg(linux_like)]
fn ifname_to_index_in(name: &str) -> io::Result<u32> {
  use rustix::net::{netdevice::name_to_index, socket_with, AddressFamily, SocketFlags, SocketType};

  let socket_fd = socket_with(
    AddressFamily::INET,
    SocketType::DGRAM,
    SocketFlags::CLOEXEC,
    None,
  )?;

  name_to_index(socket_fd, name).map_err(Into::into)
}

#[cfg(windows)]
#[inline]
fn win32_status_error(status: u32) -> io::Error {
  io::Error::from_raw_os_error(status as i32)
}

#[cfg(windows)]
fn ifname_to_index_in(name: &str) -> io::Result<u32> {
  use std::ffi::CString;

  use widestring::U16CString;
  use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER, NO_ERROR};
  use windows_sys::Win32::NetworkManagement::{
    IpHelper::{if_nametoindex, ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex},
    Ndis::NET_LUID_LH,
  };

  fn try_friendly_name(name: &str) -> io::Result<u32> {
    let wide_name =
      U16CString::from_str(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut luid = NET_LUID_LH { Value: 0 };

    // Convert friendly name to LUID. Both pointers are valid (the alias is
    // NUL-terminated and the LUID is a live local), so the only documented
    // failure, ERROR_INVALID_PARAMETER, means that no interface has this
    // alias. Report it as ERROR_FILE_NOT_FOUND, the status
    // ConvertInterfaceIndexToLuid documents for an unknown interface, which
    // std maps to `ErrorKind::NotFound`.
    let result = unsafe { ConvertInterfaceAliasToLuid(wide_name.as_ptr(), &mut luid) };
    match result {
      NO_ERROR => {}
      ERROR_INVALID_PARAMETER => return Err(win32_status_error(ERROR_FILE_NOT_FOUND)),
      status => return Err(win32_status_error(status)),
    }

    // Convert LUID to index
    let mut idx = 0u32;
    let result = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut idx) };
    if result != NO_ERROR {
      return Err(win32_status_error(result));
    }

    Ok(idx)
  }

  // Windows exposes friendly aliases through ConvertInterface*, while the
  // POSIX-compatible function accepts the raw interface name. Support both,
  // but retain the alias API's concrete status when the raw lookup also fails:
  // `if_nametoindex` intentionally provides no error code for that case.
  match try_friendly_name(name) {
    Ok(index) => Ok(index),
    Err(alias_error) => {
      let name_cstr =
        CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
      let index = unsafe { if_nametoindex(name_cstr.as_ptr() as _) };
      if index == 0 {
        Err(alias_error)
      } else {
        Ok(index)
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  // Covers the `Err(...)` arm on every platform: a name that
  // doesn't correspond to any interface should surface as
  // `Err(io::Error)`. Uses an obviously-fake string with characters
  // most kernels reject for ifnames.
  #[test]
  fn nonexistent_name_returns_err() {
    let r = ifname_to_index("nonexistent_iface_xyz_12345");
    assert!(r.is_err());
  }

  // Covers the success arm by round-tripping a real interface
  // (looked up via `interfaces()` first). Skipped on DragonFly:
  // its vmactions VM has interface churn during test runs, so a
  // name from `interfaces()` may not still resolve a moment later
  // (same root cause as the cfg-gate on `tests/interfaces.rs::ifis`).
  #[cfg(not(target_os = "dragonfly"))]
  #[test]
  fn round_trip_first_interface() {
    let ift = crate::interfaces().unwrap();
    let first = ift.iter().next().unwrap();
    let idx = ifname_to_index(first.name()).unwrap();
    assert_eq!(idx, first.index());
  }

  #[cfg(windows)]
  #[test]
  fn win32_status_error_preserves_the_returned_code() {
    assert_eq!(win32_status_error(87).raw_os_error(), Some(87));
  }

  // An unknown name must surface as the missing-interface status that
  // `interface_by_name` maps to `Ok(None)`, not as the alias API's
  // ERROR_INVALID_PARAMETER.
  #[cfg(windows)]
  #[test]
  fn unknown_name_reports_file_not_found() {
    let error = ifname_to_index("getifs-none0").unwrap_err();
    assert_eq!(
      error.raw_os_error(),
      Some(windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND as i32)
    );
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
  }
}
