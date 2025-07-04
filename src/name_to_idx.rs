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
  use rustix::net::{netdevice::name_to_index, socket, AddressFamily, SocketType};

  let socket_fd = socket(AddressFamily::INET, SocketType::DGRAM, None)?;

  name_to_index(socket_fd, name).map_err(Into::into)
}

#[cfg(windows)]
fn ifname_to_index_in(name: &str) -> io::Result<u32> {
  use std::ffi::CString;

  use widestring::U16CString;
  use windows_sys::Win32::NetworkManagement::{
    IpHelper::{if_nametoindex, ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex},
    Ndis::NET_LUID_LH,
  };

  fn try_friendly_name(name: &str) -> io::Result<u32> {
    let wide_name =
      U16CString::from_str(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut luid = NET_LUID_LH { Value: 0 };

    // Convert friendly name to LUID
    let result = unsafe { ConvertInterfaceAliasToLuid(wide_name.as_ptr(), &mut luid) };
    if result != 0 {
      return Err(io::Error::last_os_error());
    }

    // Convert LUID to index
    let mut idx = 0u32;
    let result = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut idx) };
    if result != 0 {
      return Err(io::Error::last_os_error());
    }

    Ok(idx)
  }

  // Try friendly name first
  try_friendly_name(name).or_else(|_| {
    // fallback to if_nametoindex
    let name_cstr =
      CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let res = unsafe { if_nametoindex(name_cstr.as_ptr() as _) };
    if res == 0 {
      Err(io::Error::last_os_error())
    } else {
      Ok(res)
    }
  })
}
