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
  use rustix::net::{netdevice::index_to_name, socket, AddressFamily, SocketType};

  let socket_fd = socket(AddressFamily::INET, SocketType::DGRAM, None)?;

  index_to_name(socket_fd, idx)
    .map(Into::into)
    .map_err(Into::into)
}

/// Returns the name of the interface by the given index.
#[cfg(windows)]
fn ifindex_to_name_in(idx: u32) -> io::Result<SmolStr> {
  use windows_sys::Win32::NetworkManagement::{
    IpHelper::{ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToAlias},
    Ndis::NET_LUID_LH,
  };

  let mut luid = unsafe { NET_LUID_LH { Value: 0 } };

  // Convert index to LUID
  let result = unsafe { ConvertInterfaceIndexToLuid(idx, &mut luid) };
  if result != 0 {
    return Err(io::Error::last_os_error());
  }

  // Get alias (friendly name)
  let mut name_buf = [0u16; 256]; // IF_MAX_STRING_SIZE + 1
  let result = unsafe { ConvertInterfaceLuidToAlias(&luid, name_buf.as_mut_ptr(), name_buf.len()) };
  if result != 0 {
    return Err(io::Error::last_os_error());
  }

  // Convert to string
  match crate::utils::friendly_name(name_buf.as_mut_ptr()) {
    Some(name) => Ok(name),
    None => {
      let mut name_buf = [0u8; 256];
      let hname = unsafe {
        windows_sys::Win32::NetworkManagement::IpHelper::if_indextoname(idx, name_buf.as_mut_ptr())
      };
      unsafe { Ok(CStr::from_ptr(hname as _).to_string_lossy().into()) }
    }
  }
}
