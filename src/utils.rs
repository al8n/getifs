#[cfg(windows)]
pub(crate) fn friendly_name(name: windows_sys::core::PWSTR) -> Option<smol_str::SmolStr> {
  if name.is_null() {
    return None;
  }

  unsafe {
    let len = wide_str_len(name);
    let s = match widestring::U16CStr::from_ptr(name, len) {
      Ok(s) => s,
      Err(_) => return None,
    };
    let osname_str = s.to_string_lossy();
    Some(smol_str::SmolStr::new(&osname_str))
  }
}

#[cfg(windows)]
unsafe fn wide_str_len(ptr: *mut u16) -> usize {
  let mut len = 0;
  while *ptr.add(len) != 0 {
    len += 1;
  }
  len
}
