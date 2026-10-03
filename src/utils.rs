#[cfg(windows)]
pub(crate) fn friendly_name(name: &[u16]) -> Option<smol_str::SmolStr> {
  let nul = name.iter().position(|&unit| unit == 0)?;
  if nul == 0 {
    return None;
  }
  Some(String::from_utf16(&name[..nul]).ok()?.into())
}

#[cfg(all(test, windows))]
mod tests {
  use super::friendly_name;

  #[test]
  fn friendly_name_requires_a_bounded_terminator() {
    assert_eq!(
      friendly_name(&[b'L' as u16, b'A' as u16, b'N' as u16]),
      None
    );
    assert_eq!(friendly_name(&[0, b'x' as u16]), None);
    assert_eq!(friendly_name(&[0xD800, 0]), None);
    assert_eq!(
      friendly_name(&[b'L' as u16, b'A' as u16, b'N' as u16, 0]).as_deref(),
      Some("LAN")
    );
  }
}
