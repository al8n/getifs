#[allow(unused_macros)]
macro_rules! cfg_apple {
  ($($item:item)*) => {
    $(
      #[cfg(apple)]
      #[cfg_attr(docsrs, doc(cfg(apple)))]
      $item
    )*
  }
}

#[allow(unused_macros)]
macro_rules! only_cfg_apple {
  ($($item:item)*) => {
    $(
      #[cfg(apple)]
      $item
    )*
  }
}

#[allow(unused_macros)]
macro_rules! only_cfg_not_apple {
  ($($item:item)*) => {
    $(
      #[cfg(not(apple))]
      $item
    )*
  }
}

#[allow(unused_macros)]
macro_rules! cfg_multicast {
  ($($item:item)*) => {
    $(
      #[cfg(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "linux",
        target_os = "android",
        windows
      ))]
      #[cfg_attr(
        docsrs,
        doc(cfg(any(
          target_vendor = "apple",
          target_os = "freebsd",
          target_os = "dragonfly",
          target_os = "netbsd",
          target_os = "openbsd",
          target_os = "linux",
          target_os = "android",
          windows
        )))
      )]
      $item
    )*
  }
}
