#[allow(unused_macros)]
macro_rules! cfg_apple {
  ($($item:item)*) => {
    $(
      #[cfg(any(
        target_os = "macos",
        target_os = "tvos",
        target_os = "ios",
        target_os = "watchos",
        target_os = "visionos",
      ))]
      #[cfg_attr(docsrs, doc(cfg(any(
        target_os = "macos",
        target_os = "tvos",
        target_os = "ios",
        target_os = "watchos",
        target_os = "visionos",
      ))))]
      $item
    )*
  }
}

#[allow(unused_macros)]
macro_rules! only_cfg_apple {
  ($($item:item)*) => {
    $(
      #[cfg(any(
        target_os = "macos",
        target_os = "tvos",
        target_os = "ios",
        target_os = "watchos",
        target_os = "visionos",
      ))]
      $item
    )*
  }
}

#[allow(unused_macros)]
macro_rules! only_cfg_not_apple {
  ($($item:item)*) => {
    $(
      #[cfg(not(any(
        target_os = "macos",
        target_os = "tvos",
        target_os = "ios",
        target_os = "watchos",
        target_os = "visionos",
      )))]
      $item
    )*
  }
}

#[allow(unused_macros)]
macro_rules! cfg_bsd_multicast {
  ($($item:item)*) => {
    $(
      #[cfg(any(
        target_os = "macos",
        target_os = "tvos",
        target_os = "ios",
        target_os = "watchos",
        target_os = "visionos",
        target_os = "freebsd",
      ))]
      #[cfg_attr(
        docsrs,
        doc(cfg(any(
          target_os = "macos",
          target_os = "tvos",
          target_os = "ios",
          target_os = "watchos",
          target_os = "visionos",
          target_os = "freebsd",
        )))
      )]
      $item
    )*
  };
}

macro_rules! cfg_multicast {
  ($($item:item)*) => {
    $(
      #[cfg(any(
        target_os = "macos",
        target_os = "tvos",
        target_os = "ios",
        target_os = "watchos",
        target_os = "visionos",
        target_os = "freebsd",
        target_os = "linux",
        windows
      ))]
      #[cfg_attr(
        docsrs,
        doc(cfg(any(
          target_os = "macos",
          target_os = "tvos",
          target_os = "ios",
          target_os = "watchos",
          target_os = "visionos",
          target_os = "freebsd",
          target_os = "linux",
          windows
        )))
      )]
      $item
    )*
  }
}
