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
macro_rules! cfg_bsd_multicast {
  ($($item:item)*) => {
    $(
      // DragonFly is intentionally absent: its libc bindings define
      // `NET_RT_MAXID = 4` and don't expose `NET_RT_IFMALIST`, so
      // there's no proven sysctl selector for the multicast group
      // list. Re-enable only after a DragonFly runtime test
      // demonstrates the right selector and the `IfmaMsghdr` layout
      // we hand-rolled in `compat.rs` matches the kernel.
      #[cfg(any(
        target_vendor = "apple",
        target_os = "freebsd",
      ))]
      #[cfg_attr(
        docsrs,
        doc(cfg(any(
          target_vendor = "apple",
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
      // See `cfg_bsd_multicast` for why DragonFly is excluded here.
      #[cfg(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "linux",
        windows
      ))]
      #[cfg_attr(
        docsrs,
        doc(cfg(any(
          target_vendor = "apple",
          target_os = "freebsd",
          target_os = "linux",
          windows
        )))
      )]
      $item
    )*
  }
}
