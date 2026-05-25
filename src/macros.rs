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
      // DragonFly is included here so the public multicast surface
      // exists on that target — but DragonFly's kernel does not
      // expose multicast group enumeration via sysctl
      // (`NET_RT_IFMALIST` doesn't exist; the kernel's
      // `NET_RT_MAXID = 4` confirms there are only 4 selectors,
      // none of them multicast). The DragonFly impl in
      // `bsd_like.rs::interface_multiaddr_table` returns
      // `Err(ErrorKind::Unsupported)` — see the doc comment there.
      #[cfg(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "dragonfly",
      ))]
      #[cfg_attr(
        docsrs,
        doc(cfg(any(
          target_vendor = "apple",
          target_os = "freebsd",
          target_os = "dragonfly",
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
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "dragonfly",
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
          target_os = "linux",
          target_os = "android",
          windows
        )))
      )]
      $item
    )*
  }
}
