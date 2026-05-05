// `getifs::interface_multicast_addrs` is only defined on platforms with a
// kernel-level multicast group enumeration API (see `cfg_multicast!` in
// src/macros.rs). NetBSD/OpenBSD have no such API, so the symbol is
// absent there and the example must compile to a stub instead.

#[cfg(any(
  target_vendor = "apple",
  target_os = "freebsd",
  target_os = "linux",
  windows,
))]
fn main() {
  let ift = getifs::interface_multicast_addrs().unwrap();
  for ifa in ift {
    println!("{ifa}");
  }
}

#[cfg(not(any(
  target_vendor = "apple",
  target_os = "freebsd",
  target_os = "linux",
  windows,
)))]
fn main() {
  eprintln!("interface_multicast_addrs is not available on this platform");
}
