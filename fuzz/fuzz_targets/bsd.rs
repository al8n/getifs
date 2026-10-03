#![no_main]

#[cfg(any(
  target_vendor = "apple",
  target_os = "freebsd",
  target_os = "netbsd",
  target_os = "openbsd",
  target_os = "dragonfly"
))]
use libfuzzer_sys::fuzz_target;

#[cfg(any(
  target_vendor = "apple",
  target_os = "freebsd",
  target_os = "netbsd",
  target_os = "openbsd",
  target_os = "dragonfly"
))]
fuzz_target!(|data: &[u8]| {
  getifs::__fuzzing::fuzz_bsd_parsers(data);
});

#[cfg(not(any(
  target_vendor = "apple",
  target_os = "freebsd",
  target_os = "netbsd",
  target_os = "openbsd",
  target_os = "dragonfly"
)))]
compile_error!("the BSD fuzz target requires an Apple or BSD host");
