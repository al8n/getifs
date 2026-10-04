#![no_main]

#[cfg(any(target_os = "linux", target_os = "android"))]
use libfuzzer_sys::fuzz_target;

#[cfg(any(target_os = "linux", target_os = "android"))]
fuzz_target!(|data: &[u8]| {
  getifs::__fuzzing::fuzz_netlink_dump(data);
});

#[cfg(not(any(target_os = "linux", target_os = "android")))]
compile_error!("the netlink fuzz target requires a Linux or Android host");
