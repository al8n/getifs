use std::env::var;

fn main() {
  // Rerun only when this script changes: its output depends on nothing but
  // the target OS.
  println!("cargo:rerun-if-changed=build.rs");

  let os = var("CARGO_CFG_TARGET_OS").unwrap();

  // Rust's libc crate groups some OS's together which have similar APIs;
  // create similarly-named features to make `cfg` tests more concise.
  let freebsdlike = os == "freebsd" || os == "dragonfly";
  if freebsdlike {
    use_feature("freebsdlike");
  }

  let netbsdlike = os == "openbsd" || os == "netbsd";
  if netbsdlike {
    use_feature("netbsdlike");
  }

  let apple = os == "macos" || os == "ios" || os == "tvos" || os == "visionos" || os == "watchos";
  if apple {
    use_feature("apple");
  }

  if os == "linux" || os == "android" {
    use_feature("linux_like");
  }

  if apple || freebsdlike || netbsdlike {
    use_feature("bsd_like");
  }
}

fn use_feature(feature: &str) {
  println!("cargo:rustc-cfg={feature}");
}
