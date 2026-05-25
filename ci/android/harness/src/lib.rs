//! JNI shim used only by the Android instrumented test. Compiled to a
//! cdylib by cargo-ndk and loaded by the harness app so the getifs public
//! API runs inside a real app process (untrusted_app SELinux domain) — the
//! only context that reproduces the netlink `bind()` denial the autobind
//! fix removes.

use jni::objects::JClass;
use jni::sys::jstring;
use jni::JNIEnv;

/// Calls the core getifs enumeration entry points and returns an empty
/// string when they all succeed, or a newline-separated `"<call>: <error>"`
/// report otherwise. The instrumented test asserts the result is empty.
///
/// With the pre-fix eager netlink `bind()` these calls return
/// `PermissionDenied` in the app sandbox; the autobind fix makes them
/// succeed.
#[no_mangle]
pub extern "system" fn Java_dev_getifs_androidharness_NativeBridge_runChecks<'local>(
  // jni 0.21's `JNIEnv::new_string` takes `&self`, so `env` is intentionally
  // not `mut` (a `mut` here warns as unused under the pinned 0.21.x). The
  // harness builds clean via cargo-ndk in CI; do not add `mut` to match a
  // newer jni major's docs (which renamed the type to `Env`).
  env: JNIEnv<'local>,
  _class: JClass<'local>,
) -> jstring {
  let mut errors: Vec<String> = Vec::new();

  // Enumeration must not only succeed but be semantically sane: at least
  // loopback is present, a known index round-trips through
  // `interface_by_index`, and at least one interface reports a real MTU.
  // Checking only `Ok` would let the ioctl fallback pass while silently
  // returning empty or zeroed data.
  match getifs::interfaces() {
    Err(e) => errors.push(format!("interfaces: {e}")),
    Ok(ifaces) => match ifaces.first() {
      None => errors.push("interfaces() returned none (expected at least loopback)".to_string()),
      Some(first) => {
        match getifs::interface_by_index(first.index()) {
          Ok(Some(found)) if found.index() == first.index() => {}
          Ok(Some(found)) => errors.push(format!(
            "interface_by_index({}) returned index {}",
            first.index(),
            found.index()
          )),
          Ok(None) => errors.push(format!(
            "interface_by_index({}) returned None for an enumerated interface",
            first.index()
          )),
          Err(e) => errors.push(format!("interface_by_index: {e}")),
        }
        if !ifaces.iter().any(|i| i.mtu() > 0) {
          errors.push("no interface reported a non-zero MTU".to_string());
        }
      }
    },
  }

  if let Err(e) = getifs::interface_addrs() {
    errors.push(format!("interface_addrs: {e}"));
  }
  if let Err(e) = getifs::gateway_addrs() {
    errors.push(format!("gateway_addrs: {e}"));
  }

  let report = errors.join("\n");
  env
    .new_string(report)
    .expect("create java string")
    .into_raw()
}
