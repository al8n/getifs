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
  env: JNIEnv<'local>,
  _class: JClass<'local>,
) -> jstring {
  let mut errors: Vec<String> = Vec::new();

  if let Err(e) = getifs::interfaces() {
    errors.push(format!("interfaces: {e}"));
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
