//! JNI shim used only by the Android instrumented test. Compiled to a
//! cdylib by cargo-ndk and loaded by the harness app so the getifs public
//! API runs inside a real app process (untrusted_app SELinux domain) — the
//! only context that reproduces the netlink `bind()` denial the autobind
//! fix removes.

use jni::objects::JClass;
use jni::sys::jstring;
use jni::JNIEnv;
use std::net::IpAddr;

fn interface_disappeared(index: u32, name: &str) -> Result<bool, String> {
  getifs::interfaces()
    .map(|interfaces| {
      !interfaces
        .iter()
        .any(|interface| interface.index() == index && interface.name().as_str() == name)
    })
    .map_err(|error| format!("revalidate interface {name} ({index}): {error}"))
}

fn address_disappeared(index: u32, name: &str, address: IpAddr) -> Result<bool, String> {
  if interface_disappeared(index, name)? {
    return Ok(true);
  }

  getifs::interface_addrs()
    .map(|addresses| {
      !addresses
        .iter()
        .any(|candidate| candidate.index() == index && candidate.addr() == address)
    })
    .map_err(|error| format!("revalidate address {address} on {name} ({index}): {error}"))
}

fn record_interface_failure(
  errors: &mut Vec<String>,
  index: u32,
  name: &str,
  operation: &str,
  error: impl std::fmt::Display,
) -> bool {
  match interface_disappeared(index, name) {
    Ok(true) => return true,
    Ok(false) => errors.push(format!("{operation} for {name} ({index}): {error}")),
    Err(revalidation) => errors.push(revalidation),
  }
  false
}

fn record_address_failure(
  errors: &mut Vec<String>,
  index: u32,
  name: &str,
  address: IpAddr,
  error: impl std::fmt::Display,
) -> bool {
  match address_disappeared(index, name, address) {
    Ok(true) => return true,
    Ok(false) => errors.push(format!(
      "get_ifaddr_mtu({address}) for {name} ({index}): {error}"
    )),
    Err(revalidation) => errors.push(revalidation),
  }
  false
}

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

  // Enumeration must not only succeed but be semantically sane. Android 11+
  // may supply this snapshot through the RTM_GETADDR + ioctl fallback, so the
  // checks cover both lookup paths and the derived MTU APIs without assuming
  // a default route or a globally routable IPv6 address exists.
  match getifs::interfaces() {
    Err(e) => errors.push(format!("interfaces: {e}")),
    Ok(ifaces) => {
      if ifaces.is_empty() {
        errors.push("interfaces() returned none (expected at least loopback)".to_string());
      }

      for interface in &ifaces {
        let index = interface.index();
        let name = interface.name().to_string();

        match getifs::interface_by_index(index) {
          Ok(Some(found)) if found.index() == index && found.name().as_str() == name => {}
          Ok(Some(found)) => errors.push(format!(
            "interface_by_index({index}) returned {} ({}) instead of {name}",
            found.index(),
            found.name()
          )),
          Ok(None) => {
            if record_interface_failure(
              &mut errors,
              index,
              &name,
              "interface_by_index returned None",
              "interface remains present",
            ) {
              continue;
            }
          }
          Err(error) => {
            if record_interface_failure(&mut errors, index, &name, "interface_by_index", error) {
              continue;
            }
          }
        }

        match getifs::interface_by_name(&name) {
          Ok(Some(found)) if found.index() == index && found.name().as_str() == name => {}
          Ok(Some(found)) => errors.push(format!(
            "interface_by_name({name}) returned {} ({}) instead of {index}",
            found.index(),
            found.name()
          )),
          Ok(None) => {
            if record_interface_failure(
              &mut errors,
              index,
              &name,
              "interface_by_name returned None",
              "interface remains present",
            ) {
              continue;
            }
          }
          Err(error) => {
            if record_interface_failure(&mut errors, index, &name, "interface_by_name", error) {
              continue;
            }
          }
        }

        match getifs::get_interface_mtu(index) {
          Ok(mtu) if mtu == interface.mtu() => {}
          Ok(mtu) => errors.push(format!(
            "get_interface_mtu({index}) returned {mtu}, snapshot has {}",
            interface.mtu()
          )),
          Err(error) => {
            if record_interface_failure(&mut errors, index, &name, "get_interface_mtu", error) {
              continue;
            }
          }
        }

        let addresses = match interface.addrs() {
          Ok(addresses) => addresses,
          Err(error) => {
            if record_interface_failure(&mut errors, index, &name, "interface.addrs", error) {
              continue;
            }
            continue;
          }
        };
        for address in addresses {
          if address.index() != index {
            errors.push(format!(
              "{} returned address {} owned by index {}",
              name,
              address.addr(),
              address.index()
            ));
            continue;
          }

          let scoped = getifs::IfAddr::new(index, address.addr());
          match getifs::get_ifaddr_mtu(scoped) {
            Ok(mtu) if mtu == interface.mtu() => {}
            Ok(mtu) => errors.push(format!(
              "get_ifaddr_mtu({}) returned {mtu}, snapshot has {}",
              address.addr(),
              interface.mtu()
            )),
            Err(error) => {
              let _ = record_address_failure(&mut errors, index, &name, address.addr(), error);
            }
          }
        }
      }
    }
  }

  if let Err(e) = getifs::interface_addrs() {
    errors.push(format!("interface_addrs: {e}"));
  }
  if let Err(e) = getifs::gateway_addrs() {
    errors.push(format!("gateway_addrs: {e}"));
  }
  if let Err(e) = getifs::route_table() {
    errors.push(format!("route_table: {e}"));
  }
  if let Err(e) = getifs::best_local_addrs() {
    errors.push(format!("best_local_addrs: {e}"));
  }

  // Both matrix entries target API 30 or newer, where app access to
  // /proc/net is restricted. The portable API must report that limitation
  // explicitly rather than returning a misleading empty list or raw EACCES.
  match getifs::interface_multicast_addrs() {
    Err(error) if error.kind() == std::io::ErrorKind::Unsupported => {}
    Err(error) => errors.push(format!(
      "interface_multicast_addrs: expected Unsupported, got {error}"
    )),
    Ok(addrs) => errors.push(format!(
      "interface_multicast_addrs unexpectedly returned {} entries on restricted Android",
      addrs.len()
    )),
  }

  let report = errors.join("\n");
  env
    .new_string(report)
    .expect("create java string")
    .into_raw()
}
