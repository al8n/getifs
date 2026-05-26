# Android Support via Netlink Autobind — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `getifs` work inside an Android app by removing the explicit netlink `bind()` (relying on kernel autobind), and prove it in CI with an instrumented-APK test running in the `untrusted_app` SELinux domain.

**Architecture:** The Linux backend already serves `android` (`build.rs` → `linux_like`). The only runtime blocker is the eager `bind()` in `Handle::new()`, denied for `untrusted_app` (b/155595000). Dropping it makes the kernel autobind a portid on first `sendto()`, which bypasses the SELinux `bind` hook. A detached JNI shim crate + minimal Gradle project run the public API inside a real app process on an emulator to guard the behavior.

**Tech Stack:** Rust + rustix/linux-raw-sys (netlink); JNI shim (`jni` crate, cdylib) built by `cargo-ndk`; Android Gradle (AGP 8.6, Java instrumented test, androidx.test); `reactivecircus/android-emulator-runner`.

---

## File Structure

- `src/linux/netlink.rs` — **modify**: remove `bind` import + the `bind()` call in `Handle::new()`; add `autobind_tests` module.
- `Cargo.toml` — **modify**: `[package] exclude` so `/ci` and `/docs` are not published.
- `ci/android/harness/Cargo.toml` — **create**: detached cdylib crate (own `[workspace]`).
- `ci/android/harness/src/lib.rs` — **create**: JNI entry point calling the public API.
- `ci/android/settings.gradle.kts`, `build.gradle.kts`, `gradle.properties` — **create**: Gradle root.
- `ci/android/app/build.gradle.kts` — **create**: app module.
- `ci/android/app/src/main/AndroidManifest.xml` — **create**.
- `ci/android/app/src/main/java/dev/getifs/androidharness/NativeBridge.java` — **create**: loads `.so`, declares native method.
- `ci/android/app/src/androidTest/java/dev/getifs/androidharness/NetlinkInstrumentedTest.java` — **create**: the instrumented test.
- `.github/workflows/android.yml` — **create**: build job (both ABIs) + emulator instrumented-test job.

Commits (no `docs/`, no `Co-Authored-By` trailer): (1) core fix + test, (2) Cargo.toml exclude, (3) CI harness.

---

### Task 1: Core netlink fix + autobind regression test

**Files:**
- Modify: `src/linux/netlink.rs` (import block lines 6-7; `Handle::new()` lines 196-204)
- Test: `src/linux/netlink.rs` (new `#[cfg(test)] mod autobind_tests`)

> NOTE: This is Linux-only code; it does not compile on the Darwin dev host. The "run" steps execute on Linux CI (`ci.yml`). The test is a true regression guard: with the old eager `bind()` the socket is already bound before `send()`, so `before.pid() == 0` FAILS; with the fix it PASSES.

- [ ] **Step 1: Add the failing test** (append to `src/linux/netlink.rs`)

```rust
#[cfg(test)]
mod autobind_tests {
  use super::*;

  // Regression guard for Android support (issue #4). `Handle::new()`
  // intentionally does NOT bind(): the kernel autobinds a portid on the
  // first send(), and that path bypasses the SELinux `bind` check that
  // Android's untrusted_app domain denies on netlink_route_socket
  // (b/155595000). This pins the invariant the per-message nlmsg_pid
  // filter depends on:
  //   * before the first send the socket is unbound (portid 0), and
  //   * the kernel assigns a non-zero portid on send.
  // If someone reintroduces an eager bind, the first assertion fails.
  #[test]
  fn autobind_assigns_portid_on_send() {
    unsafe {
      let handle = Handle::new().expect("create netlink handle");

      let before = handle.sock().expect("getsockname before send");
      assert_eq!(before.pid(), 0, "socket must be unbound before first send");

      let req =
        NetlinkRouteRequest::new(RTM_GETLINK as u16, 1, AddressFamily::UNSPEC.as_raw() as u8, 0);
      handle.send(&req).expect("send RTM_GETLINK");

      let after = handle.sock().expect("getsockname after send");
      assert_ne!(after.pid(), 0, "kernel must autobind a portid on first send");
    }
  }
}
```

- [ ] **Step 2: Run it against the unmodified code (expect FAIL)**

Run (Linux): `cargo test --lib autobind_assigns_portid_on_send`
Expected: FAIL — `before.pid()` is non-zero because `Handle::new()` still calls `bind()`.

- [ ] **Step 3: Remove `bind` from the import** (`src/linux/netlink.rs:6-7`)

Change:
```rust
use rustix::net::{
  bind, getsockname, netlink::SocketAddrNetlink, recvfrom, sendto, socket, AddressFamily,
  RecvFlags, SendFlags, SocketType,
};
```
to:
```rust
use rustix::net::{
  getsockname, netlink::SocketAddrNetlink, recvfrom, sendto, socket, AddressFamily, RecvFlags,
  SendFlags, SocketType,
};
```

- [ ] **Step 4: Drop the `bind()` call in `Handle::new()`** (`src/linux/netlink.rs:196-204`)

Replace the body with:
```rust
  unsafe fn new() -> io::Result<Self> {
    // Create the netlink socket. We deliberately do NOT bind() it.
    //
    // The kernel auto-binds a unique portid on the first sendto()
    // (netlink_autobind), and that path does not pass through the SELinux
    // `bind` permission check that an explicit bind() triggers. Android's
    // `untrusted_app` domain denies `bind` on netlink_route_socket
    // (b/155595000) but allows the autobind-on-send that getifaddrs() and
    // Go's net package rely on — so skipping the explicit bind is what lets
    // this crate run inside an Android app. There is no behavioural change
    // on other platforms: the socket ends up with the same kernel-assigned
    // portid either way, and every entry point sends before calling
    // getsockname(), so the portid is set before the nlmsg_pid filter reads
    // it.
    let sock = socket(AddressFamily::NETLINK, SocketType::RAW, None)?;
    let sa = SocketAddrNetlink::new(0, 0);
    Ok(Self { fd: sock, sa })
  }
```

- [ ] **Step 5: Run the test + full suite (expect PASS)**

Run (Linux): `cargo test --lib` and `cargo test`
Expected: PASS, including `autobind_assigns_portid_on_send`. No `unused import: bind` warning.

- [ ] **Step 6: Commit**

```bash
git add src/linux/netlink.rs
git commit -m "feat: support Android by relying on netlink autobind

Drop the explicit bind() in the netlink Handle. Android's untrusted_app
SELinux domain denies bind on netlink_route_socket (b/155595000); the
kernel autobinds a portid on first send() without that check, which is how
getifaddrs()/Go work. End socket state and behaviour are unchanged on other
platforms. Adds a regression test pinning the autobind invariant. Closes #4."
```

---

### Task 2: JNI shim crate (detached cdylib)

**Files:**
- Create: `ci/android/harness/Cargo.toml`
- Create: `ci/android/harness/src/lib.rs`

- [ ] **Step 1: Create `ci/android/harness/Cargo.toml`**

```toml
[package]
name = "getifs-android-harness"
version = "0.0.0"
edition = "2021"
publish = false

[lib]
name = "getifs_android_harness"
crate-type = ["cdylib"]

[dependencies]
getifs = { path = "../../.." }
jni = "0.21"

# Detached from the getifs workspace: its own (empty) [workspace] table so
# this crate never affects the getifs lockfile, build, or docs.rs.
[workspace]
```

- [ ] **Step 2: Create `ci/android/harness/src/lib.rs`**

```rust
//! JNI shim used only by the Android instrumented test. Compiled to a
//! cdylib by cargo-ndk and loaded by the harness app so the getifs public
//! API runs inside a real app process (untrusted_app SELinux domain).

use jni::objects::JClass;
use jni::sys::jstring;
use jni::JNIEnv;

/// Calls the core getifs enumeration entry points and returns an empty
/// string when they all succeed, or a newline-separated `"<call>: <error>"`
/// report otherwise. The instrumented test asserts the result is empty.
///
/// With the pre-fix eager netlink bind() these calls return
/// `PermissionDenied` in the app sandbox; the autobind fix makes them
/// succeed.
#[no_mangle]
pub extern "system" fn Java_dev_getifs_androidharness_NativeBridge_runChecks<'local>(
  mut env: JNIEnv<'local>,
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
```

- [ ] **Step 3: Commit** — deferred; committed with Task 4 (CI harness).

---

### Task 3: Gradle instrumented-test project

**Files (all create):**

- [ ] **Step 1: `ci/android/settings.gradle.kts`**

```kotlin
pluginManagement {
  repositories {
    google()
    mavenCentral()
    gradlePluginPortal()
  }
}
dependencyResolutionManagement {
  repositories {
    google()
    mavenCentral()
  }
}
rootProject.name = "getifs-android-harness"
include(":app")
```

- [ ] **Step 2: `ci/android/build.gradle.kts`**

```kotlin
plugins {
  id("com.android.application") version "8.6.0" apply false
}
```

- [ ] **Step 3: `ci/android/gradle.properties`**

```properties
android.useAndroidX=true
org.gradle.jvmargs=-Xmx2048m
```

- [ ] **Step 4: `ci/android/app/build.gradle.kts`**

```kotlin
plugins {
  id("com.android.application")
}

android {
  namespace = "dev.getifs.androidharness"
  compileSdk = 34

  defaultConfig {
    applicationId = "dev.getifs.androidharness"
    minSdk = 24
    targetSdk = 34
    versionCode = 1
    versionName = "1.0"
    testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    // cargo-ndk builds only the emulator ABI into src/main/jniLibs.
    ndk { abiFilters += "x86_64" }
  }
}

dependencies {
  androidTestImplementation("androidx.test.ext:junit:1.2.1")
  androidTestImplementation("androidx.test:runner:1.6.2")
}
```

- [ ] **Step 5: `ci/android/app/src/main/AndroidManifest.xml`**

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <application android:label="getifs-android-harness" />
</manifest>
```

- [ ] **Step 6: `ci/android/app/src/main/java/dev/getifs/androidharness/NativeBridge.java`**

```java
package dev.getifs.androidharness;

/** Loads the cargo-ndk-built shim and exposes the native check. */
public final class NativeBridge {
    static {
        System.loadLibrary("getifs_android_harness");
    }

    private NativeBridge() {}

    /** Empty string on success, else a report of failed getifs calls. */
    public static native String runChecks();
}
```

- [ ] **Step 7: `ci/android/app/src/androidTest/java/dev/getifs/androidharness/NetlinkInstrumentedTest.java`**

```java
package dev.getifs.androidharness;

import static org.junit.Assert.assertEquals;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Runs in the app process (untrusted_app SELinux domain). With the pre-fix
 * eager netlink bind() this fails with PermissionDenied; the autobind fix
 * makes the calls succeed, so runChecks() returns "".
 */
@RunWith(AndroidJUnit4.class)
public class NetlinkInstrumentedTest {
    @Test
    public void getifsCallsSucceedInAppSandbox() {
        String errors = NativeBridge.runChecks();
        assertEquals("getifs calls must succeed in the app sandbox", "", errors);
    }
}
```

- [ ] **Step 8: Commit** — deferred; committed with Task 4.

---

### Task 4: CI workflow + Cargo.toml packaging exclude

**Files:**
- Modify: `Cargo.toml` (`[package]`)
- Create: `.github/workflows/android.yml`

- [ ] **Step 1: Add `exclude` to `Cargo.toml` `[package]`** (so the CI harness / local docs are never published)

Insert under `[package]` (after the existing keys, before `[[bench]]`):
```toml
exclude = ["/ci", "/docs"]
```

- [ ] **Step 2: Create `.github/workflows/android.yml`**

```yaml
name: android

on:
  push:
    branches: [main, feat/android]
  pull_request:

env:
  CARGO_TERM_COLOR: always

jobs:
  build:
    name: cross-build (android ABIs)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set NDK home for cargo-ndk
        run: echo "ANDROID_NDK_HOME=$ANDROID_NDK_LATEST_HOME" >> "$GITHUB_ENV"
      - name: Rust android targets
        run: rustup target add aarch64-linux-android x86_64-linux-android
      - name: Install cargo-ndk
        run: cargo install cargo-ndk --locked
      - name: Build getifs for both Android ABIs
        run: cargo ndk -t arm64-v8a -t x86_64 build --release

  instrumented-test:
    name: instrumented netlink test (untrusted_app)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Enable KVM
        run: |
          echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' \
            | sudo tee /etc/udev/rules.d/99-kvm4all.rules
          sudo udevadm control --reload-rules
          sudo udevadm trigger --name-match=kvm

      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: "17"

      - name: Set NDK home for cargo-ndk
        run: echo "ANDROID_NDK_HOME=$ANDROID_NDK_LATEST_HOME" >> "$GITHUB_ENV"

      - name: Rust android target
        run: rustup target add x86_64-linux-android

      - name: Install cargo-ndk
        run: cargo install cargo-ndk --locked

      - name: Build native shim into app jniLibs
        working-directory: ci/android/harness
        run: cargo ndk -t x86_64 -o ../app/src/main/jniLibs build --release

      - name: Generate Gradle wrapper (pinned)
        working-directory: ci/android
        run: gradle wrapper --gradle-version 8.9

      - name: Run instrumented test on emulator
        uses: reactivecircus/android-emulator-runner@v2
        with:
          api-level: 34
          target: google_apis
          arch: x86_64
          working-directory: ci/android
          script: ./gradlew connectedAndroidTest
```

- [ ] **Step 3: Commit harness + workflow + exclude**

```bash
git add Cargo.toml ci/android .github/workflows/android.yml
git commit -m "test(ci): add Android instrumented-APK netlink test on emulator

Runs the getifs public API inside a real app process (untrusted_app SELinux
domain) on an x86_64 emulator, the only context that reproduces the
netlink bind() denial the autobind fix removes. Detached JNI shim crate
built by cargo-ndk; minimal Gradle androidTest. Also cross-builds both
Android ABIs. Excludes /ci and /docs from the published crate."
```

---

## Self-Review

**1. Spec coverage**
- Drop bind unconditionally → Task 1 (steps 3-4). ✓
- Keep MTU/netlink, no getifaddrs/libc/new module → no new backend; only netlink.rs touched. ✓
- Attempt-and-propagate (no Unsupported stubs) → no route/gateway/multicast code changed. ✓
- Linux mechanism test (non-zero portid after send) → Task 1 test. ✓ (Also asserts unbound-before-send, making it fail on pre-fix code.)
- Faithful option-3 instrumented APK (JNI shim, Gradle androidTest, cargo-ndk, android-emulator-runner, fails on pre-fix code) → Tasks 2-4. ✓
- Detached harness, no main-crate impact → own `[workspace]` + `[package] exclude`. ✓

**2. Placeholder scan** — none. Every file has complete content; commands are exact.

**3. Type/name consistency**
- JNI symbol `Java_dev_getifs_androidharness_NativeBridge_runChecks` ↔ Java package `dev.getifs.androidharness`, class `NativeBridge`, method `runChecks`. ✓
- `.so` name `libgetifs_android_harness.so` (from `[lib] name = "getifs_android_harness"`) ↔ `System.loadLibrary("getifs_android_harness")`. ✓
- cargo-ndk `-o ../app/src/main/jniLibs` (run from `ci/android/harness`) → `ci/android/app/src/main/jniLibs/x86_64/`. ✓
- Public API used by the shim — `interfaces()`, `interface_addrs()`, `gateway_addrs()` — all exist (verified in source). ✓

## Verification matrix (what proves what, and where)

- Linux: existing suite + new `autobind_assigns_portid_on_send` → mechanism + regression guard (runs in `ci.yml`).
- `build` job: getifs compiles for `aarch64`/`x86_64` android.
- `instrumented-test` job: public API returns `Ok` in `untrusted_app`; FAILS on pre-fix code.
- **Cannot be verified on the Darwin dev host**: the netlink edit (Linux-only code) and the entire Android harness (needs NDK/Gradle/emulator). These rely on CI + the Codex review loop.

## Known risks (CI-surfaced)

- AGP/Gradle/androidx version drift (8.6.0 / 8.9 / androidx.test pins) may need bumping for the runner's SDK.
- `ANDROID_NDK_LATEST_HOME` is the GitHub-runner env var cargo-ndk consumes via `ANDROID_NDK_HOME`; if absent on the image, set explicitly.
- `google_apis` x86_64 API 34 image must boot under KVM; ATD images are an alternative if flaky.
- Route/gateway dumps in `untrusted_app` are expected to work but unverified on-device; if Android restricts them, `gateway_addrs()` would report an error and the instrumented test would catch it (then we'd narrow the shim to interface/address calls per the attempt-and-propagate decision).
