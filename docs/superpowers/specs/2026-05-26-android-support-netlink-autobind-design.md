# Android support via netlink autobind

- **Date:** 2026-05-26
- **Status:** Approved (pending spec review)
- **Issue:** [#4 — feature: support android platform](https://github.com/al8n/getifs/issues/4)
- **Branch:** `feat/android`

## Problem

On Android, every `getifs` call that touches netlink fails at runtime:

```
Failed to get network interfaces: Os { code: 13, kind: PermissionDenied, ... }
avc: denied { bind } for ... tclass=netlink_route_socket permissive=0 bug=b/155595000
```

`android` is already routed to the Linux backend (`build.rs` maps it into `linux_like`,
`Cargo.toml` shares the `rustix` / `linux-raw-sys` deps), so it compiles — but the Linux
backend speaks netlink, and Android's SELinux policy for the `untrusted_app` domain denies
the operation.

## Root cause

`src/linux/netlink.rs`, `Handle::new()`:

```rust
let sock = socket(AddressFamily::NETLINK, SocketType::RAW, None)?;
let sa = SocketAddrNetlink::new(0, 0);
bind(&sock, &sa)?;          // ← the denied operation
```

The explicit `bind()` is exactly the `{ bind } ... netlink_route_socket` that `untrusted_app`
denies (Android bug b/155595000). `untrusted_app` *is* allowed to create netlink sockets and
read dumps; it is not allowed to `bind()` them.

The `bind()` is also **unnecessary**. It does two things: request a kernel-assigned portid
(`nl_pid = 0`) and join zero multicast groups (`nl_groups = 0`). The kernel performs the same
portid assignment automatically (`netlink_autobind`) on the first `sendto()` when the socket
has no portid yet, and that autobind path does **not** go through the SELinux `bind` hook —
which is precisely why `getifaddrs()` and Go's `net` package work on Android. No code in this
crate subscribes to multicast groups or receives unsolicited messages; every operation is a
solicited request → drain-reply dump.

All netlink operations confirmed to be solicited dumps through the single `Handle`:

| Request | Public functions |
|---|---|
| `RTM_GETLINK` | `interfaces()`, `interface_by_index/name()`, MTU (`IFLA_MTU`) |
| `RTM_GETADDR` | `interface_addrs()`, `local_addrs()`, `private/public_addrs()`, `Interface::addrs()` |
| `RTM_GETROUTE` | `route_table()`, `gateway_addrs()`, `best_local_addrs()` |
| `RTM_GETNEXTHOP` | ECMP nexthop resolution inside route/gateway walks |

All six netlink entry points call `Handle::new() → send() → getsockname()` in that order, and
the per-message pid filter (`netlink.rs:278`) uses the *post-send* `getsockname` value — so
autobind-at-send leaves that logic intact.

## Decisions

1. **Keep netlink; drop the explicit bind.** No `getifaddrs`, no `libc`, no ioctl path, no new
   Android module. MTU keeps working because `IFLA_MTU` is already parsed (`netlink.rs:327`).
2. **Unconditional bind removal** (all targets, not Android-only). End socket state is identical
   to today (autobound unique portid, no groups); it saves one syscall per call and is more
   robust on any hardened-SELinux Linux. Reviewed correctness/performance: no regression.
3. **Attempt-and-propagate** for operations Android may still restrict (`route_table`,
   `gateway_addrs`, multicast `/proc/net/igmp`). No preemptive `ErrorKind::Unsupported` stubs —
   the OS is the source of truth.
4. **Faithful Android CI** via an instrumented-APK test on an emulator (see Testing). A test
   binary run via `adb shell` runs in the `shell` domain (which *can* bind), so it would not
   reproduce the bug; only a real app process is in the `untrusted_app` domain.

## The fix

`src/linux/netlink.rs`:

```rust
unsafe fn new() -> io::Result<Self> {
    // Intentionally no bind(): the kernel autobinds a unique portid on the first
    // sendto(), and that path (netlink_autobind) bypasses the SELinux `bind` check
    // an explicit bind() triggers — which Android's untrusted_app domain denies on
    // netlink_route_socket (b/155595000). Every entry point sends before
    // getsockname(), so the autobound portid is available for the pid filter.
    let sock = socket(AddressFamily::NETLINK, SocketType::RAW, None)?;
    let sa = SocketAddrNetlink::new(0, 0);
    Ok(Self { fd: sock, sa })
}
```

- Remove `bind` from the `use rustix::net::{…}` import (becomes the only unused symbol).
- `Handle.sa` stays — it is the `sendto` destination (kernel, pid 0).
- No `build.rs` / `Cargo.toml` / public-API changes.

## Android behavior after the fix

- **Works:** `interfaces()`, MTU, addresses, `local`/`private`/`public_addrs`
  (`RTM_GETLINK`/`GETADDR`).
- **Attempts, surfaces OS result:** `route_table()`, `gateway_addrs()`, `best_local_addrs()`
  (`RTM_GETROUTE`/`GETNEXTHOP`). These are read-only dumps and are expected to be permitted,
  but Android is the source of truth.
- **Multicast** (`/proc/net/igmp`, `/proc/net/igmp6`) attempts; may return a file error on
  locked-down Android (`/proc/net` restrictions). Code unchanged.

## Testing

### 1. Mechanism (Linux CI — free)

The fix makes the no-bind/autobind path the *only* path, so the existing Linux suite now
exercises it directly (regression guard + mechanism proof). Add one white-box test in
`netlink.rs`: build a `Handle`, send `RTM_GETLINK`, assert `getsockname()` returns a
**non-zero** portid after send — pinning the send-before-getsockname/autobind contract so a
future reorder can't silently regress it.

### 2. Faithful Android (instrumented APK on emulator — option 3)

Goal: run `getifs` inside a real `untrusted_app` process and assert the calls return `Ok`.
With the buggy `bind()`, `interfaces()` returns `PermissionDenied` in that domain and the test
fails; with the fix it passes.

Components:

- **JNI shim crate** (e.g. `ci/android-harness/`), detached from the main workspace via its own
  `[workspace]` table so it never affects the `getifs` crate's build, lockfile, publish, or
  docs.rs. `crate-type = ["cdylib"]`, depends on `getifs` by path, uses the `jni` crate
  (isolated here). Exposes one JNI entry point that calls `interfaces()`, `interface_addrs()`,
  and `gateway_addrs()`, returning an empty string on success or a concatenated error string.
- **Minimal Gradle project** (app module + `androidTest` instrumentation). The instrumented
  test loads the `.so` (`System.loadLibrary`), calls the native check, and asserts the returned
  status is empty (success). Manifest declares only ordinary app permissions
  (`INTERNET`, `ACCESS_NETWORK_STATE`).
- **Build glue:** `cargo-ndk` builds the shim into `app/src/main/jniLibs/<abi>/` for the
  emulator ABI (`x86_64`).
- **CI workflow** (new `.github/workflows/android.yml` or job): `ubuntu-latest` (KVM),
  JDK 17, Android SDK + NDK, Rust with the `x86_64-linux-android` target, `cargo-ndk`; boots an
  emulator with `reactivecircus/android-emulator-runner` (x86_64, API 34, `google_apis`/`default`)
  and runs `./gradlew connectedAndroidTest`.

API level / ABI / image target are tunable; x86_64 + KVM is chosen for emulator speed.

## Non-goals

- No `getifaddrs` / `libc` / ioctl MTU path.
- No new Android-specific backend module.
- No preemptive `Unsupported` stubs for routes/gateway/multicast.
- No `adb shell` smoke test (runs in `shell` domain; cannot reproduce the bug).

## Success criteria

- Existing Linux test suite passes with the bind removed.
- New portid/autobind unit test passes on Linux.
- `cargo build` / harness build succeeds for `x86_64-linux-android` (and `aarch64-linux-android`).
- Instrumented APK test passes on the emulator (`untrusted_app`): `interfaces()`,
  `interface_addrs()`, `gateway_addrs()` return `Ok`. The same test fails against the
  pre-fix code (verifies it actually guards the bug).

## Risks / open questions

- **Route/gateway dumps in `untrusted_app`:** expected to be allowed (read-only), but not yet
  confirmed on a device. If Android restricts them beyond `bind`, those specific calls return
  the OS error (per the attempt-and-propagate decision); core interface/address/MTU enumeration
  is unaffected. The instrumented test will reveal the real behavior.
- **Emulator image:** must be a non-Play image so the app runs as a standard `untrusted_app`
  and the harness can be installed; Play images are unnecessary here.
