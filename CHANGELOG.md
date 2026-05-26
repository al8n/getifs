# RELEASED

## 0.6.1 (May 26th, 2026)

Adds Android as a supported platform. The autobind change in the
netlink-socket setup applies to every Linux target as well — the
socket's end state is identical and one syscall is saved per call — and
two netlink-error-handling fixes in `netlink_interface` / `netlink_addr`
benefit all Linux callers. The public API is unchanged on every
platform, so this is a patch bump.

### Android — new platform support

Apps in Android's `untrusted_app` SELinux domain face two restrictions
that previously kept `getifs` from running there. Both are handled
transparently:

- **`bind()` on `netlink_route_socket` is denied** (Android bug
  [b/155595000](https://issuetracker.google.com/issues/155595000)).
  `Handle::new()` no longer issues an explicit `bind` — the kernel
  auto-binds a unique port id on the first `sendto()`, and that path
  bypasses the SELinux `bind` hook (the same path `getifaddrs()` and
  Go's `net` package rely on). The change is unconditional (Linux too);
  the socket's end state is identical, one syscall is saved per call,
  and Linux behaviour is unchanged.
- **`RTM_GETLINK` is denied for apps targeting API level 30+** (it
  requires the `nlmsg_readpriv` SELinux permission, neverallowed for
  `untrusted_app`). On Android the interface table falls back, on
  `PermissionDenied`, to discovering interface indices via
  `RTM_GETADDR` (which stays permitted) and reading name / MTU /
  flags with `SIOCGIFNAME` / `SIOCGIFMTU` / `SIOCGIFFLAGS` /
  `SIOCGIFINDEX` ioctls on a datagram socket —
  bionic-`getifaddrs`-style. The fallback uses `rustix` end-to-end
  (no `libc`, no `getifaddrs`). Older Android / app domains that
  still permit `RTM_GETLINK` keep the richer netlink result
  (including the MAC address).

Documented caveats on Android 11+ (API level 30+):

- `interfaces()` lists only interfaces that currently have an address
  — there is no app-permitted way to enumerate address-less ones
  without `getifaddrs`. `interface_by_index()` /
  `interface_by_name()` go straight to the ioctl path and are
  unaffected.
- `Interface::mac_addr()` is `None` (Android restricts the hardware
  address for apps).
- Interfaces with a non-UTF-8 name are skipped — one bad name no
  longer aborts the whole enumeration.
- `interface_multicast_*` returns `ErrorKind::Unsupported` —
  `/proc/net` is not readable by apps on Android 10+ (mirrors the
  existing DragonFly multicast stub).
- The ioctl socket requires `android.permission.INTERNET` (which any
  networking app already holds).

### Fixes — Linux netlink (also benefit the Android path)

- **`NLMSG_ERROR` decoded.** `netlink_interface` and `netlink_addr`
  used to flatten every `NLMSG_ERROR` reply to `EINVAL`. They now
  use the same `decode_nlmsgerr` helper as the route walkers and
  propagate the real errno — so an in-band `RTM_GETLINK` denial that
  arrives as `NLMSG_ERROR(-EACCES)` surfaces as `PermissionDenied`
  (which the Android fallback keys on), and callers anywhere can
  pattern-match `ErrorKind` instead of seeing `InvalidInput`.
- **`NLM_F_DUMP_INTR` honoured.** Both walkers now return `EINTR`
  when the kernel marks a dump interrupted (table changed mid-walk —
  DHCP renewal, VPN connect/disconnect, interface flap) instead of
  silently returning a truncated list. Matches the existing
  route-walker behaviour.
- **Multicast surface compiles on Android.** `cfg_multicast!` (and
  the matching `IfAddr` import gate in `interfaces.rs`) now includes
  `target_os = "android"`, so the cross-platform multicast public
  API exists on Android — and returns `Unsupported` as described
  above.

### CI / chore

- **Android in the `cross` matrix** — `ci.yml`'s compile-check
  matrix now covers `aarch64-linux-android` and
  `x86_64-linux-android` alongside the other Linux / BSD / Windows
  targets (`cargo check`, no NDK required).
- **Instrumented-APK emulator test.** A new `test-android` job in
  `ci.yml` builds a minimal JNI shim crate (`ci/android/harness`)
  with `cargo-ndk`, packages it into an `androidTest` APK, and runs
  `connectedAndroidTest` on an x86_64 emulator via
  `reactivecircus/android-emulator-runner`. The test asserts that
  `interfaces()`, `interface_by_index()`, `interface_addrs()`, and
  `gateway_addrs()` all return `Ok` inside a real `untrusted_app`
  process, plus semantic checks (non-empty enumeration, non-zero MTU
  somewhere, index round-trip). Running the same code via
  `adb shell` runs in the `shell` SELinux domain, which can bind
  netlink sockets, so it wouldn't reproduce the app-sandbox
  restrictions — the instrumented APK is the only context that does.
- **`x86_64-unknown-linux-musl` coverage** in `coverage.yml` — the
  pure-Rust / static-musl target. Tarpaulin (Tests + Lib) runs on
  the ubuntu coverage runner with `musl-tools` for linking, and the
  report is merged into the codecov upload alongside the other
  platforms.
- **Coverage artifact uploads tolerate transient flakes** — every
  `actions/upload-artifact` step in `coverage.yml` is
  `continue-on-error: true`, so a one-off GitHub artifact-service
  hiccup can no longer redden the coverage workflow. The
  coverage-generation step remains the real pass/fail signal, and
  `upload-codecov` already merges whatever artifacts actually made
  it.
- **README** documents the Android platform support and per-platform
  caveats in a dedicated `### Android` subsection; the OS / approach
  table now includes the Android row.
- **Published crate excludes `/ci` and `/docs`** (via
  `[package] exclude`) so the harness scaffolding and local planning
  artifacts are not shipped to crates.io.

## 0.6.0 (May 6th, 2026)

Post-`0.5.0` review pass. The crate's public surface stays
source-compatible — every fix below tightens existing semantics
(correctness, performance, robustness against kernel edge cases)
without breaking the API. The minor bump rather than a patch reflects
the breadth of behavioral changes (Linux RPDB-aware best-local
selection, lazy nexthop dump, BSD source-route filtering, Windows
forwarding-table walk, etc.) that callers exercising edge cases may
notice.

### Fixes — Linux

- **Lazy `RTM_GETNEXTHOP` dump** in `netlink_walk_routes`,
  `netlink_best_local_addrs_into`, and `rt_generic_addrs` (the gateway
  walker). The dump only runs if the route walk actually encounters an
  `RTA_NH_ID` reference. Hosts without `ip nexthop`-managed routes (the
  common case) skip the round-trip entirely; transient `EINTR` /
  `NLM_F_DUMP_INTR` from unrelated nexthop-subsystem churn no longer
  fails ordinary `route_table()` / `best_local_*()` /
  `gateway_addrs*()` calls.
- **Per-family route walk** — `route_table_by_filter` issues separate
  `AF_INET` and `AF_INET6` dumps instead of a single `AF_UNSPEC`
  request. Some kernel versions return only IPv4 for `AF_UNSPEC` route
  dumps; the per-family walk avoids silent IPv6 loss on dual-stack
  hosts.
- **`RT_TABLE_DEFAULT` (253) accepted** alongside `RT_TABLE_MAIN` (254)
  and `RT_TABLE_LOCAL` (255). Hosts with a fallback default route
  installed via `ip route add default ... table default` now surface it
  correctly.
- **RPDB precedence in best-local selection** — candidate key is now
  `(table_rank, metric, pref_rank)` lexicographic. Lower table rank
  wins regardless of metric (matching the kernel's rule chain
  `local < main < default`); within a table, lower metric wins; RFC
  4191 router preference (`RTA_PREF`) breaks equal-metric IPv6 ties
  with `HIGH < MEDIUM < LOW`.
- **ECMP correctness** — equal-key default candidates now extend
  `best_oifs` instead of replacing it, so addresses from every winning
  interface surface in `best_local_*`.
- **`RTA_VIA` cross-family gateways are dropped, documented** —
  `IpRoute` only models same-family `(dest, gateway)` pairs, so a route
  whose next-hop family differs from the destination family used to
  silently emit as `gateway = None` (on-link). They now skip cleanly;
  the omission is noted in `route_table`'s rustdoc.
- **Source-prefix and policy-table filtering** — routes with
  `rtm_src_len != 0` or `RTA_SRC` set, plus routes from custom policy
  tables, are filtered out. `route_table` / `best_local_*` rustdoc
  carries a "best-effort" caveat for policy-routed hosts.
- **Nexthop-group missing-member handling** — `resolve_nh_id` now
  returns `None` when a group leaf is missing from the nexthop
  snapshot (triggering the deferred-retry → `EINTR` path), instead of
  silently dropping the leg.
- **Malformed-attribute defence** — `dump_nexthops` filters nexthops
  with malformed `NHA_GATEWAY` payloads instead of emitting them as
  `gw = None`. Same defence for `RTA_DST` in best-local selection.
- **Receive-buffer size** — route / nexthop walkers now use a 32 KiB
  buffer (matching `iproute2`) instead of one OS page. Routes with
  large `RTA_MULTIPATH` ECMP lists or deep `NHA_GROUP` payloads no
  longer silently truncate.
- **`NLM_F_DUMP_INTR` / family-unavailable handling in `rt_generic_addrs`**
  — the gateway walker now mirrors the route walker. Interrupted
  snapshots return `EINTR`; unsupported-family errors collapse to an
  empty result.
- **Big-endian byte order** — `rt_generic_addrs`'s IPv4 gateway decode
  uses `Ipv4Addr::from([u8; 4])` instead of
  `u32::from_ne_bytes(...).swap_bytes()`. The previous form happened to
  work on little-endian Linux but produced byte-reversed addresses on
  big-endian targets (powerpc64, riscv64gc, etc.) that recently joined
  the cross-target CI matrix.

### Fixes — BSD (macOS, FreeBSD, NetBSD, OpenBSD, DragonFly)

- **`fetch()` truncation fix** — the `sysctl(NET_RT_*)` wrapper
  truncates the buffer to the kernel-written length before parsing.
  NetBSD and OpenBSD `NET_RT_IFLIST` dumps no longer surface as
  `Err(InvalidData "invalid message")` on the trailing zero-padding.
- **Source-specific routes filtered** — NetBSD's `RTF_SRC` flag and
  OpenBSD's `RTAX_SRC` / `RTAX_SRCMASK` slot bits are respected.
- **OpenBSD `rtm_priority` for best-local** — used as the
  best-default selection key. Other BSDs have no documented per-route
  priority; on those targets every default route ties and addresses
  from all default-route interfaces are returned (documented as
  best-effort).
- **Per-family union APIs** — `best_local_addrs` /
  `route_table_by_filter` walk `AF_INET` and `AF_INET6` separately so
  single-stack hosts don't lose the populated family on
  `EAFNOSUPPORT` / `EPROTONOSUPPORT` / `EOPNOTSUPP`.
- **End-of-stream sentinel** — `walk_route_table`,
  `best_local_addrs_in`, and `rt_generic_addrs_in` treat a zero-length
  record header as end-of-stream padding instead of an error.
- **Defensive netmask parsing** — `interface_addr_table_into` skips
  individual addresses with non-canonical `RTAX_NETMASK` instead of
  failing the whole walk (helps point-to-point / tunnel interfaces
  that emit peer-address bytes in the mask slot).
- **Big-endian IPv4 gateway fix** — same `swap_bytes()` byte-order
  bug as the Linux walker, fixed identically.
- **`compat::RtMsghdr` / `RtMetrics` layout assertions** — every BSD
  `RtMsghdr` and per-platform `rt_metrics` struct now has compile-time
  `size_of` and `offset_of!` checks against the kernel ABI for every
  field we read. Catches version-skew silently breaking selection on
  a future libc bump.
- **DragonFly multicast** — `multicast_addrs()` returns
  `Err(ErrorKind::Unsupported)` instead of pretending success with an
  empty list (the DragonFly kernel has no `NET_RT_IFMALIST`).

### Fixes — Windows

- **`route_table()` support** — `route_table_by_filter` walks
  `GetIpForwardTable2` and emits `IpRoute` entries. Filters expired
  rows (`ValidLifetime == 0`), multicast / broadcast destinations,
  loopback rows, and per-subnet directed-broadcast `/32` housekeeping
  rows.
- **Interface-keyed broadcast filter** — directed-broadcast suppression
  set is `HashSet<(InterfaceIndex, Ipv4Addr)>` derived from
  `GetUnicastIpAddressTable`. Multihomed hosts with a legitimate `/32`
  host route to an address coincidentally equal to another adapter's
  directed broadcast no longer get dropped. RFC 3021 `/31` prefixes
  excluded; suppression only applies to
  `PrefixLength == 32 && gw.is_none()` rows.
- **`best_local_*` via documented forwarding-table walk** — replaces
  the prior undocumented `GetBestRoute2(NULL, 0, ...)` /
  `GetBestInterfaceEx(unspec)` calls. Walks `GetIpForwardTable2` for
  `PrefixLength == 0 && ValidLifetime > 0 && !Loopback` rows, joins
  per-interface `Connected` + `Metric` from `GetIpInterfaceTable`,
  picks smallest *effective* metric (route metric + interface metric).
- **Equal-cost defaults preserved** — `best_default_route_interface`
  returns `SmallVec<u32>` instead of `Option<u32>`. Multi-homed hosts
  with equal-cost defaults across two adapters now surface addresses
  from every winning interface (matching Linux/BSD).
- **`Connected = FALSE` filter** — stale defaults pinned to a
  disconnected VPN / unplugged NIC can no longer win the metric race.

### Fixes — MTU lookup

- **Bulk path with per-interface fallback** — `get_ip_mtu` /
  `get_ipv4_mtu` / `get_ipv6_mtu` first try a single
  `interface_addrs()` dump, then fall back to per-interface iteration
  if the bulk dump fails. One unrelated malformed kernel message no
  longer aborts the whole lookup.

### Performance

- New `route` benchmark suite (`benches/route.rs`) covering
  `route_ipv4_table`, `route_ipv6_table`, `route_table`, and
  `route_table_by_filter(default_only)` on Linux / macOS / Windows.
- Linux gateway operations regained their pre-branch latency after
  the lazy nexthop fix:
  - `gateway_ipv4_addrs`: 19.9 µs (was 30.4 µs mid-branch, 18.4 µs at
    `0.5.0`)
  - `gateway_ipv6_addrs`: 16.1 µs (was 26.7 µs mid-branch, 14.3 µs at
    `0.5.0`)
  - `gateway_addrs`: 24.1 µs (was 34.4 µs mid-branch, 22.4 µs at
    `0.5.0`)

### CI / chore

- **Cross-target compile matrix** now covers Linux glibc/musl across
  aarch64 / i686 / powerpc64 / riscv64gc, FreeBSD x86_64 / i686, NetBSD
  x86_64, and Windows MinGW / MSVC i686 / x86_64.
- **Runtime BSD VMs** — `test-freebsd`, `test-netbsd`, `test-openbsd`,
  `test-dragonflybsd` jobs run inside `vmactions/*-vm@v1`. NetBSD and
  DragonFly use `cargo test --lib` (doctests + integration tests
  skipped); per-test cfg-gates in `tests/interfaces.rs` and
  `tests/filter_variants.rs` document the platform-specific gaps.
- **Coverage on all four BSDs** — `coverage-freebsd`, `coverage-netbsd`,
  `coverage-openbsd`, `coverage-dragonflybsd` use cargo-tarpaulin
  inside vmactions VMs (replacing the prior cargo-llvm-cov plumbing).
- **Dedicated MSRV CI job removed** — `rust-version = "1.85.0"` is the
  declared contract; users on Rust 1.85 follow the documented
  `cargo update -p smol_str --precise 0.3.2` /
  `cargo update -p criterion --precise 0.7.0` workaround. The DragonFly
  CI job uses these pins because pkg-shipped Rust there is 1.85.1.
- **`criterion` dev-dep range** relaxed from `^0.8` to `>=0.7, <0.9`
  so the DragonFly CI's `cargo update --precise 0.7.0` satisfies the
  constraint while normal users still resolve to the latest 0.8.x.

## 0.5.0 (April 15th, 2026)

### Fixes

- Fix the inverted `ConvertInterfaceLuidToIndex` check on Windows
  that caused the crate to discard the LUID-derived interface index
  and return `Ipv6IfIndex` on success (or `0` on failure) instead.
  Affected `interface_table`, `interface_addr_table`,
  `interface_multiaddr_table`, and `best_local_addrs_in`.
- Harden the Linux netlink attribute parser so malformed kernel
  messages can no longer panic: IPv4 `IFA_ADDRESS` payload length
  guard, `IFLA_MTU` empty-payload guard, safe bounded read for
  `IFLA_IFNAME` (replaces `CStr::from_ptr` which scanned past the
  attribute on a non-null-terminated value), and clamp of
  `rta_align_of()` against the remaining buffer so an unaligned last
  attribute cannot overflow. Added the missing bounds check in the
  `RTM_NEWROUTE` metric/oif parser.
- Fix FreeBSD build
  ([#32](https://github.com/al8n/getifs/issues/32)): `libc` does not
  expose `rt_msghdr`, `ifa_msghdr`, or `NET_RT_IFLIST2` on non-Apple
  BSDs. `getifs` now ships a `bsd_like::compat` module with local
  `#[repr(C)]` definitions for FreeBSD, DragonFly, NetBSD, and
  OpenBSD, and gates `NET_RT_IFLIST2` / `if_msghdr2` /
  `ifma_msghdr2` to Apple only.
- Fix NetBSD build: `IfaMsghdr` compat for NetBSD/OpenBSD (whose
  layouts differ from FreeBSD), and cast `if_data.ifi_mtu` to `u32`
  since NetBSD defines it as `uint64_t`.

### Performance

- Windows: `Information` no longer materializes a
  `SmallVec<IP_ADAPTER_ADDRESSES_LH>` of ~400-byte struct copies. A
  zero-copy `AdapterIter<'_>` walks the kernel's linked list in place.
- BSD routing: replace the O(n²) `results.contains(&addr)` dedup with
  an O(1) `HashSet<(index, IpAddr)>` so large routing tables scale
  linearly.
- Linux: drop the per-line `MediumVec<&str>` allocation in
  `/proc/net/igmp` and `/proc/net/igmp6` parsing — walk the
  whitespace-separated iterator directly.
- Linux: switch `ifindex_to_name` to
  `rustix::net::netdevice::index_to_name_inlined` (rustix 1.1). The
  returned stack-allocated `InlinedName` combined with `SmolStr`'s
  inline-up-to-23-bytes optimization makes the call allocation-free
  on the happy path.
- Extract a shared `adapter_index` helper on Windows, deduplicating
  three copies of the LUID→index resolution block.

### Chore

- MSRV bumped from 1.63.0 to 1.64.0.
- Bump `rustix` requirement from 1 to 1.1 (required for
  `index_to_name_inlined`).
- Bump `smallvec-wrapper` requirement from 0.3 to 0.4.
- Bump `criterion` dev-dependency from 0.7 to 0.8.
- Drop the unused `either` dependency (was declared both at the
  top level and under the Linux-specific target).

## 0.4.0 (November 4th, 2025)

- Refresh the crate description.
- Add a benchmark CI workflow with Criterion benches for
  `interfaces`, `local_ip_address`, and `gateway`.
- Bump `windows-sys` requirement from 0.60 to 0.61.
- Bump `linux-raw-sys`, `which`, and `criterion` dev-dependency
  versions.

## 0.3.4 (Jul 1st, 2025)

- Bump up versions

## 0.3.3 (May 4th, 2025)

- Fix [#8](https://github.com/al8n/getifs/issues/8)

## 0.3.2 (May 3rd, 2025)

- Fix [#6](https://github.com/al8n/getifs/issues/6)

## 0.3.1 (March 16th, 2025)

- Add `ifname_to_v6_iface`, `ifname_to_v4_iface`, and `ifname_to_iface`.

## 0.3.0 (March 7th, 2025)

- Remove `libc` on Linux platform, implement netlink by using `rustix`

## 0.2.0 (January 19th, 2025)

- Refactor `IfNet` and add `Ifv4Net`, `Ifv6Net`, `IfAddr`, `Ifv4Addr` and `Ifv6Addr`
- Add `interface_addrs`, `interface_ipv4_addrs`, `interface_ipv6_addrs`, `interface_addrs_by_filter`, `interface_ipv4_addrs_by_filter`, and `interface_ipv6_addrs_by_filter`
- Add `interface_multicast_addrs`, `interface_multicast_ipv4_addrs`, `interface_multicast_ipv6_addrs`, `interface_multicast_addrs_by_filter`, `interface_multcast_ipv4_addrs_by_filter` and `interface_multcast_ipv6_addrs_by_filter`
- Add `gateway_addrs`, `gateway_ipv4_addrs`, `gateway_ipv6_addrs`, `gateway_addrs_by_filter`, `gateway_ipv4_addrs_by_filter` and `gateway_ipv6_addrs_by_filter`
- Add `local_addrs`, `local_ipv4_addrs`, `local_ipv6_addrs`, `local_addrs_by_filter`, `local_ipv4_addrs_by_filter` and `local_ipv6_addrs_by_filter`
- Add `private_addrs`, `private_ipv4_addrs`, `private_ipv6_addrs`, `private_addrs_by_filter`, `private_ipv4_addrs_by_filter`, `private_ipv6_addrs_by_filter`
- Add `public_addrs`, `public_ipv4_addrs`, `public_ipv6_addrs`, `public_addrs_by_filter`, `public_ipv4_addrs_by_filter`, and `public_ipv6_addrs_by_filter`
- Add `ifindex_to_name` and `ifname_to_index`
