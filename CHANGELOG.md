# RELEASED

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
