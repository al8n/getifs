<div align="center">
<h1>GetIfs</h1>
</div>
<div align="center">

Cross-platform enumeration of network interfaces and their MTU, gateway, multicast, and local/private/public IP addresses — with a libc-free netlink backend on Linux and no getifaddrs dependency.


[<img alt="github" src="https://img.shields.io/badge/github-al8n/getifs-8da0cb?style=for-the-badge&logo=Github" height="22">][Github-url]
<img alt="LoC" src="https://img.shields.io/endpoint?url=https%3A%2F%2Fgist.githubusercontent.com%2Fal8n%2F327b2a8aef9003246e45c6e47fe63937%2Fraw%2Fgetifs" height="22">
[<img alt="Build" src="https://img.shields.io/github/actions/workflow/status/al8n/getifs/ci.yml?logo=Github-Actions&style=for-the-badge" height="22">][CI-url]
[<img alt="codecov" src="https://img.shields.io/codecov/c/gh/al8n/getifs?style=for-the-badge&token=6R3QFWRWHL&logo=codecov" height="22">][codecov-url]

[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-getifs-66c2a5?style=for-the-badge&labelColor=555555&logo=data:image/svg+xml;base64,PHN2ZyByb2xlPSJpbWciIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgdmlld0JveD0iMCAwIDUxMiA1MTIiPjxwYXRoIGZpbGw9IiNmNWY1ZjUiIGQ9Ik00ODguNiAyNTAuMkwzOTIgMjE0VjEwNS41YzAtMTUtOS4zLTI4LjQtMjMuNC0zMy43bC0xMDAtMzcuNWMtOC4xLTMuMS0xNy4xLTMuMS0yNS4zIDBsLTEwMCAzNy41Yy0xNC4xIDUuMy0yMy40IDE4LjctMjMuNCAzMy43VjIxNGwtOTYuNiAzNi4yQzkuMyAyNTUuNSAwIDI2OC45IDAgMjgzLjlWMzk0YzAgMTMuNiA3LjcgMjYuMSAxOS45IDMyLjJsMTAwIDUwYzEwLjEgNS4xIDIyLjEgNS4xIDMyLjIgMGwxMDMuOS01MiAxMDMuOSA1MmMxMC4xIDUuMSAyMi4xIDUuMSAzMi4yIDBsMTAwLTUwYzEyLjItNi4xIDE5LjktMTguNiAxOS45LTMyLjJWMjgzLjljMC0xNS05LjMtMjguNC0yMy40LTMzLjd6TTM1OCAyMTQuOGwtODUgMzEuOXYtNjguMmw4NS0zN3Y3My4zek0xNTQgMTA0LjFsMTAyLTM4LjIgMTAyIDM4LjJ2LjZsLTEwMiA0MS40LTEwMi00MS40di0uNnptODQgMjkxLjFsLTg1IDQyLjV2LTc5LjFsODUtMzguOHY3NS40em0wLTExMmwtMTAyIDQxLjQtMTAyLTQxLjR2LS42bDEwMi0zOC4yIDEwMiAzOC4ydi42em0yNDAgMTEybC04NSA0Mi41di03OS4xbDg1LTM4Ljh2NzUuNHptMC0xMTJsLTEwMiA0MS40LTEwMi00MS40di0uNmwxMDItMzguMiAxMDIgMzguMnYuNnoiPjwvcGF0aD48L3N2Zz4K" height="20">][doc-url]
[<img alt="crates.io" src="https://img.shields.io/crates/v/getifs?style=for-the-badge&logo=data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iaXNvLTg4NTktMSI/Pg0KPCEtLSBHZW5lcmF0b3I6IEFkb2JlIElsbHVzdHJhdG9yIDE5LjAuMCwgU1ZHIEV4cG9ydCBQbHVnLUluIC4gU1ZHIFZlcnNpb246IDYuMDAgQnVpbGQgMCkgIC0tPg0KPHN2ZyB2ZXJzaW9uPSIxLjEiIGlkPSJMYXllcl8xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB4PSIwcHgiIHk9IjBweCINCgkgdmlld0JveD0iMCAwIDUxMiA1MTIiIHhtbDpzcGFjZT0icHJlc2VydmUiPg0KPGc+DQoJPGc+DQoJCTxwYXRoIGQ9Ik0yNTYsMEwzMS41MjgsMTEyLjIzNnYyODcuNTI4TDI1Niw1MTJsMjI0LjQ3Mi0xMTIuMjM2VjExMi4yMzZMMjU2LDB6IE0yMzQuMjc3LDQ1Mi41NjRMNzQuOTc0LDM3Mi45MTNWMTYwLjgxDQoJCQlsMTU5LjMwMyw3OS42NTFWNDUyLjU2NHogTTEwMS44MjYsMTI1LjY2MkwyNTYsNDguNTc2bDE1NC4xNzQsNzcuMDg3TDI1NiwyMDIuNzQ5TDEwMS44MjYsMTI1LjY2MnogTTQzNy4wMjYsMzcyLjkxMw0KCQkJbC0xNTkuMzAzLDc5LjY1MVYyNDAuNDYxbDE1OS4zMDMtNzkuNjUxVjM3Mi45MTN6IiBmaWxsPSIjRkZGIi8+DQoJPC9nPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPC9zdmc+DQo=" height="22">][crates-url]
[<img alt="crates.io" src="https://img.shields.io/crates/d/getifs?color=critical&logo=data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBzdGFuZGFsb25lPSJubyI/PjwhRE9DVFlQRSBzdmcgUFVCTElDICItLy9XM0MvL0RURCBTVkcgMS4xLy9FTiIgImh0dHA6Ly93d3cudzMub3JnL0dyYXBoaWNzL1NWRy8xLjEvRFREL3N2ZzExLmR0ZCI+PHN2ZyB0PSIxNjQ1MTE3MzMyOTU5IiBjbGFzcz0iaWNvbiIgdmlld0JveD0iMCAwIDEwMjQgMTAyNCIgdmVyc2lvbj0iMS4xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHAtaWQ9IjM0MjEiIGRhdGEtc3BtLWFuY2hvci1pZD0iYTMxM3guNzc4MTA2OS4wLmkzIiB3aWR0aD0iNDgiIGhlaWdodD0iNDgiIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIj48ZGVmcz48c3R5bGUgdHlwZT0idGV4dC9jc3MiPjwvc3R5bGU+PC9kZWZzPjxwYXRoIGQ9Ik00NjkuMzEyIDU3MC4yNHYtMjU2aDg1LjM3NnYyNTZoMTI4TDUxMiA3NTYuMjg4IDM0MS4zMTIgNTcwLjI0aDEyOHpNMTAyNCA2NDAuMTI4QzEwMjQgNzgyLjkxMiA5MTkuODcyIDg5NiA3ODcuNjQ4IDg5NmgtNTEyQzEyMy45MDQgODk2IDAgNzYxLjYgMCA1OTcuNTA0IDAgNDUxLjk2OCA5NC42NTYgMzMxLjUyIDIyNi40MzIgMzAyLjk3NiAyODQuMTYgMTk1LjQ1NiAzOTEuODA4IDEyOCA1MTIgMTI4YzE1Mi4zMiAwIDI4Mi4xMTIgMTA4LjQxNiAzMjMuMzkyIDI2MS4xMkM5NDEuODg4IDQxMy40NCAxMDI0IDUxOS4wNCAxMDI0IDY0MC4xOTJ6IG0tMjU5LjItMjA1LjMxMmMtMjQuNDQ4LTEyOS4wMjQtMTI4Ljg5Ni0yMjIuNzItMjUyLjgtMjIyLjcyLTk3LjI4IDAtMTgzLjA0IDU3LjM0NC0yMjQuNjQgMTQ3LjQ1NmwtOS4yOCAyMC4yMjQtMjAuOTI4IDIuOTQ0Yy0xMDMuMzYgMTQuNC0xNzguMzY4IDEwNC4zMi0xNzguMzY4IDIxNC43MiAwIDExNy45NTIgODguODMyIDIxNC40IDE5Ni45MjggMjE0LjRoNTEyYzg4LjMyIDAgMTU3LjUwNC03NS4xMzYgMTU3LjUwNC0xNzEuNzEyIDAtODguMDY0LTY1LjkyLTE2NC45MjgtMTQ0Ljk2LTE3MS43NzZsLTI5LjUwNC0yLjU2LTUuODg4LTMwLjk3NnoiIGZpbGw9IiNmZmZmZmYiIHAtaWQ9IjM0MjIiIGRhdGEtc3BtLWFuY2hvci1pZD0iYTMxM3guNzc4MTA2OS4wLmkwIiBjbGFzcz0iIj48L3BhdGg+PC9zdmc+&style=for-the-badge" height="22">][crates-url]
<img alt="license" src="https://img.shields.io/badge/License-Apache%202.0/MIT-blue.svg?style=for-the-badge&fontColor=white&logoColor=f5c076&logo=data:image/svg+xml;base64,PCFET0NUWVBFIHN2ZyBQVUJMSUMgIi0vL1czQy8vRFREIFNWRyAxLjEvL0VOIiAiaHR0cDovL3d3dy53My5vcmcvR3JhcGhpY3MvU1ZHLzEuMS9EVEQvc3ZnMTEuZHRkIj4KDTwhLS0gVXBsb2FkZWQgdG86IFNWRyBSZXBvLCB3d3cuc3ZncmVwby5jb20sIFRyYW5zZm9ybWVkIGJ5OiBTVkcgUmVwbyBNaXhlciBUb29scyAtLT4KPHN2ZyBmaWxsPSIjZmZmZmZmIiBoZWlnaHQ9IjgwMHB4IiB3aWR0aD0iODAwcHgiIHZlcnNpb249IjEuMSIgaWQ9IkNhcGFfMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayIgdmlld0JveD0iMCAwIDI3Ni43MTUgMjc2LjcxNSIgeG1sOnNwYWNlPSJwcmVzZXJ2ZSIgc3Ryb2tlPSIjZmZmZmZmIj4KDTxnIGlkPSJTVkdSZXBvX2JnQ2FycmllciIgc3Ryb2tlLXdpZHRoPSIwIi8+Cg08ZyBpZD0iU1ZHUmVwb190cmFjZXJDYXJyaWVyIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiLz4KDTxnIGlkPSJTVkdSZXBvX2ljb25DYXJyaWVyIj4gPGc+IDxwYXRoIGQ9Ik0xMzguMzU3LDBDNjIuMDY2LDAsMCw2Mi4wNjYsMCwxMzguMzU3czYyLjA2NiwxMzguMzU3LDEzOC4zNTcsMTM4LjM1N3MxMzguMzU3LTYyLjA2NiwxMzguMzU3LTEzOC4zNTcgUzIxNC42NDgsMCwxMzguMzU3LDB6IE0xMzguMzU3LDI1OC43MTVDNzEuOTkyLDI1OC43MTUsMTgsMjA0LjcyMywxOCwxMzguMzU3UzcxLjk5MiwxOCwxMzguMzU3LDE4IHMxMjAuMzU3LDUzLjk5MiwxMjAuMzU3LDEyMC4zNTdTMjA0LjcyMywyNTguNzE1LDEzOC4zNTcsMjU4LjcxNXoiLz4gPHBhdGggZD0iTTE5NC43OTgsMTYwLjkwM2MtNC4xODgtMi42NzctOS43NTMtMS40NTQtMTIuNDMyLDIuNzMyYy04LjY5NCwxMy41OTMtMjMuNTAzLDIxLjcwOC0zOS42MTQsMjEuNzA4IGMtMjUuOTA4LDAtNDYuOTg1LTIxLjA3OC00Ni45ODUtNDYuOTg2czIxLjA3Ny00Ni45ODYsNDYuOTg1LTQ2Ljk4NmMxNS42MzMsMCwzMC4yLDcuNzQ3LDM4Ljk2OCwyMC43MjMgYzIuNzgyLDQuMTE3LDguMzc1LDUuMjAxLDEyLjQ5NiwyLjQxOGM0LjExOC0yLjc4Miw1LjIwMS04LjM3NywyLjQxOC0xMi40OTZjLTEyLjExOC0xNy45MzctMzIuMjYyLTI4LjY0NS01My44ODItMjguNjQ1IGMtMzUuODMzLDAtNjQuOTg1LDI5LjE1Mi02NC45ODUsNjQuOTg2czI5LjE1Miw2NC45ODYsNjQuOTg1LDY0Ljk4NmMyMi4yODEsMCw0Mi43NTktMTEuMjE4LDU0Ljc3OC0zMC4wMDkgQzIwMC4yMDgsMTY5LjE0NywxOTguOTg1LDE2My41ODIsMTk0Ljc5OCwxNjAuOTAzeiIvPiA8L2c+IDwvZz4KDTwvc3ZnPg==" height="22">

</div>

## Installation

```toml
[dependencies]
getifs = "0.5"
```

## Features

- **Zero libc dependency** on Linux (uses netlink directly)
- **MTU information** - Get interface MTU values
- **Multicast addresses** - Fetch multicast group memberships
- **Gateway discovery** - Find IPv4 and IPv6 gateway addresses
- **RFC-based filtering** - Filter addresses by RFC classification
- **High performance** - Up to 189x faster than alternatives on macOS (see benchmarks)
- **Cross-platform** - Linux, macOS, BSD, Windows support

## Quick Start

```rust
use getifs::{interfaces, local_addrs, gateway_addrs};

// Get all network interfaces
let interfaces = interfaces().unwrap();
for interface in interfaces {
    println!("Interface: {} (index: {})", interface.name(), interface.index());
    println!("  MTU: {}", interface.mtu());
    println!("  Flags: {:?}", interface.flags());
}

// Get local IP addresses
let local_ips = local_addrs().unwrap();
for ip in local_ips {
    println!("Local IP: {}", ip);
}

// Get gateway addresses
let gateways = gateway_addrs().unwrap();
for gateway in gateways {
    println!("Gateway: {}", gateway);
}
```

## Examples

- Fetching all interfaces: [examples/interfaces.rs](./examples/interfaces.rs)
- Fetching all interface addresses (excluding multicast addrs): [examples/addrs.rs](./examples/addrs.rs)
- Fetching all interface multicast addresses: [examples/multicast_addrs.rs](./examples/multicast_addrs.rs)
- Fetching gateway addresses: [examples/gateway.rs](./examples/gateway.rs)
- Fetching local ip addresses: [examples/local_ip_addrs.rs](./examples/local_ip_addrs.rs)
- Fetching ip addresses by RFC: [examples/filter_by_rfc.rs](./examples/filter_by_rfc.rs)

## Details

OS | Approach
--- | ---
Linux (no `libc`) | `socket(AF_NETLINK, SOCK_RAW \| SOCK_CLOEXEC, NETLINK_ROUTE)`
BSD-like | `sysctl`
Windows | `GetAdaptersAddresses`

## Why `getifs`?

Existing network interface crates have limitations:

- **Missing features**: Most don't support MTU or multicast addresses
- **Performance overhead**: Nearly all use `libc::getifaddrs`, which is slower
- **Unnecessary allocations**: Heavy use of heap allocations for simple queries

`getifs` addresses these by:

- Using platform-native APIs directly (netlink, sysctl, GetAdaptersAddresses)
- Minimizing allocations with `SmallVec` and `SmolStr`
- Providing comprehensive interface information including MTU and multicast support
- Achieving **significantly better performance** than alternatives:
  - **Up to 189x faster** on macOS (`interface_by_index`)
  - **Up to 37x faster** on macOS (list interfaces)
  - **2.4–2.8x faster** on Linux (interface enumeration)
  - **~7x faster** local-IP lookup on Linux
  - Comparable performance on Windows (`GetAdaptersAddresses` overhead dominates)

## Roadmap

- [ ] Support fetching routing tables

## Benchmarks

All benchmarks are run with [Criterion.rs](https://github.com/bheisler/criterion.rs) on GitHub Actions. Lower is better.

> **Note**: Automated benchmarks run on Linux, macOS, and Windows via GitHub Actions. View the latest results in the [Actions tab](https://github.com/al8n/getifs/actions/workflows/benchmark.yml) or see [benchmark documentation](.github/BENCHMARKS.md) for more details.

### Performance Summary

Numbers below compare `getifs` against `network-interface 2` and
`local-ip-address 0.6`. Each row reports median `cargo bench` time
(Criterion, 100 samples).

- **macOS (Apple M4 Pro)** — measured on a bare-metal laptop, not CI.
  The GitHub Actions macOS runners are shared virtual machines with
  highly variable latency (run-to-run wobble of ±30% on these ops),
  which obscures the real cost difference.
- **Linux (x64) / Windows (x64)** — measured on GitHub Actions
  `ubuntu-latest` / `windows-latest` runners on 2026-04-15 03:34 UTC.

| Platform | Best Operation | `getifs` | Alternative | Speedup |
|----------|----------------|----------|-------------|---------|
| **macOS** (Apple M4 Pro) | Get interface by index | 1.7 μs | 314.2 μs | **189x faster** |
| **macOS** (Apple M4 Pro) | List all interfaces | 8.4 μs | 313.0 μs | **37x faster** |
| **Linux** (x64) | Local IPv4 lookup | 13.7 μs | 94.3 μs | **6.9x faster** |
| **Linux** (x64) | List all interfaces | 41.5 μs | 111.7 μs | **2.7x faster** |
| **Windows** (x64) | Gateway IPv4 | 30.2 μs | N/A | Unique feature |

### Detailed Results

#### Interface Operations

**macOS (Apple M4 Pro, 24 GB, local bare-metal)**

| Operation | `getifs` | Alternative | Speedup |
|-----------|----------|-------------|---------|
| List all interfaces | 8.4 μs | 313.0 μs (`network-interface`) | **37x faster** |
| Get interface by index | 1.7 μs | 314.2 μs (`network-interface`) | **189x faster** |
| Get interface by name | 10.4 μs | 314.1 μs (`network-interface`) | **30x faster** |
| Get interface addresses | 8.4 μs | - | - |
| Get multicast addresses | 2.9 μs | - | - |

**Linux (GitHub Actions x64)**

| Operation | `getifs` | Alternative | Speedup |
|-----------|----------|-------------|---------|
| List all interfaces | 41.5 μs | 111.7 μs (`network-interface`) | **2.7x faster** |
| Get interface by index | 40.3 μs | 111.9 μs (`network-interface`) | **2.8x faster** |
| Get interface by name | 46.1 μs | 111.9 μs (`network-interface`) | **2.4x faster** |
| Get interface addresses | 17.3 μs | - | - |
| Get multicast addresses | 31.4 μs | - | - |

**Windows (GitHub Actions x64)**

| Operation | `getifs` | Alternative | Notes |
|-----------|----------|-------------|-------|
| List all interfaces | 974 μs | 967 μs (`network-interface`) | Within noise |
| Get interface by index | 954 μs | 976 μs (`network-interface`) | Within noise |
| Get interface by name | 1011 μs | 969 μs (`network-interface`) | Within noise |
| Get interface addresses | 958 μs | - | - |
| Get multicast addresses | 966 μs | - | - |

*Note: the Win32 `GetAdaptersAddresses` API has an inherent ~1 ms floor
that dominates every implementation — `getifs` and `network-interface`
end up within measurement noise of each other on Windows.*

#### Local IP Address Operations

**macOS (Apple M4 Pro, 24 GB, local bare-metal)**

| Operation | `getifs` | Alternative | Speedup |
|-----------|----------|-------------|---------|
| Get local IPv4 address | 6.5 μs | 9.8 μs (`local-ip-address`) | **1.5x faster** |
| Get local IPv6 address | 7.9 μs | 9.8 μs (`local-ip-address`) | **1.2x faster** |

**Linux (GitHub Actions x64)**

| Operation | `getifs` | Alternative | Speedup |
|-----------|----------|-------------|---------|
| Get local IPv4 address | 13.7 μs | 94.3 μs (`local-ip-address`) | **6.9x faster** |
| Get local IPv6 address | 11.2 μs | - | No IPv6 result from alternative |

**Windows (GitHub Actions x64)**

| Operation | `getifs` | Alternative | Notes |
|-----------|----------|-------------|-------|
| Get local IPv4 address | 963 μs | 919 μs (`local-ip-address`) | Win32 ~1 ms floor |
| Get local IPv6 address | 992 μs | 972 μs (`local-ip-address`) | Win32 ~1 ms floor |

#### Gateway Operations

| Platform | IPv4 Gateways | IPv6 Gateways | All Gateways |
|----------|---------------|---------------|--------------|
| **macOS** (M4 Pro, local) | 17.5 μs | 2.4 μs | 19.8 μs |
| **Linux** (x64, CI) | 18.4 μs | 14.3 μs | 22.4 μs |
| **Windows** (x64, CI) | 30.2 μs | 18.0 μs | 48.5 μs |

*Note: No direct alternatives available for gateway discovery, so these
are reported as absolute times rather than as speedups.*

**Why is `getifs` faster?**

- **Direct system calls**: Uses platform-native APIs (netlink on Linux, sysctl on BSD/macOS, GetAdaptersAddresses on Windows)
- **Zero-copy parsing**: Minimal allocations and efficient buffer reuse
- **No libc dependency** on Linux: Direct netlink socket communication
- **Optimized data structures**: Uses `SmallVec` and `SmolStr` to avoid heap allocations for common cases

**Platform Performance Notes:**

- **macOS**: Shows the largest speedups (30–189x on bare metal) due to
  the efficient sysctl-based implementation avoiding `getifaddrs`'s
  per-call overhead. On shared CI runners the absolute numbers are
  noisier but the ordering holds.
- **Linux**: 2.4–2.8x faster interface enumeration via direct netlink,
  and ~7x faster local-IP lookup from avoiding the test-socket round
  trip that `local-ip-address` performs.
- **Windows**: Similar performance to alternatives — `GetAdaptersAddresses`
  has an inherent ~1 ms floor that dominates every implementation.

## Sister crates

- [`iprobe`](https://github.com/al8n/iprobe): Probe if the host system supports IPv4, IPv6 and IPv4-mapped-IPv6.
- [`iprfc`](https://github.com/al8n/iprfc): Known RFCs for IP addresses.

## Pedigree

- The code in this crate is inspired by Golang's `interface.go` and [HashiCorp's go-sockaddr](https://github.com/hashicorp/go-sockaddr).

#### License

`getifs` is under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE), [LICENSE-MIT](LICENSE-MIT) for details.

Copyright (c) 2026 Al Liu.

[Github-url]: https://github.com/al8n/getifs/
[CI-url]: https://github.com/al8n/getifs/actions/workflows/ci.yml
[doc-url]: https://docs.rs/getifs
[crates-url]: https://crates.io/crates/getifs
[codecov-url]: https://app.codecov.io/gh/al8n/getifs/
