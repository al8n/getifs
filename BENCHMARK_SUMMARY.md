# Benchmark Results Summary

Date: 2025-11-03 22:04:35 UTC


## Benchmark Results for macos-latest

### System Information
- OS: macos-latest
- Runner: GitHub Actions 1000041543
- Architecture: ARM64
- Date: 2025-11-03 22:01:16 UTC

### Interface Operations

```
test getifs::interfaces ... bench:       8,539 ns/iter (+/- 322)
test getifs::interface_by_index/1 ... bench:       2,589 ns/iter (+/- 180)
test getifs::interface_by_name/lo0 ... bench:      11,600 ns/iter (+/- 844)
test getifs::interface_addrs ... bench:       8,459 ns/iter (+/- 584)
test getifs::interfaces_and_multicast_addrs/lo0 ... bench:       4,567 ns/iter (+/- 246)
test network_interface::interfaces ... bench:     180,439 ns/iter (+/- 12,605)
test network_interface::interface_by_index/1 ... bench:     188,397 ns/iter (+/- 14,906)
test network_interface::interface_by_name/lo0 ... bench:     188,260 ns/iter (+/- 12,034)
```

### Local IP Operations

```
test getifs::local_ipv4_addrs ... bench:       6,142 ns/iter (+/- 256)
test getifs::local_ipv6_addrs ... bench:       7,597 ns/iter (+/- 418)
test local_ip_address::local_ip ... bench:      10,002 ns/iter (+/- 2,420)
test local_ip_address::local_ipv6 ... bench:       9,866 ns/iter (+/- 655)
```

### Gateway Operations

```
test getifs::gateway_ipv4_addrs ... bench:      19,635 ns/iter (+/- 1,118)
test getifs::gateway_ipv6_addrs ... bench:       3,016 ns/iter (+/- 163)
test getifs::gateway_addrs ... bench:      22,764 ns/iter (+/- 1,085)
```


---

## Benchmark Results for ubuntu-latest

### System Information
- OS: ubuntu-latest
- Runner: GitHub Actions 1000041555
- Architecture: X64
- Date: 2025-11-03 22:01:32 UTC

### Interface Operations

```
test getifs::interfaces ... bench:      35,206 ns/iter (+/- 553)
test getifs::interface_by_index/1 ... bench:      35,016 ns/iter (+/- 853)
test getifs::interface_by_name/lo ... bench:      40,797 ns/iter (+/- 1,725)
test getifs::interface_addrs ... bench:      16,442 ns/iter (+/- 628)
test getifs::interfaces_and_multicast_addrs/lo ... bench:      31,459 ns/iter (+/- 590)
test network_interface::interfaces ... bench:      98,135 ns/iter (+/- 1,222)
test network_interface::interface_by_index/1 ... bench:      98,481 ns/iter (+/- 3,146)
test network_interface::interface_by_name/lo ... bench:      98,365 ns/iter (+/- 1,512)
```

### Local IP Operations

```
test getifs::local_ipv4_addrs ... bench:      13,680 ns/iter (+/- 497)
test getifs::local_ipv6_addrs ... bench:      11,393 ns/iter (+/- 647)
test local_ip_address::local_ip ... bench:      12,220 ns/iter (+/- 409)
```

### Gateway Operations

```
test getifs::gateway_ipv4_addrs ... bench:      18,128 ns/iter (+/- 756)
test getifs::gateway_ipv6_addrs ... bench:      14,494 ns/iter (+/- 662)
test getifs::gateway_addrs ... bench:      22,356 ns/iter (+/- 522)
```


---

## Benchmark Results for windows-latest

### System Information
- OS: windows-latest
- Runner: GitHub Actions 1000041551
- Architecture: X64
- Date: 2025-11-03 22:04:13 UTC

### Interface Operations

```
test getifs::interfaces ... bench:     986,184 ns/iter (+/- 16,723)
test getifs::interface_by_index/14 ... bench:     977,031 ns/iter (+/- 18,353)
test getifs::interface_by_name/Ethernet 3 ... bench:   1,024,614 ns/iter (+/- 37,875)
test getifs::interface_addrs ... bench:     977,317 ns/iter (+/- 9,001)
test getifs::interfaces_and_multicast_addrs/Ethernet 3 ... bench:     977,039 ns/iter (+/- 32,893)
test network_interface::interfaces ... bench:     979,075 ns/iter (+/- 21,526)
test network_interface::interface_by_index/14 ... bench:     984,274 ns/iter (+/- 38,876)
test network_interface::interface_by_name/Ethernet 3 ... bench:     979,412 ns/iter (+/- 25,054)
```

### Local IP Operations

```
test getifs::local_ipv4_addrs ... bench:     979,530 ns/iter (+/- 26,280)
test getifs::local_ipv6_addrs ... bench:     982,649 ns/iter (+/- 27,221)
test local_ip_address::local_ip ... bench:     926,276 ns/iter (+/- 13,975)
test local_ip_address::local_ipv6 ... bench:     982,965 ns/iter (+/- 22,932)
```

### Gateway Operations

```
test getifs::gateway_ipv4_addrs ... bench:      29,867 ns/iter (+/- 276)
test getifs::gateway_ipv6_addrs ... bench:      18,010 ns/iter (+/- 195)
test getifs::gateway_addrs ... bench:      48,201 ns/iter (+/- 351)
```


---
