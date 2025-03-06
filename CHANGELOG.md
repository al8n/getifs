# RELEASED

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
