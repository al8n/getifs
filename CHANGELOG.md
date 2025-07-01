# RELEASED

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
