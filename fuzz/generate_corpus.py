#!/usr/bin/env python3
"""Generate deterministic netlink and BSD parser seed corpora."""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parent
NETLINK_CORPUS = ROOT / "corpus" / "netlink"
BSD_CORPUS = ROOT / "corpus" / "bsd"

NLMSG_DONE = 3
NLMSG_OVERRUN = 4
RTM_NEWLINK = 16
RTM_NEWADDR = 20
RTM_NEWROUTE = 24

IFLA_ADDRESS = 1
IFLA_IFNAME = 3
IFA_ADDRESS = 1
RTA_DST = 1
RTA_OIF = 4
RTA_GATEWAY = 5


def align4(data: bytes) -> bytes:
    return data + b"\0" * ((-len(data)) % 4)


def nlmsg(message_type: int, body: bytes = b"", flags: int = 0) -> bytes:
    header = struct.pack("=IHHII", 16 + len(body), message_type, flags, 0, 0)
    return align4(header + body)


def rtattr(kind: int, payload: bytes) -> bytes:
    return align4(struct.pack("=HH", 4 + len(payload), kind) + payload)


def ifinfo(index: int = 1) -> bytes:
    return struct.pack("=BBHiII", 0, 0, 1, index, 1, 0xFFFFFFFF)


def ifaddr(index: int = 1) -> bytes:
    return struct.pack("=BBBBI", 2, 24, 0, 0, index)


def route() -> bytes:
    return struct.pack("=BBBBBBBBI", 2, 24, 0, 0, 254, 3, 0, 1, 0)


def sockaddr_v4(address: str) -> bytes:
    return bytes([16, 2, 0, 0]) + ipaddress.IPv4Address(address).packed + b"\0" * 8


def sockaddr_v6(address: str) -> bytes:
    return bytes([28, 30, 0, 0]) + b"\0" * 4 + ipaddress.IPv6Address(address).packed + b"\0" * 4


def write(corpus: Path, name: str, data: bytes) -> None:
    corpus.mkdir(parents=True, exist_ok=True)
    (corpus / name).write_bytes(data)


def generate_netlink() -> None:
    link = ifinfo() + rtattr(IFLA_IFNAME, b"fuzz0\0") + rtattr(IFLA_ADDRESS, b"\x02\0\0\0\0\x01")
    address = ifaddr() + rtattr(IFA_ADDRESS, ipaddress.IPv4Address("192.0.2.1").packed)
    route_message = (
        route()
        + rtattr(RTA_DST, ipaddress.IPv4Address("198.51.100.0").packed)
        + rtattr(RTA_GATEWAY, ipaddress.IPv4Address("192.0.2.254").packed)
        + rtattr(RTA_OIF, struct.pack("=I", 1))
    )

    write(NETLINK_CORPUS, "valid-link-done", nlmsg(RTM_NEWLINK, link) + nlmsg(NLMSG_DONE))
    write(NETLINK_CORPUS, "truncated-header", b"\x10\0\0")
    write(NETLINK_CORPUS, "negative-done", nlmsg(NLMSG_DONE, struct.pack("=i", -12)))
    write(NETLINK_CORPUS, "overrun", nlmsg(NLMSG_OVERRUN))
    write(NETLINK_CORPUS, "ifinfo", nlmsg(RTM_NEWLINK, link))
    write(NETLINK_CORPUS, "ifaddr", nlmsg(RTM_NEWADDR, address))
    write(NETLINK_CORPUS, "route", nlmsg(RTM_NEWROUTE, route_message))
    write(NETLINK_CORPUS, "mac", nlmsg(RTM_NEWLINK, ifinfo() + rtattr(IFLA_ADDRESS, b"\xff" * 6)))
    write(NETLINK_CORPUS, "declared-overrun", struct.pack("=IHHII", 4096, RTM_NEWLINK, 0, 0, 0))


def generate_bsd() -> None:
    write(BSD_CORPUS, "sockaddr-ipv4", sockaddr_v4("192.0.2.1"))
    write(BSD_CORPUS, "sockaddr-ipv6", sockaddr_v6("2001:db8::1"))
    write(BSD_CORPUS, "sockaddr-kame", sockaddr_v6("fe80:000e::1"))
    write(BSD_CORPUS, "compact-netmask-v4", bytes([7, 2, 0, 0, 255, 255, 255, 0]))
    write(BSD_CORPUS, "kernel-prefix-v4", bytes([8, 0, 0, 0, 192, 0, 2, 1]))
    write(BSD_CORPUS, "malformed-length", bytes([32, 30, 0, 0, 1, 2, 3]))


if __name__ == "__main__":
    generate_netlink()
    generate_bsd()
