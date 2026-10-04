#!/usr/bin/env python3
"""Generate deterministic netlink and BSD fuzz seed corpora.

A netlink seed is a sequence of datagrams, each prefixed by its length as a
little-endian u32. The fuzz hook replays the datagrams in order to every
netlink dump walker as the kernel's replies. A walker that opens another dump
(the nexthop dump, best-local's per-interface address dump, or the retry of an
interrupted dump) reads the next unread datagram. Every message carries
sequence number 1 and the same port id, because the walkers drop any reply
whose port id differs from that of the first message.

A BSD seed is one sysctl buffer. The routing-message seeds use the macOS
header layout, which matches the CI host of the bsd target.
"""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parent
NETLINK_CORPUS = ROOT / "corpus" / "netlink"
BSD_CORPUS = ROOT / "corpus" / "bsd"

# Linux netlink.
NLMSG_DONE = 3
NLMSG_OVERRUN = 4
NLM_F_MULTI = 0x2
NLM_F_DUMP_INTR = 0x10
RTM_NEWLINK = 16
RTM_NEWADDR = 20
RTM_NEWROUTE = 24
RTM_NEWNEXTHOP = 104

LINUX_AF_INET = 2
RT_TABLE_MAIN = 254
RTPROT_BOOT = 3
RTN_UNICAST = 1

IFLA_ADDRESS = 1
IFLA_IFNAME = 3
IFLA_MTU = 4
IFA_ADDRESS = 1
IFA_LOCAL = 2
RTA_DST = 1
RTA_OIF = 4
RTA_GATEWAY = 5
RTA_PRIORITY = 6
RTA_NH_ID = 30
NHA_ID = 1
NHA_OIF = 5
NHA_GATEWAY = 6

NETLINK_SEQ = 1
NETLINK_PID = 0x5EED

# macOS routing socket.
DARWIN_AF_INET = 2
DARWIN_AF_INET6 = 30
DARWIN_AF_LINK = 18
RTM_VERSION = 5
RTM_GET = 0x4
RTM_NEWADDR_BSD = 0xC
RTM_IFINFO = 0xE
RTF_UP = 0x1
RTF_GATEWAY = 0x2
RTF_STATIC = 0x800
RTA_DST_BSD = 0x1
RTA_GATEWAY_BSD = 0x2
RTA_NETMASK_BSD = 0x4
RTA_IFP_BSD = 0x10
RTA_IFA_BSD = 0x20
IFF_UP = 0x1
IFF_RUNNING = 0x40
IFT_ETHER = 0x6
IF_MSGHDR_SIZE = 112
IFA_MSGHDR_SIZE = 20
RT_MSGHDR_SIZE = 92
DARWIN_ALIGN = 4


def align4(data: bytes) -> bytes:
    return data + b"\0" * ((-len(data)) % 4)


def u32(value: int) -> bytes:
    return struct.pack("=I", value)


def ipv4(address: str) -> bytes:
    return ipaddress.IPv4Address(address).packed


def write(corpus: Path, name: str, data: bytes) -> None:
    corpus.mkdir(parents=True, exist_ok=True)
    (corpus / name).write_bytes(data)


# --- netlink ---------------------------------------------------------------


def nlmsg(message_type: int, body: bytes = b"", flags: int = NLM_F_MULTI) -> bytes:
    header = struct.pack(
        "=IHHII", 16 + len(body), message_type, flags, NETLINK_SEQ, NETLINK_PID
    )
    return align4(header + body)


def done() -> bytes:
    return nlmsg(NLMSG_DONE, struct.pack("=i", 0))


def rtattr(kind: int, payload: bytes) -> bytes:
    return align4(struct.pack("=HH", 4 + len(payload), kind) + payload)


def datagrams(*payloads: bytes) -> bytes:
    return b"".join(struct.pack("<I", len(payload)) + payload for payload in payloads)


def link(index: int, name: bytes, flags: int = NLM_F_MULTI) -> bytes:
    # ifinfomsg: family, pad, type (ARPHRD_ETHER), index, flags (IFF_UP), change
    body = struct.pack("=BBHiII", 0, 0, 1, index, 1, 0xFFFFFFFF)
    body += rtattr(IFLA_IFNAME, name)
    body += rtattr(IFLA_MTU, u32(1500))
    body += rtattr(IFLA_ADDRESS, b"\x02\0\0\0\0" + bytes([index]))
    return nlmsg(RTM_NEWLINK, body, flags)


def address(index: int, local: str) -> bytes:
    # ifaddrmsg: family, prefixlen, flags, scope, index
    body = struct.pack("=BBBBI", LINUX_AF_INET, 24, 0, 0, index)
    body += rtattr(IFA_LOCAL, ipv4(local))
    body += rtattr(IFA_ADDRESS, ipv4(local))
    return nlmsg(RTM_NEWADDR, body)


def route(dst_len: int, attrs: bytes) -> bytes:
    # rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type, flags
    body = struct.pack(
        "=BBBBBBBBI",
        LINUX_AF_INET,
        dst_len,
        0,
        0,
        RT_TABLE_MAIN,
        RTPROT_BOOT,
        0,
        RTN_UNICAST,
        0,
    )
    return nlmsg(RTM_NEWROUTE, body + attrs)


def nexthop(nh_id: int, oif: int, gateway: str) -> bytes:
    # nhmsg: family, scope, protocol, resvd, flags
    body = struct.pack("=BBBBI", LINUX_AF_INET, 0, RTPROT_BOOT, 0, 0)
    body += rtattr(NHA_ID, u32(nh_id))
    body += rtattr(NHA_OIF, u32(oif))
    body += rtattr(NHA_GATEWAY, ipv4(gateway))
    return nlmsg(RTM_NEWNEXTHOP, body)


def generate_netlink() -> None:
    plain_route = route(
        24,
        rtattr(RTA_DST, ipv4("198.51.100.0"))
        + rtattr(RTA_GATEWAY, ipv4("192.0.2.254"))
        + rtattr(RTA_OIF, u32(2)),
    )
    # A default route through a nexthop object resolves through a second dump.
    nexthop_default = route(0, rtattr(RTA_PRIORITY, u32(100)) + rtattr(RTA_NH_ID, u32(7)))

    write(
        NETLINK_CORPUS,
        "link-dump",
        datagrams(link(1, b"lo\0") + link(2, b"fuzz0\0") + done()),
    )
    write(
        NETLINK_CORPUS,
        "addr-dump",
        datagrams(address(2, "192.0.2.1") + done()),
    )
    write(
        NETLINK_CORPUS,
        "route-nexthop-addr",
        datagrams(
            plain_route + nexthop_default + done(),
            nexthop(7, 2, "192.0.2.254") + done(),
            address(2, "192.0.2.1") + done(),
        ),
    )
    write(
        NETLINK_CORPUS,
        "interrupted-then-clean",
        datagrams(
            link(2, b"stale0\0", NLM_F_MULTI | NLM_F_DUMP_INTR) + done(),
            link(2, b"fuzz0\0") + done(),
        ),
    )
    write(
        NETLINK_CORPUS,
        "split-datagrams",
        datagrams(link(1, b"lo\0"), link(2, b"fuzz0\0"), done()),
    )
    write(
        NETLINK_CORPUS,
        "non-utf8-name",
        datagrams(link(1, b"\xff\xfe\0") + link(2, b"fuzz0\0") + done()),
    )
    write(NETLINK_CORPUS, "truncated-header", datagrams(b"\x10\0\0"))
    write(NETLINK_CORPUS, "negative-done", datagrams(nlmsg(NLMSG_DONE, struct.pack("=i", -12))))
    write(NETLINK_CORPUS, "overrun", datagrams(nlmsg(NLMSG_OVERRUN)))
    write(
        NETLINK_CORPUS,
        "declared-overrun",
        datagrams(
            struct.pack("=IHHII", 4096, RTM_NEWLINK, NLM_F_MULTI, NETLINK_SEQ, NETLINK_PID)
        ),
    )
    write(NETLINK_CORPUS, "truncated-length-prefix", struct.pack("<I", 64) + done())


# --- BSD -------------------------------------------------------------------


def roundup(length: int) -> int:
    if length == 0:
        return DARWIN_ALIGN
    return (length + DARWIN_ALIGN - 1) & ~(DARWIN_ALIGN - 1)


def padded(sockaddr: bytes) -> bytes:
    return sockaddr + b"\0" * (roundup(sockaddr[0]) - len(sockaddr))


def sockaddr_v4(address: str) -> bytes:
    return bytes([16, 2, 0, 0]) + ipaddress.IPv4Address(address).packed + b"\0" * 8


def sockaddr_v6(address: str) -> bytes:
    return bytes([28, 30, 0, 0]) + b"\0" * 4 + ipaddress.IPv6Address(address).packed + b"\0" * 4


def sockaddr_dl(index: int, name: bytes, mac: bytes) -> bytes:
    # sdl_len, sdl_family, sdl_index, sdl_type, sdl_nlen, sdl_alen, sdl_slen, sdl_data
    data = name + mac
    body = struct.pack("=BBHBBBB", 0, DARWIN_AF_LINK, index, IFT_ETHER, len(name), len(mac), 0)
    body += data + b"\0" * max(0, 12 - len(data))
    return padded(bytes([len(body)]) + body[1:])


def ifinfo_message(index: int, sockaddrs: bytes) -> bytes:
    # if_msghdr: msglen, version, type, addrs, flags, index, pad, then if_data,
    # whose ifi_mtu sits 8 bytes in.
    if_data = b"\0" * 8 + u32(1500) + b"\0" * (IF_MSGHDR_SIZE - 16 - 12)
    header = struct.pack(
        "=HBBiiHH",
        IF_MSGHDR_SIZE + len(sockaddrs),
        RTM_VERSION,
        RTM_IFINFO,
        RTA_IFP_BSD,
        IFF_UP | IFF_RUNNING,
        index,
        0,
    )
    return header + if_data + sockaddrs


def newaddr_message(index: int, addrs: int, sockaddrs: bytes) -> bytes:
    # ifa_msghdr: msglen, version, type, addrs, flags, index, pad, metric
    header = struct.pack(
        "=HBBiiHHi",
        IFA_MSGHDR_SIZE + len(sockaddrs),
        RTM_VERSION,
        RTM_NEWADDR_BSD,
        addrs,
        0,
        index,
        0,
        0,
    )
    return header + sockaddrs


def rt_message(index: int, flags: int, addrs: int, sockaddrs: bytes) -> bytes:
    # rt_msghdr: msglen, version, type, index, pad, flags, addrs, pid, seq,
    # errno, use, inits, then 14 32-bit rt_metrics fields.
    header = struct.pack(
        "=HBBHHiiiiiiI",
        RT_MSGHDR_SIZE + len(sockaddrs),
        RTM_VERSION,
        RTM_GET,
        index,
        0,
        flags,
        addrs,
        0,
        0,
        0,
        0,
        0,
    )
    return header + b"\0" * (RT_MSGHDR_SIZE - len(header)) + sockaddrs


def generate_bsd() -> None:
    write(BSD_CORPUS, "sockaddr-ipv4", sockaddr_v4("192.0.2.1"))
    write(BSD_CORPUS, "sockaddr-ipv6", sockaddr_v6("2001:db8::1"))
    write(BSD_CORPUS, "sockaddr-kame", sockaddr_v6("fe80:000e::1"))
    write(BSD_CORPUS, "compact-netmask-v4", bytes([7, 2, 0, 0, 255, 255, 255, 0]))
    write(BSD_CORPUS, "kernel-prefix-v4", bytes([8, 0, 0, 0, 192, 0, 2, 1]))
    write(BSD_CORPUS, "malformed-length", bytes([32, 30, 0, 0, 1, 2, 3]))

    # A NET_RT_IFLIST dump: an interface and one of its addresses.
    link_address = sockaddr_dl(4, b"en0", b"\x02\0\0\0\0\x04")
    netmask = padded(bytes([7, DARWIN_AF_INET, 0, 0, 255, 255, 255]))
    write(
        BSD_CORPUS,
        "iflist-ifinfo-newaddr",
        ifinfo_message(4, link_address)
        + newaddr_message(
            4,
            RTA_NETMASK_BSD | RTA_IFP_BSD | RTA_IFA_BSD,
            netmask + link_address + sockaddr_v4("192.0.2.10"),
        ),
    )

    # A NET_RT_DUMP route with a compact gateway and netmask.
    gateway = padded(bytes([8, DARWIN_AF_INET, 0, 0]) + ipv4("192.0.2.1"))
    route_netmask = padded(bytes([5, DARWIN_AF_INET, 0, 0, 255]))
    write(
        BSD_CORPUS,
        "rtm-get-route",
        rt_message(
            4,
            RTF_UP | RTF_GATEWAY | RTF_STATIC,
            RTA_DST_BSD | RTA_GATEWAY_BSD | RTA_NETMASK_BSD,
            sockaddr_v4("10.0.0.0") + gateway + route_netmask,
        ),
    )


if __name__ == "__main__":
    generate_netlink()
    generate_bsd()
