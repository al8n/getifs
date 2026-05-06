//! Cross-BSD kernel-struct compatibility.
//!
//! The `libc` crate exports `rt_msghdr` **only** on Apple targets and
//! `ifa_msghdr` only on Apple/FreeBSD/DragonFly. For the remaining
//! BSDs we define the structs ourselves, using the layout from each
//! OS's `<net/route.h>` and `<net/if.h>`. Only the fields we actually
//! consult need to be named by hand; the remaining fields are filled
//! in so that `size_of::<...>()` equals the on-the-wire header size
//! emitted by the kernel, since callers use that to skip past the
//! header to the trailing sockaddrs.

#![allow(non_camel_case_types, dead_code)]

// =====================================================================
// rt_msghdr
// =====================================================================

#[cfg(apple)]
pub(super) use libc::rt_msghdr as RtMsghdr;

// ---- FreeBSD (and DragonFly, which shares the same layout since the
// fork) ---------------------------------------------------------------
//
// FreeBSD 14 `<net/route.h>`:
//
//     struct rt_msghdr {
//         u_short rtm_msglen;
//         u_char  rtm_version;
//         u_char  rtm_type;
//         u_short rtm_index;
//         _Alignas(sizeof(unsigned long)) int rtm_flags;
//         int     rtm_addrs;
//         pid_t   rtm_pid;
//         int     rtm_seq;
//         int     rtm_errno;
//         int     rtm_fmask;
//         u_long  rtm_inits;
//         struct  rt_metrics rtm_rmx;
//     };
//
// The `_Alignas(sizeof(unsigned long))` on `rtm_flags` forces two bytes
// of padding after `rtm_index` (which ends at offset 6) so `rtm_flags`
// lands on an 8-byte boundary on LP64 / 4-byte boundary on ILP32. Two
// bytes of padding works for both.

#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
#[repr(C)]
pub(super) struct RtMsghdr {
  pub rtm_msglen: u16,
  pub rtm_version: u8,
  pub rtm_type: u8,
  pub rtm_index: u16,
  _pad_to_flags: u16,
  pub rtm_flags: libc::c_int,
  pub rtm_addrs: libc::c_int,
  pub rtm_pid: libc::pid_t,
  pub rtm_seq: libc::c_int,
  pub rtm_errno: libc::c_int,
  pub rtm_fmask: libc::c_int,
  pub rtm_inits: libc::c_ulong,
  pub rtm_rmx: RtMetricsLong,
}

/// The flavor of `rt_metrics` used by FreeBSD/DragonFly: 14 × `u_long`.
#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
#[repr(C)]
pub(super) struct RtMetricsLong {
  pub rmx_locks: libc::c_ulong,
  pub rmx_mtu: libc::c_ulong,
  pub rmx_hopcount: libc::c_ulong,
  pub rmx_expire: libc::c_ulong,
  pub rmx_recvpipe: libc::c_ulong,
  pub rmx_sendpipe: libc::c_ulong,
  pub rmx_ssthresh: libc::c_ulong,
  pub rmx_rtt: libc::c_ulong,
  pub rmx_rttvar: libc::c_ulong,
  pub rmx_pksent: libc::c_ulong,
  pub rmx_weight: libc::c_ulong,
  pub rmx_nhidx: libc::c_ulong,
  _filler: [libc::c_ulong; 2],
}

// FreeBSD/DragonFly `rt_metrics` is 14 × u_long. On LP64 hosts (the
// only platforms these systems run on for our purposes) u_long is 8
// bytes, so the struct is 112 bytes, and `rt_msghdr` rounds out to
// 152 bytes. The static assertion fires at compile time if a future
// kernel revision changes the layout.
#[cfg(all(
  any(target_os = "freebsd", target_os = "dragonfly"),
  target_pointer_width = "64"
))]
const _: () = assert!(core::mem::size_of::<RtMetricsLong>() == 112);
#[cfg(all(
  any(target_os = "freebsd", target_os = "dragonfly"),
  target_pointer_width = "64"
))]
const _: () = assert!(core::mem::size_of::<RtMsghdr>() == 152);
#[cfg(all(
  any(target_os = "freebsd", target_os = "dragonfly"),
  target_pointer_width = "64"
))]
const _: () = {
  use core::mem::offset_of;
  assert!(offset_of!(RtMsghdr, rtm_msglen) == 0);
  assert!(offset_of!(RtMsghdr, rtm_index) == 4);
  assert!(offset_of!(RtMsghdr, rtm_flags) == 8);
  assert!(offset_of!(RtMsghdr, rtm_addrs) == 12);
  assert!(offset_of!(RtMsghdr, rtm_rmx) == 40);
  assert!(offset_of!(RtMetricsLong, rmx_recvpipe) == 32);
};

// ---- NetBSD -----------------------------------------------------------
//
// NetBSD `<net/route.h>` (modern, NetBSD 9+, verified against
// https://github.com/NetBSD/src/blob/trunk/sys/net/route.h):
//
//     struct rt_msghdr {
//         u_short rtm_msglen;
//         u_char  rtm_version;
//         u_char  rtm_type;
//         u_short rtm_index;          /* u_short, not int */
//         int     rtm_flags;
//         int     rtm_addrs;
//         pid_t   rtm_pid;
//         int     rtm_seq;
//         int     rtm_errno;
//         int     rtm_use;
//         int     rtm_inits;
//         struct  rt_metrics rtm_rmx;
//     };
//
//     struct rt_metrics {
//         uint64_t rmx_locks;
//         uint64_t rmx_mtu;
//         uint64_t rmx_hopcount;
//         uint64_t rmx_recvpipe;
//         uint64_t rmx_sendpipe;
//         uint64_t rmx_ssthresh;
//         uint64_t rmx_rtt;
//         uint64_t rmx_rttvar;
//         time_t   rmx_expire;
//         time_t   rmx_pksent;
//     };
//
// `rt_metrics` is 8 × u64 + 2 × time_t = 80 bytes (NetBSD `time_t` is
// `int64_t`).
//
// `rtm_index` is `u_short` followed by 2 bytes of compiler-inserted
// padding to align `rtm_flags` on a 4-byte boundary. We declare it
// as `u16` with an explicit `_pad_index` field so the read is correct
// on big-endian NetBSD targets (sparc64, mips, powerpc): treating
// `rtm_index` as `c_int` would interpret the kernel-zeroed padding
// bytes as the high half of the index value, mangling the result on
// big-endian. The total size and the offsets of every other field are
// the same as before — only the read of `rtm_index` differs.

#[cfg(target_os = "netbsd")]
#[repr(C)]
pub(super) struct RtMsghdr {
  pub rtm_msglen: u16,
  pub rtm_version: u8,
  pub rtm_type: u8,
  pub rtm_index: u16,
  _pad_index: u16,
  pub rtm_flags: libc::c_int,
  pub rtm_addrs: libc::c_int,
  pub rtm_pid: libc::pid_t,
  pub rtm_seq: libc::c_int,
  pub rtm_errno: libc::c_int,
  pub rtm_use: libc::c_int,
  pub rtm_inits: libc::c_int,
  // The compiler inserts 4 bytes of natural alignment padding here
  // to put `rtm_rmx` (which contains u64 fields) on an 8-byte boundary.
  pub rtm_rmx: RtMetricsU64,
}

#[cfg(target_os = "netbsd")]
#[repr(C)]
pub(super) struct RtMetricsU64 {
  pub rmx_locks: u64,
  pub rmx_mtu: u64,
  pub rmx_hopcount: u64,
  pub rmx_recvpipe: u64,
  pub rmx_sendpipe: u64,
  pub rmx_ssthresh: u64,
  pub rmx_rtt: u64,
  pub rmx_rttvar: u64,
  pub rmx_expire: libc::time_t,
  pub rmx_pksent: libc::time_t,
}

// Fail the build if NetBSD's struct sizes drift away from the
// kernel's. We slice `&buf[size_of::<RtMsghdr>()..rtm_msglen]` to
// reach the trailing sockaddrs; a wrong size desyncs every route
// record. NetBSD `time_t` is `int64_t`, so this assertion is true on
// every supported NetBSD architecture.
//
// Also assert the offset of every field we read at runtime: a
// reorder that happens to keep the total size constant but moves a
// field would otherwise pass the size check while still corrupting
// the read. This catches the previous `rtm_index: c_int` mistake
// (where the size was right but the field was 4 bytes wide instead
// of 2 + 2-byte pad).
#[cfg(target_os = "netbsd")]
const _: () = assert!(core::mem::size_of::<RtMetricsU64>() == 80);
#[cfg(target_os = "netbsd")]
const _: () = assert!(core::mem::size_of::<RtMsghdr>() == 120);
#[cfg(target_os = "netbsd")]
const _: () = {
  use core::mem::offset_of;
  assert!(offset_of!(RtMsghdr, rtm_msglen) == 0);
  assert!(offset_of!(RtMsghdr, rtm_index) == 4);
  assert!(offset_of!(RtMsghdr, rtm_flags) == 8);
  assert!(offset_of!(RtMsghdr, rtm_addrs) == 12);
  assert!(offset_of!(RtMsghdr, rtm_inits) == 32);
  assert!(offset_of!(RtMsghdr, rtm_rmx) == 40);
  assert!(offset_of!(RtMetricsU64, rmx_recvpipe) == 24);
  assert!(offset_of!(RtMetricsU64, rmx_expire) == 64);
  assert!(offset_of!(RtMetricsU64, rmx_pksent) == 72);
};

// ---- OpenBSD ----------------------------------------------------------
//
// OpenBSD has a substantially different layout (it added `rtm_hdrlen`
// and reordered fields). The fields we actually read (`rtm_flags`,
// `rtm_addrs`, `rtm_index`) still exist but at different offsets.

#[cfg(target_os = "openbsd")]
#[repr(C)]
pub(super) struct RtMsghdr {
  pub rtm_msglen: u16,
  pub rtm_version: u8,
  pub rtm_type: u8,
  pub rtm_hdrlen: u16,
  pub rtm_index: u16,
  pub rtm_tableid: u16,
  pub rtm_priority: u8,
  pub rtm_mpls: u8,
  pub rtm_addrs: libc::c_int,
  pub rtm_flags: libc::c_int,
  pub rtm_fmask: libc::c_int,
  pub rtm_pid: libc::pid_t,
  pub rtm_seq: libc::c_int,
  pub rtm_errno: libc::c_int,
  pub rtm_inits: libc::c_uint,
  pub rtm_rmx: RtMetricsOpenBsd,
}

// OpenBSD `<net/route.h>`:
//
//     struct rt_metrics {
//         u_int64_t rmx_pksent;
//         u_int64_t rmx_expire;
//         u_int     rmx_locks;
//         u_int     rmx_mtu;
//         u_int     rmx_refcnt;
//         u_int     rmx_hopcount;
//         u_int     rmx_recvpipe;
//         u_int     rmx_sendpipe;
//         u_int     rmx_ssthresh;
//         u_int     rmx_rtt;
//         u_int     rmx_rttvar;
//         u_int     rmx_pad;
//     };
//
// 2 × u64 + 10 × u_int = 16 + 40 = 56 bytes. Previous revision had
// the u64 fields and u_int fields in the wrong order (e.g. claimed
// `rmx_locks` was u64; it's actually u_int); the kernel's
// `rmx_recvpipe` ended up at offset 88 in the Rust struct vs 32 in
// the kernel struct, so `best_local_addrs_in` read garbage as the
// metric.
#[cfg(target_os = "openbsd")]
#[repr(C)]
pub(super) struct RtMetricsOpenBsd {
  pub rmx_pksent: u64,
  pub rmx_expire: u64,
  pub rmx_locks: libc::c_uint,
  pub rmx_mtu: libc::c_uint,
  pub rmx_refcnt: libc::c_uint,
  pub rmx_hopcount: libc::c_uint,
  pub rmx_recvpipe: libc::c_uint,
  pub rmx_sendpipe: libc::c_uint,
  pub rmx_ssthresh: libc::c_uint,
  pub rmx_rtt: libc::c_uint,
  pub rmx_rttvar: libc::c_uint,
  pub rmx_pad: libc::c_uint,
}

#[cfg(target_os = "openbsd")]
const _: () = assert!(core::mem::size_of::<RtMetricsOpenBsd>() == 56);
// OpenBSD rt_msghdr fields up to `rtm_inits` total 40 bytes (no
// alignment padding required because the trailing u32 keeps the
// struct 8-aligned, and rt_metrics starts u64-aligned).
#[cfg(target_os = "openbsd")]
const _: () = assert!(core::mem::size_of::<RtMsghdr>() == 96);
#[cfg(target_os = "openbsd")]
const _: () = {
  use core::mem::offset_of;
  assert!(offset_of!(RtMsghdr, rtm_msglen) == 0);
  assert!(offset_of!(RtMsghdr, rtm_index) == 6);
  assert!(offset_of!(RtMsghdr, rtm_addrs) == 12);
  assert!(offset_of!(RtMsghdr, rtm_flags) == 16);
  assert!(offset_of!(RtMsghdr, rtm_rmx) == 40);
  assert!(offset_of!(RtMetricsOpenBsd, rmx_recvpipe) == 32);
};

// =====================================================================
// ifma_msghdr (multicast group membership)
// =====================================================================
//
// Apple / FreeBSD: `libc` exports the struct + `NET_RT_IFMALIST`
// directly.
//
// DragonFly: the kernel does not expose multicast group enumeration
// via sysctl at all — `<sys/socket.h>` only defines four selectors
// (`NET_RT_DUMP`, `NET_RT_FLAGS`, `NET_RT_IFLIST`, `NET_RT_MAXID`),
// no `NET_RT_IFMALIST`. The DragonFly impl of
// `interface_multiaddr_table` therefore returns
// `Err(ErrorKind::Unsupported)` (see `bsd_like.rs`). It does not need
// an `IfmaMsghdr` or a sysctl selector, so we don't define them here.

#[cfg(target_os = "freebsd")]
pub(super) use libc::ifma_msghdr as IfmaMsghdr;

#[cfg(target_os = "freebsd")]
pub(super) use libc::NET_RT_IFMALIST;

// =====================================================================
// ifa_msghdr
// =====================================================================
//
// Apple / FreeBSD: `libc` exports the struct directly.
// DragonFly: the kernel's `struct ifa_msghdr` matches FreeBSD's (the
//   two share most of the route socket ABI since DragonFly forked
//   from FreeBSD 4.x), but the libc crate's DragonFly bindings don't
//   expose the type — define it locally with the FreeBSD layout.
// NetBSD / OpenBSD: absent from libc, define locally further down.

#[cfg(any(apple, target_os = "freebsd"))]
pub(super) use libc::ifa_msghdr as IfaMsghdr;

// DragonFly `<net/if.h>` `struct ifa_msghdr` (matches FreeBSD):
//
//     struct ifa_msghdr {
//         u_short ifam_msglen;
//         u_char  ifam_version;
//         u_char  ifam_type;
//         int     ifam_addrs;
//         int     ifam_flags;
//         u_short ifam_index;
//         int     ifam_metric;
//     };
#[cfg(target_os = "dragonfly")]
#[repr(C)]
pub(super) struct IfaMsghdr {
  pub ifam_msglen: u16,
  pub ifam_version: u8,
  pub ifam_type: u8,
  pub ifam_addrs: libc::c_int,
  pub ifam_flags: libc::c_int,
  pub ifam_index: u16,
  _pad: u16,
  pub ifam_metric: libc::c_int,
}

// NetBSD `<net/if.h>` (modern — NetBSD 8+):
//
//     struct ifa_msghdr {
//         u_short ifam_msglen __align64;
//         u_char  ifam_version;
//         u_char  ifam_type;
//         u_short ifam_index;
//         int     ifam_flags;
//         int     ifam_addrs;
//         pid_t   ifam_pid;
//         int     ifam_addrflags;
//         int     ifam_metric;
//     };
//
// The 2-byte gap after `ifam_index` is implicit C alignment for the
// following `int`.
#[cfg(target_os = "netbsd")]
#[repr(C)]
pub(super) struct IfaMsghdr {
  pub ifam_msglen: u16,
  pub ifam_version: u8,
  pub ifam_type: u8,
  pub ifam_index: u16,
  _pad_to_flags: u16,
  pub ifam_flags: libc::c_int,
  pub ifam_addrs: libc::c_int,
  pub ifam_pid: libc::pid_t,
  pub ifam_addrflags: libc::c_int,
  pub ifam_metric: libc::c_int,
}

// OpenBSD `<net/if.h>`:
//
//     struct ifa_msghdr {
//         u_short ifam_msglen;
//         u_char  ifam_version;
//         u_char  ifam_type;
//         u_short ifam_hdrlen;
//         u_short ifam_index;
//         u_short ifam_tableid;
//         u_char  ifam_pad1;
//         u_char  ifam_pad2;
//         int     ifam_addrs;
//         int     ifam_flags;
//         int     ifam_metric;
//     };
#[cfg(target_os = "openbsd")]
#[repr(C)]
pub(super) struct IfaMsghdr {
  pub ifam_msglen: u16,
  pub ifam_version: u8,
  pub ifam_type: u8,
  pub ifam_hdrlen: u16,
  pub ifam_index: u16,
  pub ifam_tableid: u16,
  pub ifam_pad1: u8,
  pub ifam_pad2: u8,
  pub ifam_addrs: libc::c_int,
  pub ifam_flags: libc::c_int,
  pub ifam_metric: libc::c_int,
}
