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

// ---- NetBSD -----------------------------------------------------------
//
// NetBSD `<net/route.h>` (modern, NetBSD 9+):
//
//     struct rt_msghdr {
//         u_short rtm_msglen;
//         u_char  rtm_version;
//         u_char  rtm_type;
//         int     rtm_index;
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
// `int64_t`). The previous version of this file declared a 16-element
// u64 array (128 bytes) and put `rmx_expire` at index 3 instead of 8;
// that made `size_of::<RtMsghdr>()` 48 bytes too long, which caused
// `parse_addrs` to start mid-sockaddr and surface as either
// `InvalidData` or silently wrong route data.
//
// `rtm_index` and `rtm_inits` are `int` (not u_short / uint32_t) — a
// 4-byte natural-alignment-padded field plays the same role as the
// previous explicit `_pad_to_flags`, but reading it as `c_int` is
// also correct on big-endian targets where reading a 4-byte field as
// `u16` would pick up the high bytes (zero) and miss the index.

#[cfg(target_os = "netbsd")]
#[repr(C)]
pub(super) struct RtMsghdr {
  pub rtm_msglen: u16,
  pub rtm_version: u8,
  pub rtm_type: u8,
  pub rtm_index: libc::c_int,
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
#[cfg(target_os = "netbsd")]
const _: () = assert!(core::mem::size_of::<RtMetricsU64>() == 80);
#[cfg(target_os = "netbsd")]
const _: () = assert!(core::mem::size_of::<RtMsghdr>() == 120);

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

// =====================================================================
// ifma_msghdr (multicast group membership)
// =====================================================================
//
// Apple / FreeBSD: `libc` exports the struct + `NET_RT_IFMALIST`
// directly. DragonFly was previously rolled in here with a hand-defined
// `IfmaMsghdr` and a hard-coded `NET_RT_IFMALIST = 4` — but DragonFly's
// libc bindings actually define `NET_RT_MAXID = 4` and don't expose
// `NET_RT_IFMALIST`, so the constant we picked was the kernel's
// max-id sentinel rather than a real selector. Multicast support on
// DragonFly is now disabled at the cfg_bsd_multicast / cfg_multicast
// macros until a runtime test on DragonFly proves the correct
// selector and `IfmaMsghdr` layout.

#[cfg(target_os = "freebsd")]
pub(super) use libc::ifma_msghdr as IfmaMsghdr;

#[cfg(target_os = "freebsd")]
pub(super) use libc::NET_RT_IFMALIST;

// =====================================================================
// ifa_msghdr
// =====================================================================
//
// Apple / FreeBSD / DragonFly: `libc` exports the struct directly.
// NetBSD / OpenBSD: absent from libc, define locally.

#[cfg(any(apple, target_os = "freebsd", target_os = "dragonfly"))]
pub(super) use libc::ifa_msghdr as IfaMsghdr;

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
