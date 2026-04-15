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

// ---- NetBSD -----------------------------------------------------------
//
// NetBSD `<net/route.h>`:
//
//     struct rt_msghdr {
//         u_short  rtm_msglen;
//         u_char   rtm_version;
//         u_char   rtm_type;
//         u_short  rtm_index;
//         int      rtm_flags;
//         int      rtm_addrs;
//         pid_t    rtm_pid;
//         int      rtm_seq;
//         int      rtm_errno;
//         int      rtm_use;
//         uint32_t rtm_inits;
//         struct   rt_metrics rtm_rmx;
//     };
//
// `rt_metrics` on NetBSD is 16 × `uint64_t` = 128 bytes.

#[cfg(target_os = "netbsd")]
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
  pub rtm_use: libc::c_int,
  pub rtm_inits: u32,
  pub rtm_rmx: RtMetricsU64,
}

#[cfg(target_os = "netbsd")]
#[repr(C)]
pub(super) struct RtMetricsU64 {
  pub rmx_locks: u64,
  pub rmx_mtu: u64,
  pub rmx_hopcount: u64,
  pub rmx_expire: u64,
  pub rmx_recvpipe: u64,
  pub rmx_sendpipe: u64,
  pub rmx_ssthresh: u64,
  pub rmx_rtt: u64,
  pub rmx_rttvar: u64,
  pub rmx_pksent: u64,
  _filler: [u64; 6],
}

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

/// `rt_metrics` on OpenBSD is `u_int64_t`-based (10 real fields + pad).
#[cfg(target_os = "openbsd")]
#[repr(C)]
pub(super) struct RtMetricsOpenBsd {
  pub rmx_locks: u64,
  pub rmx_mtu: u64,
  pub rmx_expire: u64,
  pub rmx_refcnt: u64,
  pub rmx_hopcount: u32,
  pub rmx_recvpipe: u32,
  pub rmx_sendpipe: u32,
  pub rmx_ssthresh: u32,
  pub rmx_rtt: u32,
  pub rmx_rttvar: u32,
  pub rmx_pksent: u32,
  _pad: u32,
}

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
