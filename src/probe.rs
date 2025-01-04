use std::sync::OnceLock;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock as ws;

static INIT: OnceLock<Capabilities> = OnceLock::new();

/// Returns `true` if the system supports IPv4 communication.
pub fn ipv4_enabled() -> bool {
  probe().ipv4
}

/// Returns `true` if the system supports IPv6 communication.
pub fn ipv6_enabled() -> bool {
  probe().ipv6
}

/// Returns `true` if the system understands
/// IPv4-mapped IPv6.
pub fn ipv4_mapped_ipv6() -> bool {
  probe().ipv4_mapped_ipv6
}

/// Represents the IP stack communication capabilities of the system.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Capabilities {
  ipv4: bool,
  ipv6: bool,
  ipv4_mapped_ipv6: bool,
}

impl Capabilities {
  /// Returns `true` if the system supports IPv4 communication.
  #[inline]
  pub const fn ipv4(&self) -> bool {
    self.ipv4
  }

  /// Returns `true` if the system supports IPv6 communication.
  #[inline]
  pub const fn ipv6(&self) -> bool {
    self.ipv6
  }

  /// Returns `true` if the system understands
  /// IPv4-mapped IPv6.
  #[inline]
  pub const fn ipv4_mapped_ipv6(&self) -> bool {
    self.ipv4_mapped_ipv6
  }
}

/// Probes IPv4, IPv6 and IPv4-mapped IPv6 communication
/// capabilities which are controlled by the `IPV6_V6ONLY` socket option
/// and kernel configuration.
///
/// Should we try to use the IPv4 socket interface if we're only
/// dealing with IPv4 sockets? As long as the host system understands
/// IPv4-mapped IPv6, it's okay to pass IPv4-mapped IPv6 addresses to
/// the IPv6 interface. That simplifies our code and is most
/// general. Unfortunately, we need to run on kernels built without
/// IPv6 support too. So probe the kernel to figure it out.
pub fn probe() -> Capabilities {
  *INIT.get_or_init(probe_in)
}

#[cfg(unix)]
fn probe_in() -> Capabilities {
  let mut caps = Capabilities {
    ipv4: false,
    ipv6: false,
    ipv4_mapped_ipv6: false,
  };

  // Check IPv4 support
  let ipv4_sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_TCP) };
  if ipv4_sock != -1 {
    caps.ipv4 = true;
    unsafe {
      libc::close(ipv4_sock);
    }
  }

  // Probe IPv6 and IPv4-mapped IPv6
  let probes = [
    (true, 1),  // IPv6
    (false, 0), // IPv4-mapped
  ];

  for (is_ipv6, v6_only) in probes {
    let sock = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, libc::IPPROTO_TCP) };
    if sock != -1 {
      // Set IPV6_V6ONLY option
      unsafe {
        libc::setsockopt(
          sock,
          libc::IPPROTO_IPV6,
          libc::IPV6_V6ONLY,
          &v6_only as *const _ as *const libc::c_void,
          std::mem::size_of_val(&v6_only) as libc::socklen_t,
        );
      }

      // Create bind address
      let addr = if is_ipv6 {
        let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        #[cfg(target_os = "linux")]
        {
          addr.sin6_family = libc::AF_INET6 as u16;
        }

        #[cfg(not(target_os = "linux"))]
        {
          addr.sin6_family = libc::AF_INET6 as u8;
        }

        addr.sin6_addr = libc::in6_addr {
          s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };
        addr
      } else {
        let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };

        #[cfg(not(target_os = "linux"))]
        {
          addr.sin6_family = libc::AF_INET6 as u8;
        }

        #[cfg(target_os = "linux")]
        {
          addr.sin6_family = libc::AF_INET6 as u16;
        }

        addr.sin6_addr = libc::in6_addr {
          s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1],
        };
        addr
      };

      // Attempt to bind
      let bind_result = unsafe {
        libc::bind(
          sock,
          &addr as *const _ as *const libc::sockaddr,
          std::mem::size_of_val(&addr) as libc::socklen_t,
        )
      };

      if bind_result == 0 {
        if is_ipv6 {
          caps.ipv6 = true;
        } else {
          caps.ipv4_mapped_ipv6 = true;
        }
      }

      unsafe { libc::close(sock) };
    }
  }

  caps
}

#[cfg(windows)]
fn probe_in() -> Capabilities {
  fn init_windows_sockets() -> io::Result<()> {
    unsafe {
      let mut wsa_data = std::mem::zeroed();
      if ws::WSAStartup(0x202, &mut wsa_data) != 0 {
        return Err(io::Error::last_os_error());
      }
    }
    Ok(())
  }

  fn cleanup_windows_sockets() {
    unsafe {
      ws::WSACleanup();
    }
  }

  let mut caps = Capabilities {
    ipv4: false,
    ipv6: false,
    ipv4_mapped_ipv6: false,
  };

  if init_windows_sockets().is_err() {
    return caps;
  }

  // Check IPv4 support
  let ipv4_sock = unsafe {
    ws::socket(
      ws::AF_INET as i32,
      ws::SOCK_STREAM as i32,
      ws::IPPROTO_TCP as i32,
    )
  };

  if ipv4_sock != ws::INVALID_SOCKET {
    caps.ipv4 = true;
    unsafe { ws::closesocket(ipv4_sock) };
  }

  // Probe IPv6 and IPv4-mapped IPv6
  let probes = vec![
    (true, 1),  // IPv6
    (false, 0), // IPv4-mapped
  ];

  for (is_ipv6, v6_only) in probes {
    let sock = unsafe {
      ws::socket(
        ws::AF_INET6 as i32,
        ws::SOCK_STREAM as i32,
        ws::IPPROTO_TCP as i32,
      )
    };

    if sock != ws::INVALID_SOCKET {
      // Set IPV6_V6ONLY option
      unsafe {
        ws::setsockopt(
          sock,
          ws::IPPROTO_IPV6 as i32,
          ws::IPV6_V6ONLY as i32,
          &v6_only as *const _ as *const i8,
          std::mem::size_of_val(&v6_only) as i32,
        );
      }

      // Create bind address
      let addr = if is_ipv6 {
        let mut addr: ws::SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
        addr.sin6_family = ws::AF_INET6 as u16;
        addr.sin6_addr.u.Byte = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        addr
      } else {
        let mut addr: ws::SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
        addr.sin6_family = ws::AF_INET6 as u16;
        addr.sin6_addr.u.Byte = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1];
        addr
      };

      // Attempt to bind
      let bind_result = unsafe {
        ws::bind(
          sock,
          &addr as *const _ as *const ws::SOCKADDR,
          std::mem::size_of_val(&addr) as i32,
        )
      };

      if bind_result != ws::SOCKET_ERROR {
        if is_ipv6 {
          caps.ipv6 = true;
        } else {
          caps.ipv4_mapped_ipv6 = true;
        }
      }

      unsafe { ws::closesocket(sock) };
    }
  }

  cleanup_windows_sockets();

  caps
}

#[test]
fn t() {
  let caps = probe();
  println!("IPv4 enabled: {}", caps.ipv4);
  println!("IPv6 enabled: {}", caps.ipv6);
  println!("IPv4-mapped IPv6 enabled: {}", caps.ipv4_mapped_ipv6);
}
