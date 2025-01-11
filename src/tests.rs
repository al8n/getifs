#![allow(dead_code)]

use std::{net::IpAddr, process::Command, thread, time::Duration};

use crate::interfaces;

#[cfg(any(
  target_os = "macos",
  target_os = "tvos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "visionos",
  target_os = "dragonfly",
  target_os = "freebsd",
  target_os = "netbsd",
  target_os = "openbsd",
))]
mod bsd;

#[cfg(target_os = "linux")]
mod linux;

struct TestInterface {
  name: String,
  local: IpAddr,
  remote: IpAddr,
  setup_cmds: Vec<Command>,
  teardown_cmds: Vec<Command>,
}

impl TestInterface {
  fn new(local: IpAddr, remote: IpAddr) -> Self {
    Self {
      name: String::new(),
      local,
      remote,
      setup_cmds: Vec::new(),
      teardown_cmds: Vec::new(),
    }
  }

  fn setup(&mut self) -> std::io::Result<()> {
    for cmd in &mut self.setup_cmds {
      let status = cmd.status()?;
      if !status.success() {
        return Err(std::io::Error::new(
          std::io::ErrorKind::Other,
          format!("command failed: {:?}", cmd),
        ));
      }
      match cmd.output() {
        Ok(output) => {
          if !output.status.success() {
            return Err(std::io::Error::new(
              std::io::ErrorKind::Other,
              format!("command failed: {:?}", cmd),
            ));
          }
        }
        Err(e) => {
          return Err(std::io::Error::new(
            e.kind(),
            format!("args={:?} err={e}", cmd.get_args()),
          ));
        }
      }
    }

    Ok(())
  }

  fn teardown(&mut self) -> std::io::Result<()> {
    for cmd in &mut self.teardown_cmds {
      let status = cmd.status()?;
      if !status.success() {
        return Err(std::io::Error::new(
          std::io::ErrorKind::Other,
          format!("command failed: {:?}", cmd),
        ));
      }
      match cmd.output() {
        Ok(output) => {
          if !output.status.success() {
            return Err(std::io::Error::new(
              std::io::ErrorKind::Other,
              format!("command failed: {:?}", cmd),
            ));
          }
        }
        Err(e) => {
          return Err(std::io::Error::new(
            e.kind(),
            format!("args={:?} err={e}", cmd.get_args()),
          ));
        }
      }
    }

    Ok(())
  }
}

#[test]
#[cfg(not(any(
  target_os = "macos",
  target_os = "tvos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "visionos",
)))]
fn point_to_point_interface() {
  let uid = unsafe { libc::getuid() };
  if uid != 0 {
    return;
  }

  // Using IPv4 link-local addresses
  let local: IpAddr = "169.254.0.1".parse().unwrap();
  let remote: IpAddr = "169.254.0.254".parse().unwrap();

  for i in 0..3 {
    let mut ti = TestInterface::new(local, remote);

    if let Err(e) = ti.set_point_to_point(5963 + i) {
      panic!("test requires external command: {}", e);
    }

    match ti.setup() {
      Ok(_) => {
        std::thread::sleep(Duration::from_millis(3));
      }
      Err(e) => {
        let err_msg = e.to_string();
        if err_msg.contains("No such device") && err_msg.contains("gre0") {
          println!("skipping test; no gre0 device. likely running in container?");
          return; // Skip test; no gre0 device
        }
        panic!("{}", e);
      }
    }

    match interfaces() {
      Ok(interfaces) => {
        for ifi in interfaces {
          if ti.name != ifi.name {
            continue;
          }
          let ifat = ifi.addrs();
          for ifa in ifat {
            if ifa.addr() == remote {
              ti.teardown().unwrap();
              panic!("got {ifa:?}");
            }
          }
        }
      }
      Err(e) => {
        ti.teardown().unwrap();
        panic!("{}", e);
      }
    }

    ti.teardown().unwrap();
    std::thread::sleep(Duration::from_millis(3));
  }
}

#[test]
fn test_interface_arrival_and_departure() {
  if std::env::var("RUST_TEST_SHORT").is_ok() {
    return;
  }

  let uid = unsafe { libc::getuid() };
  if uid != 0 {
    return;
  }

  let local: IpAddr = "169.254.0.1".parse().unwrap();
  let remote: IpAddr = "169.254.0.254".parse().unwrap();
  let ip = remote;

  for vid in [1002, 1003, 1004, 1005].iter() {
    let ift1 = interfaces().unwrap();

    let mut ti = TestInterface::new(local, remote);

    if let Err(e) = ti.set_broadcast(*vid) {
      println!("test requires external command: {}", e);
      return;
    }

    ti.setup().unwrap();
    thread::sleep(Duration::from_millis(3));

    let ift2 = match interfaces() {
      Ok(interfaces) => interfaces,
      Err(e) => {
        ti.teardown().unwrap();
        panic!("{}", e);
      }
    };

    if ift2.len() <= ift1.len() {
      for ifi in &ift1 {
        println!("before: {:?}", ifi);
      }
      for ifi in &ift2 {
        println!("after: {:?}", ifi);
      }
      ti.teardown().unwrap();
      panic!("got {}; want gt {}", ift2.len(), ift1.len());
    }

    for ifi in ift2.iter() {
      if ti.name != ifi.name {
        continue;
      }

      let addrs = ifi.addrs();
      for addr in addrs {
        if let IpAddr::V4(addr_ip) = addr.addr() {
          if ip == IpAddr::V4(addr_ip) {
            ti.teardown().unwrap();
            panic!("got {:?}", addr);
          }
        }
      }
    }

    ti.teardown().unwrap();
    thread::sleep(Duration::from_millis(3));

    let ift3 = interfaces().unwrap();
    if ift3.len() >= ift2.len() {
      for ifi in &ift2 {
        println!("before: {:?}", ifi);
      }
      for ifi in &ift3 {
        println!("after: {:?}", ifi);
      }
      panic!("got {}; want lt {}", ift3.len(), ift2.len());
    }
  }
}
