use std::{io, process::Command};

use super::TestInterface;

impl TestInterface {
  pub fn set_broadcast(&mut self, vid: usize) -> std::io::Result<()> {
    #[cfg(target_os = "openbsd")]
    {
      self.name = format!("vether{}", vid);
    }

    #[cfg(not(target_os = "openbsd"))]
    {
      self.name = format!("vlan{vid}");
    }

    let ifconfig =
      which::which("ifconfig").map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))?;

    // `Command::new` already specifies the program; the previous code
    // also pushed "ifconfig" as argv[1] (a port-from-Go thinko, since
    // Go's `Cmd.Args` includes argv[0] but Rust's `args()` does not),
    // so the resulting invocation was `ifconfig ifconfig <name> create`
    // and ifconfig parsed "ifconfig" as the interface name.
    let mut setup_cmd = Command::new(&ifconfig);
    setup_cmd.arg(&self.name).arg("create");
    self.setup_cmds.push(setup_cmd);

    let mut teardown_cmd = Command::new(&ifconfig);
    teardown_cmd.arg(&self.name).arg("destroy");
    self.teardown_cmds.push(teardown_cmd);

    Ok(())
  }

  pub fn set_point_to_point(&mut self, suffix: i32) -> io::Result<()> {
    self.name = format!("gif{suffix}");

    let ifconfig =
      which::which("ifconfig").map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))?;

    let mut setup_cmd = Command::new(&ifconfig);
    setup_cmd.arg(&self.name).arg("create");
    self.setup_cmds.push(setup_cmd);

    let mut setup_addr_cmd = Command::new(&ifconfig);
    setup_addr_cmd
      .arg(&self.name)
      .arg("inet")
      .arg(self.local.to_string())
      .arg(self.remote.to_string());
    self.setup_cmds.push(setup_addr_cmd);

    let mut teardown_cmd = Command::new(&ifconfig);
    teardown_cmd.arg(&self.name).arg("destroy");
    self.teardown_cmds.push(teardown_cmd);

    Ok(())
  }

  pub fn set_link_local(&mut self, _suffix: i32) -> io::Result<()> {
    Err(io::Error::other("not yet implemented for BSD"))
  }
}
