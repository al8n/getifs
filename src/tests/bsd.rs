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

    let mut setup_cmd = Command::new(&ifconfig);
    setup_cmd.args(["ifconfig", &self.name, "create"]);
    self.setup_cmds.push(setup_cmd);

    let mut teardown_cmd = Command::new(&ifconfig);
    teardown_cmd.args(["ifconfig", &self.name, "destroy"]);
    self.teardown_cmds.push(teardown_cmd);

    Ok(())
  }

  pub fn set_point_to_point(&mut self, suffix: i32) -> io::Result<()> {
    self.name = format!("gif{suffix}");

    let ifconfig =
      which::which("ifconfig").map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))?;

    let mut setup_cmd = Command::new(&ifconfig);
    setup_cmd.args(["ifconfig", &self.name, "create"]);
    self.setup_cmds.push(setup_cmd);

    let mut setup_addr_cmd = Command::new(&ifconfig);
    setup_addr_cmd.args([
      "ifconfig",
      &self.name,
      "inet",
      &self.local.to_string(),
      &self.remote.to_string(),
    ]);
    self.setup_cmds.push(setup_addr_cmd);

    let mut teardown_cmd = Command::new(&ifconfig);
    teardown_cmd.args(["ifconfig", &self.name, "destroy"]);
    self.teardown_cmds.push(teardown_cmd);

    Ok(())
  }

  pub fn set_link_local(&mut self, _suffix: i32) -> io::Result<()> {
    Err(io::Error::new(
      io::ErrorKind::Other,
      "not yet implemented for BSD",
    ))
  }
}
