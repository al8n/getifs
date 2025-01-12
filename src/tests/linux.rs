use super::TestInterface;

use std::{io, process::Command};

impl TestInterface {
  pub fn set_broadcast(&mut self, suffix: i32) -> io::Result<()> {
    self.name = format!("gotest{}", suffix);

    let ip = which::which("ip").map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))?;

    let mut setup_link_cmd = Command::new(&ip);
    setup_link_cmd.args(["ip", "link", "add", &self.name, "type", "dummy"]);
    self.setup_cmds.push(setup_link_cmd);

    let mut setup_addr_cmd = Command::new(&ip);
    setup_addr_cmd.args([
      "ip",
      "address",
      "add",
      &self.local.to_string(),
      "peer",
      &self.remote.to_string(),
      "dev",
      &self.name,
    ]);
    self.setup_cmds.push(setup_addr_cmd);

    let mut teardown_addr_cmd = Command::new(&ip);
    teardown_addr_cmd.args([
      "ip",
      "address",
      "del",
      &self.local.to_string(),
      "peer",
      &self.remote.to_string(),
      "dev",
      &self.name,
    ]);
    self.teardown_cmds.push(teardown_addr_cmd);

    let mut teardown_link_cmd = Command::new(&ip);
    teardown_link_cmd.args(["ip", "link", "delete", &self.name, "type", "dummy"]);
    self.teardown_cmds.push(teardown_link_cmd);

    Ok(())
  }

  pub fn set_link_local(&mut self, suffix: i32) -> io::Result<()> {
    self.name = format!("gotest{}", suffix);

    let ip = which::which("ip").map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))?;

    let mut setup_link_cmd = Command::new(&ip);
    setup_link_cmd.args(["ip", "link", "add", &self.name, "type", "dummy"]);
    self.setup_cmds.push(setup_link_cmd);

    let mut setup_addr_cmd = Command::new(&ip);
    setup_addr_cmd.args([
      "ip",
      "address",
      "add",
      &self.local.to_string(),
      "dev",
      &self.name,
    ]);
    self.setup_cmds.push(setup_addr_cmd);

    let mut teardown_addr_cmd = Command::new(&ip);
    teardown_addr_cmd.args([
      "ip",
      "address",
      "del",
      &self.local.to_string(),
      "dev",
      &self.name,
    ]);
    self.teardown_cmds.push(teardown_addr_cmd);

    let mut teardown_link_cmd = Command::new(&ip);
    teardown_link_cmd.args(["ip", "link", "delete", &self.name, "type", "dummy"]);
    self.teardown_cmds.push(teardown_link_cmd);

    Ok(())
  }

  pub fn set_point_to_point(&mut self, suffix: i32) -> io::Result<()> {
    self.name = format!("gotest{}", suffix);

    let ip = which::which("ip").map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))?;

    let mut setup_tunnel_cmd = Command::new(&ip);
    setup_tunnel_cmd.args([
      "ip",
      "tunnel",
      "add",
      &self.name,
      "mode",
      "gre",
      "local",
      &self.local.to_string(),
      "remote",
      &self.remote.to_string(),
    ]);
    self.setup_cmds.push(setup_tunnel_cmd);

    let mut setup_addr_cmd = Command::new(&ip);
    setup_addr_cmd.args([
      "ip",
      "address",
      "add",
      &self.local.to_string(),
      "peer",
      &self.remote.to_string(),
      "dev",
      &self.name,
    ]);
    self.setup_cmds.push(setup_addr_cmd);

    let mut teardown_addr_cmd = Command::new(&ip);
    teardown_addr_cmd.args([
      "ip",
      "address",
      "del",
      &self.local.to_string(),
      "peer",
      &self.remote.to_string(),
      "dev",
      &self.name,
    ]);
    self.teardown_cmds.push(teardown_addr_cmd);

    let mut teardown_tunnel_cmd = Command::new(&ip);
    teardown_tunnel_cmd.args([
      "ip",
      "tunnel",
      "del",
      &self.name,
      "mode",
      "gre",
      "local",
      &self.local.to_string(),
      "remote",
      &self.remote.to_string(),
    ]);
    self.teardown_cmds.push(teardown_tunnel_cmd);

    Ok(())
  }
}
