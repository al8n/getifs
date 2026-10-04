// `getifs::interface_multicast_addrs` exists on every supported platform, but
// Android, DragonFly, NetBSD, and OpenBSD return `ErrorKind::Unsupported`
// because they give getifs no way to enumerate multicast group memberships.

use std::io;

fn main() -> io::Result<()> {
  let addrs = match getifs::interface_multicast_addrs() {
    Ok(addrs) => addrs,
    Err(error) if error.kind() == io::ErrorKind::Unsupported => {
      eprintln!("multicast group enumeration is unsupported here: {error}");
      return Ok(());
    }
    Err(error) => return Err(error),
  };

  for addr in addrs {
    println!("{addr}");
  }
  Ok(())
}
