use getifs::{default_interfaces, Interface};

fn show_family(label: &str, interfaces: &[Interface]) {
  if interfaces.is_empty() {
    println!("No {label} default interfaces were captured.");
    return;
  }

  println!("{label} default interfaces:");
  for interface in interfaces {
    println!("{} (index {})", interface.name(), interface.index());
  }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let defaults = default_interfaces()?;
  if defaults.is_empty() {
    println!("No usable default-route interfaces were captured.");
  }

  show_family("IPv4", defaults.ipv4());
  show_family("IPv6", defaults.ipv6());
  Ok(())
}
