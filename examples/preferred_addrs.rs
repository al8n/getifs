use std::fmt::Display;

use getifs::{
  order, preferred_private_addr, preferred_public_addr, preferred_public_addr_by,
  preferred_public_ipv4_addr, preferred_public_ipv6_addr, AddressComparator,
};

fn show<T: Display>(label: &str, value: Option<T>) {
  match value {
    Some(value) => println!("{label}: {value}"),
    None => println!("{label}: none captured (normal on this topology)"),
  }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  println!(
    "Public means a local classified interface address, not an external NAT public-IP probe."
  );
  println!("Private means a forwardable RFC 6890 classification, not only RFC1918.");

  show("Preferred public address", preferred_public_addr()?);
  show("Preferred private address", preferred_private_addr()?);
  show(
    "Preferred public IPv4 address",
    preferred_public_ipv4_addr()?,
  );
  show(
    "Preferred public IPv6 address",
    preferred_public_ipv6_addr()?,
  );

  let custom_order = order::ipv4_first()
    .then(order::larger_network_first())
    .then(order::by_interface_index().reverse());
  // `_by` changes ranking only; UP, forwardability, and classification stay fixed.
  show(
    "Preferred public address with custom order",
    preferred_public_addr_by(custom_order)?,
  );

  Ok(())
}
