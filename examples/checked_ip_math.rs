//! All addresses below are synthetic documentation or boundary values.

use std::net::Ipv4Addr;

use getifs::{
  ipnet::{Ipv4Net, Ipv6Net},
  CheckedIpAddrExt, CheckedIpNetExt, UsableIpNetExt,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let point_to_point: Ipv4Net = "192.0.2.0/31".parse()?;
  println!(
    "IPv4 /31 usable range: {} through {}",
    point_to_point.first_usable(),
    point_to_point.last_usable()
  );
  match point_to_point.nth_usable(1) {
    Some(address) => println!("IPv4 /31 usable host #1: {address}"),
    None => println!("IPv4 /31 usable host #1 is absent."),
  }

  let single_v6: Ipv6Net = "2001:db8::1/128".parse()?;
  println!("IPv6 /128 usable host: {}", single_v6.first_usable());

  match Ipv4Addr::BROADCAST.checked_add(1) {
    Some(address) => println!("Unexpected IPv4 overflow result: {address}"),
    None => println!("IPv4 address overflow returns None."),
  }

  let network: Ipv4Net = "192.0.2.250/24".parse()?;
  match network.checked_add_address(10) {
    Some(next) => println!("Address offset crosses the subnet: {next}"),
    None => println!("Address offset overflowed."),
  }
  match network.checked_add_subnets(1) {
    Some(next) => println!("Whole-subnet offset preserves host bits: {next}"),
    None => println!("Whole-subnet offset overflowed."),
  }

  let all_ipv4: Ipv4Net = "0.0.0.0/0".parse()?;
  match all_ipv4.checked_add_subnets(1) {
    Some(next) => println!("Unexpected adjacent /0 subnet: {next}"),
    None => println!("A nonzero whole-subnet offset from /0 returns None."),
  }

  Ok(())
}
