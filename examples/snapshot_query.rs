use getifs::{
  order, predicate, rfc, AddressComparator, Flags, InterfaceAddress, InterfaceAddressIteratorExt,
  InterfacePredicate, InterfaceSnapshot,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let snapshot = InterfaceSnapshot::capture()?;
  let all_ipv4 = "0.0.0.0/0".parse()?;
  let special_purpose = predicate::name(|name| !name.is_empty())
    .and(predicate::cidr(all_ipv4))
    .and(predicate::rfc(rfc::RFC6890))
    .and(predicate::flags(Flags::UP));

  let comparator = order::larger_network_first()
    .then(|left: InterfaceAddress<'_>, right: InterfaceAddress<'_>| {
      right.index().cmp(&left.index())
    })
    .then(order::by_address());
  let addresses: Vec<_> = snapshot.matching(special_purpose).sorted_with(&comparator);

  if addresses.is_empty() {
    println!("No UP RFC 6890 special-purpose IPv4 addresses were captured.");
  } else {
    println!("UP RFC 6890 special-purpose IPv4 addresses:");
    for address in addresses {
      println!(
        "{} on {} (index {})",
        address.network(),
        address.name(),
        address.index()
      );
    }
  }

  Ok(())
}
