use getifs::{interface_addrs_by_filter, rfc};

fn main() {
  let addrs = interface_addrs_by_filter(|addr| rfc::RFC3330.contains(addr)).unwrap();
  for addr in addrs {
    println!("RFC3330 IP addr: {}", addr);
  }
}
