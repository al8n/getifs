use getifs::interface_addrs;

fn main() {
  let addrs = interface_addrs().unwrap();
  for addr in addrs {
    println!("IP addr: {addr}");
  }
}
