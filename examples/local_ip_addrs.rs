use getifs::local_addrs;

fn main() {
  let addrs = local_addrs().unwrap();
  for addr in addrs {
    println!("Local IP addr: {addr}");
  }
}
