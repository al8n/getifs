use getifs::interface_multicast_addrs;

fn main() {
  let ift = interface_multicast_addrs().unwrap();
  for ifa in ift {
    println!("{}", ifa);
  }
}
