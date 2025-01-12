use getifs::gateway_addrs;

fn main() {
  let gateways = gateway_addrs().unwrap();
  for gw in gateways {
    println!("Gateway: {}", gw);
  }
}
