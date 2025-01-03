use getifs::interfaces;

#[test]
fn ifis() {
  let ifis = interfaces().unwrap();
  for ifi in ifis {
    println!("{:?}", ifi.multicast_addresses().unwrap());
  }
}
