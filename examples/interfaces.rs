use getifs::interfaces;

fn main() {
  let ift = interfaces().unwrap();
  for ifi in ift {
    println!("{ifi:?}");
  }
}
