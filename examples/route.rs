use getifs::route_table;

fn main() {
  let routes = route_table().unwrap();
  for r in routes {
    println!("Route: {r}");
  }
}
