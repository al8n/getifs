use getifs::interfaces;

pub fn interface_disappeared(index: u32, name: &str) -> bool {
  !interfaces()
    .expect("refresh interface snapshot after lookup race")
    .iter()
    .any(|interface| interface.index() == index && interface.name().as_str() == name)
}
