use getifs::{interfaces, HardwareAddr};

fn kind(address: &HardwareAddr) -> &'static str {
  match address {
    HardwareAddr::Mac(_) => "EUI-48 MAC",
    HardwareAddr::Eui64(_) => "EUI-64",
    HardwareAddr::InfiniBand(_) => "InfiniBand",
    HardwareAddr::Raw(_) => "raw",
    _ => "future hardware-address type",
  }
}

fn show_synthetic(label: &str, bytes: &[u8]) {
  match HardwareAddr::from_bytes(bytes) {
    Some(address) => println!(
      "{label}: {} bytes ({})",
      address.as_bytes().len(),
      kind(&address)
    ),
    None => println!("{label}: absent"),
  }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let mut saw_hardware = false;
  for interface in interfaces()? {
    match interface.hardware_addr() {
      Some(address) => {
        saw_hardware = true;
        let mac_compatibility = if interface.mac_addr().is_some() {
          "six-byte MAC compatibility accessor is available"
        } else {
          "six-byte MAC compatibility accessor is unavailable"
        };
        println!(
          "{}: {} bytes ({kind}); {mac_compatibility}",
          interface.name(),
          address.as_bytes().len(),
          kind = kind(address),
        );
      }
      None => println!("{}: no hardware address captured", interface.name()),
    }
  }
  if !saw_hardware {
    println!("No interfaces with hardware addresses were captured.");
  }

  show_synthetic("Synthetic EUI-64", &[1, 2, 3, 4, 5, 6, 7, 8]);
  show_synthetic("Synthetic InfiniBand", &[1; 20]);
  show_synthetic("Synthetic raw address", &[1, 2, 3, 4, 5]);
  show_synthetic("Synthetic all-zero address", &[0; 6]);
  Ok(())
}
