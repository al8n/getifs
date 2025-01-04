use criterion::*;
use getifs::SmolStr;
use network_interface::NetworkInterfaceConfig;

fn loopback_interface() -> Option<getifs::Interface> {
  let ift = getifs::interfaces().unwrap();
  ift
    .iter()
    .find(|ifi| {
      ifi
        .flags()
        .contains(getifs::Flags::LOOPBACK & getifs::Flags::UP)
    })
    .cloned()
}

fn bench_getifs_interfaces(c: &mut Criterion) {
  c.bench_function("getifs::interfaces", |b| {
    b.iter(|| {
      getifs::interfaces().unwrap();
    })
  });
}

fn bench_getifs_interface_by_index(c: &mut Criterion) {
  let idx = loopback_interface().map_or(0, |ifi| ifi.index());
  c.bench_with_input(
    BenchmarkId::new("getifs::interface_by_index", idx),
    &idx,
    |b, idx| {
      b.iter(|| {
        getifs::interface_by_index(*idx).unwrap();
      })
    },
  );
}

fn bench_getifs_interface_by_name(c: &mut Criterion) {
  let name = loopback_interface().map_or(SmolStr::default(), |ifi| ifi.name().clone());
  c.bench_with_input(
    BenchmarkId::new("getifs::interface_by_name", name.clone()),
    &name,
    |b, name| {
      b.iter(|| {
        getifs::interface_by_name(name).unwrap();
      })
    },
  );
}

fn bench_getifs_interface_addrs(c: &mut Criterion) {
  c.bench_function("getifs::interface_addrs", |b| {
    b.iter(|| {
      getifs::interface_addrs().unwrap();
    })
  });
}

fn bench_getifs_interfaces_and_multicast_addrs(c: &mut Criterion) {
  let ifi = loopback_interface().unwrap();
  c.bench_with_input(
    BenchmarkId::new("getifs::interfaces_and_multicast_addrs", ifi.name().clone()),
    &ifi,
    |b, ifi| {
      b.iter(|| {
        ifi.multicast_addresses().unwrap();
      })
    },
  );
}

fn bench_network_interface_interfaces(c: &mut Criterion) {
  c.bench_function("network_interface::interfaces", |b| {
    b.iter(|| {
      network_interface::NetworkInterface::show().unwrap();
    })
  });
}

fn bench_network_interface_interface_by_index(c: &mut Criterion) {
  let idx = loopback_interface().map_or(0, |ifi| ifi.index());
  c.bench_with_input(
    BenchmarkId::new("network_interface::interface_by_index", idx),
    &idx,
    |b, idx| {
      b.iter(|| {
        network_interface::NetworkInterface::show()
          .unwrap()
          .into_iter()
          .find(|ifi| ifi.index == *idx);
      })
    },
  );
}

fn bench_network_interface_interface_by_name(c: &mut Criterion) {
  let name = loopback_interface().map_or(SmolStr::default(), |ifi| ifi.name().clone());
  c.bench_with_input(
    BenchmarkId::new("network_interface::interface_by_name", name.clone()),
    &name,
    |b, name| {
      b.iter(|| {
        network_interface::NetworkInterface::show()
          .unwrap()
          .into_iter()
          .find(|ifi| ifi.name == *name);
      })
    },
  );
}

criterion_group!(
  benches,
  bench_getifs_interfaces,
  bench_getifs_interface_by_index,
  bench_getifs_interface_by_name,
  bench_getifs_interface_addrs,
  bench_getifs_interfaces_and_multicast_addrs,
  bench_network_interface_interfaces,
  bench_network_interface_interface_by_index,
  bench_network_interface_interface_by_name,
);

criterion_main!(benches);
