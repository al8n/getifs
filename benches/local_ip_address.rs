use criterion::*;

fn bench_getifs_local_ipv4(c: &mut Criterion) {
  c.bench_function("getifs::local_ipv4_addrs", |b| {
    b.iter(|| {
      getifs::local_ipv4_addrs().unwrap();
    })
  });
}

fn bench_getifs_local_ipv6(c: &mut Criterion) {
  c.bench_function("getifs::local_ipv6_addrs", |b| {
    b.iter(|| {
      getifs::local_ipv6_addrs().unwrap();
    })
  });
}

fn bench_local_ip_address_local_ipv4(c: &mut Criterion) {
  c.bench_function("local_ip_address::local_ip", |b| {
    b.iter(|| {
      local_ip_address::local_ip().unwrap();
    })
  });
}

fn bench_local_ip_address_local_ipv6(c: &mut Criterion) {
  c.bench_function("local_ip_address::local_ipv6", |b| {
    b.iter(|| {
      local_ip_address::local_ipv6().unwrap();
    })
  });
}

criterion_group!(
  getifs_benches,
  bench_getifs_local_ipv4,
  bench_getifs_local_ipv6,
);

criterion_group!(
  comparison_benches,
  bench_local_ip_address_local_ipv4,
  bench_local_ip_address_local_ipv6,
);

criterion_main!(getifs_benches, comparison_benches);
