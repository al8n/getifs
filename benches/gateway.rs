use criterion::*;

fn bench_getifs_gateway_ipv4(c: &mut Criterion) {
  c.bench_function("getifs::gateway_ipv4_addrs", |b| {
    b.iter(|| {
      getifs::gateway_ipv4_addrs().unwrap();
    })
  });
}

fn bench_getifs_gateway_ipv6(c: &mut Criterion) {
  c.bench_function("getifs::gateway_ipv6_addrs", |b| {
    b.iter(|| {
      getifs::gateway_ipv6_addrs().unwrap();
    })
  });
}

criterion_group!(
  benches,
  bench_getifs_gateway_ipv4,
  bench_getifs_gateway_ipv6,
);

criterion_main!(benches);
