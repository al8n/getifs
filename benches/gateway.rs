use criterion::*;

fn bench_getifs_gateway_ipv4(c: &mut Criterion) {
  // Check if gateway functionality is available before benchmarking
  if getifs::gateway_ipv4_addrs().is_ok() {
    c.bench_function("getifs::gateway_ipv4_addrs", |b| {
      b.iter(|| {
        let _ = getifs::gateway_ipv4_addrs();
      })
    });
  } else {
    println!("Skipping getifs::gateway_ipv4_addrs - not available on this system");
  }
}

fn bench_getifs_gateway_ipv6(c: &mut Criterion) {
  // Check if gateway functionality is available before benchmarking
  if getifs::gateway_ipv6_addrs().is_ok() {
    c.bench_function("getifs::gateway_ipv6_addrs", |b| {
      b.iter(|| {
        let _ = getifs::gateway_ipv6_addrs();
      })
    });
  } else {
    println!("Skipping getifs::gateway_ipv6_addrs - not available on this system");
  }
}

fn bench_getifs_gateway_all(c: &mut Criterion) {
  // Check if gateway functionality is available before benchmarking
  if getifs::gateway_addrs().is_ok() {
    c.bench_function("getifs::gateway_addrs", |b| {
      b.iter(|| {
        let _ = getifs::gateway_addrs();
      })
    });
  } else {
    println!("Skipping getifs::gateway_addrs - not available on this system");
  }
}

criterion_group!(
  benches,
  bench_getifs_gateway_ipv4,
  bench_getifs_gateway_ipv6,
  bench_getifs_gateway_all,
);

criterion_main!(benches);
