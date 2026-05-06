use criterion::*;

fn bench_getifs_route_ipv4_table(c: &mut Criterion) {
  if getifs::route_ipv4_table().is_ok() {
    c.bench_function("getifs::route_ipv4_table", |b| {
      b.iter(|| {
        let _ = getifs::route_ipv4_table();
      })
    });
  } else {
    println!("Skipping getifs::route_ipv4_table - not available on this system");
  }
}

fn bench_getifs_route_ipv6_table(c: &mut Criterion) {
  if getifs::route_ipv6_table().is_ok() {
    c.bench_function("getifs::route_ipv6_table", |b| {
      b.iter(|| {
        let _ = getifs::route_ipv6_table();
      })
    });
  } else {
    println!("Skipping getifs::route_ipv6_table - not available on this system");
  }
}

fn bench_getifs_route_table(c: &mut Criterion) {
  if getifs::route_table().is_ok() {
    c.bench_function("getifs::route_table", |b| {
      b.iter(|| {
        let _ = getifs::route_table();
      })
    });
  } else {
    println!("Skipping getifs::route_table - not available on this system");
  }
}

fn bench_getifs_route_table_default_only(c: &mut Criterion) {
  // Filter to default routes only — the most common real-world use of
  // `route_table_by_filter` (and the cheapest, since it lets the closure
  // reject most rows). Measures the per-row filter overhead in addition
  // to the dump.
  if getifs::route_table_by_filter(|r| r.is_default()).is_ok() {
    c.bench_function("getifs::route_table_by_filter/default_only", |b| {
      b.iter(|| {
        let _ = getifs::route_table_by_filter(|r| r.is_default());
      })
    });
  } else {
    println!("Skipping getifs::route_table_by_filter - not available on this system");
  }
}

criterion_group!(
  benches,
  bench_getifs_route_ipv4_table,
  bench_getifs_route_ipv6_table,
  bench_getifs_route_table,
  bench_getifs_route_table_default_only,
);

criterion_main!(benches);
