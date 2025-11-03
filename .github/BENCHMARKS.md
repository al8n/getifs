# Benchmark CI Documentation

This document explains how the benchmark CI works and how to use the results.

## Overview

The benchmark CI automatically runs performance benchmarks on three platforms:
- **Linux** (ubuntu-latest)
- **macOS** (macos-latest)
- **Windows** (windows-latest)

## Trigger Conditions

The benchmark workflow runs automatically when:

1. **Push to main** - When code affecting benchmarks is pushed to main
   - Changes to `benches/**`
   - Changes to `src/**`
   - Changes to `Cargo.toml` or `Cargo.lock`
   - Changes to the benchmark workflow itself

2. **Pull Requests** - Same conditions as push to main
   - Results are posted as a PR comment

3. **Manual Trigger** - Via GitHub Actions UI
   - Go to Actions → Benchmarks → Run workflow

4. **Scheduled** - Monthly on the 1st at 00:00 UTC
   - Tracks performance trends over time

## Benchmark Suite

The CI runs three benchmark suites:

### 1. Interface Operations
- `getifs::interfaces` - List all network interfaces
- `getifs::interface_by_index` - Get interface by index
- `getifs::interface_by_name` - Get interface by name
- `getifs::interface_addrs` - Get all interface addresses
- `getifs::interfaces_and_multicast_addrs` - Get multicast addresses
- Comparisons with `network-interface` crate

### 2. Local IP Address Operations
- `getifs::local_ipv4_addrs` - Get local IPv4 addresses
- `getifs::local_ipv6_addrs` - Get local IPv6 addresses
- Comparisons with `local-ip-address` crate

### 3. Gateway Operations
- `getifs::gateway_ipv4_addrs` - Get IPv4 gateways
- `getifs::gateway_ipv6_addrs` - Get IPv6 gateways
- `getifs::gateway_addrs` - Get all gateway addresses

## Accessing Results

### Via GitHub Actions UI

1. Go to the [Actions tab](https://github.com/al8n/getifs/actions)
2. Click on the "Benchmarks" workflow
3. Select a workflow run
4. Download artifacts:
   - `benchmark-results-ubuntu-latest` - Linux results
   - `benchmark-results-macos-latest` - macOS results
   - `benchmark-results-windows-latest` - Windows results
   - `benchmark-results-combined` - All results combined
   - `criterion-detailed-*` - Detailed Criterion.rs results with charts

### Via API

```bash
# Get latest benchmark run
gh run list --workflow=benchmark.yml --limit 1

# Download artifacts
gh run download <run-id>
```

### In Pull Requests

For pull requests, the benchmark results are automatically posted as a comment showing:
- Performance comparison across all three platforms
- Any significant performance changes

## Artifact Contents

Each platform-specific artifact contains:

```
benchmark-results-{os}/
├── benchmark-interfaces-{os}.txt    # Raw interfaces benchmark output
├── benchmark-local-ip-{os}.txt      # Raw local IP benchmark output
├── benchmark-gateway-{os}.txt       # Raw gateway benchmark output
├── benchmark-summary-{os}.md        # Formatted summary
└── criterion-{os}/                  # Criterion detailed results (optional)
```

The combined artifact contains:
```
benchmark-results-combined/
├── BENCHMARK_SUMMARY.md             # Combined summary from all platforms
└── all-results/                     # All platform-specific results
```

## Understanding Results

### Raw Output Format

Criterion outputs results in the following format:
```
test benchmark_name ... bench:   17,908 ns/iter (+/- 404)
```

Where:
- `17,908 ns/iter` - Average time per iteration in nanoseconds
- `(+/- 404)` - Standard deviation

### Performance Guidelines

- **< 1 μs (1,000 ns)** - Excellent, very fast
- **1-10 μs** - Good, acceptable for most use cases
- **10-100 μs** - Moderate, may need optimization for hot paths
- **> 100 μs** - Slow, consider optimization

## Running Benchmarks Locally

### Run all benchmarks
```bash
cargo bench
```

### Run specific benchmark suite
```bash
cargo bench --bench interfaces
cargo bench --bench local_ip_address
cargo bench --bench gateway
```

### Run with specific output format
```bash
cargo bench --bench interfaces -- --output-format bencher
```

### View Criterion HTML reports
```bash
cargo bench
# Open target/criterion/report/index.html in a browser
```

## Comparing Benchmarks

### Compare against baseline
```bash
# Save current results as baseline
cargo bench -- --save-baseline main

# Make changes...

# Compare against baseline
cargo bench -- --baseline main
```

### Compare two commits
```bash
# Benchmark commit A
git checkout commit-a
cargo bench -- --save-baseline commit-a

# Benchmark commit B
git checkout commit-b
cargo bench -- --baseline commit-a
```

## CI Cache

The benchmark CI uses GitHub Actions cache to speed up builds:
- Cargo registry
- Cargo git dependencies
- Build artifacts

Cache key: `${{ runner.os }}-bench-${{ hashFiles('**/Cargo.lock') }}`

## Troubleshooting

### Benchmarks fail on certain platforms

Some benchmarks may fail on certain platforms due to:
- Missing network interfaces (CI runners may have limited network setup)
- Permission issues (gateway discovery may require elevated permissions)
- Platform-specific bugs

The workflow uses `continue-on-error: true` to ensure all benchmarks run even if one fails.

### Gateway benchmarks fail

Gateway detection may fail in CI environments with restricted network access. This is expected and the workflow handles it gracefully.

### Out of memory errors

If benchmarks OOM:
1. Reduce the number of iterations in Criterion configuration
2. Run benchmarks sequentially instead of in parallel
3. Request more memory in CI (requires GitHub plan upgrade)

## Customization

### Change benchmark frequency

Edit `.github/workflows/benchmark.yml`:
```yaml
schedule:
  - cron: '0 0 1 * *'  # Change this cron expression
```

### Add new benchmarks

1. Create benchmark file in `benches/`
2. Add benchmark to `Cargo.toml`:
   ```toml
   [[bench]]
   name = "my_benchmark"
   harness = false
   ```
3. Add to workflow in `.github/workflows/benchmark.yml`:
   ```yaml
   - name: Run benchmarks - my_benchmark
     run: cargo bench --bench my_benchmark -- --output-format bencher | tee benchmark-my-${{ matrix.os }}.txt
   ```

### Modify artifact retention

Edit `.github/workflows/benchmark.yml`:
```yaml
- name: Upload benchmark results
  uses: actions/upload-artifact@v4
  with:
    retention-days: 90  # Change this value (1-90 days)
```

## Best Practices

1. **Review benchmark results** before merging PRs that affect performance
2. **Set performance budgets** for critical operations
3. **Track trends** over time using scheduled runs
4. **Document** any intentional performance trade-offs
5. **Investigate** unexpected performance regressions immediately

## Resources

- [Criterion.rs Documentation](https://bheisler.github.io/criterion.rs/book/)
- [Rust Performance Book](https://nnethercote.github.io/perf-book/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
