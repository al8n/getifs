# Benchmark Quick Start Guide

Quick reference for running and viewing benchmarks.

## Running Benchmarks

### Automated (CI)

Benchmarks run automatically on:
- ✅ Push to `main` (when benchmark code changes)
- ✅ Pull requests (results posted as comment)
- ✅ Monthly schedule (1st of each month)
- ✅ Manual trigger (GitHub Actions UI)

**View Results**: [GitHub Actions → Benchmarks](https://github.com/al8n/getifs/actions/workflows/benchmark.yml)

### Local

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench --bench interfaces

# Run all benchmarks and generate summary (like CI)
./.github/scripts/run-benchmarks-local.sh

# View detailed HTML reports
open target/criterion/report/index.html
```

## CI Platforms

| Platform | OS | Architecture |
|----------|----|--------------
| Linux | ubuntu-latest | x86_64 |
| macOS | macos-latest | x86_64/ARM64 |
| Windows | windows-latest | x86_64 |

## Benchmark Suites

### 1. Interfaces (`interfaces.rs`)
- List all network interfaces
- Get interface by index/name
- Get interface addresses and multicast addresses
- Compare with `network-interface` crate

### 2. Local IP (`local_ip_address.rs`)
- Get local IPv4/IPv6 addresses
- Compare with `local-ip-address` crate

### 3. Gateway (`gateway.rs`)
- Get IPv4/IPv6 gateway addresses
- Get all gateway addresses

## Accessing CI Results

### Download Artifacts

**Via Web UI:**
1. Go to [Actions → Benchmarks](https://github.com/al8n/getifs/actions/workflows/benchmark.yml)
2. Click on a workflow run
3. Scroll to "Artifacts" section
4. Download desired artifacts

**Via CLI:**
```bash
# Install GitHub CLI
brew install gh  # macOS
# or: https://cli.github.com/

# Download latest benchmark results
gh run list --workflow=benchmark.yml --limit 1
gh run download <run-id>
```

### Artifact Contents

```
benchmark-results-{os}/
├── benchmark-interfaces-{os}.txt     # Raw output
├── benchmark-local-ip-{os}.txt       # Raw output
├── benchmark-gateway-{os}.txt        # Raw output
└── benchmark-summary-{os}.md         # Formatted summary

benchmark-results-combined/
└── BENCHMARK_SUMMARY.md              # All platforms combined

criterion-detailed-{os}/              # Detailed Criterion results
└── report/
    └── index.html                     # Charts and statistics
```

## Understanding Results

```
test getifs::interfaces ... bench:   17,908 ns/iter (+/- 404)
                                      ^^^^^^                ^^^
                                      Time per iteration    Std deviation
```

**Performance Scale:**
- 🟢 **< 1 μs (1,000 ns)** - Excellent
- 🟡 **1-10 μs** - Good
- 🟠 **10-100 μs** - Moderate
- 🔴 **> 100 μs** - Needs optimization

**Current Performance (macOS M1 Max):**
- List interfaces: ~18 μs (🟡)
- Get by index: ~2.7 μs (🟡)
- Local IPv4: ~14 μs (🟡)
- Gateway IPv4: ~12.6 μs (🟡)

## Manually Trigger CI Benchmark

1. Go to [Actions → Benchmarks](https://github.com/al8n/getifs/actions/workflows/benchmark.yml)
2. Click "Run workflow" button (top right)
3. Select branch
4. Click "Run workflow"
5. Wait ~10-15 minutes for completion
6. Download artifacts

## Comparing Performance

### Compare two branches
```bash
# Benchmark main branch
git checkout main
cargo bench -- --save-baseline main

# Benchmark your feature branch
git checkout feature-branch
cargo bench -- --baseline main
```

### Compare with previous run
```bash
# First run (creates baseline)
cargo bench -- --save-baseline previous

# Make changes...

# Compare against baseline
cargo bench -- --baseline previous
```

## Troubleshooting

**Gateway benchmarks fail?**
- Normal in restricted CI environments
- Try locally with: `cargo bench --bench gateway`

**Out of memory?**
- Close other applications
- Reduce Criterion sample size in benchmark code

**Benchmark times vary significantly?**
- Close background applications
- Ensure laptop is plugged in (prevents CPU throttling)
- Run multiple times: `cargo bench -- --sample-size 100`

## Next Steps

📖 **Full Documentation**: [.github/BENCHMARKS.md](.github/BENCHMARKS.md)

🔧 **Modify Benchmarks**: Edit files in `benches/`

📊 **View Trends**: Download monthly scheduled benchmark results

🎯 **Set Performance Budget**: Add performance gates in CI

## Quick Commands

```bash
# Run and save as baseline
cargo bench -- --save-baseline main

# Compare against baseline
cargo bench -- --baseline main

# Run only fast benchmarks
cargo bench --bench interfaces

# Run with verbose output
cargo bench -- --verbose

# Run specific test
cargo bench --bench interfaces getifs::interfaces

# Generate report without running
cargo criterion --message-format=json

# Run local CI script
./.github/scripts/run-benchmarks-local.sh
```

## CI Workflow File

Location: `.github/workflows/benchmark.yml`

Edit this file to:
- Change benchmark frequency
- Add new benchmark suites
- Modify artifact retention
- Add performance gates

## Related Files

- `.github/workflows/benchmark.yml` - CI workflow definition
- `.github/BENCHMARKS.md` - Full documentation
- `.github/scripts/parse-benchmarks.sh` - Parse raw results
- `.github/scripts/run-benchmarks-local.sh` - Run locally like CI
- `benches/` - Benchmark source code
