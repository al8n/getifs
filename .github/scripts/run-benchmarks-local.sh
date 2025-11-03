#!/bin/bash
# Script to run all benchmarks locally and generate reports
# This mimics what the CI does

set -e

echo "======================================"
echo "Running Benchmarks Locally"
echo "======================================"
echo ""

# Create results directory
mkdir -p benchmark-results
cd benchmark-results

echo "1. Running interfaces benchmark..."
cargo bench --bench interfaces -- --output-format bencher 2>&1 | tee benchmark-interfaces.txt

echo ""
echo "2. Running local_ip_address benchmark..."
cargo bench --bench local_ip_address -- --output-format bencher 2>&1 | tee benchmark-local-ip.txt

echo ""
echo "3. Running gateway benchmark..."
cargo bench --bench gateway -- --output-format bencher 2>&1 | tee benchmark-gateway.txt || echo "Gateway benchmark failed (this is ok)"

echo ""
echo "======================================"
echo "Generating Summary..."
echo "======================================"

# Get OS information
OS=$(uname -s)
ARCH=$(uname -m)
DATE=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

# Create summary
cat > benchmark-summary.md <<EOF
## Benchmark Results

### System Information
- OS: $OS
- Architecture: $ARCH
- Date: $DATE

### Interface Operations

\`\`\`
$(grep "^test " benchmark-interfaces.txt 2>/dev/null || echo "No results")
\`\`\`

### Local IP Operations

\`\`\`
$(grep "^test " benchmark-local-ip.txt 2>/dev/null || echo "No results")
\`\`\`

### Gateway Operations

\`\`\`
$(grep "^test " benchmark-gateway.txt 2>/dev/null || echo "No results")
\`\`\`

---

For detailed results with charts and statistics, see:
- target/criterion/report/index.html

EOF

cat benchmark-summary.md

echo ""
echo "======================================"
echo "Results saved to: benchmark-results/"
echo "======================================"
echo ""
echo "Files created:"
ls -lh benchmark-*.txt benchmark-summary.md 2>/dev/null || true
echo ""
echo "View detailed Criterion reports:"
echo "  open ../target/criterion/report/index.html"
echo ""
