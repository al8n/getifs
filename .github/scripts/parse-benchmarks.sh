#!/bin/bash
set -e

# Script to parse and format benchmark results
# Usage: ./parse-benchmarks.sh <benchmark-file.txt>

if [ $# -eq 0 ]; then
    echo "Usage: $0 <benchmark-file.txt>"
    exit 1
fi

BENCH_FILE=$1

if [ ! -f "$BENCH_FILE" ]; then
    echo "Error: File $BENCH_FILE not found"
    exit 1
fi

echo "# Benchmark Results"
echo ""
echo "## Summary"
echo ""

# Parse benchmark output and create a markdown table
echo "| Benchmark | Time (ns/iter) | Variance |"
echo "|-----------|----------------|----------|"

grep "^test " "$BENCH_FILE" | while IFS= read -r line; do
    # Extract benchmark name
    name=$(echo "$line" | sed -E 's/test ([^.]+) \.\.\. bench:[[:space:]]+([0-9,]+) ns\/iter \(\+\/- ([0-9,]+)\)/\1/')
    # Extract time
    time=$(echo "$line" | sed -E 's/test ([^.]+) \.\.\. bench:[[:space:]]+([0-9,]+) ns\/iter \(\+\/- ([0-9,]+)\)/\2/')
    # Extract variance
    variance=$(echo "$line" | sed -E 's/test ([^.]+) \.\.\. bench:[[:space:]]+([0-9,]+) ns\/iter \(\+\/- ([0-9,]+)\)/\3/')

    # Clean up the name
    name=$(echo "$name" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    # Format with proper spacing
    if [ -n "$name" ] && [ -n "$time" ]; then
        # Convert to microseconds if time is large
        if [ "${time//,/}" -gt 10000 ]; then
            time_us=$(echo "scale=2; ${time//,/} / 1000" | bc)
            echo "| \`$name\` | $time ns (~${time_us} μs) | ±$variance |"
        else
            echo "| \`$name\` | $time ns | ±$variance |"
        fi
    fi
done

echo ""
echo "## Detailed Output"
echo ""
echo "\`\`\`"
grep "^test " "$BENCH_FILE"
echo "\`\`\`"
