#!/usr/bin/env bash

set -euo pipefail

# AddressSanitizer enables LeakSanitizer on Linux. Keep leak detection enabled
# explicitly so the job's label and behavior stay aligned.
export ASAN_OPTIONS="${ASAN_OPTIONS:+${ASAN_OPTIONS}:}detect_leaks=1"
export RUSTFLAGS="${RUSTFLAGS:+${RUSTFLAGS} }-Zsanitizer=address"

printf '%s\n' 'Running Linux AddressSanitizer with LeakSanitizer enabled.'
cargo +nightly test -Zbuild-std --target x86_64-unknown-linux-gnu --lib --tests --all-features
