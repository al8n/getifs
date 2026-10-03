#!/usr/bin/env bash

set -euo pipefail

# Resolve like an MSRV-aware consumer: newest versions whose rust-version fits.
export CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback

repo_root=${1:-"$PWD"}
scratch_root=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
worktree=$(mktemp -d "${scratch_root%/}/getifs-msrv.XXXXXX")

cleanup() {
  rm -rf -- "$worktree"
}
trap cleanup EXIT

# A library lockfile is intentionally not tracked. Archive the checked-out
# revision so the MSRV job resolves from scratch and cannot inherit .git,
# target/, or a developer's local Cargo.lock.
git -C "$repo_root" archive --format=tar HEAD | tar -xf - -C "$worktree"

cd "$worktree"
cargo +1.85.0 generate-lockfile
cargo +1.85.0 check --lib --all-features
cargo +1.85.0 test --lib --tests --all-features
cargo +1.85.0 doc --no-deps --all-features
cargo +1.85.0 test --doc --all-features
