#!/usr/bin/env bash

set -euo pipefail

: "${CARGO_TARGET_DIR:?CARGO_TARGET_DIR must be set}"

package_name=${1:-getifs}
version=$(awk -F ' *= *' '$1 == "version" { gsub(/"/, "", $2); print $2; exit }' Cargo.toml)
if [[ -z "$version" ]]; then
  printf 'Could not determine package version from Cargo.toml\n' >&2
  exit 1
fi

# Cargo.lock remains untracked for this library, but the release candidate is
# always resolved once and then all package/publish operations are locked.
cargo generate-lockfile
cargo package --locked

crate_path="$CARGO_TARGET_DIR/package/${package_name}-${version}.crate"
if [[ ! -f $crate_path ]]; then
  printf 'Expected package archive was not created: %s\n' "$crate_path" >&2
  exit 1
fi

if tar -tzf "$crate_path" | grep -E '(^|/)(ci|docs|fuzz)(/|$)'; then
  printf 'Release archive contains an excluded development directory\n' >&2
  exit 1
fi

unpack_root=$(mktemp -d "${TMPDIR:-/tmp}/getifs-package.XXXXXX")
cleanup() {
  rm -rf -- "$unpack_root"
}
trap cleanup EXIT

tar -xzf "$crate_path" -C "$unpack_root"
package_root="$unpack_root/${package_name}-${version}"
if [[ ! -d $package_root ]]; then
  printf 'Expected package root was not extracted: %s\n' "$package_root" >&2
  exit 1
fi

(
  cd "$package_root"
  export CARGO_TARGET_DIR="$CARGO_TARGET_DIR/packaged"
  cargo check --locked
  cargo build --locked
  cargo test --locked --lib --tests
)

# The unpacked crate intentionally contains Cargo.toml.orig, so Cargo rejects
# republishing from that directory. Run the publish dry-run from the original
# release candidate after validating the archive's extracted contents.
cargo publish --dry-run --locked
