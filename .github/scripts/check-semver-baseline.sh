#!/usr/bin/env bash

set -euo pipefail

# Pull requests compare against their declared base. Pushes compare against
# the prior main commit, which makes a later 0.7.0 change obey patch-level
# compatibility instead of repeatedly receiving the initial minor bump's
# allowance. workflow_dispatch falls back to HEAD^ for a useful local run.
candidate=${GETIFS_SEMVER_BASELINE:-}
if [[ -z "$candidate" && ${GITHUB_EVENT_NAME:-} == "pull_request" ]]; then
  candidate=${PULL_REQUEST_BASE_SHA:-}
fi
if [[ -z "$candidate" && ${GITHUB_EVENT_NAME:-} == "push" ]]; then
  candidate=${PUSH_BEFORE_SHA:-}
fi
if [[ $candidate == "0000000000000000000000000000000000000000" ]]; then
  candidate=
fi
if [[ -z "$candidate" ]]; then
  candidate=HEAD^
fi

baseline=$(git rev-parse --verify "${candidate}^{commit}")
head=$(git rev-parse HEAD)

if [[ $baseline == "$head" ]]; then
  printf 'SemVer baseline resolves to the current commit: %s\n' "$baseline" >&2
  exit 1
fi
if ! git merge-base --is-ancestor "$baseline" HEAD; then
  printf 'SemVer baseline is not an ancestor of HEAD: %s\n' "$baseline" >&2
  exit 1
fi

printf 'Using SemVer baseline %s\n' "$baseline"
if [[ -n ${GITHUB_OUTPUT:-} ]]; then
  printf 'rev=%s\n' "$baseline" >> "$GITHUB_OUTPUT"
fi
