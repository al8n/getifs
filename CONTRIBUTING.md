# Contributing

`getifs` supports Rust 1.85.0 and newer. Before sending a change, run the
relevant checks with Rust 1.85.0 as well as the normal platform test suite.
Changes must be exercised on the platform paths they affect; Linux, Android,
BSD/macOS, and Windows code should not be assumed equivalent.

Run MSRV and package verification from a clean, committed candidate. The MSRV
helper intentionally archives `HEAD`, so uncommitted edits are not part of its
isolated validation.

Keep `unsafe` changes small and reviewed. State the layout, lifetime,
alignment, and kernel/API invariants that make the operation sound, and add a
focused test whenever an input can be represented without a live kernel call.

Public items, feature behavior, and documented error behavior are part of the
SemVer contract. A change that removes, narrows, or changes them needs an
appropriate version bump and should pass the SemVer check against its actual
base revision. Keep examples, generated/snapshot-style documentation, and
platform notes synchronized with behavior.

Benchmark changes should include a reproducible `cargo bench` comparison and
avoid treating noisy runner measurements as a regression by themselves. For
releases at or after 1.0, an MSRV increase is announced only in a minor
release.

See [RELEASE.md](RELEASE.md) for the release gates and
[SECURITY.md](SECURITY.md) for security reporting.
