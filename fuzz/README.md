# getifs fuzzing

The fuzz targets call the crate's cfg-only `getifs::__fuzzing` hooks. They do
not duplicate production parsers. From the repository root, install the CLI
with stable Rust, then generate the deterministic binary corpus before a run:

```sh
cargo +stable install cargo-fuzz --locked --version 0.12.0
cd fuzz
python3 generate_corpus.py
cargo +nightly fuzz run netlink corpus/netlink -- -runs=1000
```

Run `netlink` on Linux or Android. Run the BSD target on macOS, FreeBSD,
NetBSD, OpenBSD, or DragonFly:

```sh
cd fuzz
python3 generate_corpus.py
cargo +nightly fuzz run bsd corpus/bsd -- -runs=1000
```

The targets fail to compile on an unsupported host instead of succeeding as a
no-op. Pull requests replay the generated corpus with fixed
`-runs=1000 -seed=1` smoke runs. Scheduled and manually dispatched CI uses
bounded randomized `-max_total_time=60` runs per target.

`corpus/`, `artifacts/`, and cargo-fuzz build output are generated locally and
are intentionally ignored.
