# getifs fuzzing

The fuzz targets call the crate's cfg-only `getifs::__fuzzing` hooks. They do
not duplicate production parsers. Generate the deterministic binary corpus
before a run:

```sh
python3 generate_corpus.py
cd fuzz
cargo fuzz run netlink corpus/netlink -- -runs=1000
```

Run `netlink` on Linux or Android. Run the BSD target on macOS, FreeBSD,
NetBSD, OpenBSD, or DragonFly:

```sh
python3 generate_corpus.py
cd fuzz
cargo fuzz run bsd corpus/bsd -- -runs=1000
```

The targets fail to compile on an unsupported host instead of succeeding as a
no-op. Pull requests replay the generated corpus with fixed runs; scheduled
and manually dispatched CI uses `-max_total_time=60` per target.

`corpus/`, `artifacts/`, and cargo-fuzz build output are generated locally and
are intentionally ignored.
