# getifs fuzzing

The fuzz targets call the crate's cfg-only `getifs::__fuzzing` hooks. Both
drive the production walkers rather than fuzz-only copies:

- `netlink` runs every netlink dump walker (link, address, best-local
  selection, nexthop, route, and gateway) over replayed kernel replies. The
  input reaches the `DumpMessages` framing checks, the per-message attribute
  loops, the retry of an interrupted dump, and nexthop resolution.
- `bsd` runs the sysctl message walkers (interfaces, addresses, multicast
  groups, gateways, routes, and best-local route selection) and the sockaddr
  decoders they call (`parse`, `parse_addrs`, the inet address decoders, and
  `take_sockaddr_frame`).

## Input format

A `netlink` input is a sequence of datagrams, each prefixed by its length as
a little-endian `u32`. A truncated final datagram is ignored. Every walker
starts from a fresh replay of the whole sequence and receives one datagram per
`recv`; requests are discarded. A walker that opens another dump (the nexthop
dump, best-local's per-interface address dump, or the retry of an interrupted
dump) continues with the next unread datagram, and running out of datagrams
fails the walk. Replies must carry sequence number 1 and the port id of the
first message of the first datagram; the walkers reject any other message.

A `bsd` input is one sysctl buffer of routing messages in the host's native
layout. Every walker parses the whole buffer, and every sockaddr decoder reads
it as one sockaddr.

`generate_corpus.py` writes seeds in both formats. Its BSD routing-message
seeds use the macOS header layout, which matches the CI host of the `bsd`
target.

## Running

From the repository root, install the CLI with stable Rust, then generate the
deterministic binary corpus before a run:

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
