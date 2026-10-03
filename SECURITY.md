# Security policy

Please report suspected vulnerabilities through this repository's GitHub issue
tracker. Include the affected version, a minimal reproduction, impact, and any
relevant platform details. If public issue details would create unnecessary
risk, open a minimal report and ask the maintainer for a suitable follow-up
channel.

Do not attach unredacted interface names, IP or MAC addresses, routing tables,
or other raw network-discovery output to a public report. Redact it first, or
share it through the follow-up channel agreed with the maintainer.

The public dependency name `paste` is an alias for the maintained `pastey`
0.2.3 crate. The original `paste` crate can still appear transitively through
sister crates. RUSTSEC-2024-0436 identifies that original crate as
unmaintained only; it is not evidence of an exploitable vulnerability. The
advisory CI job ignores only this advisory and continues to fail on every other
reported advisory.
