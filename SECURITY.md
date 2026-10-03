# Security policy

Please report suspected vulnerabilities privately through GitHub: open this
repository's **Security** tab and choose **Report a vulnerability**, or go to
<https://github.com/al8n/getifs/security/advisories/new>. Do not report
vulnerabilities in public issues, pull requests, or discussions. Include the
affected version, a minimal reproduction, impact, and any relevant platform
details.

If you cannot use a GitHub account, open a public issue that asks the
maintainer for a private contact channel, and leave out any details of the
vulnerability.

Do not attach unredacted interface names, IP or MAC addresses, routing tables,
or other raw network-discovery output to a report, even a private one. Redact
it first.

The public dependency name `paste` is an alias for the maintained `pastey`
0.2.3 crate. The original `paste` crate can still appear transitively through
sister crates. RUSTSEC-2024-0436 identifies that original crate as
unmaintained only; it is not evidence of an exploitable vulnerability. The
advisory CI job ignores only this advisory and continues to fail on every other
reported advisory.
