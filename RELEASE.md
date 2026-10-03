# Release process

1. Start from a clean, reviewed `main` checkout. Run every required CI gate,
   including MSRV, platform tests, SemVer, sanitizer, Miri parser fixtures,
   coverage, and package verification.
2. Update the version and changelog, then review the final diff. Generate the
   release archive and inspect both its contents and `.cargo_vcs_info.json` so
   the VCS SHA is the source actually being released.
3. Obtain explicit manual authorization before running `cargo publish`. CI only
   performs `cargo publish --dry-run`; it never receives a publishing token.
4. After publication, create the version tag at that exact reviewed source
   commit, push it, and create the GitHub Release from the corresponding
   changelog entry.

Run the MSRV and package checks only from that clean, committed candidate. The
MSRV helper validates an archive of `HEAD`; this prevents local uncommitted
edits from being mistaken for release-verified source.

The historical 0.6.0 and 0.6.1 releases do not have GitHub tags. Recover their
source revisions from the published crate's `.cargo_vcs_info.json`; do not
guess or create tags/releases as part of routine maintenance.

The release gates are part of the safety and parser contract. See
[SECURITY.md](SECURITY.md), the CI workflow, and the parser-focused Miri job
before approving a release.
