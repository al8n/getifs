# Release process

1. Start from a clean, reviewed `main` checkout. Run every required CI gate,
   including MSRV, platform tests, SemVer, sanitizer, Miri parser fixtures,
   coverage, and package verification.
2. Update the version and changelog, then review the final diff. Generate the
   release archive and inspect both its contents and `.cargo_vcs_info.json` so
   the VCS SHA is the source actually being released.
3. After every required CI run for the exact reviewed commit is green, create
   the `v<version>` tag at that commit and push it. The tag must match the
   package version and its commit must be an ancestor of `main`.
4. The tag push runs `.github/workflows/crates.yml`, which resolves the ignored
   `Cargo.lock` once, verifies the package against that run-scoped lockfile, and
   then waits for approval of the `crates-io` environment. Pull requests and
   manual workflow runs perform verification only; they cannot authenticate or
   publish.
5. Before approving the environment, manually confirm that all required CI for
   the exact tagged commit is green and that the prepare and verification jobs
   succeeded. The release workflow enforces tag/version and `main` ancestry,
   but it does not query the status of the other CI workflows.
6. Approval authorizes the publish job to obtain a short-lived crates.io token
   with OIDC and run `cargo publish --locked --no-verify` against the already
   verified source and lockfile. After publication is confirmed, create the
   GitHub Release from the corresponding changelog entry.

Run the MSRV and package checks only from that clean, committed candidate. The
MSRV helper validates an archive of `HEAD`; this prevents local uncommitted
edits from being mistaken for release-verified source.

The historical 0.6.0 and 0.6.1 releases do not have GitHub tags. Recover their
source revisions from the published crate's `.cargo_vcs_info.json`; do not
guess or create tags/releases as part of routine maintenance.

The release gates are part of the safety and parser contract. See
[SECURITY.md](SECURITY.md), the CI workflow, and the parser-focused Miri job
before approving a release.
