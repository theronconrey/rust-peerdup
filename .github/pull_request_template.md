<!-- SPDX-License-Identifier: MIT -->

## What and why

<!-- What this changes, and the problem it solves. Link issues. -->

## Checklist (CONTRIBUTING.md, section 6)

- [ ] `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` pass
- [ ] Fedora CI is green (RPM build, rpmlint, install smoke test)
- [ ] `License:` in the spec still matches `%cargo_license_summary` (CI prints it)
- [ ] New files have SPDX headers
- [ ] No new crate that compiles bundled C code, or the PR says why
- [ ] Works with SELinux enforcing
- [ ] Unit changes pass `systemd-analyze security --user` review
- [ ] Non-obvious crate behavior is written up in `INTEGRATION_NOTES.md`
- [ ] Wire or on-disk format changes are called out below
- [ ] Commits are signed off (`git commit -s`)

## Exceptions to the rules

<!-- Anything above that this PR can't follow, and why. Delete if none. -->
