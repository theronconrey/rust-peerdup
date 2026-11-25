# Contributing to rust-peerdup

**Rule: everything in this repository follows Fedora best practices.** That
covers code, packaging, systemd units, D-Bus files and docs. Fedora is the
first platform rust-peerdup ships on, as an RPM in the
[theronconrey/peerdup](https://copr.fedorainfracloud.org/coprs/theronconrey/peerdup/)
Copr project, next to tamarack. Windows and macOS builds come later
(ROADMAP.md, phase 9) and must not make the Linux side less Fedora-native.

If a change can't follow these rules, the pull request must say why and what
the exception is.

The authoritative sources are the
[Fedora Packaging Guidelines](https://docs.fedoraproject.org/en-US/packaging-guidelines/)
and the
[Rust Packaging Guidelines](https://docs.fedoraproject.org/en-US/packaging-guidelines/Rust/).
Where this file and those disagree, those win; open an issue to fix this file.

## 1. Design: built on Fedora's platform

| Job | Use | Not |
| --- | --- | --- |
| Run the daemon | A systemd user unit, started by D-Bus activation or at login | Forking, PID files, autostart scripts |
| CLI to daemon | D-Bus on the session bus (`org.peerdup.Daemon1`) | A private socket protocol or HTTP server |
| Logging | stdout/stderr to the journal (`journalctl --user -u rust-peerdup`) | Log files, ad-hoc rotation |
| Network reach | iroh: outbound QUIC, hole-punching, relay fallback; no inbound port | Fixed ports that need firewall rules, UPnP |
| Per-user state | `$XDG_DATA_HOME/rust-peerdup` | Dotfiles in `$HOME`, anything system-wide |
| TLS | System OpenSSL (crypto-policies) wherever a crate gives us the choice | Hard-coded protocols or ciphers |

## 2. Security

- **SELinux is always enforcing.** Never disable it or set it permissive, in
  code, docs or tests. The daemon runs as the user, unconfined_t on a
  desktop; it needs no policy of its own as long as it stays in the user's
  files.
- **Least privilege.** The daemon never needs root. Nothing here may add a
  setuid binary, a system service or a polkit rule without a design note.
- **Sandbox the unit.** `systemd/rust-peerdup.service` uses every option a
  user unit can use without privileges; relax one only with a comment
  saying why. Check with `systemd-analyze security --user`.
- **Keys and identities stay private.** `identity.key` and `keys.bin` are
  0600 and never logged. Tickets are secrets; don't log them either.
- **Input is untrusted.** Everything from peers, tickets and D-Bus is
  validated; signatures are checked before anything is applied
  (CLAUDE.md, "Auth ops are append-only and signed").

## 3. Packaging

- rust-peerdup ships as an RPM built from `rust-peerdup.spec` in this
  repository, with the cargo-rpm-macros (`%cargo_prep`, `%cargo_build`,
  `%cargo_install`, `%cargo_test`), so it gets Fedora's compiler flags and
  hardening.
- **Vendored crates, as a documented exception.** Fedora prefers every crate
  as its own `rust-*` package. p2panda and iroh, and many of
  the crates under them, are not packaged, so the spec builds from a vendor
  tarball, the way the Rust guidelines allow when there is no other way:
  - `packaging/vendor.sh` makes it, filtered to Linux targets with
    `cargo vendor-filterer` (no prebuilt Windows or macOS libraries), and
    reproducibly.
  - `%cargo_prep -v vendor`; no `%cargo_generate_buildrequires`; no `-devel`
    subpackage.
  - `%cargo_vendor_manifest` writes `cargo-vendor.txt`, shipped as
    `%license`, which gives every bundled crate a `bundled(crate(NAME))`
    Provides, so Fedora's security tooling can find us.
  - If a crate we use gets packaged in Fedora, that does not change this; if
    *all* of them are, switch to `%cargo_generate_buildrequires`.
- `License:` is an SPDX expression covering rust-peerdup **and** every
  vendored crate. CI prints `%cargo_license_summary`; when a `Cargo.lock`
  change adds a license, update `License:` in the same pull request.
- Known gaps against crypto-policies and system trust, all from vendored
  crates and all needing upstream changes; prefer crate features that use
  system libraries whenever upstream offers them:
  - `ring` (rustls, under iroh's QUIC) compiles its own crypto, and
    rustls doesn't follow crypto-policies.
  - `webpki-roots` (via iroh's relay and DNS clients) builds Mozilla's CA
    list into the binary instead of reading `ca-certificates` (it is where
    `CDLA-Permissive-2.0` in `License:` comes from).
- SQLite is linked from the system: `libsqlite3-sys` (under p2panda-net's
  address book) would compile its own copy, so the spec sets
  `LIBSQLITE3_SYS_USE_PKG_CONFIG=1` and `packaging/vendor.sh` drops the
  bundled sources. CI checks the installed binary links `libsqlite3`.
- Builds work offline (as in `mock` and Copr's build step). `rpmlint` must
  be clean, or each remaining warning explained in `rust-peerdup.rpmlintrc`.
- The version lives in `Cargo.toml`; the spec's `Version:` must match it (CI
  checks). A release is: bump both, add a `%changelog` entry, tag `vX.Y.Z`,
  publish a GitHub release. The release workflow attaches the vendor
  tarball and Packit builds it into the Copr project.

## 4. Rust

- Build with the `rust` and `cargo` Fedora ships in its supported releases;
  CI runs on `fedora:latest` and `fedora:rawhide`. Don't use features or
  crates that need a newer compiler than `fedora:latest` has.
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  `cargo test` pass, with `--locked`.
- Every source file starts with an SPDX header:
  `// SPDX-License-Identifier: MIT` (`#` in scripts and config files).
- New dependencies: check the crate's license (it lands in `License:`) and
  whether it compiles C code (it lands in the BuildRequires and in
  section 3). Prefer crates already in Fedora.

## 5. systemd and D-Bus

- The user unit ships in `/usr/lib/systemd/user`, the activation file in
  `/usr/share/dbus-1/services`. Neither is enabled by the package; D-Bus
  activation starts the daemon on demand.
- `install.sh` is for development builds only. It rewrites the unit's
  `ExecStart=` for `~/.local/bin`; the file in the repository stays
  correct for the RPM.

## 6. Pull requests

Every PR confirms:

- [ ] `cargo fmt`, `cargo clippy -D warnings`, `cargo test`, rpmlint pass
- [ ] `License:` still matches `%cargo_license_summary` (CI prints it)
- [ ] New files have SPDX headers
- [ ] No new crate that compiles bundled C code, or the PR says why
- [ ] Works with SELinux enforcing
- [ ] Unit changes pass `systemd-analyze security --user` review
- [ ] Non-obvious crate behavior is written up in `INTEGRATION_NOTES.md`
- [ ] Any exception to these rules is explained in the PR

Commits are signed off (`git commit -s`, Developer Certificate of Origin).
