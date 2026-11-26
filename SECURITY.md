# Security policy

rust-peerdup handles encryption keys and syncs files between machines, so
security reports are welcome and taken seriously.

## Reporting a vulnerability

Report privately through GitHub:
**[open a private security advisory](https://github.com/theronconrey/rust-peerdup/security/advisories/new)**.
Please don't open a public issue or pull request for a vulnerability.

Include what you can of:

- the version (`rpm -q rust-peerdup`, or the git commit),
- what an attacker needs (a peer on the share, a revoked member, someone on
  the same machine, someone on the network, someone holding a ticket),
- what they get, and steps or a proof of concept.

Never include real invite tickets, `identity.key` or `keys.bin`; make
throwaway ones.

You'll get an acknowledgement within a week. Fixes are released through
the [theronconrey/peerdup](https://copr.fedorainfracloud.org/coprs/theronconrey/peerdup/)
Copr project, and the advisory is published once a fixed build is
available.

## Supported versions

rust-peerdup is pre-1.0. Only the latest release and `main` get security
fixes.

## Known limitations

These are known and tracked, so they don't need a report (new angles on
them do):

- By default peers that can't connect directly meet through n0's public
  relays, which see who talks to whom (not what). `--relay-url` changes
  this.
- Some vendored crates bring their own crypto and CA list instead of
  following Fedora's crypto-policies (CONTRIBUTING.md, section 3).

The threat model is in `INTEGRATION_NOTES.md` ("Threat model: wire-only").
