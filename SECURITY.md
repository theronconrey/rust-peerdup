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

- Daemons on different networks don't find each other yet (an invite
  doesn't carry the inviter's address); same-LAN sync works.
- Sync announces are not signed and write permission is not enforced on
  them, so a revoked member or a reader can still push changes.
- A peer that fetches blobs isn't yet checked against share membership;
  everything it can fetch is ciphertext, and it needs a manifest hash from
  gossip to find anything.
- Some vendored crates bring their own crypto and CA list instead of
  following Fedora's crypto-policies (CONTRIBUTING.md, section 3).

The threat model is in `INTEGRATION_NOTES.md` ("Threat model: wire-only").
