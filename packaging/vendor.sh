#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Builds the two RPM sources for rust-peerdup.spec from a git checkout:
#
#   rust-peerdup-<version>.tar.gz         the source, as `git archive` makes it
#   rust-peerdup-<version>-vendor.tar.xz  the crate dependencies (vendor/)
#
# The vendor tarball is filtered to Linux targets with cargo-vendor-filterer,
# so it carries no Windows or macOS import libraries or other prebuilt
# binaries. It is reproducible: same Cargo.lock, same tarball.
#
# Packit runs this to make the sources for every Copr build
# (.packit.yaml); the release workflow runs it to attach the vendor tarball
# to a GitHub release, which is what the spec's Source1 points at.
#
# Usage: packaging/vendor.sh [OUTDIR]     (default: the repository root)
# Needs: git, cargo, cargo-vendor-filterer, xz, and network access.
# Prints the path of the source tarball last (Packit reads that line).

set -euo pipefail

repo="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
outdir="$(realpath "${1:-$repo}")"
name=rust-peerdup
version="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$repo/Cargo.toml" | head -n1)"
[ -n "$version" ] || { echo "no version in Cargo.toml" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Fedora builds every Linux architecture Rust supports (%{rust_arches}).
(cd "$repo" && cargo vendor-filterer \
    --platform='*-unknown-linux-gnu' \
    --platform='*-unknown-linux-gnueabihf' \
    "$work/vendor" >&2)

tar --sort=name --mtime="@0" --owner=0 --group=0 --numeric-owner \
    --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
    -C "$work" -cJf "$outdir/$name-$version-vendor.tar.xz" vendor

git -C "$repo" archive --format=tar.gz --prefix="$name-$version/" \
    -o "$outdir/$name-$version.tar.gz" HEAD

# Packit reads this last line; it wants a path relative to the spec file's
# directory when the tarballs land there.
if [ "$outdir" = "$repo" ]; then
    echo "$name-$version.tar.gz"
else
    echo "$outdir/$name-$version.tar.gz"
fi
