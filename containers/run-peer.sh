#!/usr/bin/env bash
# Helper: run the containerized "peer B" rust-peerdup daemon alongside a
# host install. Uses --network host so mDNS discovery works on the host
# loopback (the daemon currently announces 127.0.0.1 — see
# INTEGRATION_NOTES.md "Announce a reachable address").
#
# Volumes (all bind-mounted with the shared SELinux label `:z`, so the
# detached daemon container and ad-hoc CLI invocations can both touch
# them concurrently — `:Z` private labelling caused MCS-tag collisions
# when an ad-hoc container relabelled paths the daemon was still using):
#   - $HOST_DATA:  peer's data dir (identity.key, shares/, auth.log, etc.)
#   - $HOST_SHARE: peer's share root, so you can see synced files from
#                  outside the container
#
# The host-built binary at ~/.local/bin/rust-peerdup is mounted into the
# container so a `cargo build --release && ./install.sh` on the host
# is immediately picked up by the container on next start (no rebuild).
#
# Usage:
#   ./containers/run-peer.sh whoami
#   ./containers/run-peer.sh share-list
#   ./containers/run-peer.sh share-join <ticket> --path /share
#   ./containers/run-peer.sh serve --bt-port 41001       # foreground
#   ./containers/run-peer.sh -d serve --bt-port 41001    # background
#
# Use the env vars to override defaults:
#   PEER_NAME=peer-c HOST_SHARE=/tmp/peer-c-share ./containers/run-peer.sh ...

set -euo pipefail

PEER_NAME="${PEER_NAME:-peer-b}"
HOST_DATA="${HOST_DATA:-/tmp/${PEER_NAME}-data}"
HOST_SHARE="${HOST_SHARE:-/tmp/${PEER_NAME}-share}"
HOST_BIN="${HOST_BIN:-$HOME/.local/bin/rust-peerdup}"
IMAGE="${IMAGE:-rust-peerdup-peer}"

[ -x "$HOST_BIN" ] || { echo "host binary not found at $HOST_BIN — run ./install.sh first" >&2; exit 1; }
mkdir -p "$HOST_DATA" "$HOST_SHARE"

DETACH=()
if [ "${1-}" = "-d" ]; then
    DETACH=("-d" "--name" "$PEER_NAME" "--replace")
    shift
fi

# Pass the rest of the CLI to rust-peerdup via the entrypoint. If the
# user doesn't pass a subcommand, the image's default CMD (serve) runs.
exec podman run --rm "${DETACH[@]}" \
    --network host \
    -v "${HOST_DATA}:/data:z" \
    -v "${HOST_SHARE}:/share:z" \
    -v "${HOST_BIN}:/usr/local/bin/rust-peerdup:ro,z" \
    "$IMAGE" \
    --data-dir /data "$@"
