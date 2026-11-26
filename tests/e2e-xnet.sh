#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Two daemons on two separate networks sync a share.
#
# Peer A and peer B run in Fedora containers on two different Docker
# networks, which can't route to each other or see each other's mDNS; they
# can only meet through a relay or a hole-punched path. B joins with a
# ticket that carries A's address (ticket v3), then the script checks that
# A's files reach B and an edit on B reaches A.
#
# Usage: tests/e2e-xnet.sh path/to/rust-peerdup   (a binary built on Fedora)
# Needs: docker, and internet access for the relays. Extra arguments for
# `serve` (e.g. --relay-url URL) can be passed in PEERDUP_SERVE_ARGS.

set -euo pipefail

BIN="$(realpath "${1:?usage: e2e-xnet.sh path/to/rust-peerdup}")"
IMAGE="${PEERDUP_XNET_IMAGE:-registry.fedoraproject.org/fedora:latest}"
TIMEOUT="${PEERDUP_E2E_TIMEOUT:-240}"
RUN="xnet-$$"
SERVE_ARGS="${PEERDUP_SERVE_ARGS:-}"

ok()   { printf '\033[1;32m  ok\033[0m %s\n' "$*"; }
info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
logs() {
    for p in a b; do
        echo "---- daemon ${p^^} log (tail) ----" >&2
        docker exec "$RUN-$p" sh -c 'tail -n 80 /tmp/serve.log' >&2 2>/dev/null || true
    done
}
fail() { printf '\033[1;31mFAIL\033[0m %s\n' "$*" >&2; logs; exit 1; }

cleanup() {
    set +e
    docker rm -f "$RUN-a" "$RUN-b" >/dev/null 2>&1
    docker network rm "$RUN-net-a" "$RUN-net-b" >/dev/null 2>&1
}
trap cleanup EXIT INT TERM

# inside <peer> <command...>: run a shell command in that peer's container.
inside() { local p="$1"; shift; docker exec "$RUN-$p" sh -c "$*"; }
pd() { local p="$1"; shift; inside "$p" "rust-peerdup --data-dir /data $*"; }

start_daemon() {
    docker exec -d "$RUN-$1" sh -c \
        "RUST_LOG=rust_peerdup=info,iroh=warn exec rust-peerdup --data-dir /data serve --no-dbus $SERVE_ARGS >>/tmp/serve.log 2>&1"
}
# Match the process name exactly (-x), not the command line: the shell
# running pkill has the same words in its own command line.
stop_daemon() {
    inside "$1" "pkill -TERM -x rust-peerdup; for i in \$(seq 50); do pgrep -x rust-peerdup >/dev/null || exit 0; sleep 0.2; done; exit 1"
}

wait_for() {
    local what="$1"; shift
    local deadline=$((SECONDS + TIMEOUT))
    until "$@" >/dev/null 2>&1; do
        [ "$SECONDS" -lt "$deadline" ] || fail "timed out after ${TIMEOUT}s: $what"
        sleep 2
    done
    ok "$what"
}

tree_sums() { inside "$1" "cd /share && find . -path ./.peerdup -prune -o -type f -print0 | sort -z | xargs -0 -r sha256sum"; }
same_tree() { [ "$(tree_sums a)" = "$(tree_sums b)" ] && [ -n "$(tree_sums a)" ]; }

info "Two containers on two isolated networks"
docker network create "$RUN-net-a" >/dev/null
docker network create "$RUN-net-b" >/dev/null
for p in a b; do
    docker run -d --name "$RUN-$p" --network "$RUN-net-$p" \
        -v "$BIN:/usr/local/bin/rust-peerdup:ro" "$IMAGE" sleep infinity >/dev/null
    inside "$p" "command -v pkill >/dev/null || dnf -y -q install procps-ng >/dev/null"
    inside "$p" "mkdir -p /share"
done
ok "A on $RUN-net-a, B on $RUN-net-b"

info "A creates a share and comes online"
inside a "echo 'hello across networks' > /share/hello.txt && mkdir -p /share/sub && head -c 2000000 /dev/urandom > /share/sub/blob.bin"
pd a "share-add --name xnet-$RUN --path /share --role sync" >/dev/null
share_id="$(pd a share-list | awk 'NR>1 {print $1; exit}')"
start_daemon a
wait_for "A wrote its address with a home relay" inside a "grep -qi relay /data/endpoint.json"
stop_daemon a || fail "A did not stop"

info "A invites B; the ticket carries A's address"
pub_b="$(pd b whoami)"
pd a "share-invite $share_id $pub_b --auth-role writer 2>/dev/null" \
    | docker exec -i "$RUN-b" rust-peerdup --data-dir /data share-join - --path /share >/dev/null
inside b "test -s /data/shares/$share_id/bootstrap.json" || fail "B has no bootstrap address"
ok "B joined $share_id with A as its bootstrap"

info "Both daemons run"
start_daemon a
start_daemon b
wait_for "A's files reach B across networks" same_tree

info "B edits a file"
inside b "echo 'edited on B' >> /share/hello.txt"
wait_for "B's edit reaches A" inside a "grep -q 'edited on B' /share/hello.txt"
wait_for "trees agree" same_tree

info "e2e-xnet passed"
