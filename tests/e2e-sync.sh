#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Two daemons, one share, real file transfer over iroh-blobs.
#
# A creates a share and invites B; both run `serve` with their own data
# dirs (direct mode, no D-Bus). The script then checks, with timeouts:
#
#   1. A's files arrive at B, byte for byte.
#   2. An edit on B arrives at A.
#   3. A new file in a subdirectory on A arrives at B.
#   4. A deletion on A is applied at B.
#   5. Nothing leaks into either share root (no staging files left over).
#
# Usage: tests/e2e-sync.sh [path/to/rust-peerdup]   (default: target/debug)
# Peers find each other on the local network (mDNS), so this runs on one
# host or in one container.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:-$REPO_ROOT/target/debug/rust-peerdup}"
[ -x "$BIN" ] || { echo "no binary at $BIN" >&2; exit 1; }

SCRATCH="$(mktemp -d /tmp/peerdup-e2e-sync.XXXXXX)"
DATA_A="$SCRATCH/data-a"; DATA_B="$SCRATCH/data-b"
ROOT_A="$SCRATCH/share-a"; ROOT_B="$SCRATCH/share-b"
LOG_A="$SCRATCH/a.log"; LOG_B="$SCRATCH/b.log"
PID_A=""; PID_B=""
TIMEOUT="${PEERDUP_E2E_TIMEOUT:-90}"

ok()   { printf '\033[1;32m  ok\033[0m %s\n' "$*"; }
info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
fail() {
    printf '\033[1;31mFAIL\033[0m %s\n' "$*" >&2
    echo "---- daemon A log (tail) ----" >&2; tail -n 60 "$LOG_A" >&2 || true
    echo "---- daemon B log (tail) ----" >&2; tail -n 60 "$LOG_B" >&2 || true
    exit 1
}

cleanup() {
    set +e
    for pid in $PID_A $PID_B; do kill -TERM "$pid" 2>/dev/null; done
    for pid in $PID_A $PID_B; do wait "$pid" 2>/dev/null; done
    if [ -n "${KEEP_SCRATCH:-}" ]; then echo "kept $SCRATCH"; else rm -rf "$SCRATCH"; fi
}
trap cleanup EXIT INT TERM

# wait_for <description> <command...>: poll until the command succeeds.
wait_for() {
    local what="$1"; shift
    local deadline=$((SECONDS + TIMEOUT))
    until "$@" >/dev/null 2>&1; do
        [ "$SECONDS" -lt "$deadline" ] || fail "timed out after ${TIMEOUT}s: $what"
        sleep 1
    done
    ok "$what"
}

same_tree() { diff -r --exclude=.peerdup "$ROOT_A" "$ROOT_B"; }

export RUST_LOG="${RUST_LOG:-rust_peerdup=info}"

info "Setting up peers"
mkdir -p "$ROOT_A/docs" "$ROOT_B"
echo "hello from A" > "$ROOT_A/hello.txt"
head -c 3000000 /dev/urandom > "$ROOT_A/docs/blob.bin"   # spans many chunks

"$BIN" --data-dir "$DATA_A" share-add --topic "e2e-sync-$$-$RANDOM" --path "$ROOT_A" --role sync >/dev/null
SHARE_ID="$("$BIN" --data-dir "$DATA_A" share-list | awk 'NR>1 {print $1; exit}')"
[ -n "$SHARE_ID" ] || fail "no share id from share-list"
PUB_B="$("$BIN" --data-dir "$DATA_B" whoami)"
"$BIN" --data-dir "$DATA_A" share-invite "$SHARE_ID" "$PUB_B" --auth-role writer 2>/dev/null \
    | "$BIN" --data-dir "$DATA_B" share-join - --path "$ROOT_B" >/dev/null
ok "A created share $SHARE_ID and B joined it"

info "Starting both daemons"
"$BIN" --data-dir "$DATA_A" serve --no-dbus >"$LOG_A" 2>&1 & PID_A=$!
"$BIN" --data-dir "$DATA_B" serve --no-dbus >"$LOG_B" 2>&1 & PID_B=$!

wait_for "A's files arrive at B" same_tree

info "Editing on B"
echo "edited on B" >> "$ROOT_B/hello.txt"
wait_for "B's edit arrives at A" grep -q "edited on B" "$ROOT_A/hello.txt"
wait_for "trees agree after B's edit" same_tree

info "Adding a file in a new subdirectory on A"
mkdir -p "$ROOT_A/new/deeper"
echo "nested" > "$ROOT_A/new/deeper/file.txt"
wait_for "new nested file arrives at B" test -f "$ROOT_B/new/deeper/file.txt"
wait_for "trees agree after the new file" same_tree

info "Deleting a file on A"
rm "$ROOT_A/docs/blob.bin"
wait_for "deletion is applied at B" test ! -e "$ROOT_B/docs/blob.bin"
wait_for "trees agree after the deletion" same_tree

if find "$ROOT_A" "$ROOT_B" -name '*.peerdup-tmp' | grep -q .; then
    fail "staging files left in a share root"
fi
ok "no staging files left behind"

for p in $PID_A $PID_B; do
    kill -0 "$p" 2>/dev/null || fail "a daemon exited early"
done
ok "both daemons still running"
info "e2e-sync passed"
