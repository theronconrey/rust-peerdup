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
#   6. While B fetches a large file from A, and A is stalled mid-transfer
#      (SIGSTOP), B's share loop still runs: a local edit on B is noticed
#      within seconds. Fetches run off the loop. The two versions are
#      concurrent; B's wins, and A keeps big.bin (B never had it) and
#      republishes it, so both sides end with both files.
#   7. Concurrent edits to one file: B is stopped, both edit same.txt,
#      B starts. Both converge with the winning edit in same.txt and
#      exactly one conflict copy holding the other.
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
BIG_MB="${PEERDUP_E2E_BIG_MB:-256}"

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
    for pid in $PID_A $PID_B; do kill -CONT "$pid" 2>/dev/null; kill -TERM "$pid" 2>/dev/null; done
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

# within <seconds> <description> <command...>: like wait_for, shorter.
within() {
    local secs="$1" what="$2"; shift 2
    local deadline=$((SECONDS + secs))
    until "$@" >/dev/null 2>&1; do
        [ "$SECONDS" -lt "$deadline" ] || fail "not within ${secs}s: $what"
        sleep 0.2
    done
    ok "$what (within ${secs}s)"
}

count() { grep -c "$1" "$2" || true; }
more_than() { [ "$(count "$1" "$2")" -gt "$3" ]; }

export RUST_LOG="${RUST_LOG:-rust_peerdup=debug}"

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

info "Fetching a ${BIG_MB} MiB file while its provider stalls"
fetches_before="$(count "fetching a large file" "$LOG_B")"
applied_before="$(count "applied remote version" "$LOG_B")"
changes_before="$(count "local change detected" "$LOG_B")"
# Written beside the root and renamed in, so A publishes it once, whole.
head -c "$((BIG_MB * 1024 * 1024))" /dev/urandom > "$SCRATCH/big.bin"
mv "$SCRATCH/big.bin" "$ROOT_A/big.bin"
deadline=$((SECONDS + TIMEOUT))
until more_than "fetching a large file" "$LOG_B" "$fetches_before"; do
    [ "$SECONDS" -lt "$deadline" ] || fail "B never started fetching big.bin"
    sleep 0.05
done
kill -STOP "$PID_A"
ok "B started fetching big.bin; A is stopped"
if more_than "applied remote version" "$LOG_B" "$applied_before"; then
    fail "B finished fetching before A was stopped; raise PEERDUP_E2E_BIG_MB"
fi
echo "edited on B during the fetch" > "$ROOT_B/during-fetch.txt"
within 10 "B notices a local edit while its fetch is stalled" \
    more_than "local change detected" "$LOG_B" "$changes_before"
[ ! -e "$ROOT_B/big.bin" ] || fail "big.bin applied while its provider was stopped"
kill -CONT "$PID_A"
wait_for "trees agree after the stalled fetch" same_tree
for r in "$ROOT_A" "$ROOT_B"; do
    [ -f "$r/big.bin" ] && [ -f "$r/during-fetch.txt" ] || fail "$r lost a side's file"
done
ok "both sides kept big.bin and B's edit"
rm "$ROOT_A/big.bin"
wait_for "big.bin's deletion reaches B" test ! -e "$ROOT_B/big.bin"

info "Concurrent edits to the same file"
echo "original" > "$ROOT_A/same.txt"
wait_for "same.txt reaches B" grep -qx original "$ROOT_B/same.txt"
sleep 3   # let B announce the version back, so A knows B has it
kill -TERM "$PID_B"; wait "$PID_B" 2>/dev/null || true; PID_B=""
changes_before="$(count "local change detected" "$LOG_A")"
echo "edit on A" > "$ROOT_A/same.txt"
wait_for "A publishes its edit" more_than "local change detected" "$LOG_A" "$changes_before"
echo "edit on B" > "$ROOT_B/same.txt"
"$BIN" --data-dir "$DATA_B" serve --no-dbus >>"$LOG_B" 2>&1 & PID_B=$!
copies_in() { find "$1" -name 'same (conflict from *' -not -name '*.peerdup-tmp' | wc -l; }
one_copy_each() {
    same_tree && [ "$(copies_in "$ROOT_A")" -eq 1 ] && [ "$(copies_in "$ROOT_B")" -eq 1 ]
}
wait_for "both sides converge with one conflict copy" one_copy_each
sleep 12   # one announce round: no further copies appear
one_copy_each || fail "conflict copies kept multiplying"
winner="$(cat "$ROOT_A/same.txt")"
copy="$(cat "$(find "$ROOT_A" -name 'same (conflict from *')")"
case "$winner/$copy" in
    "edit on A/edit on B"|"edit on B/edit on A") ;;
    *) fail "same.txt has '$winner' and the copy has '$copy'" ;;
esac
ok "same.txt has '$winner'; the conflict copy has the losing '$copy'"

if find "$ROOT_A" "$ROOT_B" -name '*.peerdup-tmp' | grep -q .; then
    fail "staging files left in a share root"
fi
ok "no staging files left behind"

for p in $PID_A $PID_B; do
    kill -0 "$p" 2>/dev/null || fail "a daemon exited early"
done
ok "both daemons still running"
info "e2e-sync passed"
