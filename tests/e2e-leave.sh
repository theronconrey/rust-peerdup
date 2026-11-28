#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Members leave a share on their own, with three daemons on one host:
# A is the Owner, B a Writer, C a Reader.
#
#   1. C runs share-leave (direct mode: C's daemon is stopped, and finishes
#      the leave when it starts again).
#   2. A learns of it over gossip and rotates the key at once (it is the
#      only Owner, so the designated rotator); B installs the new key.
#   3. B edits, and A applies the edit under the new epoch.
#   4. C's data dir no longer has the share, its files stay, and C gets
#      nothing new.
#   5. The only Owner can't leave.
#
# Usage: tests/e2e-leave.sh [path/to/rust-peerdup]   (default: target/debug)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:-$REPO_ROOT/target/debug/rust-peerdup}"
[ -x "$BIN" ] || { echo "no binary at $BIN" >&2; exit 1; }

SCRATCH="$(mktemp -d /tmp/peerdup-e2e-leave.XXXXXX)"
TIMEOUT="${PEERDUP_E2E_TIMEOUT:-90}"
QUIET="${PEERDUP_E2E_QUIET:-20}"   # how long "never arrives" is watched
declare -A PID

ok()   { printf '\033[1;32m  ok\033[0m %s\n' "$*"; }
info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
fail() {
    printf '\033[1;31mFAIL\033[0m %s\n' "$*" >&2
    for p in a b c; do
        echo "---- daemon ${p^^} log (tail) ----" >&2
        tail -n 40 "$SCRATCH/$p.log" >&2 2>/dev/null || true
    done
    exit 1
}

cleanup() {
    set +e
    for p in "${!PID[@]}"; do kill -TERM "${PID[$p]}" 2>/dev/null; done
    for p in "${!PID[@]}"; do wait "${PID[$p]}" 2>/dev/null; done
    if [ -n "${KEEP_SCRATCH:-}" ]; then echo "kept $SCRATCH"; else rm -rf "$SCRATCH"; fi
}
trap cleanup EXIT INT TERM

data() { echo "$SCRATCH/data-$1"; }
root() { echo "$SCRATCH/share-$1"; }
pd() { local p="$1"; shift; "$BIN" --data-dir "$(data "$p")" "$@"; }
start() { pd "$1" serve --no-dbus >>"$SCRATCH/$1.log" 2>&1 & PID[$1]=$!; }
stop() { kill -TERM "${PID[$1]}" 2>/dev/null || true; wait "${PID[$1]}" 2>/dev/null || true; unset "PID[$1]"; }

wait_for() {
    local what="$1"; shift
    local deadline=$((SECONDS + TIMEOUT))
    until "$@" >/dev/null 2>&1; do
        [ "$SECONDS" -lt "$deadline" ] || fail "timed out after ${TIMEOUT}s: $what"
        sleep 1
    done
    ok "$what"
}

# never <description> <command...>: the command must stay false for $QUIET s.
never() {
    local what="$1"; shift
    local deadline=$((SECONDS + QUIET))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if "$@" >/dev/null 2>&1; then fail "it happened: $what"; fi
        sleep 1
    done
    ok "for ${QUIET}s, never: $what"
}

has() { grep -q "$2" "$(root "$1")/$3" 2>/dev/null; }
exists() { test -e "$(root "$1")/$2"; }
# A daemon's log without colour codes.
plain_log() { sed -e 's/\x1b\[[0-9;]*m//g' "$SCRATCH/$1.log"; }
logged() { plain_log "$1" | grep -q "$2"; }

export RUST_LOG="${RUST_LOG:-rust_peerdup=info}"

info "A creates a share and invites B (writer) and C (reader)"
mkdir -p "$(root a)" "$(root b)" "$(root c)"
echo "hello from A" > "$(root a)/hello.txt"
pd a share-add --name "e2e-leave-$$-$RANDOM" --path "$(root a)" --role sync >/dev/null
share="$(pd a share-list | awk 'NR>1 {print $1; exit}')"
pub_b="$(pd b whoami)"; pub_c="$(pd c whoami)"
pd a share-invite "$share" "$pub_b" --auth-role writer 2>/dev/null | pd b share-join - --path "$(root b)" >/dev/null
pd a share-invite "$share" "$pub_c" --auth-role reader 2>/dev/null | pd c share-join - --path "$(root c)" >/dev/null
ok "share $share: A owner, B writer, C reader"

start a; start b; start c
wait_for "A's file reaches B" has b "hello from A" hello.txt
wait_for "A's file reaches C" has c "hello from A" hello.txt

info "C leaves the share"
stop c
pd c share-leave "$share" >/dev/null
test -e "$(data c)/shares/$share/leaving" || fail "share-leave wrote no leaving marker"
pd c share-members "$share" | grep -q "$pub_c" && fail "C still lists itself as a member"
ok "C signed its own removal; its daemon finishes the leave on start"
start c

dropped() { local m; m="$(pd "$1" share-members "$share")" && ! grep -q "$pub_c" <<<"$m"; }
wait_for "A learns that C left" dropped a
wait_for "B learns that C left" dropped b
wait_for "A rotates the key for the remaining members" logged a "a member left: rotated the share key"
plain_log a | grep -m1 "a member left: rotated the share key" | cut -c1-220 | sed 's/^/    /'
wait_for "B installs the rotated key" logged b "installed rotated key"

c_gone() { ! test -e "$(data c)/shares/$share"; }
# C sends its leave for about a minute before it drops the share.
TIMEOUT=$((TIMEOUT + 60)) wait_for "C removes the share from its data dir" c_gone
logged c "left the share and removed it from this machine" \
    || fail "C did not log that it left"
has c "hello from A" hello.txt || fail "C's copy of the files is gone"
ok "C's files stay in its share folder"

info "B (writer) edits after the rotation"
echo "from B after C left" >> "$(root b)/hello.txt"
wait_for "B's edit reaches A" has a "from B after C left" hello.txt
a_applied_epoch2() { plain_log a | grep "applied remote version" | grep -q "epoch=2"; }
wait_for "A applied B's edit under epoch 2" a_applied_epoch2

info "A adds a file after C left"
echo "after C left" > "$(root a)/after-leave.txt"
wait_for "the new file reaches B" exists b after-leave.txt
never "the new file reaches C" exists c after-leave.txt
never "B's edit reaches C" has c "from B after C left" hello.txt

info "The only Owner can't leave"
stop a
if pd a share-leave "$share" >"$SCRATCH/a-leave.out" 2>&1; then
    fail "A, the only Owner, was allowed to leave"
fi
grep -q "only Owner" "$SCRATCH/a-leave.out" \
    || { cat "$SCRATCH/a-leave.out" >&2; fail "no clear error for the only Owner's leave"; }
sed 's/^/    /' "$SCRATCH/a-leave.out" | head -4
test -e "$(data a)/shares/$share/leaving" && fail "a refused leave wrote the marker"
pd a share-members "$share" | grep -q "owner" || fail "A is no longer listed as the Owner"
ok "A's leave was refused and A is still the Owner"

kill -0 "${PID[b]}" 2>/dev/null || fail "daemon B exited early"
for p in a b c; do
    if plain_log "$p" | grep -E "ERROR|MessageTooLarge|gossip publish"; then
        fail "daemon ${p^^} logged an error"
    fi
done
ok "no errors in any log"
info "e2e-leave passed"
