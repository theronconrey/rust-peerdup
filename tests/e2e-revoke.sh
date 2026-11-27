#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Roles and revocation, end to end, with four daemons on one host:
# A is the Owner, B and D Writers, C a Reader.
#
#   1. A's files reach B and C.
#   2. A Writer's edit (B) reaches A.
#   3. A Reader's edit (C) stays local: A and B never get it.
#   4. A revokes B. A new file from A reaches C but never B (B is refused
#      at the connection and can't decrypt the new epoch anyway).
#   5. B's edits after its revocation never reach A.
#   6. C learns of the revocation over gossip (B leaves its member list),
#      blocks B and closes B's live connections, and installs the rotated
#      key, with an auth log well over 4 KiB:
#      A also invites $EXTRA throwaway members that never run a daemon.
#      p2panda-net's default 4 KiB message limit used to drop these
#      messages (wire format v4); no daemon may log a publish failure.
#   7. Old keys after revocation (INTEGRATION_NOTES.md): D is stopped
#      before the revocation and edits while offline. Restarted, it doesn't
#      know of the revocation and publishes its edit under the old key
#      epoch 1; A, which knows, refuses that version. D then gets the auth
#      ops and the rotated key, re-encrypts its version under epoch 2, and
#      A and C accept it. B never gets it.
#
# Usage: tests/e2e-revoke.sh [path/to/rust-peerdup]   (default: target/debug)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:-$REPO_ROOT/target/debug/rust-peerdup}"
[ -x "$BIN" ] || { echo "no binary at $BIN" >&2; exit 1; }

SCRATCH="$(mktemp -d /tmp/peerdup-e2e-revoke.XXXXXX)"
TIMEOUT="${PEERDUP_E2E_TIMEOUT:-90}"
QUIET="${PEERDUP_E2E_QUIET:-20}"   # how long "never arrives" is watched
EXTRA="${PEERDUP_E2E_EXTRA:-24}"   # throwaway members, to grow the auth log
declare -A PID

ok()   { printf '\033[1;32m  ok\033[0m %s\n' "$*"; }
info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
fail() {
    printf '\033[1;31mFAIL\033[0m %s\n' "$*" >&2
    for p in a b c d; do
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
stop() { kill -TERM "${PID[$1]}"; wait "${PID[$1]}" 2>/dev/null || true; unset "PID[$1]"; }

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

export RUST_LOG="${RUST_LOG:-rust_peerdup=info}"

info "A creates a share and invites B and D (writers) and C (reader)"
mkdir -p "$(root a)" "$(root b)" "$(root c)" "$(root d)"
echo "hello from A" > "$(root a)/hello.txt"
pd a share-add --name "e2e-revoke-$$-$RANDOM" --path "$(root a)" --role sync >/dev/null
share="$(pd a share-list | awk 'NR>1 {print $1; exit}')"
pub_b="$(pd b whoami)"; pub_c="$(pd c whoami)"; pub_d="$(pd d whoami)"
pd a share-invite "$share" "$pub_b" --auth-role writer 2>/dev/null | pd b share-join - --path "$(root b)" >/dev/null
pd a share-invite "$share" "$pub_c" --auth-role reader 2>/dev/null | pd c share-join - --path "$(root c)" >/dev/null
pd a share-invite "$share" "$pub_d" --auth-role writer 2>/dev/null | pd d share-join - --path "$(root d)" >/dev/null
ok "share $share: A owner, B and D writers, C reader"

# Invited after B and C, so B and C only hear of them over gossip.
for i in $(seq 1 "$EXTRA"); do
    pub_x="$(pd "x$i" whoami)"
    pd a share-invite "$share" "$pub_x" --auth-role reader >/dev/null 2>&1
done
ops_bytes="$(stat -c %s "$(data a)/shares/$share/auth.log")"
[ "$ops_bytes" -gt 4096 ] || fail "auth.log is only $ops_bytes bytes; want more than 4 KiB"
ok "A invited $EXTRA throwaway readers (auth.log: $ops_bytes bytes)"

# C's view of the members, read from its auth.log (no lock needed).
members_c() { pd c share-members "$share"; }
c_has_all_members() { [ "$(members_c | grep -c '^[0-9a-f]\{64\} ')" -ge $((EXTRA + 4)) ]; }
c_dropped_b() { local m; m="$(members_c)" && ! grep -q "$pub_b" <<<"$m"; }
c_rotated() { grep -q "installed rotated key" "$SCRATCH/c.log"; }

start a; start b; start c; start d
wait_for "A's file reaches B" has b "hello from A" hello.txt
wait_for "A's file reaches C" has c "hello from A" hello.txt
wait_for "A's file reaches D" has d "hello from A" hello.txt
wait_for "C learns every member over gossip" c_has_all_members

info "B (writer) edits"
echo "from B" >> "$(root b)/hello.txt"
wait_for "B's edit reaches A" has a "from B" hello.txt
wait_for "B's edit reaches C" has c "from B" hello.txt
wait_for "B's edit reaches D" has d "from B" hello.txt

info "C (reader) edits"
echo "from C" > "$(root c)/reader-note.txt"
never "C's file reaches A" exists a reader-note.txt
never "C's file reaches B" exists b reader-note.txt

info "D goes offline before the revocation"
stop d

info "A revokes B"
stop a
pd a share-revoke "$share" "$pub_b" >/dev/null
start a
pd a share-members "$share" | grep -q "$pub_b" && fail "B still listed as a member"
ok "B is no longer a member"
wait_for "C learns over gossip that B was revoked" c_dropped_b
wait_for "C installs the rotated key" c_rotated
# C ran throughout; B was only a member of this share, so C blocks it and
# closes the connections B has open to it, not just new ones.
# (Field names are coloured in the log, hence the sed.)
cut_b_lines() {
    sed -e 's/\x1b\[[0-9;]*m//g' "$SCRATCH/c.log" \
        | grep "no longer a member of any share" | grep "node=$pub_b"
}
c_cut_b() { cut_b_lines | grep -q .; }
wait_for "C cuts B off once it learns of the revocation" c_cut_b
cut_b_lines | head -1 | cut -c1-220 | sed 's/^/    /'

info "A adds a file after the revocation"
echo "after revoking B" > "$(root a)/secret.txt"
wait_for "the new file reaches C" exists c secret.txt
never "the new file reaches B" exists b secret.txt

info "B (revoked) edits"
echo "B after revocation" >> "$(root b)/hello.txt"
never "B's post-revocation edit reaches A" has a "B after revocation" hello.txt

info "Old keys after revocation: D, offline during the revocation, edits"
# B and C stop. While D hasn't heard of the revocation it still trusts B
# and would serve B anything it publishes: that is the residual risk the
# epoch rule can't remove (INTEGRATION_NOTES.md, "Old keys after
# revocation"), so B must not be running to see it. C stops so that A is
# the only daemon that knows of the revocation.
stop b; stop c
echo "offline edit from D" > "$(root d)/from-d.txt"
stop a
start d
d_restarted() { [ "$(grep -c "sync started" "$SCRATCH/d.log")" -ge 2 ]; }
wait_for "D starts again" d_restarted

# A sends its auth log and pending rotations every 10 s, the first time
# 10 s after it starts; until then D can't learn of the revocation. D
# announces every 10 s. So A runs for 8 s at a time until one of D's
# announces lands in that window and A refuses D's epoch-1 version.
refused_d() { grep -q "requires >= 2 after a revocation" "$SCRATCH/a.log"; }
refused=""
for round in 1 2 3 4 5 6 7 8; do
    start a
    deadline=$((SECONDS + 8))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if refused_d; then refused=1; break; fi
        sleep 0.5
    done
    [ -n "$refused" ] && break
    stop a
done
[ -n "$refused" ] || fail "A never refused D's epoch-1 version"
grep -m1 "requires >= 2 after a revocation" "$SCRATCH/a.log" | sed 's/^/    /'
ok "A refused D's version under epoch 1 (round $round)"
grep -q "republished under epoch" "$SCRATCH/d.log" \
    && fail "D re-encrypted before it had the rotated key"
has a "offline edit from D" from-d.txt && fail "D's epoch-1 version reached A"

start c
d_rotated() { grep -q "installed rotated key" "$SCRATCH/d.log"; }
d_republished() { grep -q "republished under epoch 2" "$SCRATCH/d.log"; }
d_dropped_b() { local m; m="$(pd d share-members "$share")" && ! grep -q "$pub_b" <<<"$m"; }
wait_for "D installs the rotated key" d_rotated
wait_for "D re-encrypts its current version under epoch 2" d_republished
grep -m1 "republished under epoch 2" "$SCRATCH/d.log" | sed 's/^/    /'
wait_for "D's edit reaches A under epoch 2" has a "offline edit from D" from-d.txt
wait_for "D's edit reaches C" has c "offline edit from D" from-d.txt
wait_for "D learns that B was revoked" d_dropped_b

start b
never "D's edit reaches B" exists b from-d.txt

for p in a b c d; do
    kill -0 "${PID[$p]}" 2>/dev/null || fail "daemon ${p^^} exited early"
done
ok "all four daemons still running"

for p in a b c d; do
    if grep -E "MessageTooLarge|gossip publish" "$SCRATCH/$p.log"; then
        fail "daemon ${p^^} failed to publish a gossip message"
    fi
done
ok "no gossip publish failures in any log"
info "e2e-revoke passed"
