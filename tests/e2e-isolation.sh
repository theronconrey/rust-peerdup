#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Per-share isolation and live revocation, with three daemons on one host.
# A owns two shares, X and Y, both named "photos"; B is a Writer of both
# and C a Writer of Y only. C also makes a share of its own named
# "photos". A runs on a private D-Bus session bus, so it can revoke while
# it runs, as a desktop daemon does.
#
#   1. Names are labels: the three "photos" shares have three ids, and
#      C's own share never hears from A's (with topics derived from the
#      name, it had X's id and topic).
#   2. X's files reach B; Y's reach B and C.
#   3. A revokes B from Y while everything runs. B is still a member of
#      X, so A keeps its connection, and B can still hear Y's announces
#      over it (iroh-gossip has no per-topic gate; INTEGRATION_NOTES.md,
#      "Members-only connections"). When B asks A for Y's new version, A's
#      blob gate refuses it: B isn't a member of Y. Y's new file reaches
#      C, never B; X still syncs with B.
#   4. A revokes B from X too. B is in none of A's shares now, so A
#      closes B's live connections at once (logged, with how many), and B
#      gets no gossip after that: A's next edit to X never reaches B, and
#      B logs no announce for it.
#
# Needs dbus-daemon. Usage: tests/e2e-isolation.sh [path/to/rust-peerdup]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:-$REPO_ROOT/target/debug/rust-peerdup}"
[ -x "$BIN" ] || { echo "no binary at $BIN" >&2; exit 1; }
command -v dbus-daemon >/dev/null 2>&1 \
    || { echo "dbus-daemon is required (dnf install dbus-daemon)" >&2; exit 1; }

SCRATCH="$(mktemp -d /tmp/peerdup-e2e-isolation.XXXXXX)"
TIMEOUT="${PEERDUP_E2E_TIMEOUT:-90}"
QUIET="${PEERDUP_E2E_QUIET:-20}"   # how long "never arrives" is watched
BUS="unix:path=$SCRATCH/bus"
declare -A PID

ok()   { printf '\033[1;32m  ok\033[0m %s\n' "$*"; }
info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
fail() {
    printf '\033[1;31mFAIL\033[0m %s\n' "$*" >&2
    for p in a b c bus; do
        echo "---- ${p} log (tail) ----" >&2
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
# A client command through A's running daemon, over the private bus.
viabus() { DBUS_SESSION_BUS_ADDRESS="$BUS" "$BIN" "$@"; }
start() { pd "$1" serve --no-dbus >>"$SCRATCH/$1.log" 2>&1 & PID[$1]=$!; }
start_a() {
    DBUS_SESSION_BUS_ADDRESS="$BUS" \
        RUST_LOG="rust_peerdup=info,p2panda_net::iroh_endpoint::authoriser=warn" \
        "$BIN" --data-dir "$(data a)" serve >>"$SCRATCH/a.log" 2>&1 &
    PID[a]=$!
}

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
# The id of the share of daemon $1 whose folder is $2 (share-list: ID ROLE NAME PATH).
id_of() { pd "$1" share-list | awk -v p="$2" 'NR > 1 && $4 == p {print $1}'; }
# Log lines of daemon $1 that contain both $2 and $3.
lines() { grep -F -- "$2" "$SCRATCH/$1.log" 2>/dev/null | grep -F -- "$3" || true; }
count() { lines "$@" | grep -c . || true; }

export RUST_LOG="${RUST_LOG:-rust_peerdup=info}"

info "A private session bus for A"
cat >"$SCRATCH/bus.conf" <<EOF
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>$BUS</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
EOF
dbus-daemon --config-file="$SCRATCH/bus.conf" --nofork --nopidfile >"$SCRATCH/bus.log" 2>&1 &
PID[bus]=$!
wait_for "the bus listens" test -S "$SCRATCH/bus"

info "A makes X and Y, both named photos; B joins both, C joins Y"
for r in a-x a-y b-x b-y c-y c-z; do mkdir -p "$(root "$r")"; done
echo "x from A" > "$(root a-x)/x.txt"
echo "y from A" > "$(root a-y)/y.txt"
pd a share-add --name photos --path "$(root a-x)" --role sync >/dev/null
pd a share-add --name photos --path "$(root a-y)" --role sync >/dev/null
X="$(id_of a "$(root a-x)")"; Y="$(id_of a "$(root a-y)")"
[ -n "$X" ] && [ -n "$Y" ] || fail "no share ids (X=$X Y=$Y)"
[ "$X" != "$Y" ] || fail "two shares named photos got the same id $X"
pub_b="$(pd b whoami)"; pub_c="$(pd c whoami)"
pd a share-invite "$X" "$pub_b" --auth-role writer 2>/dev/null | pd b share-join - --path "$(root b-x)" >/dev/null
pd a share-invite "$Y" "$pub_b" --auth-role writer 2>/dev/null | pd b share-join - --path "$(root b-y)" >/dev/null
pd a share-invite "$Y" "$pub_c" --auth-role writer 2>/dev/null | pd c share-join - --path "$(root c-y)" >/dev/null
echo "C's own photos" > "$(root c-z)/own.txt"
pd c share-add --name photos --path "$(root c-z)" --role sync >/dev/null
Z="$(id_of c "$(root c-z)")"
[ -n "$Z" ] && [ "$Z" != "$X" ] && [ "$Z" != "$Y" ] || fail "C's own photos share has id $Z"
ok "three shares named photos, three ids: X=$X Y=$Y, C's own Z=$Z"
for p in a c; do
    perms="$(stat -c %a "$(data "$p")"/shares/*/share.json | sort -u)"
    [ "$perms" = 600 ] || fail "${p^^}'s share.json files are mode $perms, not 600"
done
ok "share.json (it holds the topic secret) is 0600"

start_a; start b; start c
wait_for "A registers on its session bus" grep -q "registered on session bus" "$SCRATCH/a.log"
wait_for "X's file reaches B" has b-x "x from A" x.txt
wait_for "Y's file reaches B" has b-y "y from A" y.txt
wait_for "Y's file reaches C" has c-y "y from A" y.txt
z_hears_a() { exists c-z x.txt || exists c-z y.txt || [ "$(count c "received remote announce" "$Z")" -gt 0 ]; }
never "anything of A's shares reaches C's own photos share" z_hears_a

info "A revokes B from Y while it runs (over D-Bus)"
viabus share-revoke "$Y" "$pub_b" >/dev/null || fail "revoking B from Y over D-Bus failed"
viabus share-members "$Y" | grep -q "$pub_b" && fail "B is still a member of Y"
ok "B is no longer a member of Y"
echo "y after revoking B" > "$(root a-y)/y2.txt"
wait_for "Y's new file reaches C" has c-y "y after revoking B" y2.txt
gate_refused_b() { [ "$(count a "refused a blob request: not a member of the share it belongs to" "node=$pub_b")" -gt 0 ]; }
wait_for "A's blob gate refuses B's requests for Y's blobs" gate_refused_b
lines a "refused a blob request" "node=$pub_b" | head -1 | cut -c1-220 | sed 's/^/    /'
never "Y's new file reaches B" exists b-y y2.txt
a_cut_b() { [ "$(count a "no longer a member of any share" "node=$pub_b")" -gt 0 ]; }
a_cut_b && fail "A cut B off although B is still a member of X"
ok "A kept B's connection: B is still a member of X"
echo "x again" > "$(root a-x)/x2.txt"
wait_for "X still syncs with B" has b-x "x again" x2.txt

info "A revokes B from X too: B is in none of A's shares"
heard_before="$(count b "received remote announce" "$X")"
blocked_before="$(count a "blocked" "connection attempt")"
viabus share-revoke "$X" "$pub_b" >/dev/null || fail "revoking B from X over D-Bus failed"
wait_for "A cuts B off" a_cut_b
cut_line="$(lines a "no longer a member of any share" "node=$pub_b" | head -1)"
echo "$cut_line" | cut -c1-220 | sed 's/^/    /'
echo "$cut_line" | grep -qE "closed=[1-9]" || fail "A had no live connection to B to close"
ok "A closed B's live connections"

echo "x after revoking B" > "$(root a-x)/x3.txt"
published() { [ "$(count a "local change detected" "$X")" -ge 2 ]; }
wait_for "A publishes its edit to X" published
b_heard() { exists b-x x3.txt || [ "$(count b "received remote announce" "$X")" -gt "$heard_before" ]; }
never "B hears of A's edit to X" b_heard
blocked_after="$(count a "blocked" "connection attempt")"
info "A refused $((blocked_after - blocked_before)) connection attempt(s) since (B's, and A's own to B)"

for p in a b c; do
    kill -0 "${PID[$p]}" 2>/dev/null || fail "daemon ${p^^} exited early"
done
ok "all three daemons still running"
info "e2e-isolation passed"
