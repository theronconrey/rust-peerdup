#!/usr/bin/env bash
# Phase 5e: 4-peer revocation end-to-end test.
#
# Spins up peer A on the host (in a temp data dir, NOT the user's real
# install) plus peers B, C, D as podman containers, all on `--network
# host` with distinct BT ports. Walks through:
#
#   1. A creates a share, invites B/C/D as writers.
#   2. All four daemons start. A drops a file into the share root.
#   3. Verify B, C, D all receive the file (initial sync works).
#   4. A revokes B. A's daemon restarts to broadcast the rotation.
#   5. Verify keyring sizes after rotation:
#        A=64B (epoch 2 appended), C=64B (received), D=64B (received),
#        B=32B (revoked, no envelope addressed to B).
#   6. A writes a new file under epoch 2.
#   7. Verify C and D get the plaintext; B downloads the ciphertext
#      shadow blob but cannot decrypt it (no plaintext lands in B's
#      share root).
#   8. Verify share-members shows {A, C, D} on each remaining peer.
#
# Exit code 0 = all assertions hold. Non-zero with a FAIL line on the
# first violated assertion. The cleanup trap stops containers and wipes
# scratch dirs so reruns don't collide.
#
# Usage (from repo root):
#   ./tests/e2e-revoke.sh
#
# Requirements: podman, a `cargo build --release`-ready toolchain (the
# script will build if `target/release/rust-peerdup` is missing). The
# `containers/Containerfile` image must already be built — do that
# once with:
#   podman build -t rust-peerdup-peer -f containers/Containerfile .

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Per-run unique suffix so reruns don't collide.
RUN_ID="$$-$(date +%s)"
DATA_A="/tmp/peerdup-e2e-a-${RUN_ID}"
SHARE_A="/tmp/peerdup-e2e-a-share-${RUN_ID}"
PEERS=(b c d)
PORTS=(41001 41002 41003)
TOPIC="e2e-revoke-${RUN_ID}"
BIN="${REPO_ROOT}/target/release/rust-peerdup"

declare -A DATA_DIR SHARE_DIR PUBKEY
for p in "${PEERS[@]}"; do
    DATA_DIR[$p]="/tmp/peerdup-e2e-${p}-${RUN_ID}-data"
    SHARE_DIR[$p]="/tmp/peerdup-e2e-${p}-${RUN_ID}-share"
done

DAEMON_A_PID=""

ok()   { printf '\033[1;32m  ok\033[0m %s\n' "$*"; }
info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

cleanup() {
    set +e
    # On failure, dump B's container logs to /tmp/ so the cause is visible
    # after teardown. On success the test produced its own evidence.
    if [ -n "${B_LOG_DUMP:-}" ]; then
        podman logs "peer-b-${RUN_ID}" >"$B_LOG_DUMP" 2>&1 || true
    fi
    if [ -n "$DAEMON_A_PID" ] && kill -0 "$DAEMON_A_PID" 2>/dev/null; then
        kill -TERM "$DAEMON_A_PID" 2>/dev/null
        wait "$DAEMON_A_PID" 2>/dev/null
    fi
    for p in "${PEERS[@]}"; do
        podman rm -f "peer-${p}-${RUN_ID}" 2>/dev/null
    done
    rm -rf "$DATA_A" "$SHARE_A"
    for p in "${PEERS[@]}"; do
        rm -rf "${DATA_DIR[$p]}" "${SHARE_DIR[$p]}"
    done
}
trap cleanup EXIT INT TERM

# Wrapper around containers/run-peer.sh so the per-peer env-var
# scaffolding is encapsulated and unique per run.
peer() {
    local p="$1"; shift
    PEER_NAME="peer-${p}-${RUN_ID}" \
    HOST_DATA="${DATA_DIR[$p]}" \
    HOST_SHARE="${SHARE_DIR[$p]}" \
    "${REPO_ROOT}/containers/run-peer.sh" "$@"
}

# ── Preflight ────────────────────────────────────────────────────────────────

command -v podman >/dev/null 2>&1 || fail "podman is required"
podman image exists rust-peerdup-peer \
    || fail "container image 'rust-peerdup-peer' not built. Run: podman build -t rust-peerdup-peer -f containers/Containerfile ."

if [ ! -x "$BIN" ]; then
    info "Building release binary..."
    if [ -f "$HOME/.cargo/env" ]; then
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
    fi
    cargo build --release >/dev/null
fi
[ -x "$BIN" ] || fail "release binary missing at $BIN"

# Make sure no stale containers from a previous failed run are around.
for p in "${PEERS[@]}"; do
    podman rm -f "peer-${p}-${RUN_ID}" 2>/dev/null || true
done

# ── 1. Identities ────────────────────────────────────────────────────────────

info "Generating identities for A, B, C, D..."
mkdir -p "$DATA_A" "$SHARE_A"
PUBKEY_A=$("$BIN" --data-dir "$DATA_A" whoami)
[ "${#PUBKEY_A}" -eq 64 ] || fail "A pubkey wrong length: ${#PUBKEY_A}"
ok "A: $PUBKEY_A"
for p in "${PEERS[@]}"; do
    PUBKEY[$p]=$(peer "$p" whoami)
    [ "${#PUBKEY[$p]}" -eq 64 ] || fail "${p^^} pubkey wrong length: ${#PUBKEY[$p]}"
    ok "${p^^}: ${PUBKEY[$p]}"
done

# ── 2. share-add + invite each ───────────────────────────────────────────────

info "A creates share and invites B, C, D..."
"$BIN" --data-dir "$DATA_A" share-add --topic "$TOPIC" --path "$SHARE_A" --role sync >/dev/null
SHARE_ID=$("$BIN" --data-dir "$DATA_A" share-list | tail -1 | awk '{print $1}')
[ -n "$SHARE_ID" ] || fail "could not capture SHARE_ID"
ok "share id: $SHARE_ID"

for p in "${PEERS[@]}"; do
    TICKET=$("$BIN" --data-dir "$DATA_A" share-invite "$SHARE_ID" "${PUBKEY[$p]}" --auth-role writer 2>/dev/null | grep -v '^#' | grep -v '^$')
    [ -n "$TICKET" ] || fail "ticket for ${p^^} was empty"
    peer "$p" share-join "$TICKET" --path /share >/dev/null
    ok "${p^^} joined"
done

# A authored every Add op locally, so its view is already complete. The
# joiners' tickets only carried the log up to their own Add — peer B
# doesn't yet know about C and D, etc. Cross-peer convergence happens
# once daemons run and gossip the auth ops.
A_MEMBERS=$("$BIN" --data-dir "$DATA_A" share-members "$SHARE_ID" | tail -n +2 | grep -c .)
[ "$A_MEMBERS" -eq 4 ] || fail "A sees $A_MEMBERS members after all invites, expected 4"
ok "A sees 4 members in the auth state (cross-peer convergence checked after daemons start)"

# ── 3. Initial content + start daemons ──────────────────────────────────────

echo "epoch1-content-${RUN_ID}" > "$SHARE_A/file1.txt"

info "Starting daemons (A foreground via &; B/C/D detached)..."
"$BIN" --data-dir "$DATA_A" serve --bt-port 41000 >/tmp/peerdup-a-${RUN_ID}.log 2>&1 &
DAEMON_A_PID=$!

for i in 0 1 2; do
    p="${PEERS[$i]}"
    port="${PORTS[$i]}"
    peer "$p" -d serve --bt-port "$port" >/dev/null
done

# Give discovery + initial fetch room. 10s announce tick + transfer.
sleep 12

# ── 4. Initial sync assertions ───────────────────────────────────────────────

for p in "${PEERS[@]}"; do
    [ -f "${SHARE_DIR[$p]}/file1.txt" ] || fail "${p^^} did not receive file1.txt"
done
ok "B, C, D all received file1.txt"

# Cross-peer auth convergence: now that all daemons have ticked at least
# once, each peer should have learned the full membership via gossip.
for who in A "${PEERS[@]}"; do
    if [ "$who" = "A" ]; then
        actual=$("$BIN" --data-dir "$DATA_A" share-members "$SHARE_ID" | tail -n +2 | grep -c .)
    else
        actual=$(peer "$who" share-members "$SHARE_ID" | tail -n +2 | grep -c .)
    fi
    [ "$actual" -eq 4 ] || fail "${who^^} sees $actual members after gossip, expected 4"
done
ok "post-gossip: all four peers converged on 4 members"

# Pre-revoke keyring sizes: all 32B (single epoch 1 key).
for who in A "${PEERS[@]}"; do
    if [ "$who" = "A" ]; then
        sz=$(stat -c '%s' "$DATA_A/shares/$SHARE_ID/keys.bin")
    else
        sz=$(stat -c '%s' "${DATA_DIR[$who]}/shares/$SHARE_ID/keys.bin")
    fi
    [ "$sz" -eq 32 ] || fail "${who^^} keys.bin pre-revoke is ${sz}B, expected 32"
done
ok "pre-revoke: all keyrings are 32B (single epoch 1)"

# ── 5. A revokes B + restart daemon to broadcast ─────────────────────────────

info "A revokes B and restarts daemon..."
"$BIN" --data-dir "$DATA_A" share-revoke "$SHARE_ID" "${PUBKEY[b]}" >/dev/null

# Restart A's daemon so the in-memory state picks up the new auth log + pending rotation.
kill -TERM "$DAEMON_A_PID"
wait "$DAEMON_A_PID" 2>/dev/null || true
"$BIN" --data-dir "$DATA_A" serve --bt-port 41000 >>/tmp/peerdup-a-${RUN_ID}.log 2>&1 &
DAEMON_A_PID=$!

# Wait long enough for at least one announce tick (10s) plus generous slack
# for the rotation envelope to reach C and D and be installed.
sleep 18

# ── 6. Post-revoke keyring assertions ────────────────────────────────────────

A_SZ=$(stat -c '%s' "$DATA_A/shares/$SHARE_ID/keys.bin")
B_SZ=$(stat -c '%s' "${DATA_DIR[b]}/shares/$SHARE_ID/keys.bin")
C_SZ=$(stat -c '%s' "${DATA_DIR[c]}/shares/$SHARE_ID/keys.bin")
D_SZ=$(stat -c '%s' "${DATA_DIR[d]}/shares/$SHARE_ID/keys.bin")

[ "$A_SZ" -eq 64 ] || fail "A keys.bin = ${A_SZ}B, expected 64 (rotation epoch 2 appended on revoke)"
[ "$C_SZ" -eq 64 ] || fail "C keys.bin = ${C_SZ}B, expected 64 (rotation envelope received + installed)"
[ "$D_SZ" -eq 64 ] || fail "D keys.bin = ${D_SZ}B, expected 64 (rotation envelope received + installed)"
[ "$B_SZ" -eq 32 ] || fail "B keys.bin = ${B_SZ}B, expected 32 (revoked, no envelope addressed to B)"
ok "post-revoke keyrings: A=64 B=32 C=64 D=64"

# Membership view: A, C, D should see 3 members; B should see 3 members but
# not include itself (B observed its own Remove via gossip).
for who in A c d; do
    if [ "$who" = "A" ]; then
        actual=$("$BIN" --data-dir "$DATA_A" share-members "$SHARE_ID" | tail -n +2 | grep -c .)
    else
        actual=$(peer "$who" share-members "$SHARE_ID" | tail -n +2 | grep -c .)
    fi
    [ "$actual" -eq 3 ] || fail "${who^^} sees $actual members post-revoke, expected 3"
done
ok "A, C, D each see exactly 3 members"

if peer b share-members "$SHARE_ID" | tail -n +2 | grep -q "${PUBKEY[b]}"; then
    fail "B still sees itself as a member after revoke; auth gossip didn't propagate"
fi
ok "B no longer sees itself as a member"

# ── 7. New content under epoch 2 ─────────────────────────────────────────────

info "A writes new content (will be encrypted under epoch 2)..."
echo "epoch2-secret-${RUN_ID}" > "$SHARE_A/secret.txt"
sleep 12

# Plaintext should reach C and D, NOT B.
[ -f "${SHARE_DIR[c]}/secret.txt" ] || fail "C did not receive secret.txt plaintext"
[ -f "${SHARE_DIR[d]}/secret.txt" ] || fail "D did not receive secret.txt plaintext"
if [ -f "${SHARE_DIR[b]}/secret.txt" ]; then
    fail "SECURITY: B received secret.txt plaintext after revoke"
fi
ok "C and D got plaintext; B did not"

# Content equality check on the lucky two.
diff -q "$SHARE_A/secret.txt" "${SHARE_DIR[c]}/secret.txt" >/dev/null || fail "C's plaintext differs from A's"
diff -q "$SHARE_A/secret.txt" "${SHARE_DIR[d]}/secret.txt" >/dev/null || fail "D's plaintext differs from A's"
ok "C and D plaintext byte-identical to A's"

# B should still pull the ciphertext blob over BT (Phase 6 will block this);
# the proof of correctness here is that B has the .bin but no plaintext.
[ -f "${SHARE_DIR[b]}/.peerdup/encrypted/secret.txt.bin" ] || fail "B did not even receive the ciphertext blob — gossip path is broken"
ok "B received ciphertext blob (will be plaintext-blocked in Phase 6)"

# Confirm B logged a decrypt-related warning (any of several substrings — the
# load-bearing assertion is "B has no plaintext", already passed). The
# decrypt-failure log can lag the actual fetch by a few seconds depending on
# how fast librqbit advertises completion; poll-with-timeout instead of
# checking once.
B_LOG_DUMP="/tmp/peerdup-e2e-b-${RUN_ID}.log"
LOG_FOUND=0
for _ in $(seq 1 15); do
    if podman logs "peer-b-${RUN_ID}" 2>&1 \
            | grep -E -q "no key for epoch|decrypting shadow|apply_remote failed"; then
        LOG_FOUND=1
        break
    fi
    sleep 1
done
if [ "$LOG_FOUND" -eq 1 ]; then
    ok "B logged a decrypt-related warning (expected)"
    B_LOG_DUMP=""  # success: don't keep the dump on cleanup
else
    podman logs "peer-b-${RUN_ID}" >"$B_LOG_DUMP" 2>&1 || true
    fail "B's logs lack the expected decrypt failure markers after 15s; full log saved to $B_LOG_DUMP"
fi

# ── Done ────────────────────────────────────────────────────────────────────

printf '\n\033[1;32mPhase 5e: all assertions passed.\033[0m\n'
