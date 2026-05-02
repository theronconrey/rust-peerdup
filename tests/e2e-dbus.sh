#!/usr/bin/env bash
# Phase 7: D-Bus IPC end-to-end smoke test.
#
# Spins up an isolated XDG_DATA_HOME that the daemon will use both for its
# data dir and (more importantly) for the activation .service file the
# session bus reads. Then confirms:
#
#   1. Without any prior daemon, `org.peerdup.Daemon1` is NOT yet a name
#      the bus has seen.
#   2. Calling `rust-peerdup whoami` succeeds, and after the call the bus
#      has activated the daemon — its name appears on `busctl --user list`
#      and a `rust-peerdup ... serve` process is alive.
#   3. `busctl --user introspect` exposes all 10 methods.
#   4. `share-add` / `share-list` round-trip works via D-Bus.
#   5. Stopping the daemon and re-calling `share-list` re-activates it
#      and the previously added share is still there.
#
# Run from the repo root:
#   ./tests/e2e-dbus.sh
#
# Requirements: a session bus (DBUS_SESSION_BUS_ADDRESS or
# $XDG_RUNTIME_DIR/bus), busctl, pgrep, and a `cargo build --release`-ready
# toolchain.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

RUN_ID="$$-$(date +%s)"
SCRATCH="/tmp/peerdup-dbus-e2e-${RUN_ID}"
DATA_DIR="${SCRATCH}/data"
SHARE_DIR="${SCRATCH}/share"
DBUS_DIR="${SCRATCH}/dbus-1/services"
DBUS_NAME="org.peerdup.Daemon1"
TOPIC="dbus-e2e-${RUN_ID}"

BIN="${REPO_ROOT}/target/release/rust-peerdup"

ok()   { printf '\033[1;32m  ok\033[0m %s\n' "$*"; }
info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

cleanup() {
    set +e
    # Best-effort: stop the activated daemon if it's still around. We
    # identify it by its data-dir path on the cmdline so we don't kill
    # the user's real daemon.
    if pids=$(pgrep -f "rust-peerdup.*${DATA_DIR}" 2>/dev/null); then
        echo "$pids" | xargs -r kill -TERM 2>/dev/null
        sleep 1
        echo "$pids" | xargs -r kill -KILL 2>/dev/null
    fi
    rm -rf "$SCRATCH"
}
trap cleanup EXIT INT TERM

# ── Preflight ────────────────────────────────────────────────────────────────

command -v busctl >/dev/null 2>&1 || fail "busctl is required"
command -v pgrep  >/dev/null 2>&1 || fail "pgrep is required"

if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ] && [ ! -e "${XDG_RUNTIME_DIR:-/missing}/bus" ]; then
    fail "no session bus available (DBUS_SESSION_BUS_ADDRESS unset and \$XDG_RUNTIME_DIR/bus missing). Run inside a desktop session or wrap in dbus-run-session."
fi

if [ ! -x "$BIN" ]; then
    info "Building release binary..."
    if [ -f "$HOME/.cargo/env" ]; then
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
    fi
    cargo build --release >/dev/null
fi
[ -x "$BIN" ] || fail "release binary missing at $BIN"

# Refuse to run if the user's real activation file is already present —
# the bus would prefer it to ours and we'd fight for the bus name. Tell
# the user to uninstall first.
USER_DBUS="$HOME/.local/share/dbus-1/services/${DBUS_NAME}.service"
if [ -f "$USER_DBUS" ]; then
    fail "an existing activation file is present at $USER_DBUS; remove it (./uninstall.sh) before running this test"
fi

# ── 1. Lay down the activation file in our private XDG_DATA_HOME ────────────

mkdir -p "$DBUS_DIR" "$DATA_DIR" "$SHARE_DIR"
# We need to point Exec= at *this* test's binary path (with --data-dir
# override and a non-default BT port so we don't collide with the user's
# real install if it's running on 41000).
TEST_PORT="41099"
cat > "${DBUS_DIR}/${DBUS_NAME}.service" <<EOF
[D-BUS Service]
Name=${DBUS_NAME}
Exec=${BIN} --data-dir ${DATA_DIR} serve --bt-port ${TEST_PORT}
EOF
ok "wrote ${DBUS_DIR}/${DBUS_NAME}.service"

# Override XDG_DATA_DIRS so the bus looks at our scratch first. The
# session bus picks up activation files from
# $XDG_DATA_HOME/dbus-1/services and $XDG_DATA_DIRS/dbus-1/services on
# startup; we can't restart the bus from inside a test, but we *can*
# point the env at our scratch so subsequent CLI invocations
# (which bring their own connection) see the activation file.
#
# Actually, the bus reads its directory list at startup, NOT per-call.
# To get it to see our activation file we have to either:
#   (a) restart the bus (intrusive on a desktop session), or
#   (b) use the `--watch-bind` / "ReloadConfig" path: dbus-broker reloads
#       directories on `org.freedesktop.DBus.ReloadConfig` (no-op on
#       classic dbus-daemon — works on dbus-broker which Fedora ships).
#
# Try the reload; if it fails we tell the user.
export XDG_DATA_HOME="$SCRATCH"
busctl --user call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig >/dev/null 2>&1 \
    || true

# Verify the bus does NOT yet have an active org.peerdup.Daemon1 owner.
if busctl --user list 2>/dev/null | awk '{print $1}' | grep -qx "${DBUS_NAME}"; then
    fail "${DBUS_NAME} already owns a name on the session bus before our daemon ran"
fi
ok "pre-test: ${DBUS_NAME} is not currently active"

# ── 2. Whoami should auto-activate the daemon ────────────────────────────────

info "Calling 'rust-peerdup whoami' (should auto-activate)..."
WHOAMI_OUT=$("$BIN" whoami 2>&1) || fail "whoami failed: $WHOAMI_OUT"
[ "${#WHOAMI_OUT}" -eq 64 ] || fail "whoami output was not 64 hex chars: '$WHOAMI_OUT'"
ok "whoami returned: $WHOAMI_OUT"

# Now the daemon should be running and the bus name should be live.
sleep 1
if ! busctl --user list 2>/dev/null | awk '{print $1}' | grep -qx "${DBUS_NAME}"; then
    fail "after whoami, ${DBUS_NAME} is still not on the bus — activation failed"
fi
ok "${DBUS_NAME} is now active on the bus"

if ! pgrep -f "rust-peerdup.*${DATA_DIR}" >/dev/null 2>&1; then
    fail "no rust-peerdup serve process found for ${DATA_DIR}"
fi
ok "daemon process is alive"

# ── 3. Introspection: all 10 methods present ────────────────────────────────

INTROSPECT=$(busctl --user introspect "${DBUS_NAME}" /org/peerdup/Daemon1 2>&1) \
    || fail "introspect failed: $INTROSPECT"

for method in Whoami ShareList ShareAdd ShareJoin ShareInvite ShareRevoke \
              ShareMembers SharePeers ShareRotateKey ShareRemove; do
    if ! echo "$INTROSPECT" | grep -q "\.${method} "; then
        if ! echo "$INTROSPECT" | grep -q " ${method} "; then
            echo "$INTROSPECT" >&2
            fail "introspection missing method ${method}"
        fi
    fi
done
ok "all 10 methods present in introspection"

# ── 4. share-add + share-list round-trip ─────────────────────────────────────

mkdir -p "$SHARE_DIR"
echo "phase7-content" > "$SHARE_DIR/file1.txt"
"$BIN" share-add --topic "$TOPIC" --path "$SHARE_DIR" --role sync >/dev/null \
    || fail "share-add via D-Bus failed"
ok "share-add succeeded"

LIST_OUT=$("$BIN" share-list)
echo "$LIST_OUT" | grep -q "$TOPIC" || { echo "$LIST_OUT"; fail "share-list output missing $TOPIC"; }
SHARE_ID=$(echo "$LIST_OUT" | tail -1 | awk '{print $1}')
[ -n "$SHARE_ID" ] || fail "could not extract share id from share-list"
ok "share-list shows the new share: $SHARE_ID"

# ── 5. Stop daemon, share-list re-activates and persists ─────────────────────

info "Stopping the activated daemon..."
PID=$(pgrep -f "rust-peerdup.*${DATA_DIR}" | head -1)
[ -n "$PID" ] || fail "no PID to kill"
kill -TERM "$PID"
# Give it a moment to release the bus name.
for _ in $(seq 1 10); do
    if ! pgrep -f "rust-peerdup.*${DATA_DIR}" >/dev/null 2>&1; then break; fi
    sleep 1
done
if pgrep -f "rust-peerdup.*${DATA_DIR}" >/dev/null 2>&1; then
    fail "daemon did not stop after SIGTERM"
fi
ok "daemon stopped"

# Now re-call share-list. The bus should re-activate.
LIST_OUT2=$("$BIN" share-list)
echo "$LIST_OUT2" | grep -q "$TOPIC" || { echo "$LIST_OUT2"; fail "after re-activation, share-list lost the share"; }
ok "re-activated daemon still has the share"

if ! pgrep -f "rust-peerdup.*${DATA_DIR}" >/dev/null 2>&1; then
    fail "daemon did not re-activate"
fi
ok "daemon re-activated by share-list call"

# ── Done ────────────────────────────────────────────────────────────────────

printf '\n\033[1;32mPhase 7: D-Bus IPC e2e passed.\033[0m\n'
