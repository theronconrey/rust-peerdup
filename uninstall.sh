#!/usr/bin/env bash
# rust-peerdup uninstaller
#
# Stops the systemd user service if running, removes the binary at
# ~/.local/bin/rust-peerdup, and removes the unit at
# ~/.config/systemd/user/rust-peerdup.service.
#
# Does NOT delete your data directory (~/.local/share/rust-peerdup) or
# any share roots — this is intentional, removing the tool shouldn't
# lose user content.

set -euo pipefail

BIN_DIR="$HOME/.local/bin"
UNIT_DIR="$HOME/.config/systemd/user"
BIN_NAME="rust-peerdup"
UNIT_NAME="rust-peerdup.service"

info()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m  ok\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m warn\033[0m %s\n' "$*"; }

if command -v systemctl >/dev/null 2>&1; then
    if systemctl --user --quiet is-active "$UNIT_NAME"; then
        info "Stopping peerdup..."
        systemctl --user stop "$UNIT_NAME" || true
    fi
    if systemctl --user --quiet is-enabled "$UNIT_NAME" 2>/dev/null; then
        info "Disabling peerdup..."
        systemctl --user disable "$UNIT_NAME" || true
    fi
fi

if [ -f "$UNIT_DIR/$UNIT_NAME" ]; then
    rm -f "$UNIT_DIR/$UNIT_NAME"
    ok "Removed $UNIT_DIR/$UNIT_NAME"
fi

if [ -x "$BIN_DIR/$BIN_NAME" ] || [ -L "$BIN_DIR/$BIN_NAME" ]; then
    rm -f "$BIN_DIR/$BIN_NAME"
    ok "Removed $BIN_DIR/$BIN_NAME"
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl --user daemon-reload || true
fi

DATA_DIR="$HOME/.local/share/rust-peerdup"
if [ -d "$DATA_DIR" ]; then
    warn "Data directory left in place: $DATA_DIR"
    warn "Delete manually with 'rm -rf $DATA_DIR' if you want a clean wipe."
fi

ok "rust-peerdup uninstalled."
