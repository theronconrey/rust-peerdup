#!/usr/bin/env bash
# rust-peerdup installer
#
# Builds the release binary, installs it to ~/.local/bin/rust-peerdup, and
# drops a systemd user unit at ~/.config/systemd/user/rust-peerdup.service
# so the daemon can be started with `systemctl --user start rust-peerdup`.
#
# Run from the repo root:
#   ./install.sh
#
# Idempotent: re-running upgrades the binary in place.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$HOME/.local/bin"
UNIT_DIR="$HOME/.config/systemd/user"
BIN_NAME="rust-peerdup"
UNIT_NAME="rust-peerdup.service"

info()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m  ok\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m warn\033[0m %s\n' "$*"; }
die()   { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# ── prerequisite checks ───────────────────────────────────────────────────────

[ -f "$REPO_ROOT/Cargo.toml" ] || die "must run from the rust-peerdup repo root (no Cargo.toml here)"
[ -f "$REPO_ROOT/systemd/$UNIT_NAME" ] || die "missing $REPO_ROOT/systemd/$UNIT_NAME"

if ! command -v cargo >/dev/null 2>&1; then
    if [ -f "$HOME/.cargo/env" ]; then
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
    fi
fi
command -v cargo >/dev/null 2>&1 || die "cargo not found - install rustup (https://rustup.rs) and retry"

if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemctl not found - the unit file will be installed but not enabled"
fi

# ── build ────────────────────────────────────────────────────────────────────

info "Building release binary..."
( cd "$REPO_ROOT" && cargo build --release )
[ -x "$REPO_ROOT/target/release/$BIN_NAME" ] || die "build did not produce target/release/$BIN_NAME"
ok "Built $REPO_ROOT/target/release/$BIN_NAME"

# ── install binary ───────────────────────────────────────────────────────────

mkdir -p "$BIN_DIR"
install -m 0755 "$REPO_ROOT/target/release/$BIN_NAME" "$BIN_DIR/$BIN_NAME"
ok "Installed $BIN_DIR/$BIN_NAME"

# ── install systemd user unit ────────────────────────────────────────────────

mkdir -p "$UNIT_DIR"
install -m 0644 "$REPO_ROOT/systemd/$UNIT_NAME" "$UNIT_DIR/$UNIT_NAME"
ok "Installed $UNIT_DIR/$UNIT_NAME"

if command -v systemctl >/dev/null 2>&1; then
    systemctl --user daemon-reload
    ok "systemd user daemon-reloaded"
fi

# ── PATH check ───────────────────────────────────────────────────────────────

if ! printf '%s' ":$PATH:" | grep -q ":$BIN_DIR:"; then
    warn "$BIN_DIR is not in your PATH"
    warn "Add to your shell profile then reopen the terminal:"
    printf '\n    export PATH="$HOME/.local/bin:$PATH"\n\n'
fi

# ── done ─────────────────────────────────────────────────────────────────────

cat <<EOF

$(printf '\033[1;32mrust-peerdup installed.\033[0m')

Quick reference:

  Print this peer's public key (share with the inviter):
      $BIN_NAME whoami

  Create a share (you become its Owner):
      $BIN_NAME share-add --topic <name> --path <folder> --role sync

  Invite another peer (they ran 'whoami' and sent you their pubkey):
      $BIN_NAME share-invite <share-id> <invitee-pubkey> --auth-role writer

  Join a share from a ticket:
      $BIN_NAME share-join <ticket> --path <local-folder>

  Inspect membership:
      $BIN_NAME share-members <share-id>

  Run the daemon as a systemd user service:
      systemctl --user enable --now rust-peerdup
      journalctl --user -u rust-peerdup -f    # follow logs
      systemctl --user stop rust-peerdup      # stop

  Or run it in the foreground for testing:
      $BIN_NAME serve --bt-port 41000

If you'll log out while the daemon should keep running, also enable lingering:
      sudo loginctl enable-linger \$USER
EOF
