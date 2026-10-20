#!/usr/bin/env bash
set -euo pipefail

SRC="${1:-./agents}"
DEST="/opt/edr"

if [[ $EUID -ne 0 ]]; then
    echo "Run as root (sudo)." >&2
    exit 1
fi

if [[ ! -d "$SRC" ]]; then
    echo "Source directory not found: $SRC" >&2
    exit 1
fi

if [[ -d "$DEST" ]]; then
    rm -rf $DEST
fi

mkdir -p "$DEST"

apt install python3-watchdog python3-psutil python3-yaml python3-flask python3-requests

# Trailing "/." copies contents (including dotfiles) and preserves attributes
cp -a "$SRC"/. "$DEST"/

# Root-owned, not writable by others, since this will run as root
chown -R root:root "$DEST"
chmod -R go-w "$DEST"

echo "Copied $SRC -> $DEST"

SYSTEMD_DIR="/etc/systemd/system"

for f in services/*.service; do
    [[ -e "$f" ]] || continue
    unit="$(basename "$f")"
    target="$SYSTEMD_DIR/$unit"

    if [[ -e "$target" || -L "$target" ]]; then
        echo "Removing existing $unit"
        systemctl disable --now "$unit" 2>/dev/null || true
        rm -f -- "$target"
    fi

    install -o root -g root -m 644 "$f" "$target"
    systemctl enable "$unit"
done

systemctl daemon-reload

# Start (or restart) the units after the reload picks up the new definitions
for f in services/*.service; do
    [[ -e "$f" ]] || continue
    systemctl restart "$(basename "$f")"
done
