#!/usr/bin/env bash
set -euo pipefail
DEST=/tmp/bugtraceai-artifacts
mkdir -p "$DEST"
cp "$(dirname "$0")/artifacts/benign_phpinfo.jpg" "$DEST/benign_phpinfo.jpg"
chmod 0644 "$DEST/benign_phpinfo.jpg"
sha256sum "$DEST/benign_phpinfo.jpg"
file "$DEST/benign_phpinfo.jpg"
echo "[OK] Artefacto benigno instalado en $DEST/benign_phpinfo.jpg"
