#!/usr/bin/env bash
set -euo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSETS_DIR="$BASE_DIR/assets"
mkdir -p "$ASSETS_DIR"
cat > "$ASSETS_DIR/brute.txt" <<'EOF'
123456
12345
password
admin
qwerty
letmein
EOF
cat > "$ASSETS_DIR/benign_phpinfo.php" <<'EOF'
<?php
phpinfo();
?>
EOF
chmod 0644 "$ASSETS_DIR/brute.txt" "$ASSETS_DIR/benign_phpinfo.php"
echo "[OK] Assets generados en $ASSETS_DIR"
