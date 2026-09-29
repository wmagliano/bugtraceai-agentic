#!/usr/bin/env bash
set -Eeuo pipefail

# BugTraceAI - Recolector de contexto para migración a v3.0.0
# Uso:
#   chmod +x collect_bugtraceai_context.sh
#   ./collect_bugtraceai_context.sh /ruta/al/proyecto
#
# Opcional:
#   ./collect_bugtraceai_context.sh /ruta/al/proyecto salida.tar.gz

PROJECT_DIR="${1:-$PWD}"
PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT_FILE="${2:-$PWD/bugtraceai_context_${STAMP}.tar.gz}"
WORK_DIR="$(mktemp -d)"
BUNDLE_DIR="$WORK_DIR/bugtraceai_context"

cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

mkdir -p "$BUNDLE_DIR/project" "$BUNDLE_DIR/metadata" "$BUNDLE_DIR/recent_logs"

echo "[+] Proyecto: $PROJECT_DIR"
echo "[+] Salida:   $OUT_FILE"

{
  echo "collected_at=$(date -Iseconds)"
  echo "hostname=$(hostname 2>/dev/null || true)"
  echo "user=$(id -un 2>/dev/null || true)"
  echo "project_dir=$PROJECT_DIR"
  echo "kernel=$(uname -a 2>/dev/null || true)"
  echo "python=$(python3 --version 2>&1 || true)"
  echo "bash=$BASH_VERSION"
} > "$BUNDLE_DIR/metadata/system.txt"

if command -v tree >/dev/null 2>&1; then
  tree -a -L 4 -I '.git|venv|.venv|__pycache__|node_modules|models|model|weights|artifacts|runs|tmp' \
    "$PROJECT_DIR" > "$BUNDLE_DIR/metadata/project_tree.txt" 2>&1 || true
else
  find "$PROJECT_DIR" -maxdepth 4 \
    -not -path '*/.git/*' -not -path '*/venv/*' -not -path '*/.venv/*' \
    -not -path '*/__pycache__/*' -not -path '*/node_modules/*' \
    -not -path '*/models/*' -not -path '*/model/*' \
    -printf '%P\n' | sort > "$BUNDLE_DIR/metadata/project_tree.txt"
fi

find "$PROJECT_DIR" -type f \
  -not -path '*/.git/*' -not -path '*/venv/*' -not -path '*/.venv/*' \
  -not -path '*/__pycache__/*' -not -path '*/node_modules/*' \
  -printf '%s\t%P\n' 2>/dev/null | sort -n > "$BUNDLE_DIR/metadata/file_inventory.tsv"

python3 -m pip freeze > "$BUNDLE_DIR/metadata/pip_freeze.txt" 2>/dev/null || true

if git -C "$PROJECT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  mkdir -p "$BUNDLE_DIR/metadata/git"
  git -C "$PROJECT_DIR" status --short > "$BUNDLE_DIR/metadata/git/status.txt" 2>&1 || true
  git -C "$PROJECT_DIR" log --oneline --decorate -n 50 > "$BUNDLE_DIR/metadata/git/log.txt" 2>&1 || true
  git -C "$PROJECT_DIR" diff > "$BUNDLE_DIR/metadata/git/working_tree.diff" 2>&1 || true
  git -C "$PROJECT_DIR" diff --cached > "$BUNDLE_DIR/metadata/git/staged.diff" 2>&1 || true
  git -C "$PROJECT_DIR" branch --show-current > "$BUNDLE_DIR/metadata/git/branch.txt" 2>&1 || true
  git -C "$PROJECT_DIR" remote -v | sed -E 's#(https?://)[^/@]+:[^/@]+@#\1REDACTED@#g' \
    > "$BUNDLE_DIR/metadata/git/remotes.txt" 2>&1 || true
fi

is_sensitive_path() {
  local rel="$1"
  case "$rel" in
    *.pem|*.key|*.p12|*.pfx|*.crt|*.cer|*.kdbx|*.sqlite|*.db) return 0 ;;
    *.env|.env|*/.env|*/.env.*) return 0 ;;
    *cookie*|*cookies*|*session_cookie*|*dvwa_cookie*) return 0 ;;
    *secret*|*secrets*|*credential*|*credentials*) return 0 ;;
    *id_rsa*|*id_ed25519*|*authorized_keys*) return 0 ;;
  esac
  return 1
}

while IFS= read -r -d '' src; do
  rel="${src#$PROJECT_DIR/}"
  case "$rel" in
    .git/*|venv/*|.venv/*|*/venv/*|*/.venv/*|*/__pycache__/*|\
    node_modules/*|*/node_modules/*|models/*|model/*|weights/*|\
    */models/*|*/model/*|*/weights/*|artifacts/*|*/artifacts/*|\
    runs/*|*/runs/*|tmp/*|*/tmp/*) continue ;;
  esac

  if is_sensitive_path "$rel"; then
    echo "$rel" >> "$BUNDLE_DIR/metadata/excluded_sensitive_files.txt"
    continue
  fi

  case "$rel" in
    *.py|*.sh|*.bash|*.zsh|*.fish|*.json|*.jsonl|*.yaml|*.yml|*.toml|*.ini|*.cfg|*.conf|\
    *.md|*.txt|*.rst|*.prompt|Dockerfile|docker-compose.yml|docker-compose.yaml|Makefile|\
    requirements*.txt|pyproject.toml|poetry.lock|Pipfile|Pipfile.lock|*.service|*.timer)
      mkdir -p "$BUNDLE_DIR/project/$(dirname "$rel")"
      cp -a "$src" "$BUNDLE_DIR/project/$rel"
      ;;
  esac
done < <(find "$PROJECT_DIR" -type f -print0)

if [[ -d "$PROJECT_DIR/logs" ]]; then
  mapfile -t RECENT_LOGS < <(
    find "$PROJECT_DIR/logs" -type f \
      -not -iname '*cookie*' -not -iname '*login*.html' -not -iname '*security*.html' \
      -not -iname '*.pcap' -printf '%T@\t%p\n' 2>/dev/null \
      | sort -nr | head -n 50 | cut -f2-
  )

  for src in "${RECENT_LOGS[@]:-}"; do
    [[ -f "$src" ]] || continue
    size="$(stat -c '%s' "$src" 2>/dev/null || echo 0)"
    if (( size > 5242880 )); then
      rel="${src#$PROJECT_DIR/}"
      echo -e "${size}\t${rel}" >> "$BUNDLE_DIR/metadata/excluded_large_logs.tsv"
      continue
    fi
    rel="${src#$PROJECT_DIR/}"
    mkdir -p "$BUNDLE_DIR/recent_logs/$(dirname "$rel")"
    cp -a "$src" "$BUNDLE_DIR/recent_logs/$rel"
  done
fi

while IFS= read -r -d '' src; do
  rel="${src#$PROJECT_DIR/}"
  case "$rel" in logs/*|*cookie*|*login*.html|*security*.html) continue ;; esac
  size="$(stat -c '%s' "$src" 2>/dev/null || echo 0)"
  (( size <= 5242880 )) || continue
  mkdir -p "$BUNDLE_DIR/recent_logs/$(dirname "$rel")"
  cp -a "$src" "$BUNDLE_DIR/recent_logs/$rel"
done < <(
  find "$PROJECT_DIR" -type f \
    \( -iname '*telemetry*.jsonl' -o -iname '*trace*.jsonl' -o -iname '*decision*.jsonl' \
       -o -iname '*lifecycle*.jsonl' -o -iname '*contract*.jsonl' \
       -o -iname '*snapshot*.json' -o -iname 'knowledge.json' \) -print0 2>/dev/null
)

mkdir -p "$BUNDLE_DIR/metadata/grep"
grep -RInE --exclude-dir=.git --exclude-dir=venv --exclude-dir=.venv \
  --exclude-dir=__pycache__ --exclude-dir=node_modules --exclude='*.jsonl' \
  'class .*TUI|Textual|rich\.|App\(|run_tui|cassette|reasoner|executor|scheduler|analysis_queue|technical contract|MCP|telemetry|jsonl' \
  "$PROJECT_DIR" > "$BUNDLE_DIR/metadata/grep/architecture_hits.txt" 2>/dev/null || true

grep -RInE --exclude-dir=.git --exclude-dir=venv --exclude-dir=.venv \
  --exclude-dir=__pycache__ --exclude-dir=node_modules --exclude='*.jsonl' \
  'llama|8080|9001|BUGTRACEAI_|TARGET_HOST|ALLOWED_BINARIES|command_substitution|backtick|shell operator' \
  "$PROJECT_DIR" > "$BUNDLE_DIR/metadata/grep/runtime_hits.txt" 2>/dev/null || true

cat > "$BUNDLE_DIR/README_COLLECTION.txt" <<'TXT'
Paquete de contexto para revisar BugTraceAI y preparar la migración a v3.0.0.

Incluye código, configuración, prompts, estructura, información Git,
dependencias y telemetría reciente.

Excluye intencionalmente .env, secretos, cookies, sesiones, claves,
bases de datos, modelos GGUF, entornos virtuales, node_modules y binarios grandes.

Antes de compartir:
  tar -tzf archivo.tar.gz | less
TXT

mkdir -p "$(dirname "$OUT_FILE")"
tar -C "$WORK_DIR" -czf "$OUT_FILE" "$(basename "$BUNDLE_DIR")"
sha256sum "$OUT_FILE" | tee "${OUT_FILE}.sha256" 2>/dev/null || true

echo
echo "[OK] Paquete generado:"
echo "     $OUT_FILE"
echo
echo "Subí estos dos archivos:"
echo "     $(basename "$OUT_FILE")"
echo "     $(basename "$OUT_FILE").sha256"
