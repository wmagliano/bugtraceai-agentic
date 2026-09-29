#!/usr/bin/env bash
set -euo pipefail

PROJECT="${1:-$PWD}"
PROJECT="$(realpath "$PROJECT")"

OUT="bugtraceai_source_$(date +%Y%m%d_%H%M%S).tar.gz"

echo "[+] Proyecto: $PROJECT"
echo "[+] Generando: $OUT"

tar \
    --exclude='.git' \
    --exclude='venv' \
    --exclude='.venv' \
    --exclude='__pycache__' \
    --exclude='node_modules' \
    --exclude='logs' \
    --exclude='runs' \
    --exclude='runtime' \
    --exclude='artifacts' \
    --exclude='forensics' \
    --exclude='forensic*' \
    --exclude='models' \
    --exclude='model' \
    --exclude='weights' \
    --exclude='*.gguf' \
    --exclude='*.bin' \
    --exclude='*.pcap' \
    --exclude='*.cap' \
    --exclude='*.core' \
    --exclude='*.sqlite' \
    --exclude='*.db' \
    --exclude='*.zip' \
    --exclude='*.tar' \
    --exclude='*.tar.gz' \
    --exclude='*.7z' \
    --exclude='*.log' \
    --exclude='*.csv' \
    --exclude='*.png' \
    --exclude='*.jpg' \
    --exclude='*.jpeg' \
    --exclude='*.gif' \
    --exclude='*.mp4' \
    --exclude='*.mp3' \
    --exclude='*.wav' \
    --exclude='*.pdf' \
    --exclude='*.docx' \
    --exclude='*.pptx' \
    --exclude='*.xlsx' \
    --exclude='*.env' \
    --exclude='*cookie*' \
    --exclude='*session*' \
    --exclude='*.pem' \
    --exclude='*.key' \
    -czf "$OUT" \
    -C "$(dirname "$PROJECT")" \
    "$(basename "$PROJECT")"

echo
echo "[OK] Archivo generado:"
echo "    $OUT"
echo

echo "[+] Tamaño:"
du -h "$OUT"

echo
echo "[+] Contenido (primeros 100 archivos):"
tar -tf "$OUT" | head -100

