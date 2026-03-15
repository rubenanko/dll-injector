#!/usr/bin/env bash
# deploy.sh — build and copy artifacts to the Windows share
set -euo pipefail

SHARE="${SHARE:-$HOME/windows_share}"
MODE="${MODE:-debug}"

echo "[*] Building (MODE=$MODE)..."
make MODE="$MODE" clean all

echo "[*] Deploying to $SHARE ..."
mkdir -p "$SHARE"
cp -f build/dll-injector.exe build/injected-dll.dll "$SHARE/"

echo "[+] Done. Files in $SHARE:"
ls -lh "$SHARE/dll-injector.exe" "$SHARE/injected-dll.dll"
