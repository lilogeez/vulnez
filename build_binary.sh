#!/usr/bin/env bash
set -euo pipefail
PY=python3
OUT=dist

rm -rf $OUT build || true

# Try one-file; fallback to one-folder if failed
$PY -m PyInstaller --name vulnez --onefile vulnez/cli.py || {
  echo "PyInstaller onefile failed, trying one-folder..."
  $PY -m PyInstaller --name vulnez vulnez/cli.py
}
echo "Binary build complete. Check dist/"
