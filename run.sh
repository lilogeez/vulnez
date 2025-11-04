#!/usr/bin/env bash
# run.sh - helper to activate venv and start VulnEZ menu or API
set -euo pipefail

if [ -f ".venv/bin/activate" ]; then
  source .venv/bin/activate
else
  echo "[!] No .venv found. Create and install requirements first:"
  echo "    python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt"
fi

if [ "${1:-}" = "api" ]; then
  uvicorn api.server:app --host 0.0.0.0 --port 8080 --reload
  exit 0
fi

python3 vulnez.py
