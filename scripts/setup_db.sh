#!/usr/bin/env bash
set -euo pipefail
python3 - <<'PY'
from vulnez import db
print("[*] Inisialisasi database...")
db.init_db()
print("[+] Database siap.")
PY
