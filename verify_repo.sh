#!/usr/bin/env bash
# verify_repo.sh - cek apakah semua file VulnEZ ada di repo
set -euo pipefail

ROOT=$(pwd)
missing=0

files=(
".gitignore"
"LICENSE"
"README.md"
"requirements.txt"
"config.yaml.example"
"install-deps.sh"
"run.sh"
"vulnez.py"
"runner.py"
"Dockerfile"
".github/workflows/ci.yml"
".pre-commit-config.yaml"
"scans/__init__.py"
"scans/amass_scan.py"
"scans/httpx_scan.py"
"scans/nuclei_scan.py"
"scans/masscan_scan.py"
"scans/nmap_scan.py"
"scans/auth_playwright.py"
"verifier/verify.py"
"storage/db.py"
"api/server.py"
"parser/nmap_parser.py"
"reporter/enhanced_report.py"
"utils/cvss.py"
)

echo "Checking VulnEZ repo files..."
for f in "${files[@]}"; do
  if [ -f "$ROOT/$f" ]; then
    printf "OK  : %s\n" "$f"
  else
    printf "MISS: %s\n" "$f"
    missing=$((missing+1))
  fi
done

echo
if [ "$missing" -eq 0 ]; then
  echo "All files present ✅"
  exit 0
else
  echo "Missing $missing file(s). Please add the missing files listed above."
  exit 2
fi
