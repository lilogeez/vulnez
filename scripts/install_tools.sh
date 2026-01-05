#!/usr/bin/env bash
set -euo pipefail
echo "[*] Installer VulnEZ (Debian/Ubuntu/Kali). Jalankan di VM/WSL yang terisolasi."
if [ "$(id -u)" -ne 0 ]; then
  echo "Jalankan dengan sudo: sudo $0"
  exit 2
fi
MODE="${1:-minimal}"
apt-get update
apt-get install -y build-essential git curl wget unzip ca-certificates jq python3-pip golang-go nmap nikto sqlmap ruby-full make gcc libssl-dev libffi-dev python3-dev wkhtmltopdf || true
export GOPATH=${GOPATH:-/root/go}
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
go_install(){ pkg=$1; GO111MODULE=on go install -v "$pkg" || true; }
echo "[*] Menginstal alat minimal (subfinder, httpx, ffuf)"
go_install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go_install github.com/projectdiscovery/httpx/cmd/httpx@latest
go_install github.com/ffuf/ffuf@latest
if [ "$MODE" = "full" ]; then
  go_install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
  go_install github.com/OJ/gobuster/v3@latest
  go_install github.com/michenriksen/aquatone@latest
  go_install github.com/sensepost/gowitness@latest
  go_install github.com/gitleaks/gitleaks/v8@latest
fi
echo "[+] Selesai. Pastikan \$GOPATH/bin berada di PATH."
