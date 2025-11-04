#!/usr/bin/env bash
# install-deps.sh - Kali installer for VulnEZ
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] Run as root: sudo bash install-deps.sh"
  exit 1
fi

USER_NAME="$(logname)"
USER_HOME="/home/${USER_NAME}"
export DEBIAN_FRONTEND=noninteractive

apt update
apt -y upgrade

# Core packages
apt install -y python3 python3-pip python3-venv git build-essential curl wget jq \
  nmap masscan nikto sqlmap gobuster snmp freerdp2-x11 \
  smbclient smbmap crackmapexec seclists docker.io

systemctl enable --now docker || true

# Install Go for projectdiscovery tools
if ! command -v go >/dev/null 2>&1; then
  GO_VER="1.21.7"
  cd /tmp
  wget -q "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "go${GO_VER}.linux-amd64.tar.gz"
  cat > /etc/profile.d/go_path.sh <<'EOF'
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
export GOPATH=${GOPATH:-$HOME/go}
EOF
  chmod +x /etc/profile.d/go_path.sh
fi

USER_GOPATH="${USER_HOME}/go"
mkdir -p "${USER_GOPATH}/bin"
chown -R "${USER_NAME}:${USER_NAME}" "${USER_GOPATH}"

export GOPATH="${USER_GOPATH}"
export PATH="${PATH}:${GOPATH}/bin"

# Go-based tools (install as non-root)
su - "${USER_NAME}" -c "export GOPATH=${GOPATH}; export PATH=\$PATH:${GOPATH}/bin; \
  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true; \
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest || true; \
  go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest || true; \
  go install github.com/ffuf/ffuf@latest || true; \
"

# feroxbuster via cargo if needed (non-root)
su - "${USER_NAME}" -c 'if ! command -v feroxbuster >/dev/null 2>&1; then if ! command -v cargo >/dev/null 2>&1; then curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; fi; source $HOME/.cargo/env || true; cargo install feroxbuster || true; fi'

# Install python pip packages globally (recommended to use venv per-repo)
pip3 install --upgrade pip
pip3 install --upgrade pip setuptools wheel

# Playwright install and browsers for the user
pip3 install playwright==1.44.0
su - "${USER_NAME}" -c "python3 -m playwright install --with-deps || true"

# FastAPI / Uvicorn and DB libs
pip3 install fastapi uvicorn[standard] sqlalchemy

echo "[*] Installer finished. Next steps:"
echo "1) cd into VulnEZ repo"
echo "2) python3 -m venv .venv && source .venv/bin/activate"
echo "3) pip install -r requirements.txt"
echo "4) python3 -m playwright install --with-deps"
echo "5) ./run.sh"
