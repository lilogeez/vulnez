# 🛡️ VulnEZ - Automated Pentest Framework

**VulnEZ** is a powerful, lightweight, and automated penetration testing suite designed for Red Teamers, Bug Hunters, and System Administrators. It automates the entire audit lifecycle—from reconnaissance to reporting—following **NIST SP 800-115** and **OWASP** standards.

---

## ✨ Key Features

* 🔥 **9+ Integrated Tools:** Orchestrates Nmap, Nuclei, Subfinder, HTTPX, GAU, Wafw00f, WhatWeb, Nikto, and Feroxbuster in one seamless pipeline.
* 📊 **Professional Reporting:** Generates high-quality PDF reports with Executive Summary, Risk Tables, and Raw Evidence appendices.
* 🧠 **Smart Input Logic:** Automatically detects and handles Domains, URLs, and IPs to prevent tool crashes.
* 📸 **Visual Recon:** Automated screenshot capture of targets using Playwright.
* 🚀 **Anti-Crash Engine:** Intelligent timeout handling and fallback mechanisms (Manual Risk DB) if AI services are unavailable.

---

## ⚙️ Prerequisites (Requirements)

Before installing, ensure your system has the following:

* **Operating System:** Kali Linux (Recommended), Ubuntu 20.04+, or Debian.
* **Python:** Version 3.10 or higher.
* **Go:** Latest version (for Nuclei/Subfinder).
* **Access:** Root/Sudo privileges (required for Nmap SYN scans).

---

## 🚀 Installation Guide

### 1. Install System Tools (Kali Linux/Debian)
First, install the core engines required by VulnEZ:

```bash
sudo apt update
sudo apt install -y nmap masscan nikto wafw00f sqlmap whatweb sslscan feroxbuster jq chromium-driver

# Install Go if needed
sudo apt install golang -y

# Install Tools
go install -v [github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest](https://github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)
go install -v [github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest](https://github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)
go install -v [github.com/projectdiscovery/httpx/cmd/httpx@latest](https://github.com/projectdiscovery/httpx/cmd/httpx@latest)
go install -v [github.com/lc/gau/v2/cmd/gau@latest](https://github.com/lc/gau/v2/cmd/gau@latest)

# Add Go binary path to your system
export PATH=$PATH:$(go env GOPATH)/bin

# Clone Repository
git clone [https://github.com/lilogeez/VulnEZ.git](https://github.com/lilogeez/VulnEZ.git)
cd VulnEZ

# Create Virtual Environment (Recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install Python Dependencies
pip install -r requirements.txt

# Install Browser for Screenshots
playwright install chromium

# For Activate Evironment
source .venv/bin/activate

sudo .venv/bin/python3 vulnez.py

⚠️ Disclaimer
This tool is for educational purposes and authorized security testing only. The developer is not responsible for any misuse or damage caused by this tool. Always obtain proper permission before scanning any target.

Developed by lilogeez
