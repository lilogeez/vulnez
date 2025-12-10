# VulnEZ — Complete Final Release (Automated Pentest Framework)

VulnEZ is a modular, local-first pentest & red-team orchestrator focused on stability, structured reporting (NIST SP 800-115 + OWASP), and extensibility. No external AI/APIs required.

Highlights
- Multi-tool orchestration with graceful fallback when tools are missing.
- Presets: safe (default), fast, full, aggressive (consent-gated).
- Structured standardized findings (.std.json) with CVSS-lite heuristics + OWASP mapping.
- Offline CVE enrichment (use local NVD JSON), red-team safe wrappers, exporters (CSV/PDF).
- Built-in consent/audit logging for aggressive operations.
- Simple single-command CLI: python -m vulnez scan <target> --mode full

Quickstart
1. Create branch (optional but recommended)
   git checkout -b automated/mvp-final

2. Copy files into repo (overwrite as needed).

3. Create virtualenv & install:
   python3 -m venv .venv
   source .venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt

4. Copy config:
   cp config.example.yaml config.yaml
   (edit config.yaml if you want to enable/disable tools)

5. Run smoke tests:
   pytest -q

6. Detect tools:
   python -m vulnez tools_list

7. Run safe scan:
   python -m vulnez scan example.com --mode safe

8. Run full scan (longer, non-intrusive by default):
   python -m vulnez scan example.com --mode full

9. Aggressive scans require explicit typed consent:
   python -m vulnez scan example.com --mode aggressive
   Type "I HAVE AUTHORIZATION" when prompted.

Reporting outputs
- reports/<target>_<timestamp>.json  (raw findings)
- reports/<target>_<timestamp>.html  (human readable report)
- reports/<target>_<timestamp>.std.json (standardized findings with severity & OWASP mapping)
- reports/consent.log  (audit log of consent timestamps)
