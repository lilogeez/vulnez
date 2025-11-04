```markdown
# VulnEZ — One‑Click Pentest Pipeline

VulnEZ adalah toolkit pentest open‑source yang dirancang agar mudah digunakan oleh pentester, bug hunter, dan tim keamanan. Masukkan target, pilih mode, dan VulnEZ akan menjalankan rangkaian reconnaissance, authenticated scanning (via Playwright), template checks (nuclei), fast port discovery (masscan → nmap), verifikasi temuan, serta menghasilkan laporan profesional (HTML / CSV / JSON).

Kenapa VulnEZ?
- Mudah: satu CLI untuk alur lengkap recon → scan → report.
- Aman‑by‑default: timeout, masking kredensial, sandboxable workflows.
- Profesional: output terstruktur, estimasi CVSS, dan API untuk integrasi tim.
- Extensible: plugin‑friendly — tambahkan scanner atau verifier baru dengan mudah.

Fitur utama
- Subdomain discovery (amass / subfinder)
- HTTP probing (httpx) dan browser‑based authenticated scans (Playwright)
- Template vulnerability checks (nuclei) + simple verification engine
- Fast port discovery (masscan) + nmap follow‑up and XML → JSON parsing
- Combined reports: combined.json, combined.csv, combined.html (VulnEZ‑branded)
- Simple persistence (SQLite) + FastAPI skeleton for programmatic access
- Installer script untuk Kali Linux, Dockerfile, CI skeleton, pre‑commit hooks

Quick start (Kali Linux)
1. Clone repo:
   git clone git@github.com:<username>/vulnez.git
   cd vulnez

2. Satu kali: install dependency sistem (jalankan sebagai root / sudo):
   sudo bash install-deps.sh

3. Buat virtualenv dan pasang dependensi Python:
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   python3 -m playwright install --with-deps

4. Jalankan VulnEZ:
   chmod +x run.sh
   ./run.sh
   (atau `python3 vulnez.py`)

Menu utama (ringkasan)
1) Quick Discovery Pipeline — subdomain → http probe → nuclei → masscan → nmap → report  
2) Quick Web Scan — httpx → nuclei → report  
3) Quick Port Scan — masscan → nmap → report  
4) Authenticated Scan — login via Playwright → scan  
5) Run Verification — reduce false positives (verification engine)  
6) Start API Server — FastAPI (uvicorn)  
7) Open last HTML report  
8) Exit

Safety & Legal
- Jalankan hanya terhadap aset yang Anda miliki izin tertulis.
- Beberapa module (masscan, nuclei, sqlmap, exploitation plugins) bersifat agresif — gunakan dengan hati‑hati.
- Gunakan environment terisolasi (VM/container) untuk scan.

Contributing
- Ikuti pre-commit hooks untuk konsistensi (black + flake8 + detect-secrets).
- Tambah plugin di folder `scans/` dengan kontrak sederhana: `run_<tool>(target, outdir, config) -> dict`.
- Buat issue atau PR, sertakan test dan dokumentasi untuk fitur baru.

License
- MIT — lihat file LICENSE untuk detail.

Contact / Support
- Buat issue di GitHub repository untuk bug/fitur, atau buat diskusi di repo.
```
