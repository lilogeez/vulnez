# VulnEZ — Toolkit Keamanan Open-Source (Indonesia)

Versi: 0.5.0

Ringkasan
VulnEZ adalah toolkit modular untuk assessment dan manajemen temuan keamanan yang mencakup:
- Recon & OSINT
- Network & Web scanning
- Template scanning (nuclei)
- Fuzzing & discovery
- Authenticated scanning (OWASP ZAP)
- SQL injection pipeline (sqlmap)
- SCA / IaC scanning (skeleton)
- Vulnerability management (DB + UI + workflow)
- Scheduler & agent (enqueue / worker)
- Notifikasi (Slack / SMTP / Webhook)
- Pembuatan laporan (OWASP & NIST) dan ekspor PDF

Kiat singkat
1. Gunakan WSL2/Ubuntu atau VM Linux untuk menjalankan alat eksternal (Go tools, nmap, dll.).
2. Selalu jalankan `--dry-run` sebelum eksekusi nyata.
3. Modul destruktif memerlukan `--confirm-legal-plus` dan password proteksi.

Instalasi singkat (Kali/Ubuntu/WSL)
1. Clone repo:
   git clone <URL-REPO>
   cd <repo>
2. Buat virtualenv:
   python3 -m venv .venv
   source .venv/bin/activate
3. Install dependency:
   pip install -r requirements.txt
4. Inisialisasi DB:
   bash scripts/setup_db.sh
5. Jalankan tes:
   pytest -q
6. Dry-run contoh:
   python -m vulnez.cli run --target example.com --profile quick --modules recon --dry-run --confirm-legal

Dokumen
- docs/INSTALL.md — panduan instalasi lengkap
- docs/USAGE.md — panduan penggunaan

Lisensi
- MIT (file LICENSE)
