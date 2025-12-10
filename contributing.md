# 🤝 Panduan Kontribusi untuk VulnEZ

Kami menyambut kontribusi dari komunitas! Dengan berkontribusi, Anda membantu membuat VulnEZ menjadi alat yang lebih baik dan lebih aman.

## 📝 Dasar-Dasar Kontribusi

1.  **Fork** repositori ini dan buat *branch* fitur Anda (`git checkout -b fitur/nama-fitur`).
2.  **Kode:** Pastikan kode Anda mematuhi **PEP 8** dan di-*format* menggunakan `black`. Gunakan *type hinting* sebisa mungkin.
3.  **Commit:** Tulis pesan *commit* yang jelas. Kami menyarankan format **Conventional Commits** (misalnya, `feat: tambahkan dukungan nuclei baru` atau `fix: perbaiki parser nmap`).
4.  **Tests:** Semua perbaikan *bug* atau fitur baru **HARUS** disertai dengan *unit test* yang sesuai di direktori `tests/`. Pastikan semua tes lolos: `pytest -q`.
5.  **Pull Request (PR):** Buka PR ke *branch* `main` dan isi *template* PR yang sudah disediakan.

## 🧪 Mengatur Lingkungan Lokal

```bash
# Clone
git clone [https://github.com/lilogeez/vulnez.git](https://github.com/lilogeez/vulnez.git)
cd vulnez

# Setup Virtual Environment
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install pytest black  # Tools development

# Jalankan Test
pytest -q

# Format Kode (Sebelum PR)
black .
