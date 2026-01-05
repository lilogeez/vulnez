from pathlib import Path
import hashlib
from dotenv import load_dotenv
import os

load_dotenv()

OUTPUT_DIR = Path(os.environ.get("VULNEZ_OUTPUT_DIR","outputs"))
OUTPUT_DIR.mkdir(exist_ok=True, parents=True)

DEFAULT_CONCURRENCY = int(os.environ.get("VULNEZ_CONCURRENCY","6"))
DEFAULT_TIMEOUTS = {
    "subfinder": 300,
    "amass": 900,
    "nmap": 600,
    "ffuf": 600,
    "nuclei": 900,
    "sqlmap": 1800,
    "masscan": 300,
    "gobuster": 600,
    "dirsearch": 900,
    "sslyze": 300
}

CRITICAL_PASSWORD = os.environ.get("VULNEZ_CRITICAL_PW","2727")
CRITICAL_PW_HASH = hashlib.sha256(CRITICAL_PASSWORD.encode()).hexdigest()

LEGAL_CONFIRM_TEXT = (
    "PERINGATAN: Pastikan Anda memiliki izin eksplisit untuk melakukan pengujian.\n"
    "Modul destruktif memerlukan --confirm-legal-plus dan password proteksi."
)

NUCLEI_TEMPLATES = Path(os.environ.get("NUCLEI_TEMPLATES","nuclei-templates"))
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK","")
SMTP_SERVER = os.environ.get("SMTP_SERVER","")
SMTP_PORT = int(os.environ.get("SMTP_PORT","587"))
SMTP_USER = os.environ.get("SMTP_USER","")
SMTP_PASS = os.environ.get("SMTP_PASS","")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN","")
