#!/usr/bin/env python3
import typer, getpass, hashlib, subprocess, sys
from pathlib import Path
from typing import List, Optional
from vulnez import config, db
from vulnez.core.runner import Task, TaskRunner

app = typer.Typer(help='VulnEZ — CLI manajemen & eksekusi')

def _cek_pw(pw: str) -> bool:
    return hashlib.sha256(pw.encode()).hexdigest() == config.CRITICAL_PW_HASH

def _banner():
    print('='*72)
    print('VULNEZ'.center(72))
    print('Toolkit Keamanan — Pilih menu atau gunakan perintah langsung'.center(72))
    print('='*72)

@app.command()
def menu():
    """Menu interaktif: pilih nomor untuk menjalankan fungsi."""
    _banner()
    menu = [
        'Recon & Subdomain (subfinder, amass)',
        'Network & Port Scan (masscan, nmap)',
        'Web discovery & fuzz (ffuf, gobuster)',
        'Template scan (nuclei)',
        'Web scanners (nikto, wpscan)',
        'OSINT & Repo scanning (theHarvester, gitleaks)',
        'SCA / IaC scan (trivy, checkov, bandit)',
        'SQLMap pipeline (harvest -> requests)',
        'OWASP ZAP (autentikasi & baseline)',
        'Vulnerability Management (DB import/export/assign)',
        'Agent & Scheduler (enqueue / worker)',
        'Reports (OWASP/NIST -> PDF)',
        'Notifikasi (uji Slack/email)',
        'Kritis: tindakan destruktif (password diperlukan)',
        'Keluar'
    ]
    for i, m in enumerate(menu, start=1):
        print(f"{i:2}) {m}")
    try:
        c = int(input('Pilihan: ').strip())
    except Exception:
        print('Pilihan tidak valid. Keluar.')
        return
    if c == 1:
        target = input('Masukkan domain target: ').strip()
        if input('Ketik YES jika Anda memiliki izin eksplisit: ').strip() != 'YES':
            print('Izin tidak dikonfirmasi. Batal.'); return
        tasks = [
            Task(name=f'subfinder:{target}', cmd=['subfinder','-d',target,'-silent','-o',str(Path('outputs')/target/f'subfinder_{target}.txt')]),
            Task(name=f'amass:{target}', cmd=['amass','enum','-d',target,'-passive','-o',str(Path('outputs')/target/f'amass_{target}.txt')])
        ]
        TaskRunner(concurrency=config.DEFAULT_CONCURRENCY, target=target, output_dir=Path('outputs')/target).run_tasks(tasks)
    elif c == 10:
        summary = input('Path ke summary.json: ').strip()
        if not Path(summary).exists():
            print('File summary tidak ditemukan.'); return
        n = db.import_summary(summary)
        print(f'Berhasil impor {n} temuan ke DB.')
    elif c == 12:
        target = input('Target untuk laporan: ').strip()
        tpl = input('Template (owasp/nist) [owasp]: ').strip() or 'owasp'
        subprocess.run([sys.executable, '-m', 'vulnez.cli', 'report_cmd', '--target', target, '--template', tpl])
    elif c == 14:
        pw = getpass.getpass('Masukkan password kritis: ')
        if not _cek_pw(pw):
            print('Password salah. Akses ditolak.'); return
        print('Menu kritis terbuka. Untuk eksekusi destruktif gunakan run_tasks_json.py dengan --confirm-legal-plus.')
    else:
        print('Opsi belum diimplementasikan di menu ini. Gunakan perintah CLI langsung.')

@app.command()
def run(target: str, profile: str = 'quick', modules: Optional[List[str]] = typer.Option(None), concurrency: int = 4, dry_run: bool = False, confirm_legal: bool = False, confirm_legal_plus: bool = False):
    """Jalankan modul secara non-interaktif."""
    if not confirm_legal:
        print('Anda harus mengkonfirmasi izin dengan --confirm-legal'); raise typer.Exit(code=1)
    tasks = []
    if not modules:
        modules = ['recon','webscan']
    for m in modules:
        if m == 'recon':
            tasks.append(Task(name=f'subfinder:{target}', cmd=['subfinder','-d',target,'-silent','-o',str(Path('outputs')/target/f'subfinder_{target}.txt')]))
        if m == 'webscan':
            tasks.append(Task(name=f'nuclei:{target}', cmd=['nuclei','-u',f'http://{target}','-o',str(Path('outputs')/target/f'nuclei_{target}.json'),'-json']))
    TaskRunner(concurrency=concurrency, target=target, output_dir=Path('outputs')/target, dry_run=dry_run, confirm_legal_plus=confirm_legal_plus).run_tasks(tasks)

@app.command()
def report_cmd(target: str = typer.Option(...), template: str = typer.Option('owasp'), out_pdf: Optional[str] = typer.Option(None)):
    from vulnez.report.generator import load_findings, render_report
    from vulnez.report.pdf_generator import md_to_pdf
    target_dir = Path('outputs')/target
    summary = target_dir / 'summary.json'
    if not summary.exists():
        print('summary.json tidak ditemukan. Jalankan scanning terlebih dahulu.'); raise typer.Exit(code=1)
    findings = load_findings(str(summary))
    md = target_dir / f'report_{template}.md'
    render_report(findings, template_name=f'{template}_template.md.j2', out=str(md))
    pdf_out = Path(out_pdf) if out_pdf else target_dir / f'report_{template}.pdf'
    try:
        md_to_pdf(md, pdf_out)
        print(f'[+] PDF tersimpan di {pdf_out}')
    except Exception as e:
        print(f'[!] Gagal membuat PDF: {e}')

if __name__ == '__main__':
    app()
