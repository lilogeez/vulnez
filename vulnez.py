cat > vulnez.py <<'EOF'
#!/usr/bin/env python3
import os, sys, subprocess, time, socket, shutil, json, re
from datetime import datetime
from urllib.parse import urlparse
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.prompt import Prompt
from xhtml2pdf import pisa

# Optional imports (Graceful degradation)
try:
    import xmltodict
    from playwright.sync_api import sync_playwright
    import google.generativeai as genai
except ImportError:
    pass

console = Console()
VERSION = "1.0.0"

# --- CONFIG ---
# Masukkan API Key jika ada, jika tidak biarkan kosong (akan pakai manual logic)
GEMINI_API_KEY = "AIzaSyCsyCDqGbotW0OCv7UkPBzFqvgBrwMGUNg"

# --- RISK DATABASE (NIST/OWASP MAPPING) ---
PORT_KB = {
    '21': {'s': 'FTP', 'r': 'High', 'd': 'Cleartext protocol. Sniffing risk.', 'rec': 'Use SFTP.'},
    '22': {'s': 'SSH', 'r': 'Medium', 'd': 'Management port.', 'rec': 'Enforce Key Auth.'},
    '23': {'s': 'Telnet', 'r': 'Critical', 'd': 'Insecure legacy protocol.', 'rec': 'Disable immediately.'},
    '80': {'s': 'HTTP', 'r': 'Medium', 'd': 'Unencrypted Web.', 'rec': 'Enforce HTTPS.'},
    '443': {'s': 'HTTPS', 'r': 'Info', 'd': 'Encrypted Web.', 'rec': 'Check SSL Ciphers.'},
    '3306': {'s': 'MySQL', 'r': 'High', 'd': 'Database exposed.', 'rec': 'Firewall restriction.'},
    '5432': {'s': 'PostgreSQL', 'r': 'High', 'd': 'Database exposed.', 'rec': 'Firewall restriction.'},
    '8080': {'s': 'HTTP-Proxy', 'r': 'Medium', 'd': 'Alt Web/Admin.', 'rec': 'Audit access.'},
    '9000': {'s': 'Portainer', 'r': 'Critical', 'd': 'Docker Mgmt. ROOT RISK.', 'rec': 'Restrict access!'}
}

def get_bin(name):
    path = shutil.which(name)
    if not path:
        # Cek path go standar
        gopath = os.path.expanduser("~/go/bin/" + name)
        if os.path.exists(gopath): return gopath
    return path or name

def run_cmd(cmd, logfile):
    with open(logfile, "w") as f:
        f.write(f"COMMAND: {cmd}\n\nOUTPUT:\n")
        f.flush()
        try:
            # Timeout diperpanjang agar tidak 'kosong' prematur
            subprocess.run(cmd, shell=True, stdout=f, stderr=subprocess.STDOUT, timeout=900)
        except subprocess.TimeoutExpired:
            f.write("\n[TIMEOUT] Process killed.")
        except Exception as e:
            f.write(f"\n[ERROR] {e}")

def smart_input():
    raw = Prompt.ask("[bold cyan]Target (Domain/IP)[/bold cyan]").strip()
    if not raw: sys.exit()
    
    if "://" in raw:
        url = raw
        domain = urlparse(url).netloc
    else:
        domain = raw
        url = f"https://{domain}"
    
    # Resolve IP Manual (Penting untuk Nmap)
    try:
        ip = socket.gethostbyname(domain)
    except:
        console.print(f"[yellow][!] DNS Resolve Gagal untuk {domain}.[/yellow]")
        ip = Prompt.ask("[bold red]Masukkan IP Target Manual[/bold red]").strip()
    
    return domain, ip, url

def generate_report(outdir, domain, ip):
    console.print("[*] Generating NIST Report...")
    
    # 1. PARSE DATA
    ports = []
    crit_count = 0
    if os.path.exists(f"{outdir}/nmap.xml"):
        try:
            with open(f"{outdir}/nmap.xml", 'rb') as f:
                d = xmltodict.parse(f)
                host = d.get('nmaprun', {}).get('host', {})
                if host:
                    pdata = host.get('ports', {}).get('port', [])
                    if isinstance(pdata, dict): pdata = [pdata]
                    for p in pdata:
                        pid = p['@portid']
                        svc = p.get('service', {}).get('@name', 'unknown')
                        kb = PORT_KB.get(pid, {'r': 'Info', 'd': 'Open Port', 'rec': 'Verify'})
                        if kb['r'] in ['Critical', 'High']: crit_count += 1
                        ports.append({'p': pid, 's': svc, 'r': kb['r'], 'd': kb['d'], 'rec': kb['rec']})
        except: pass

    vulns = []
    if os.path.exists(f"{outdir}/nuclei.json"):
        with open(f"{outdir}/nuclei.json") as f:
            for line in f:
                try:
                    j = json.loads(line)
                    vulns.append({'s': j['info']['severity'], 'n': j['info']['name'], 'h': j['host']})
                except: pass

    # 2. EXECUTIVE SUMMARY (AI / MANUAL)
    ai_text = ""
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-1.5-flash')
        ctx = f"Target: {domain}. Open Ports: {len(ports)}. Crit: {crit_count}. Vulns: {len(vulns)}."
        res = model.generate_content(f"Buat Executive Summary Pentest (Bahasa Indonesia, Standar NIST). Data: {ctx}. Format HTML P.")
        if res.text: ai_text = res.text.replace("```html","").replace("```","")
    except: pass
    
    if not ai_text:
        risk = "CRITICAL" if crit_count > 0 else "MODERATE"
        ai_text = f"<p>Audit keamanan teknis pada <strong>{domain}</strong> selesai. Status Risiko: <strong>{risk}</strong>. Ditemukan {len(ports)} layanan terbuka dan {len(vulns)} temuan web.</p>"

    # 3. HTML BUILDER
    p_rows = "".join([f"<tr><td><b>{x['p']}</b></td><td>{x['s']}</td><td style='color:{'red' if x['r'] in ['Critical','High'] else 'black'}'><b>{x['r']}</b></td><td>{x['d']}<br><i>{x['rec']}</i></td></tr>" for x in ports]) or "<tr><td colspan='4'>No open ports.</td></tr>"
    v_rows = "".join([f"<tr><td><b style='color:red'>{x['s'].upper()}</b></td><td>{x['n']}</td><td>{x['h']}</td></tr>" for x in vulns]) or "<tr><td colspan='3'>No vulnerabilities found.</td></tr>"
    
    def get_log(n): return open(f"{outdir}/{n}", errors='replace').read()[:2000] if os.path.exists(f"{outdir}/{n}") else "Log Not Found"

    html = f"""
    <html><head><style>
        @page {{ size: A4; margin: 2cm; }}
        body {{ font-family: Helvetica; color: #333; font-size: 10pt; }}
        h1 {{ color: #002b36; border-bottom: 2px solid #002b36; }}
        h2 {{ background: #eee; padding: 5px; margin-top: 20px; border-left: 5px solid #002b36; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th {{ background: #002b36; color: white; padding: 5px; text-align:left; }}
        td {{ border-bottom: 1px solid #ccc; padding: 5px; }}
        pre {{ background: #f5f5f5; padding: 5px; font-size: 7pt; border: 1px solid #ddd; }}
    </style></head><body>
        <div style="text-align:center; margin-top:50px;">
            <h1>PENETRATION TEST REPORT</h1>
            <h3>Target: {domain} ({ip})</h3>
            <p>{datetime.now().strftime('%Y-%m-%d')}</p>
            <p><strong>Standard: NIST SP 800-115 / OWASP</strong></p>
        </div>
        <pdf:nextpage />
        <h2>1. Executive Summary</h2>{ai_text}
        <h2>2. Infrastructure (Nmap)</h2>
        <table><thead><tr><th>Port</th><th>Service</th><th>Risk</th><th>Analysis</th></tr></thead><tbody>{p_rows}</tbody></table>
        <h2>3. Web Vulnerabilities (OWASP)</h2>
        <table><thead><tr><th>Severity</th><th>Finding</th><th>Location</th></tr></thead><tbody>{v_rows}</tbody></table>
        <pdf:nextpage />
        <h2>4. Technical Evidence (Raw Logs)</h2>
        <h3>Nmap</h3><pre>{get_log('nmap.log')}</pre>
        <h3>Wafw00f</h3><pre>{get_log('waf.log')}</pre>
        <h3>Nikto</h3><pre>{get_log('nikto.log')}</pre>
        <h3>Feroxbuster</h3><pre>{get_log('ferox.log')}</pre>
        <h3>WhatWeb</h3><pre>{get_log('whatweb.log')}</pre>
    </body></html>
    """
    
    pdf = f"{outdir}/Report.pdf"
    with open(pdf, "wb") as f: pisa.CreatePDF(html, dest=f)
    return pdf

def main():
    os.system('clear')
    console.print(Panel("[bold green]VULNEZ[/bold green] [bold white]AUTOMATED PENTEST[/bold white]", style="bold blue"))
    
    # 1. Setup
    domain, ip, url = smart_input()
    console.print(f"\n[+] Target: {domain} | IP: {ip}")
    outdir = f"results/{domain}_{int(time.time())}"
    os.makedirs(outdir, exist_ok=True)
    os.makedirs(f"{outdir}/screenshots", exist_ok=True)

    # 2. Execution Loop
    with Progress(SpinnerColumn(), BarColumn(), TextColumn("{task.description}"), transient=False) as progress:
        task = progress.add_task("Auditing...", total=100)
        
        # STEP 1: RECON
        progress.update(task, description="[1/6] Recon (Subfinder/GAU)...")
        sf, gau, hx = get_bin("subfinder"), get_bin("gau"), get_bin("httpx")
        run_cmd(f"{sf} -d {domain} -silent -o {outdir}/subs.txt", f"{outdir}/subfinder.log")
        run_cmd(f"{gau} {domain} --subs", f"{outdir}/gau.log")
        progress.update(task, advance=15)

        # STEP 2: VISUAL
        progress.update(task, description="[2/6] Visual (Screenshot)...")
        try:
            with sync_playwright() as p:
                b = p.chromium.launch(headless=True)
                pg = b.new_page(); pg.goto(url, timeout=30000); pg.screenshot(path=f"{outdir}/screenshots/main.png"); b.close()
        except: pass
        progress.update(task, advance=10)

        # STEP 3: INFRA
        progress.update(task, description="[3/6] Infra (Nmap)...")
        nm = get_bin("nmap")
        # Mode Stabil: -sT (Connect), -Pn (No Ping), -T4 (Speed)
        run_cmd(f"sudo {nm} -Pn -sT -sV --top-ports 2000 --open {ip} -oX {outdir}/nmap.xml", f"{outdir}/nmap.log")
        progress.update(task, advance=25)

        # STEP 4: TECH
        progress.update(task, description="[4/6] Tech (Wafw00f/WhatWeb)...")
        waf, ww = get_bin("wafw00f"), get_bin("whatweb")
        run_cmd(f"{waf} {url}", f"{outdir}/waf.log")
        run_cmd(f"{ww} {url} --color=never", f"{outdir}/whatweb.log")
        progress.update(task, advance=10)

        # STEP 5: WEB
        progress.update(task, description="[5/6] Web (Nuclei/Nikto/Ferox)...")
        nc, nk, ferox = get_bin("nuclei"), get_bin("nikto"), get_bin("feroxbuster")
        run_cmd(f"{nc} -u {url} -t /home/kali/nuclei-templates -severity critical,high,medium,low,info -jsonl -o {outdir}/nuclei.json", f"{outdir}/nuclei.log")
        run_cmd(f"{nk} -h {url} -maxtime 5m", f"{outdir}/nikto.log")
        run_cmd(f"{ferox} -u {url} --depth 1 --time-limit 2m --silent --no-state", f"{outdir}/ferox.log")
        progress.update(task, advance=30)

        # STEP 6: REPORT
        progress.update(task, description="Finalizing...", advance=10)
        pdf = generate_report(outdir, domain, ip)
    
    console.print(f"\n[bold green]SUCCESS.[/bold green] Report: {os.path.abspath(pdf)}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Please run as root (sudo) for Nmap.")
        sys.exit(1)
    main()
EOF
