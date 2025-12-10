# Tool registry, OSINT, scanners (wrappers), and safe fallbacks
import shutil
import subprocess
import logging
import aiohttp
import socket
import asyncio

LOG = logging.getLogger("vulnez.modules")

COMMON_TOOLS = [
    "amass","subfinder","assetfinder","naabu","masscan","nmap","gobuster","ffuf","feroxbuster",
    "nuclei","nikto","sqlmap","httpx","gau","waybackurls","whatweb","wafw00f","theharvester","sslyze"
]

class ToolRegistry:
    def __init__(self):
        self.tools = {t: {"path": None, "version": None} for t in COMMON_TOOLS}

    def detect_all(self):
        for t in self.tools.keys():
            p = shutil.which(t)
            self.tools[t]["path"] = p
            if p:
                try:
                    out = subprocess.run([p, "--version"], capture_output=True, text=True, timeout=8)
                    ver = out.stdout.strip().splitlines()[0] if out.stdout else (out.stderr.strip().splitlines()[0] if out.stderr else "")
                    self.tools[t]["version"] = ver
                except Exception:
                    try:
                        out = subprocess.run([p, "-version"], capture_output=True, text=True, timeout=6)
                        ver = out.stdout.strip().splitlines()[0] if out.stdout else (out.stderr.strip().splitlines()[0] if out.stderr else "")
                        self.tools[t]["version"] = ver
                    except Exception:
                        self.tools[t]["version"] = ""
        LOG.info("Tool detection complete.")

    def list_tools(self):
        return self.tools

# ---------- OSINT ----------
async def crtsh_subdomains(domain, session=None, timeout=15):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    close = False
    if session is None:
        session = aiohttp.ClientSession()
        close = True
    try:
        async with session.get(url, timeout=timeout) as resp:
            if resp.status != 200:
                LOG.debug("crt.sh returned %s", resp.status)
                return []
            data = await resp.json(content_type=None)
            subs = set()
            for item in data:
                name = item.get("name_value")
                if name:
                    for n in name.split("\n"):
                        subs.add(n.strip().lstrip("*."))
            return sorted(s for s in subs if s)
    except Exception as e:
        LOG.debug("crt.sh failed: %s", e)
        return []
    finally:
        if close:
            await session.close()

async def amass_enum(domain, timeout=120):
    amass_bin = shutil.which("amass")
    if not amass_bin:
        return []
    proc = await asyncio.create_subprocess_exec(amass_bin, "enum", "-d", domain, "-silent", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        LOG.warning("amass timed out")
        return []
    lines = stdout.decode().splitlines()
    return sorted({l.strip() for l in lines if l.strip()})

def get_whois(domain):
    try:
        import whois
        w = whois.whois(domain)
        return {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "emails": w.emails
        }
    except Exception as e:
        LOG.debug("whois failed: %s", e)
        return {}

async def enumerate_subdomains(domain, use_amass=True):
    domain = domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        import urllib.parse
        domain = urllib.parse.urlparse(domain).hostname or domain
    results = set()
    if use_amass:
        try:
            am = await amass_enum(domain)
            for s in am:
                results.add(s)
        except Exception:
            pass
    async with aiohttp.ClientSession() as session:
        try:
            crt = await crtsh_subdomains(domain, session=session)
            for s in crt:
                results.add(s)
        except Exception:
            pass
    final = []
    for s in sorted(results):
        try:
            socket.gethostbyname(s)
            final.append(s)
        except Exception:
            pass
    if domain not in final:
        final.insert(0, domain)
    return final

# ------------------ utilities ------------------
async def _run_cmd_get_stdout(cmd, timeout=60):
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            LOG.warning("Command timed out: %s", " ".join(cmd))
            return ""
        return stdout.decode(errors="ignore")
    except Exception as e:
        LOG.debug("Failed to run command %s: %s", " ".join(cmd), e)
        return ""

# ------------------ Scanners & wrappers ------------------
async def nmap_scan(host, timeout=120):
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        LOG.debug("nmap missing; skipping")
        return None
    return await _run_cmd_get_stdout([nmap_bin, "-Pn", "-sV", "-oX", "-", host], timeout=timeout)

async def naabu_scan(host, timeout=40):
    naabu_bin = shutil.which("naabu")
    if not naabu_bin:
        LOG.debug("naabu missing; skipping")
        return None
    return await _run_cmd_get_stdout([naabu_bin, "-host", host, "-silent"], timeout=timeout)

async def httpx_probe(host, timeout=20):
    httpx = shutil.which("httpx")
    if not httpx:
        LOG.debug("httpx missing; fallback to internal http_checks")
        return None
    return await _run_cmd_get_stdout([httpx, "-silent", "-status-code", "-title", "-location", "-threads", "10", "-u", host], timeout=timeout)

async def gau_wayback(host, timeout=30):
    results = {}
    gau_bin = shutil.which("gau")
    way_bin = shutil.which("waybackurls")
    if gau_bin:
        out = await _run_cmd_get_stdout([gau_bin, host], timeout=timeout)
        results["gau"] = out
    if way_bin:
        out = await _run_cmd_get_stdout([way_bin, host], timeout=timeout)
        results["waybackurls"] = out
    return results

async def ffuf_dir(host, wordlist=None, timeout=60):
    ffuf = shutil.which("ffuf")
    if not ffuf:
        LOG.debug("ffuf missing; skipping")
        return None
    wl = wordlist or "/usr/share/wordlists/dirb/common.txt"
    target = host if host.startswith("http") else f"https://{host}"
    return await _run_cmd_get_stdout([ffuf, "-u", f"{target}/FUZZ", "-w", wl, "-s", "-ac", "-t", "40"], timeout=timeout)

async def whatweb_run(host, timeout=20):
    whatweb = shutil.which("whatweb")
    if not whatweb:
        return None
    return await _run_cmd_get_stdout([whatweb, host], timeout=timeout)

async def wafw00f_run(host, timeout=20):
    waf = shutil.which("wafw00f")
    if not waf:
        return None
    return await _run_cmd_get_stdout([waf, host], timeout=timeout)

async def http_checks(host, timeout=15):
    targets = []
    if host.startswith("http://") or host.startswith("https://"):
        targets = [host]
    else:
        targets = [f"https://{host}", f"http://{host}"]
    results = []
    async with aiohttp.ClientSession() as session:
        for url in targets:
            try:
                async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
                    text = await resp.text(errors="ignore")
                    title = None
                    s = text.find("<title")
                    if s != -1:
                        s = text.find(">", s)
                        if s != -1:
                            e = text.find("</title>", s)
                            if e != -1:
                                title = text[s+1:e].strip()
                    results.append({"url": url, "status": resp.status, "headers": dict(resp.headers), "title": title})
            except Exception as e:
                LOG.debug("HTTP check failed for %s: %s", url, e)
    return results

async def dir_fuzz(host, wordlist=None, timeout=30):
    gobuster = shutil.which("gobuster")
    if gobuster:
        wl = wordlist or "/usr/share/wordlists/dirb/common.txt"
        proc_cmd = [gobuster, "dir", "-u", host if host.startswith("http") else f"https://{host}", "-w", wl, "-q"]
        return await _run_cmd_get_stdout(proc_cmd, timeout=timeout)
    bl = ["admin","login","dashboard","robots.txt","sitemap.xml","phpinfo.php"]
    found = []
    async with aiohttp.ClientSession() as session:
        for p in bl:
            url = host if host.startswith("http") else f"https://{host}/{p}"
            try:
                async with session.get(url, timeout=5, allow_redirects=False) as resp:
                    if resp.status in (200,301,302):
                        found.append({"path": p, "status": resp.status, "url": str(resp.url)})
            except Exception:
                pass
    return found

async def nikto_scan(host, timeout=90):
    nikto = shutil.which("nikto")
    if not nikto:
        LOG.debug("nikto missing; skipping")
        return None
    url = host if host.startswith("http") else f"http://{host}"
    return await _run_cmd_get_stdout([nikto, "-h", url, "-Format", "txt"], timeout=timeout)

async def nuclei_scan(host, timeout=120):
    nuclei = shutil.which("nuclei")
    if not nuclei:
        LOG.debug("nuclei missing; skipping")
        return None
    url = host if host.startswith("http") else f"https://{host}"
    return await _run_cmd_get_stdout([nuclei, "-u", url, "-silent"], timeout=timeout)
