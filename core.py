import os
import datetime
import json
import logging
import asyncio
from .modules import ToolRegistry, enumerate_subdomains, get_whois, nmap_scan, naabu_scan, httpx_probe, http_checks, dir_fuzz, nikto_scan, nuclei_scan, gau_wayback, ffuf_dir, whatweb_run, wafw00f_run
from .report import ReportGenerator
from . import redteam, cve

LOG = logging.getLogger("vulnez")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

class Orchestrator:
    def __init__(self, config):
        self.config = config or {}
        g = self.config.get("general", {}) or {}
        self.outdir = g.get("output_dir", "reports")
        os.makedirs(self.outdir, exist_ok=True)
        self.concurrency = g.get("concurrency", 6)
        self.timeout = g.get("request_timeout", 15)
        self.nvd_db_path = g.get("nvd_db_path", "")
        self.presets = (self.config.get("presets", {}) or {})
        self.tools_cfg = (self.config.get("tools", {}) or {})
        self.tool_registry = ToolRegistry()
        self.reporter = ReportGenerator(outdir=self.outdir)
        self.nvd_db = None
        if self.nvd_db_path:
            try:
                db = cve.NVDLocalDB()
                db.load_from_file(self.nvd_db_path)
                self.nvd_db = db
            except Exception as e:
                LOG.warning("Could not load NVD DB: %s", e)

    def _resolve_preset(self, mode):
        if not mode:
            return self.presets.get("safe", [])
        return self.presets.get(mode, self.presets.get("safe", []))

    def run_cli(self, target, mode=None, tool_list=None):
        LOG.info("Starting scan for target: %s (mode=%s)", target, mode)
        preset_steps = self._resolve_preset(mode)
        if mode == "aggressive":
            if not self._consent_check(target):
                LOG.info("Consent not provided. Abort aggressive mode.")
                return
        asyncio.run(self._run(target, preset_steps, tool_list, mode=mode))

    def _consent_check(self, target):
        print("AGGRESSIVE MODE selected. You must have explicit authorization to test this target.")
        print(f"Target: {target}")
        confirm = input("Type 'I HAVE AUTHORIZATION' to continue: ").strip()
        if confirm == "I HAVE AUTHORIZATION":
            with open(os.path.join(self.outdir, "consent.log"), "a", encoding="utf-8") as fh:
                fh.write(f"{datetime.datetime.utcnow().isoformat()} - {target}\n")
            return True
        return False

    async def _run(self, target, steps, tool_list, mode=None):
        findings = {"target": target, "start_time": datetime.datetime.utcnow().isoformat(), "osint": {}, "scans": [], "notes": []}
        LOG.info("Detecting available tools...")
        self.tool_registry.detect_all()
        tools_available = self.tool_registry.list_tools()
        findings["tools"] = tools_available

        # OSINT
        if "osint" in steps:
            try:
                LOG.info("Running OSINT...")
                subs = await enumerate_subdomains(target, use_amass=bool(tools_available.get("amass", {}).get("path")))
                whois = get_whois(target)
                findings["osint"]["subdomains"] = subs
                findings["osint"]["whois"] = whois
            except Exception as e:
                LOG.exception("OSINT error: %s", e)
                findings["notes"].append(f"OSINT error: {e}")

        # fast discovery (naabu)
        discovered_hosts = set([target])
        if "fast_discovery" in steps:
            if tools_available.get("naabu", {}).get("path"):
                try:
                    LOG.info("Running naabu fast discovery...")
                    out = await naabu_scan(target)
                    for line in (out or "").splitlines():
                        txt = line.strip()
                        if txt:
                            discovered_hosts.add(txt)
                except Exception as e:
                    LOG.debug("naabu error: %s", e)

        for s in findings["osint"].get("subdomains", []):
            discovered_hosts.add(s)

        sem = asyncio.Semaphore(self.concurrency)

        async def scan_host(host):
            async with sem:
                LOG.info("Scanning host %s", host)
                result = {"host": host, "http": None, "nmap": None, "dirfuzz": None, "external": {}}
                try:
                    if tools_available.get("httpx", {}).get("path"):
                        result["http_probe_raw"] = await httpx_probe(host)
                    else:
                        result["http"] = await http_checks(host, timeout=self.timeout)

                    if tools_available.get("nmap", {}).get("path"):
                        result["nmap"] = await nmap_scan(host, timeout=120)

                    if tools_available.get("ffuf", {}).get("path"):
                        result["dirfuzz"] = await ffuf_dir(host)
                    else:
                        result["dirfuzz"] = await dir_fuzz(host)

                    if tools_available.get("nikto", {}).get("path") and "nikto" in steps:
                        result["external"]["nikto"] = await nikto_scan(host)
                    if tools_available.get("nuclei", {}).get("path") and "nuclei" in steps:
                        result["external"]["nuclei"] = await nuclei_scan(host)
                    if "wayback" in steps:
                        result["external"]["wayback"] = await gau_wayback(host)

                    result["external"]["whatweb"] = await whatweb_run(host)
                    result["external"]["wafw00f"] = await wafw00f_run(host)
                except Exception as e:
                    LOG.exception("Error scanning %s: %s", host, e)
                    result["error"] = str(e)
                findings["scans"].append(result)

        tasks = [scan_host(h) for h in discovered_hosts]
        await asyncio.gather(*tasks)

        # Red-team aggressive suite (consent required). Only run if preset includes "redteam"
        if "redteam" in steps:
            LOG.info("Running red-team suite (aggressive). Ensure consent has been provided.")
            try:
                rt_results = await redteam.run_redteam_suite(target, interface=None, allow_responder=False, timeout_per_tool=120)
                findings.setdefault("redteam", {}).update(rt_results or {})
            except Exception as e:
                LOG.exception("Redteam suite error: %s", e)
                findings["notes"].append(f"Redteam error: {e}")

        findings["end_time"] = datetime.datetime.utcnow().isoformat()
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        base = f"{target.replace('/', '_')}_{timestamp}"
        json_path = os.path.join(self.outdir, f"{base}.json")
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)
        html_path = os.path.join(self.outdir, f"{base}.html")
        self.reporter.render_to_file(findings, html_path)
        # CVE enrichment if NVD loaded
        if self.nvd_db:
            try:
                stdjson = os.path.splitext(html_path)[0] + ".std.json"
                if os.path.exists(stdjson):
                    LOG.info("Enriching standardized findings with NVD CVEs")
                    import json as _j
                    data = _j.load(open(stdjson, "r", encoding="utf-8"))
                    std_findings = data.get("standard_findings", [])
                    enriched = cve.enrich_findings_with_nvd(std_findings, self.nvd_db)
                    _j.dump({"standard_findings": enriched}, open(stdjson, "w", encoding="utf-8"), indent=2)
            except Exception as e:
                LOG.debug("CVE enrichment failed: %s", e)

        LOG.info("Scan complete. Report: %s / %s", json_path, html_path)
        return findings
