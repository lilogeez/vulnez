# (same as earlier Stage-3 enrich module) - parse nmap xml, cvss-lite, mappings
from xml.etree import ElementTree as ET
import re
import hashlib
import datetime

OWASP_RULES = {
    "A1-Injection": ["sql", "sqlmap", "union", "select", "SQLException", "syntax error", "ORA-"],
    "A2-Broken Authentication": ["login", "auth", "authentication", "session", "jwt", "cookie", "set-cookie"],
    "A3-Sensitive Data Exposure": ["tls", "ssl", "certificate", "sha1", "unencrypted", "creditcard", "credit card", "ssn"],
    "A5-Broken Access Control": ["privilege", "unauthoriz", "403", "access denied", "forbidden"],
    "A6-Security Misconfiguration": ["server-header", "x-frame-options", "x-xss-protection", "misconfig", "directory listing"],
    "A9-Using Components with Known Vulnerabilities": ["version", "cpe", "apache", "nginx", "tomcat", "openssl", "struts"],
    "A10-Insufficient Logging & Monitoring": ["no audit", "no logging", "no monitoring"],
}

def _short_hash(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()[:8]

def parse_nmap_xml(xml_text: str):
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return {}
    result = {"hosts": [], "run_stats": {}}
    for host in root.findall("host"):
        h = {"addresses": [], "hostnames": [], "ports": [], "os": None}
        for addr in host.findall("address"):
            addrtype = addr.get("addrtype")
            addrval = addr.get("addr")
            h["addresses"].append({"type": addrtype, "addr": addrval})
        hostnames = host.find("hostnames")
        if hostnames is not None:
            for hn in hostnames.findall("hostname"):
                name = hn.get("name")
                if name:
                    h["hostnames"].append(name)
        ports = host.find("ports")
        if ports is not None:
            for p in ports.findall("port"):
                portid = p.get("portid")
                proto = p.get("protocol")
                state_el = p.find("state")
                service_el = p.find("service")
                state = state_el.get("state") if state_el is not None else ""
                svc = {}
                if service_el is not None:
                    svc = {
                        "name": service_el.get("name"),
                        "product": service_el.get("product"),
                        "version": service_el.get("version"),
                        "extrainfo": service_el.get("extrainfo"),
                        "ostype": service_el.get("ostype"),
                        "method": service_el.get("method"),
                        "conf": service_el.get("conf")
                    }
                h["ports"].append({
                    "port": int(portid) if portid and portid.isdigit() else portid,
                    "proto": proto,
                    "state": state,
                    "service": svc
                })
        os_el = host.find("os")
        if os_el is not None:
            os_matches = []
            for m in os_el.findall("osmatch"):
                os_matches.append({"name": m.get("name"), "accuracy": m.get("accuracy")})
            if os_matches:
                h["os"] = os_matches
        result["hosts"].append(h)
    runstats = root.find("runstats")
    if runstats is not None:
        stats = {}
        finished = runstats.find("finished")
        if finished is not None:
            stats["time"] = finished.get("time")
            stats["elapsed"] = finished.get("elapsed")
        result["run_stats"] = stats
    return result

def cvss_lite_score_from_port(port_entry: dict):
    port = port_entry.get("port")
    svc = port_entry.get("service") or {}
    name = (svc.get("name") or "").lower()
    product = (svc.get("product") or "").lower()
    version = (svc.get("version") or "").lower()
    state = port_entry.get("state") or ""
    score = 0
    if state not in ("open","open|filtered","open,filtered"):
        return "Low"
    dangerous_ports = {21:2, 22:1, 23:3, 80:1, 443:1, 445:3, 3389:3, 1521:2, 3306:2, 5432:2}
    if isinstance(port, int) and port in dangerous_ports:
        score += dangerous_ports[port]
    if any(k in product for k in ("apache","tomcat","nginx","iis","openssl","struts")):
        score += 2
    if re.search(r"(beta|dev|test|snapshot)", version):
        score += 1
    if any(k in name for k in ("mysql","mariadb","postgres","mssql","oracle")):
        score += 2
    if score >= 5:
        return "Critical"
    if score >= 3:
        return "High"
    if score >= 2:
        return "Medium"
    return "Low"

def map_to_owasp_from_text(text: str):
    if not text:
        return []
    matches = set()
    t = text.lower()
    for label, tokens in OWASP_RULES.items():
        for tok in tokens:
            if tok.lower() in t:
                matches.add(label)
                break
    return sorted(matches)

def normalize_external_result(tool_name: str, raw_text: str):
    if not raw_text:
        return None
    snippet = raw_text.strip()
    if len(snippet) > 8000:
        snippet = snippet[:8000] + "\n...[truncated]"
    lines = [l.strip() for l in snippet.splitlines() if l.strip()]
    lines = lines[:200]
    return {"tool": tool_name, "text": "\n".join(lines)}

def generate_standard_findings(findings: dict):
    std = []
    for scan in findings.get("scans", []):
        host = scan.get("host")
        nmap_raw = scan.get("nmap")
        if nmap_raw:
            parsed = parse_nmap_xml(nmap_raw) if nmap_raw.strip().startswith("<") else {}
            for h in parsed.get("hosts", []):
                for p in h.get("ports", []):
                    sev = cvss_lite_score_from_port(p)
                    title = f"Open port {p.get('port')}/{p.get('proto')} - {p.get('service', {}).get('name')}"
                    desc = f"Service: {p.get('service')}\nHost addresses: {h.get('addresses')}"
                    evidence = [ {"type":"nmap_port", "data": str(p)} ]
                    owasp = map_to_owasp_from_text(str(p.get("service") or ""))
                    fid = f"F-{_short_hash(host + title)}"
                    rec = recommendation_for_port(p)
                    std.append({
                        "id": fid,
                        "host": host,
                        "title": title,
                        "description": desc,
                        "evidence": evidence,
                        "severity": sev,
                        "owasp": owasp,
                        "nist": ["NIST SP 800-115"],
                        "recommendation": rec,
                        "timestamp": datetime.datetime.utcnow().isoformat()
                    })
        for h in scan.get("http") or []:
            url = h.get("url")
            status = h.get("status")
            title = f"HTTP {status} at {url}"
            desc = f"Headers: {h.get('headers')}"
            evidence = [{"type":"http_response", "data": h.get("headers")}]
            owasp = map_to_owasp_from_text(" ".join([str(status), h.get("title") or "", str(h.get("headers") or "")]))
            sev = "Medium" if status and status >= 400 else "Low"
            fid = f"F-{_short_hash(host + url)}"
            rec = recommendation_for_http(h)
            std.append({
                "id": fid,
                "host": host,
                "title": title,
                "description": desc,
                "evidence": evidence,
                "severity": sev,
                "owasp": owasp,
                "nist": ["NIST SP 800-115"],
                "recommendation": rec,
                "timestamp": datetime.datetime.utcnow().isoformat()
            })
        for tool, raw in (scan.get("external") or {}).items():
            if not raw:
                continue
            summary = normalize_external_result(tool, raw if isinstance(raw, str) else str(raw))
            title = f"{tool} results on {host}"
            desc = f"Tool {tool} raw output snippet"
            evidence = [summary] if summary else []
            owasp = map_to_owasp_from_text(summary.get("text") if summary else "")
            sev = "Low"
            txt = (summary.get("text") or "").lower() if summary else ""
            if "critical" in txt or "high" in txt:
                sev = "High"
            elif "medium" in txt:
                sev = "Medium"
            fid = f"F-{_short_hash(host + tool + (summary.get('text')[:40] if summary else ''))}"
            rec = recommendation_for_tool(tool, summary.get("text") if summary else "")
            std.append({
                "id": fid,
                "host": host,
                "title": title,
                "description": desc,
                "evidence": evidence,
                "severity": sev,
                "owasp": owasp,
                "nist": ["NIST SP 800-115"],
                "recommendation": rec,
                "timestamp": datetime.datetime.utcnow().isoformat()
            })
    return std

def recommendation_for_port(port_entry: dict):
    port = port_entry.get("port")
    svc = port_entry.get("service") or {}
    name = svc.get("name") or ""
    rec = []
    rec.append(f"Review service running on port {port}. Verify latest patches and secure configuration.")
    if name.lower() in ("telnet",):
        rec.append("Disable telnet; use SSH with key auth.")
    if name.lower() in ("ftp",):
        rec.append("Avoid anonymous FTP; use SFTP or secure transfer.")
    if name.lower() in ("mssql", "mysql", "postgresql", "oracle"):
        rec.append("Ensure authentication is enforced; restrict DB access to trusted hosts.")
    return " ".join(rec)

def recommendation_for_http(http_entry: dict):
    headers = http_entry.get("headers") or {}
    recs = []
    if headers and not any(k.lower() == "strict-transport-security" for k in headers.keys()):
        recs.append("Enable HSTS (Strict-Transport-Security) to enforce HTTPS.")
    if headers and not any(k.lower() == "content-security-policy" for k in headers.keys()):
        recs.append("Consider adding Content-Security-Policy to mitigate XSS.")
    if http_entry.get("status") and http_entry.get("status") >= 400:
        recs.append("Investigate server-side errors and fix server misconfigurations.")
    return " ".join(recs) if recs else "Review responses and headers for security best-practices."

def recommendation_for_tool(tool_name: str, txt: str):
    if not txt:
        return f"Review {tool_name} raw output for details."
    txtl = txt.lower()
    if "sql injection" in txtl or "sql" in txtl:
        return "Validate and sanitize inputs; use parameterized queries; consider WAF rules."
    if "xss" in txtl:
        return "Implement output encoding and input validation; add CSP header."
    return f"Review findings from {tool_name} and apply vendor guidance / update components."
