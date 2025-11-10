import re, requests
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
def estimate_cvss_from_severity(sev):
    if not sev: return 0.0
    s = sev.lower()
    if s=="critical": return 9.5
    if s=="high": return 7.5
    if s=="medium": return 5.0
    if s=="low": return 2.5
    return 0.0
def get_best_cvss(entry, api_key=None):
    return {"cve": None, "cvss": 0.0}
