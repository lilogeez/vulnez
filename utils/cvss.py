import os, re
import requests
CVE_RE=re.compile(r"CVE-\d{4}-\d{4,7}",re.I)
def estimate_cvss_from_severity(sev:str)->float:
    if not sev: return 0.0
    s=sev.lower()
    if s=="critical": return 9.5
    if s=="high": return 7.5
    if s=="medium": return 5.0
    if s=="low": return 2.5
    return 0.0

def lookup_cvss_vulners(cve:str,api_key:None):
    try:
        r=requests.get(f"https://vulners.com/api/v3/search/id/?id={cve}",timeout=10)
        if r.status_code==200:
            j=r.json(); d=j.get("data",{}); cvss=d.get("cvss",{}).get("score")
            if cvss: return float(cvss)
    except Exception:
        return None
    return None

def get_best_cvss(entry,api_key:None=None):
    cves=[]
    if isinstance(entry.get("result"),list):
        for r in entry["result"]:
            if isinstance(r,dict) and r.get("cves"): cves.extend(r.get("cves"))
    txt=str(entry.get("result",""))
    for m in CVE_RE.findall(txt): cves.append(m.upper())
    for cve in cves:
        score=lookup_cvss_vulners(cve,api_key=api_key)
        if score: return {"cve":cve,"cvss":score}
    if isinstance(entry.get("result"),list) and entry["result"]:
        sev_priority={"critical":4,"high":3,"medium":2,"low":1}
        best=None
        for r in entry["result"]:
            s=(r.get("severity") or "").lower()
            if s and (not best or sev_priority.get(s,0)>sev_priority.get(best,0)): best=s
        if best: return {"cve":None,"cvss":estimate_cvss_from_severity(best),"estimated_from":best}
    if "cve" in txt.lower() or "vulnerab" in txt.lower(): return {"cve":None,"cvss":4.0}
    return {"cve":None,"cvss":0.0}
