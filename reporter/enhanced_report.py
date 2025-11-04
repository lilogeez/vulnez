# reporter with VulnEZ styled header
import json, csv, time
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
from utils.cvss import get_best_cvss

TEMPLATE_DIR = Path(__file__).parent / "templates"; TEMPLATE_DIR.mkdir(exist_ok=True)
TEMPLATE_FILE = TEMPLATE_DIR / "enhanced_report.html"
if not TEMPLATE_FILE.exists():
    TEMPLATE_FILE.write_text("""<!doctype html><html><head><meta charset="utf-8"><title>VulnEZ Report</title><style>body{font-family:Arial;background:#fbfbfb} .header{background:#fff;border-bottom:4px solid #8b0000;padding:18px} .title{color:#8b0000;font-size:32px;font-weight:700}</style></head><body><div class="header"><div class="title">VulnEZ</div><div>Automated Recon & Scanning</div></div><div class="container">{% for e in entries %}<h3>{{e.tool_name}} — {{e.status}}</h3><pre>{{e.result}}</pre>{% endfor %}</div></body></html>""")

env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=select_autoescape(["html","xml"]))
def score_severity(entry):
    score=0
    if isinstance(entry.get("result"), list):
        for r in entry["result"]:
            sev=(r.get("severity") or "").lower()
            if sev=="critical": score+=100
            elif sev=="high": score+=50
            elif sev=="medium": score+=20
            elif sev=="low": score+=5
    else:
        txt=str(entry.get("result","")).lower()
        if "vulnerab" in txt or "cve" in txt: score+=20
    return score

def generate_all_reports(json_file,outdir):
    outdir=Path(outdir); outdir.mkdir(parents=True,exist_ok=True)
    data=json.loads(Path(json_file).read_text())
    for e in data:
        e["severity_score"]=score_severity(e); e["short"]=str(e.get("result"))[:300]; e["cvss_info"]=get_best_cvss(e)
    Path(outdir/"combined.json").write_text(json.dumps(data,indent=2))
    csvfile=outdir/"combined.csv"
    with open(csvfile,"w",newline='',encoding='utf-8') as f:
        writer=csv.writer(f); writer.writerow(["tool_name","status","start_time","end_time","duration","severity_score","cvss","short"])
        for e in data:
            cv=e.get("cvss_info",{}); writer.writerow([e.get("tool_name"),e.get("status"),e.get("start_time"),e.get("end_time"),e.get("duration"),e.get("severity_score"),cv.get("cvss"),e.get("short")])
    tmpl=env.get_template("enhanced_report.html"); html=tmpl.render(entries=data,generated=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    out_html=outdir/"combined.html"; out_html.write_text(html)
    return {"json":str(outdir/"combined.json"),"csv":str(csvfile),"html":str(out_html)}
