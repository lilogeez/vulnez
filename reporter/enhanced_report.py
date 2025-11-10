import json
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
import csv, time

TEMPLATE_DIR = Path(__file__).parent / "templates"; TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATE_FILE = TEMPLATE_DIR / "enhanced_report.html"
if not TEMPLATE_FILE.exists():
    TEMPLATE_FILE.write_text("<html><body><h1>VulnEZ Report</h1>{% for e in entries %}<h2>{{e.tool_name}}</h2><pre>{{e.result}}</pre>{% endfor %}</body></html>")

env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=select_autoescape(["html","xml"]))

def generate_all_reports(json_file, outdir):
    outdir = Path(outdir); outdir.mkdir(parents=True, exist_ok=True)
    data = json.loads(Path(json_file).read_text()) if Path(json_file).exists() else []
    Path(outdir / "combined.json").write_text(json.dumps(data, indent=2))
    csvfile = outdir / "combined.csv"
    with open(csvfile, "w", newline='', encoding='utf-8') as f:
        f.write("tool_name,status,short\n")
        for e in data:
            f.write(f"{e.get('tool_name')},{e.get('status')},{str(e.get('result'))[:80].replace(',',' ')}\n")
    tmpl = env.get_template("enhanced_report.html")
    html = tmpl.render(entries=data)
    out_html = outdir / "combined.html"; out_html.write_text(html)
    return {"json": str(outdir/"combined.json"), "csv": str(csvfile), "html": str(out_html)}
