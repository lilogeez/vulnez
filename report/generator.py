from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path
import json, datetime

TEMPLATES = Path(__file__).parent / 'templates'
env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=select_autoescape([]))

def load_findings(summary_json: str):
    p = Path(summary_json)
    if not p.exists(): return []
    try:
        return json.loads(p.read_text())
    except Exception:
        return []

def render_report(findings, template_name='owasp_template.md.j2', out='report.md'):
    tpl = env.get_template(template_name)
    for f in findings:
        f.setdefault('short', (f.get('stdout') or f.get('stderr') or '')[:800])
    content = tpl.render(findings=findings, generated_at=datetime.datetime.datetime.utcnow().isoformat()+'Z')
    Path(out).write_text(content)
    print('[+] Laporan dibuat:', out)
