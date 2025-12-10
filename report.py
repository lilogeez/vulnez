import os
import jinja2
import datetime
import logging
from .enrich import generate_standard_findings

LOG = logging.getLogger("vulnez.report")

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")
REPORT_TEMPLATE = "report_full.html.j2"

class ReportGenerator:
    def __init__(self, templates_dir=TEMPLATES_DIR, outdir=None):
        self.env = jinja2.Environment(loader=jinja2.FileSystemLoader(templates_dir), autoescape=True)
        self.template = self.env.get_template(REPORT_TEMPLATE)
        self.outdir = outdir or "reports"

    def enrich_and_render(self, raw_findings: dict):
        standardized = generate_standard_findings(raw_findings)
        ctx = {
            "generated_at": datetime.datetime.utcnow().isoformat(),
            "findings": raw_findings,
            "standard_findings": standardized
        }
        return ctx

    def render(self, raw_findings: dict):
        ctx = self.enrich_and_render(raw_findings)
        return self.template.render(ctx)

    def render_to_file(self, raw_findings: dict, outpath: str):
        content = self.render(raw_findings)
        os.makedirs(os.path.dirname(outpath) or ".", exist_ok=True)
        with open(outpath, "w", encoding="utf-8") as fh:
            fh.write(content)
        LOG.info("Report saved to %s", outpath)
        std_json_path = os.path.splitext(outpath)[0] + ".std.json"
        try:
            import json
            with open(std_json_path, "w", encoding="utf-8") as fh:
                json.dump(self.enrich_and_render(raw_findings), fh, indent=2)
            LOG.info("Standardized findings saved to %s", std_json_path)
        except Exception as e:
            LOG.debug("Could not write standardized findings JSON: %s", e)
