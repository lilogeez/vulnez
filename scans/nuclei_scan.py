import shutil, subprocess, json
from pathlib import Path
import re, time

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

def run_nuclei(target, outdir, timeout=120, templates=None):
    outdir = Path(outdir); outdir.mkdir(parents=True, exist_ok=True)
    if not shutil.which("nuclei"):
        return {"tool_name":"NUCLEI","result":"nuclei not installed","status":"skipped"}
    out_json = outdir / "nuclei.jsonl"
    cmd = ["nuclei","-u",target,"-json","-o",str(out_json)]
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    parsed = []
    if out_json.exists():
        with open(out_json) as f:
            for line in f:
                try:
                    j = json.loads(line)
                    parsed.append(j)
                except Exception:
                    continue
    return {"tool_name":"NUCLEI","result":parsed if parsed else "no findings","status":"success" if parsed else "info"}
