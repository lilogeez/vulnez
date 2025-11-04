import shutil, subprocess, json, time
from pathlib import Path
import re

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

def run_nuclei(target, outdir, timeout=120, templates=None):
    outdir = Path(outdir); outdir.mkdir(parents=True, exist_ok=True)
    if not shutil.which("nuclei"):
        return {"tool_name":"NUCLEI","start_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "end_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "result":"nuclei not found","status":"skipped","error_message":""}
    out_json = outdir/"nuclei.jsonl"
    cmd = ["nuclei","-u",target,"-json","-o",str(out_json)]
    if templates: cmd += ["-t",templates]
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    parsed=[]
    if out_json.exists():
        with open(out_json) as f:
            for line in f:
                if line.strip():
                    try:
                        j=json.loads(line)
                        info=j.get("info",{})
                        raw=json.dumps(j)
                        cves=sorted({m.upper() for m in CVE_RE.findall(raw)})
                        parsed.append({"name":info.get("name"),"severity":info.get("severity"),"host":j.get("host"),"template":j.get("template"),"cves":cves,"raw":j})
                    except Exception:
                        continue
    return {"tool_name":"NUCLEI","start_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "end_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "result":parsed if parsed else "no findings","output_file":str(out_json) if out_json.exists() else "","status":"success" if parsed else "info","error_message":p.stderr}
