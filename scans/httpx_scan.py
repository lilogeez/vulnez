import shutil, subprocess
from pathlib import Path

def run_httpx(targets_file, outdir, timeout=60):
    outdir = Path(outdir); outdir.mkdir(parents=True, exist_ok=True)
    if not shutil.which("httpx"):
        return {"tool_name":"HTTPX","result":"httpx not installed","status":"skipped"}
    out_json = outdir / "httpx.jsonl"
    cmd = ["httpx","-l",str(targets_file),"-json","-o",str(out_json)]
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    return {"tool_name":"HTTPX","result":str(out_json) if out_json.exists() else "no output","status":"success" if out_json.exists() else "error"}
