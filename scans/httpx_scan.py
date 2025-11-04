import shutil, subprocess, time
from pathlib import Path

def run_httpx(targets_file, outdir, timeout=60):
    outdir = Path(outdir); outdir.mkdir(parents=True, exist_ok=True)
    if not shutil.which("httpx"):
        return {"tool_name":"HTTPX","start_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "end_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "result":"httpx not found","status":"skipped","error_message":""}
    out_json = outdir/"httpx.jsonl"
    cmd = ["httpx","-l",str(targets_file),"-json","-o",str(out_json),"-timeout","10","-threads","20"]
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    return {"tool_name":"HTTPX","start_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "end_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "result":f"Saved httpx to {out_json}" if out_json.exists() else "no output","output_file":str(out_json) if out_json.exists() else "", "status":"success" if out_json.exists() else "error", "error_message":p.stderr}
