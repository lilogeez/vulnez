import shutil, subprocess, time
from pathlib import Path

def run_masscan(target, outdir, ports="1-65535", rate="1000", timeout=120):
    outdir = Path(outdir); outdir.mkdir(parents=True, exist_ok=True)
    if not shutil.which("masscan"):
        return {"tool_name":"MASSCAN","start_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "end_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "result":"masscan not found","status":"skipped","error_message":""}
    xml_out = outdir/"masscan.xml"
    cmd=["masscan",target,"-p",ports,"--rate",rate,"-oX",str(xml_out)]
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    return {"tool_name":"MASSCAN","start_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "end_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "result":f"Saved {xml_out}" if xml_out.exists() else "no xml","output_file":str(xml_out) if xml_out.exists() else "","status":"success" if xml_out.exists() else "error","error_message":p.stderr}
