import shutil, subprocess, time
from pathlib import Path

def run_nmap(target, outdir, ports=None, args=None, timeout=180):
    outdir = Path(outdir); outdir.mkdir(parents=True, exist_ok=True)
    if not shutil.which("nmap"):
        return {"tool_name":"NMAP","start_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "end_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "result":"nmap not found","status":"skipped","error_message":""}
    xml_out = outdir/"nmap.xml"
    cmd = ["nmap","-sV","-oX",str(xml_out),target]
    if ports: cmd = ["nmap","-sV","-p",ports,"-oX",str(xml_out),target]
    if args and isinstance(args,list): cmd = ["nmap"]+args+["-sV","-oX",str(xml_out),target]
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    return {"tool_name":"NMAP","start_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "end_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "result":f"Saved {xml_out}" if xml_out.exists() else "no xml","output_file":str(xml_out) if xml_out.exists() else "","status":"success" if xml_out.exists() else "error","error_message":p.stderr}
