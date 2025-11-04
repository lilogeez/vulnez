import shutil, subprocess, time
from pathlib import Path

def run_amass(target, outdir, config=None):
    outdir = Path(outdir); outdir.mkdir(parents=True, exist_ok=True)
    subs_file = outdir / "subdomains.txt"
    found = set()
    if shutil.which("amass"):
        cmd = ["amass","enum","-d",target,"-o",str(outdir/"amass.txt")]
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if (outdir/"amass.txt").exists():
            with open(outdir/"amass.txt") as f:
                for l in f: 
                    if l.strip(): found.add(l.strip())
    if shutil.which("subfinder"):
        cmd = ["subfinder","-d",target,"-o",str(outdir/"subfinder.txt")]
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if (outdir/"subfinder.txt").exists():
            with open(outdir/"subfinder.txt") as f:
                for l in f:
                    if l.strip(): found.add(l.strip())
    with open(subs_file,"w") as f:
        for s in sorted(found): f.write(s+"\n")
    return {"tool_name":"AMASS_SUBFINDER","start_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "end_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "result":f"Found {len(found)} subdomains", "subdomains_file":str(subs_file), "status":"success" if found else "warning", "error_message":""}
