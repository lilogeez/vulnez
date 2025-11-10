#!/usr/bin/env python3
# vulnez.py - minimal main for VulnEZ (job based, uses runner and status_manager)

import time
from pathlib import Path
from status_manager import JobManager
from runner import safe_run, find_executable
import json

JM = JobManager()
RESULTS_JSON = Path("combined_scan_results.json")

def write_entry(entry):
    data = []
    if RESULTS_JSON.exists():
        try:
            data = json.loads(RESULTS_JSON.read_text())
        except Exception:
            data = []
    data.append(entry)
    RESULTS_JSON.write_text(json.dumps(data, indent=2))

def run_simple_pipeline(target):
    job_id = JM.create_job(target)
    JM.update_state(job_id, "running")
    outdir = Path("reports") / f"{target}_{int(time.time())}"
    outdir.mkdir(parents=True, exist_ok=True)
    JM.update_step(job_id, "workdir", {"path": str(outdir)})

    steps = [
        ("AMASS", ["amass", "enum", "-d", target, "-o", str(outdir / "amass.txt")]),
        ("HTTPX", ["httpx", "-u", target, "-json", "-o", str(outdir / "httpx.jsonl")]),
        ("NUCLEI", ["nuclei", "-u", target, "-json", "-o", str(outdir / "nuclei.jsonl")]),
    ]

    for name, cmd in steps:
        JM.update_step(job_id, name, {"status": "pending"})
        exe = find_executable(cmd[0])
        if not exe:
            JM.append_log(job_id, f"{name}: binary not found, skipping.\n")
            JM.update_step(job_id, name, {"status": "skipped"})
            continue
        JM.update_step(job_id, name, {"status": "running"})
        res = safe_run(cmd, timeout=300)
        JM.append_log(job_id, f"{name} result: returncode={res.get('returncode')}\n")
        if res.get("success"):
            JM.update_step(job_id, name, {"status": "done"})
        else:
            JM.update_step(job_id, name, {"status": "error", "error": res.get("stderr")})
    JM.update_state(job_id, "finished")
    JM.append_log(job_id, "Pipeline finished\n")
    write_entry({"tool_name":"JOB_SUMMARY","result":f"job://{job_id}"})
    return job_id

def main():
    print("VulnEZ minimal launcher")
    while True:
        print("\n1) Run pipeline (minimal)")
        print("2) List jobs")
        print("3) Exit")
        c = input("Choice: ").strip()
        if c == "1":
            t = input("Target (domain or IP): ").strip()
            jid = run_simple_pipeline(t)
            print("Job created:", jid)
        elif c == "2":
            for j in JM.list_jobs():
                print(j["id"], j["state"], j.get("target"))
        elif c == "3":
            break
        else:
            print("Invalid")

if __name__ == '__main__':
    main()
