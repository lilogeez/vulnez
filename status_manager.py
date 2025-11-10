# status_manager.py - minimal job manager (writes job.json + job.log)
import json, time, uuid
from pathlib import Path

ROOT = Path("reports") / "jobs"
ROOT.mkdir(parents=True, exist_ok=True)

def _job_path(job_id):
    return ROOT / job_id

def _job_file(job_id):
    return _job_path(job_id) / "job.json"

class JobManager:
    def create_job(self, target, profile="pipeline"):
        job_id = f"{int(time.time())}_{uuid.uuid4().hex[:8]}"
        p = _job_path(job_id)
        p.mkdir(parents=True, exist_ok=True)
        job = {"id": job_id, "target": target, "profile": profile, "state": "created", "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "steps": {}, "logs": []}
        _job_file(job_id).write_text(json.dumps(job, indent=2))
        return job_id

    def load_job(self, job_id):
        f = _job_file(job_id)
        if not f.exists(): raise FileNotFoundError("job not found")
        return json.loads(f.read_text())

    def save_job(self, job_id, job):
        _job_file(job_id).write_text(json.dumps(job, indent=2))

    def update_state(self, job_id, state):
        job = self.load_job(job_id)
        job["state"] = state
        job["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.save_job(job_id, job)

    def update_step(self, job_id, step_name, info):
        job = self.load_job(job_id)
        job.setdefault("steps", {})
        job["steps"][step_name] = {**job["steps"].get(step_name, {}), **info}
        self.save_job(job_id, job)

    def append_log(self, job_id, line):
        p = _job_path(job_id)
        p.mkdir(parents=True, exist_ok=True)
        lf = p / "job.log"
        with open(lf, "a", encoding="utf-8") as f: f.write(line)
        job = self.load_job(job_id)
        job.setdefault("logs", []).append({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "line": line})
        job["logs"] = job["logs"][-1000:]
        self.save_job(job_id, job)

    def list_jobs(self):
        out = []
        for p in sorted(ROOT.iterdir(), reverse=True):
            jf = p / "job.json"
            if jf.exists():
                try:
                    out.append(json.loads(jf.read_text()))
                except Exception:
                    continue
        return out

    def get_job(self, job_id):
        return self.load_job(job_id)
