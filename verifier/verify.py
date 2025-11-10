import json, time
from pathlib import Path

def run_verification(results_json_path):
    p = Path(results_json_path)
    if not p.exists():
        return {"result":"no results"}
    data = json.loads(p.read_text())
    verified = []
    for entry in data:
        if entry.get("tool_name") == "NUCLEI":
            verified.append({"name":"placeholder","verified":False})
    return {"verified_count": len(verified), "items": verified}
