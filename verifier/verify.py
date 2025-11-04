# verifier skeleton: safe re-checks
import json, time
from pathlib import Path

def run_verification(results_json_path):
    p = Path(results_json_path)
    if not p.exists():
        return {"tool_name":"VERIFIER","start_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),"end_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),"result":"no input","status":"error","error_message":"no results"}
    data = json.loads(p.read_text())
    verified=[]
    for entry in data:
        if entry.get("tool_name")=="NUCLEI" and isinstance(entry.get("result"), list):
            for r in entry["result"]:
                verified.append({"name":r.get("name"),"host":r.get("host"),"verified":False,"note":"placeholder - implement specific verifier"})
    return {"tool_name":"VERIFIER","start_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),"end_time":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),"result":{"verified_count":len(verified),"items":verified},"status":"success","error_message":""}
