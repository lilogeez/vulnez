from fastapi import FastAPI, HTTPException
from pathlib import Path
import json

app = FastAPI(title="VulnEZ API", version="0.1")

@app.get("/")
def root(): return {"message":"VulnEZ API"}

@app.get("/results")
def results():
    p=Path("combined_scan_results.json")
    if not p.exists(): raise HTTPException(status_code=404, detail="No results")
    return json.loads(p.read_text())

@app.get("/reports/latest")
def latest():
    rdir=Path("reports")
    if not rdir.exists(): raise HTTPException(status_code=404, detail="No reports")
    htmls=list(rdir.rglob("combined.html"))
    if not htmls: raise HTTPException(status_code=404, detail="No combined.html")
    latest=sorted(htmls,key=lambda p:p.stat().st_mtime)[-1]
    return {"report_path":str(latest)}
