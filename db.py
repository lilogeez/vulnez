import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from sqlalchemy import create_engine, Column, Integer, String, Text, Float, Boolean, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
import datetime
import hashlib
import json

DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL:
    engine = create_engine(DATABASE_URL, future=True)
else:
    sqlite_path = Path(os.environ.get("VULNEZ_OUTPUT_DIR", "outputs")) / "vulnez_findings.db"
    engine = create_engine(f"sqlite:///{sqlite_path}", connect_args={"check_same_thread": False}, future=True)

SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
Base = declarative_base()

def _make_uid(*parts) -> str:
    return hashlib.sha1(("|".join(parts)).encode()).hexdigest()

class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String(64), unique=True, index=True)
    name = Column(String(512))
    tool = Column(String(128))
    target = Column(String(256))
    ts = Column(String(64))
    severity = Column(String(32))
    cvss = Column(Float, nullable=True)
    cve = Column(String(256), nullable=True)
    owasp = Column(String(256), nullable=True)
    summary = Column(Text, nullable=True)
    raw_json = Column(Text, nullable=True)
    status = Column(String(32), default="new")
    assigned = Column(String(128), default="")
    verified = Column(Boolean, default=False)

class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String(64), unique=True, index=True)
    name = Column(String(256))
    cmd = Column(Text)
    status = Column(String(32), default="queued")
    target = Column(String(256), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    result = Column(Text, nullable=True)

def init_db():
    Base.metadata.create_all(bind=engine)

def import_summary(summary_json: str, target: Optional[str] = None) -> int:
    init_db()
    s = SessionLocal()
    data = json.loads(Path(summary_json).read_text())
    inserted = 0
    for item in data:
        name = item.get("name", "unnamed")
        tool = name.split(":")[0] if ":" in name else name
        ts = item.get("ts") or (datetime.datetime.datetime.utcnow().isoformat() + "Z")
        uid = _make_uid(name, tool, target or "", ts)
        existing = s.query(Finding).filter_by(uid=uid).first()
        if existing:
            continue
        f = Finding(uid=uid, name=name, tool=tool, target=target or "", ts=ts,
                    summary=(item.get("stdout") or "")[:1000], raw_json=json.dumps(item))
        s.add(f)
        inserted += 1
    s.commit(); s.close()
    return inserted

def list_findings(limit: int = 200, where: Optional[str] = None) -> List[Dict[str, Any]]:
    init_db()
    s = SessionLocal()
    q = s.query(Finding).order_by(Finding.id.desc()).limit(limit)
    rows = q.all()
    out = []
    for r in rows:
        out.append({"id": r.id, "uid": r.uid, "name": r.name, "tool": r.tool, "target": r.target, "ts": r.ts,
                    "severity": r.severity, "cvss": r.cvss, "cve": r.cve, "owasp": r.owasp, "status": r.status,
                    "assigned": r.assigned, "verified": r.verified})
    s.close()
    return out

def update_finding_status(fid:int, status:str):
    init_db()
    s = SessionLocal()
    f = s.query(Finding).filter_by(id=fid).first()
    if not f:
        s.close(); return False
    f.status = status
    s.commit(); s.close()
    return True

def assign_finding(fid:int, assignee:str):
    init_db()
    s = SessionLocal()
    f = s.query(Finding).filter_by(id=fid).first()
    if not f:
        s.close(); return False
    f.assigned = assignee
    s.commit(); s.close()
    return True

def mark_verified(fid:int, verified:bool=True):
    init_db()
    s = SessionLocal()
    f = s.query(Finding).filter_by(id=fid).first()
    if not f:
        s.close(); return False
    f.verified = bool(verified)
    s.commit(); s.close()
    return True

def enqueue_tasks(task_list):
    init_db()
    s = SessionLocal()
    inserted = 0
    for t in task_list:
        uid = _make_uid(t.get("name",""), json.dumps(t.get("cmd", [])))
        existing = s.query(Task).filter_by(uid=uid).first()
        if existing:
            continue
        task = Task(uid=uid, name=t.get("name"), cmd=json.dumps(t.get("cmd")), status="queued", target=t.get("target",""))
        s.add(task)
        inserted += 1
    s.commit(); s.close()
    return inserted

def fetch_next_task():
    init_db()
    s = SessionLocal()
    task = s.query(Task).filter_by(status="queued").order_by(Task.id.asc()).first()
    if not task:
        s.close(); return None
    task.status = "processing"
    task.started_at = datetime.datetime.datetime.utcnow()
    s.commit()
    cmd = json.loads(task.cmd)
    tid = task.id
    s.close()
    return {"id": tid, "uid": task.uid, "name": task.name, "cmd": cmd, "target": task.target}

def update_task_status(tid:int, status:str, result: Optional[str] = None):
    init_db()
    s = SessionLocal()
    t = s.query(Task).filter_by(id=tid).first()
    if not t:
        s.close(); return False
    t.status = status
    if status in ("done","failed"):
        t.finished_at = datetime.datetime.datetime.utcnow()
        t.result = result or ""
    s.commit(); s.close()
    return True
