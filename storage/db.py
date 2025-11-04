# storage/db.py - simple SQLite helper
import sqlite3, json
from pathlib import Path
DB_PATH = Path("vulnez_results.db")

def init_db():
    conn=sqlite3.connect(str(DB_PATH)); c=conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, target TEXT, start_time TEXT, end_time TEXT, metadata TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, scan_id INTEGER, tool TEXT, severity INTEGER, cve TEXT, details TEXT, FOREIGN KEY(scan_id) REFERENCES scans(id))""")
    conn.commit(); conn.close()

def save_scan(target,start,end,metadata):
    conn=sqlite3.connect(str(DB_PATH)); c=conn.cursor()
    c.execute("INSERT INTO scans (target,start_time,end_time,metadata) VALUES (?,?,?,?)",(target,start,end,json.dumps(metadata)))
    conn.commit(); conn.close()

init_db()
