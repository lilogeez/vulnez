#!/usr/bin/env python3
import time, signal, subprocess, json
from vulnez import db

STOP = False
def _signal(sig, frame):
    global STOP; STOP = True
signal.signal(signal.SIGINT, _signal); signal.signal(signal.SIGTERM, _signal)

def run_task(task):
    tid = task['id']
    cmd = task['cmd']
    print(f"[+] Menjalankan task {tid}: {' '.join(cmd)}")
    db.update_task_status(tid, 'running')
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        result = json.dumps({'returncode': proc.returncode, 'stdout': proc.stdout[:10000], 'stderr': proc.stderr[:10000]})
        status = 'done' if proc.returncode == 0 else 'failed'
        db.update_task_status(tid, status, result)
        print(f"[+] Task {tid} selesai: {status}")
    except Exception as e:
        db.update_task_status(tid, 'failed', str(e))
        print(f"[!] Task {tid} gagal: {e}")

def main(poll_interval=5):
    print('[*] Agent VulnEZ berjalan. Tekan Ctrl+C untuk stop.')
    while not STOP:
        task = db.fetch_next_task()
        if task:
            run_task(task)
        else:
            time.sleep(poll_interval)
    print('[*] Agent berhenti.')

if __name__ == '__main__':
    main()
