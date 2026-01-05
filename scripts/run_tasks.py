#!/usr/bin/env python3
import argparse, json
from pathlib import Path
from vulnez.core.runner import Task, TaskRunner
from vulnez import db

p = argparse.ArgumentParser()
p.add_argument('tasks_file')
p.add_argument('--concurrency', type=int, default=4)
p.add_argument('--dry-run', action='store_true')
p.add_argument('--target', default='generated')
p.add_argument('--confirm-legal-plus', action='store_true')
p.add_argument('--enqueue', action='store_true', help='Masukkan tasks ke antrean DB tanpa menjalankan langsung')
args = p.parse_args()

js = json.loads(Path(args.tasks_file).read_text())
if args.enqueue:
    inserted = db.enqueue_tasks(js)
    print(f'[+] Enqueued {inserted} tasks ke DB')
    raise SystemExit(0)

tasks = [Task(name=t['name'], cmd=t['cmd'], timeout=t.get('timeout',600), destructive=t.get('destructive', False)) for t in js]
TaskRunner(concurrency=args.concurrency, target=args.target, output_dir=Path('outputs')/args.target, dry_run=args.dry_run, confirm_legal_plus=args.confirm_legal_plus).run_tasks(tasks)
