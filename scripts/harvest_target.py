#!/usr/bin/env python3
import argparse, json
from pathlib import Path
from urllib.parse import urlparse, parse_qs

p = argparse.ArgumentParser()
p.add_argument('--target', required=True)
p.add_argument('--min-params', type=int, default=1)
args = p.parse_args()
outdir = Path('outputs')/args.target
if not outdir.exists():
    print('[!] outputs/<target> tidak ditemukan'); raise SystemExit(1)
urls=[]
for f in outdir.glob('*'):
    try:
        for l in f.read_text(errors='ignore').splitlines():
            l=l.strip()
            if (l.startswith('http://') or l.startswith('https://')) and ('?' in l):
                urls.append(l.split()[0])
    except Exception:
        continue
selected=[]
for u in sorted(set(urls)):
    try:
        if len(parse_qs(urlparse(u).query))>=args.min_params:
            selected.append(u)
    except Exception:
        continue
(outdir/'sqlmap_targets.txt').write_text('\\n'.join(selected))
tasks=[{'name':f'sqlmap:{u}', 'cmd':['sqlmap','-u',u,'--batch','--output-dir',str(outdir/'sqlmap')], 'timeout':1800, 'destructive':True} for u in selected]
(outdir/'sqlmap_tasks.json').write_text(json.dumps(tasks, indent=2))
print(f'[+] Generated {len(tasks)} sqlmap tasks -> {outdir/"sqlmap_tasks.json"}')
