#!/usr/bin/env python3
import argparse
from pathlib import Path
from urllib.parse import urlparse

p = argparse.ArgumentParser()
p.add_argument('--target', required=True)
args = p.parse_args()
inpath = Path('outputs')/args.target/'sqlmap_targets.txt'
if not inpath.exists():
    print('[!] sqlmap_targets.txt tidak ditemukan'); raise SystemExit(1)
outdir = Path('outputs')/args.target/'sqlmap_requests'; outdir.mkdir(parents=True, exist_ok=True)
for i, url in enumerate([l.strip() for l in inpath.read_text().splitlines() if l.strip()], start=1):
    u = urlparse(url)
    path = u.path or '/'
    if u.query: path += '?' + u.query
    host = u.netloc
    lines = [f'GET {path} HTTP/1.1', f'Host: {host}', 'User-Agent: VulnEZ/1.0', 'Accept: */*', '', '']
    (outdir/f'sqlmap_req_{i}.txt').write_text('\\n'.join(lines))
print('[+] Berhasil membuat request files di', outdir)
