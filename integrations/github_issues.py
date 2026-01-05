import requests
import os
from typing import Optional
from vulnez import config

def create_issue(repo: str, title: str, body: str, token: Optional[str] = None) -> dict:
    token = token or config.GITHUB_TOKEN
    if not token:
        raise RuntimeError('Token GitHub tidak disediakan')
    url = f'https://api.github.com/repos/{repo}/issues'
    headers = {'Authorization': f'token {token}', 'Accept': 'application/vnd.github+json'}
    payload = {'title': title, 'body': body}
    r = requests.post(url, json=payload, headers=headers, timeout=15)
    if r.status_code in (200,201):
        return r.json()
    else:
        raise RuntimeError(f'Gagal membuat issue: {r.status_code} {r.text}')
