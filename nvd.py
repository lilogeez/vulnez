import json
from pathlib import Path

def build_cve_map(nvd_json_path: str):
    p = Path(nvd_json_path)
    if not p.exists():
        raise FileNotFoundError(p)
    data = json.loads(p.read_text())
    mapping = {}
    for item in data.get('CVE_Items', []):
        cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
        if not cve_id:
            continue
        impact = item.get('impact', {})
        cvss_v3 = impact.get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore')
        mapping[cve_id] = {'cvss_v3': cvss_v3}
    return mapping
