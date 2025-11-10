import xml.etree.ElementTree as ET
from pathlib import Path
import json

def parse_nmap_xml(xml_path):
    xml_path = Path(xml_path)
    if not xml_path.exists():
        return {"error":"file not found"}
    tree = ET.parse(str(xml_path)); root = tree.getroot()
    res=[]
    for host in root.findall("host"):
        h={"addresses":[],"ports":[]}
        for addr in host.findall("address"):
            a = addr.get("addr"); 
            if a: h["addresses"].append(a)
        ports = host.find("ports")
        if ports:
            for p in ports.findall("port"):
                portid = p.get("portid"); proto = p.get("protocol")
                state = p.find("state").get("state") if p.find("state") is not None else None
                service = p.find("service"); svc = service.attrib if service is not None else {}
                h["ports"].append({"port":portid,"protocol":proto,"state":state,"service":svc})
        res.append(h)
    return res

def nmap_to_json(xml_path, out_json):
    data = parse_nmap_xml(xml_path)
    Path(out_json).write_text(json.dumps(data, indent=2))
    return out_json
