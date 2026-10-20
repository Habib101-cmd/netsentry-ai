import re

from defusedxml import ElementTree as ET

MAX_XML_BYTES = 20_000_000  # SEC-12
CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,})\s+(\d+(?:\.\d+)?)")


def _vulners(port) -> list[dict]:
    found: dict[str, float] = {}
    for script in port.findall("script"):
        if script.get("id") == "vulners":
            for cve, cvss in CVE_RE.findall(script.get("output", "")):
                found[cve] = max(found.get(cve, 0.0), float(cvss))
    return [{"cve": c, "cvss": s} for c, s in sorted(found.items(), key=lambda x: -x[1])]


def parse_nmap_xml(xml_text: str) -> dict:
    if len(xml_text.encode("utf-8", errors="ignore")) > MAX_XML_BYTES:
        raise ValueError("Sortie Nmap trop volumineuse")
    root = ET.fromstring(xml_text)  # defusedxml : XXE / entités refusées
    hosts = []
    for h in root.findall("host"):
        status = h.find("status")
        ip = mac = None
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                ip = a.get("addr")
            elif a.get("addrtype") == "mac":
                mac = a.get("addr")
        if ip is None:
            continue
        hn = h.find("hostnames/hostname")
        om = h.find("os/osmatch")
        services = []
        for p in h.findall("ports/port"):
            st = p.find("state")
            sv = p.find("service")
            name = sv.get("name") if sv is not None else None
            if sv is not None and sv.get("tunnel") == "ssl" and name == "http":
                name = "https"
            conf = int(sv.get("conf", "0")) * 10 if sv is not None else 0
            services.append({
                "port": int(p.get("portid")),
                "protocol": p.get("protocol"),
                "state": st.get("state") if st is not None else "unknown",
                "name": name,
                "product": sv.get("product") if sv is not None else None,
                "version": sv.get("version") if sv is not None else None,
                "confidence": conf,
                "vulnerabilities": _vulners(p),
            })
        hosts.append({
            "ip": ip, "mac": mac,
            "hostname": hn.get("name") if hn is not None else None,
            "os_guess": om.get("name") if om is not None else None,
            "state": status.get("state") if status is not None else "unknown",
            "services": services,
        })
    return {"nmap_version": root.get("version"), "hosts": hosts}
