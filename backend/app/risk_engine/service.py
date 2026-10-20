from sqlalchemy import select

from app.models.scan import Finding
from app.risk_engine.engine import evaluate, load_rules
from app.timeutils import utcnow


def analyze_scan(db, scan, hosts):
    rules = load_rules()
    now = utcnow()
    for host in hosts:
        for svc in host.services:
            info = {"port": svc.port, "protocol": svc.protocol, "state": svc.state,
                    "name": svc.name, "product": svc.product, "version": svc.version,
                    "confidence": svc.confidence,
                    "cves": [{"cve": v.cve, "cvss": v.cvss} for v in svc.vulnerabilities]}
            for d in evaluate(rules, host.criticality, info):
                key = f"{d['rule_id']}|{host.ip}|{svc.port}/{svc.protocol}"
                prev = db.scalar(select(Finding).where(Finding.key == key)
                                 .order_by(Finding.id.desc()).limit(1))
                status, comment, by, first_seen = "new", None, None, now
                if prev:
                    first_seen = prev.first_seen
                    if prev.status in ("accepted", "in_progress"):  # on garde les décisions humaines
                        status, comment, by = prev.status, prev.accepted_comment, prev.accepted_by
                db.add(Finding(scan_id=scan.id, host_id=host.id, service_id=svc.id, key=key,
                               status=status, accepted_comment=comment, accepted_by=by,
                               first_seen=first_seen, last_seen=now, **d))
