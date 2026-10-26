from app.models.scan import Finding, Host, Scan, Service
from app.timeutils import utcnow


def mk_scan(db, profile="standard", target="172.30.0.0/24", status="done"):
    s = Scan(scope_id=1, target=target, profile=profile, status=status, created_by=1)
    db.add(s)
    db.commit()
    return s


def mk_host(db, scan, ip, ports=(), state="up"):
    h = Host(scan_id=scan.id, ip=ip, state=state)
    for port, name, version in ports:
        h.services.append(Service(port=port, protocol="tcp", state="open", name=name, version=version, confidence=100))
    db.add(h)
    db.commit()
    return h


def mk_finding(db, scan, host, rule, port, score, level="medium", evidence="e"):
    now = utcnow()
    f = Finding(
        scan_id=scan.id,
        host_id=host.id,
        key=f"{rule}|{host.ip}|{port}/tcp",
        rule_id=rule,
        rule_version=1,
        title=f"Regle {rule}",
        level=level,
        score=score,
        factors=[],
        justification="j",
        evidence=evidence,
        recommendation="r",
        first_seen=now,
        last_seen=now,
    )
    db.add(f)
    db.commit()
    return f
