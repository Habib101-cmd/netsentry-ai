import ipaddress
from collections import Counter

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.models.scan import Finding, Host, Scan

LEVELS = ["critical", "high", "medium", "low", "info"]
NO_RESPONSE_NOTE = (
    "Ne répond plus lors de ce scan (hôte éteint, filtré ou délai dépassé) : "
    "cela ne prouve pas qu'il a disparu."
)


def _hosts(db, scan_id):
    return db.scalars(select(Host).where(Host.scan_id == scan_id)
                      .options(selectinload(Host.services))).all()


def _findings(db, scan_id):
    return db.scalars(select(Finding).where(Finding.scan_id == scan_id)
                      .options(selectinload(Finding.host))).all()


def _in(ip: str, target: str) -> bool:
    return ipaddress.ip_address(ip) in ipaddress.ip_network(target, strict=False)


def _open(host):
    return {(s.port, s.protocol): s for s in host.services if s.state == "open"}


def _sig(s):
    return {"name": s.name, "product": s.product, "version": s.version}


def _fdict(f):
    return {"rule_id": f.rule_id, "title": f.title, "ip": f.host.ip,
            "port": f.key.split("|")[2], "level": f.level, "score": f.score}


def _summary(hosts, findings):
    by_level = Counter(f.level for f in findings)
    return {"hosts_up": sum(1 for h in hosts if h.state == "up"),
            "findings": len(findings),
            "by_level": {lvl: by_level.get(lvl, 0) for lvl in LEVELS},
            "total_score": sum(f.score for f in findings)}


def _info(scan: Scan):
    return {"id": scan.id, "target": scan.target, "profile": scan.profile,
            "finished_at": scan.finished_at}


def compare_scans(db, base: Scan, other: Scan) -> dict:
    """base = scan de référence (avant), other = scan comparé (après)."""
    bh, oh = _hosts(db, base.id), _hosts(db, other.id)
    bf, of = _findings(db, base.id), _findings(db, other.id)
    b_up = {h.ip: h for h in bh if h.state == "up"}
    o_up = {h.ip: h for h in oh if h.state == "up"}

    notes = []
    if not ipaddress.ip_network(base.target, strict=False).overlaps(
            ipaddress.ip_network(other.target, strict=False)):
        notes.append("Les deux scans ne couvrent pas les mêmes adresses : aucune comparaison fiable n'est possible.")
    ports_ok = base.profile != "discovery" and other.profile != "discovery"
    if not ports_ok:
        notes.append("Un des scans est une découverte rapide (sans ports) : ports, services et constats ne sont pas comparés.")
    elif base.profile != other.profile:
        notes.append("Les profils de scan sont différents : certaines différences peuvent venir du profil.")

    def by_ip(ip): return ipaddress.ip_address(ip)  # noqa: E731
    new_hosts = [{"ip": ip, "open_ports": sorted(p for p, _ in _open(o_up[ip]))}
                 for ip in sorted(o_up, key=by_ip) if ip not in b_up and _in(ip, base.target)]
    missing_hosts = [{"ip": ip, "status": "no_response", "note": NO_RESPONSE_NOTE}
                     for ip in sorted(b_up, key=by_ip) if ip not in o_up and _in(ip, other.target)]

    new_ports, closed_ports, service_changes = [], [], []
    if ports_ok:
        for ip in sorted(b_up.keys() & o_up.keys(), key=by_ip):
            a, b = _open(b_up[ip]), _open(o_up[ip])
            for k in sorted(b.keys() - a.keys()):
                new_ports.append({"ip": ip, "port": k[0], "protocol": k[1], "service": b[k].name})
            for k in sorted(a.keys() - b.keys()):
                closed_ports.append({"ip": ip, "port": k[0], "protocol": k[1], "service": a[k].name})
            for k in sorted(a.keys() & b.keys()):
                if _sig(a[k]) != _sig(b[k]):
                    service_changes.append({"ip": ip, "port": k[0], "protocol": k[1],
                                            "before": _sig(a[k]), "after": _sig(b[k])})

    findings = {"compared": ports_ok, "new": [], "resolved": [], "changed": []}
    if ports_ok:
        bmap, omap = {f.key: f for f in bf}, {f.key: f for f in of}
        findings["new"] = [_fdict(omap[k]) for k in sorted(omap.keys() - bmap.keys())]
        # un constat n'est « plus observé » que si l'hôte a bien répondu au second scan
        findings["resolved"] = [_fdict(bmap[k]) for k in sorted(bmap.keys() - omap.keys())
                                if bmap[k].host.ip in o_up]
        findings["changed"] = [{**_fdict(omap[k]), "score_before": bmap[k].score, "score_after": omap[k].score}
                               for k in sorted(bmap.keys() & omap.keys())
                               if bmap[k].score != omap[k].score]

    return {"base": _info(base), "other": _info(other), "notes": notes,
            "new_hosts": new_hosts, "missing_hosts": missing_hosts,
            "new_ports": new_ports, "closed_ports": closed_ports,
            "service_changes": service_changes, "findings": findings,
            "summary": {"base": _summary(bh, bf), "other": _summary(oh, of)}}
