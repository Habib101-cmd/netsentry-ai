import ipaddress

from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.models.scan import Finding, Host, Scan, Service

LEVEL_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
LEVELS = ["critical", "high", "medium", "low", "info"]
NOTES = [
    "Un scan de ports ne permet pas de reconstruire la topologie physique complète : "
    "cette carte n'est pas un plan du réseau.",
    "Trait plein : relation observée (l'équipement a répondu au scanner ; le chemin réseau n'est pas connu). "
    "Trait pointillé : relation supposée (passerelle probable d'après l'adresse .1 du sous-réseau).",
    "Le regroupement par sous-réseau /24 est supposé d'après les adresses IP.",
]


def build_map(db, scan: Scan) -> dict:
    hosts = db.scalars(
        select(Host).where(Host.scan_id == scan.id, Host.state == "up").options(selectinload(Host.services))
    ).all()
    hosts = sorted(hosts, key=lambda h: ipaddress.ip_address(h.ip))

    worst: dict[int, str] = {}
    for level, host_id in db.execute(select(Finding.level, Finding.host_id).where(Finding.scan_id == scan.id)).all():
        if host_id not in worst or LEVEL_RANK[level] > LEVEL_RANK[worst[host_id]]:
            worst[host_id] = level

    groups: dict[str, list[Host]] = {}
    for h in hosts:
        net = str(ipaddress.ip_network(f"{h.ip}/24", strict=False))
        groups.setdefault(net, []).append(h)

    nodes = [{"id": "scanner", "type": "scanner", "label": "Scanner"}]
    edges = []
    for net, group in groups.items():
        nodes.append({"id": f"net:{net}", "type": "subnet", "label": net})
        gw_ip = str(ipaddress.ip_network(net).network_address + 1)
        gateway = next((h for h in group if h.ip == gw_ip), None)
        for h in group:
            nodes.append(
                {
                    "id": f"h{h.id}",
                    "type": "host",
                    "parent": f"net:{net}",
                    "host_id": h.id,
                    "ip": h.ip,
                    "hostname": h.hostname,
                    "open_ports": sum(1 for s in h.services if s.state == "open"),
                    "worst_level": worst.get(h.id),
                }
            )
            edges.append(
                {
                    "id": f"o{h.id}",
                    "source": "scanner",
                    "target": f"h{h.id}",
                    "kind": "observed",
                    "reason": "Équipement actif : a répondu au scanner",
                }
            )
            if gateway is not None and h is not gateway:
                edges.append(
                    {
                        "id": f"a{h.id}",
                        "source": f"h{h.id}",
                        "target": f"h{gateway.id}",
                        "kind": "assumed",
                        "reason": "Passerelle supposée (adresse .1 du sous-réseau), non observée",
                    }
                )
    return {"scan_id": scan.id, "nodes": nodes, "edges": edges, "notes": NOTES}


def build_timeline(db, profile: str | None = None, limit: int = 200) -> list[dict]:
    stmt = select(Scan).where(Scan.status == "done")
    if profile:
        stmt = stmt.where(Scan.profile == profile)
    scans = list(reversed(db.scalars(stmt.order_by(Scan.id.desc()).limit(limit)).all()))
    ids = [s.id for s in scans]
    if not ids:
        return []
    up = dict(
        db.execute(
            select(Host.scan_id, func.count()).where(Host.scan_id.in_(ids), Host.state == "up").group_by(Host.scan_id)
        ).all()
    )
    ports = dict(
        db.execute(
            select(Host.scan_id, func.count(Service.id))
            .join(Service, Service.host_id == Host.id)
            .where(Host.scan_id.in_(ids), Service.state == "open")
            .group_by(Host.scan_id)
        ).all()
    )
    by_level = {i: {lvl: 0 for lvl in LEVELS} for i in ids}
    total_score = {i: 0 for i in ids}
    for sid, level, n, score in db.execute(
        select(Finding.scan_id, Finding.level, func.count(), func.sum(Finding.score))
        .where(Finding.scan_id.in_(ids))
        .group_by(Finding.scan_id, Finding.level)
    ).all():
        by_level[sid][level] = n
        total_score[sid] += int(score or 0)
    return [
        {
            "id": s.id,
            "target": s.target,
            "profile": s.profile,
            "finished_at": s.finished_at,
            "hosts_up": up.get(s.id, 0),
            "open_ports": ports.get(s.id, 0),
            "findings": sum(by_level[s.id].values()),
            "by_level": by_level[s.id],
            "total_score": total_score[s.id],
        }
        for s in scans
    ]
