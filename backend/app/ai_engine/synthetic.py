"""Simulateur de scans réseau : variations bénignes + injection d'anomalies étiquetées."""

import random
from dataclasses import dataclass

from app.ai_engine.features import Snapshot

ROLES = [
    {(80, "tcp"): "http", (443, "tcp"): "https"},
    {(80, "tcp"): "http", (443, "tcp"): "https", (22, "tcp"): "ssh"},
    {(22, "tcp"): "ssh"},
    {(5432, "tcp"): "postgresql", (22, "tcp"): "ssh"},
    {(21, "tcp"): "ftp", (22, "tcp"): "ssh"},
    {(25, "tcp"): "smtp", (110, "tcp"): "pop3", (143, "tcp"): "imap", (22, "tcp"): "ssh"},
]
HOST_DOWN_PROB = 0.02  # variation bénigne : hôte injoignable pendant un scan
PORT_FLAP_PROB = 0.01  # variation bénigne : port non vu pendant un scan
DRIFT_PROB = 0.02  # évolution bénigne : un service est ajouté ou retiré durablement (par hôte et par scan)
BENIGN_NEW_NAMES = ["http-alt", "domain", "ntp", "snmp"]
NEW_PORT_NUMBERS = [2222, 3000, 8000, 8080, 8443, 8888, 9000]
UNUSUAL_SERVICES = [
    (23, "telnet"),
    (3389, "ms-wbt-server"),
    (5900, "vnc"),
    (6379, "redis"),
    (27017, "mongodb"),
    (445, "microsoft-ds"),
]
NEW_HOST_POOL = [(22, "ssh"), (80, "http"), (443, "https"), (8080, "http-proxy"), (3306, "mysql"), (21, "ftp")]
ANOMALY_TYPES = ["new_host", "new_port", "unusual_service", "port_spike"]


@dataclass
class Simulation:
    snapshots: list[Snapshot]
    labels: list[dict[str, str]]  # labels[t][ip] = type d'anomalie injectée à l'instant t


def simulate(
    seed: int,
    n_hosts: int = 15,
    weeks: int = 8,
    scans_per_week: int = 7,
    inject: bool = False,
    warmup: int = 21,
    inject_prob: float = 0.5,
) -> Simulation:
    rng = random.Random(seed)
    base = {f"10.20.0.{10 + i}": dict(rng.choice(ROLES)) for i in range(n_hosts)}
    new_hosts = 0
    snapshots, labels = [], []
    for t in range(weeks * scans_per_week):
        down = {ip for ip in base if rng.random() < HOST_DOWN_PROB}
        lab: dict[str, str] = {}
        if inject and t >= warmup and rng.random() < inject_prob:
            kind = rng.choice(ANOMALY_TYPES)
            if kind == "new_host":
                new_hosts += 1
                ip = f"10.20.0.{100 + new_hosts}"
                k = rng.randint(2, 6)
                port, name = rng.choice(UNUSUAL_SERVICES)
                ports = {(port, "tcp"): name}
                for p, n in rng.sample(NEW_HOST_POOL, k - 1):
                    ports[(p, "tcp")] = n
                base[ip] = ports
            else:
                ip = rng.choice([x for x in base if x not in down])
                ports = base[ip]
                if kind == "new_port":
                    for _ in range(rng.randint(1, 2)):
                        number = rng.choice([p for p in NEW_PORT_NUMBERS if (p, "tcp") not in ports])
                        ports[(number, "tcp")] = rng.choice(sorted(set(ports.values())))
                elif kind == "unusual_service":
                    port, name = rng.choice([u for u in UNUSUAL_SERVICES if u[1] not in ports.values()])
                    ports[(port, "tcp")] = name
                else:  # port_spike
                    for number in rng.sample(range(2000, 9000), rng.randint(10, 30)):
                        ports.setdefault((number, "tcp"), "unknown")
            lab[ip] = kind
        for ip in list(base):  # évolutions bénignes de configuration (non étiquetées)
            if ip in lab or ip in down or rng.random() >= DRIFT_PROB:
                continue
            ports = base[ip]
            if len(ports) > 1 and rng.random() < 0.4:
                ports.pop(rng.choice(sorted(ports)))
            else:
                free = [p for p in NEW_PORT_NUMBERS if (p, "tcp") not in ports]
                if free:
                    known = rng.random() < 0.75
                    name = rng.choice(sorted(set(ports.values()))) if known else rng.choice(BENIGN_NEW_NAMES)
                    ports[(rng.choice(free), "tcp")] = name
        snap: Snapshot = {}
        for ip, ports in base.items():
            if ip in down:
                continue
            keep = {k: v for k, v in ports.items() if ip in lab or rng.random() >= PORT_FLAP_PROB}
            snap[ip] = keep
        snapshots.append(snap)
        labels.append(lab)
    return Simulation(snapshots, labels)
