"""Caractéristiques du détecteur d'anomalies : fonctions pures, sans base de données."""

FEATURES = ["open_ports", "identified_services", "new_services",
            "hosts_delta", "change_freq", "unusual_ratio"]
UNKNOWN_NAMES = {"", "unknown", "tcpwrapped"}
REF_WINDOW = 3    # nb de scans précédents formant le profil de référence d'un hôte
FREQ_WINDOW = 5   # nb de transitions utilisées pour la fréquence de changement
MIN_HISTORY = 2   # nb minimal de scans précédents comparables pour analyser

# Un instantané = {ip: {(port, protocole): nom_du_service}} (hôtes actifs, ports ouverts)
Snapshot = dict[str, dict[tuple[int, str], str]]


def _name(value: str | None) -> str:
    return (value or "").lower()


def extract_features(history: list[Snapshot], current: Snapshot) -> dict[str, dict[str, float]]:
    """history : scans précédents (du plus ancien au plus récent) ; current : scan analysé."""
    if not history:
        return {}
    recent = history[-REF_WINDOW:]
    prev_count = len(history[-1])
    hosts_delta = abs(len(current) - prev_count) / max(1, prev_count)
    out = {}
    for ip, ports in current.items():
        ref_ports: set = set()
        ref_names: set = set()
        for snap in recent:
            if ip in snap:
                ref_ports |= set(snap[ip])
                ref_names |= {_name(n) for n in snap[ip].values()}
        seq = [set(snap[ip]) for snap in history[-(FREQ_WINDOW + 1):] if ip in snap]
        changes = sum(1 for a, b in zip(seq, seq[1:]) if a != b)
        change_freq = changes / (len(seq) - 1) if len(seq) > 1 else 0.0
        names = [_name(n) for n in ports.values()]
        unusual = sum(1 for n in names if n not in ref_names) / len(names) if names else 0.0
        out[ip] = {
            "open_ports": float(len(ports)),
            "identified_services": float(sum(1 for n in names if n not in UNKNOWN_NAMES)),
            "new_services": float(sum(1 for k in ports if k not in ref_ports)),
            "hosts_delta": round(hosts_delta, 4),
            "change_freq": round(change_freq, 4),
            "unusual_ratio": round(unusual, 4),
        }
    return out
