WEIGHTS = {"rule_severity": 0.40, "host_criticality": 0.20, "exposure": 0.15,
           "cvss": 0.15, "confidence": 0.10}
CRITICALITY = {"low": 20, "normal": 50, "high": 90}


def level_for(score: int) -> str:
    if score < 20:
        return "info"
    if score < 40:
        return "low"
    if score < 60:
        return "medium"
    if score < 80:
        return "high"
    return "critical"


def compute_score(rule_severity: int, criticality: str, exposure: int, confidence: int,
                  cvss: float | None = None):
    """Retourne (score 0-100, niveau, détail des facteurs affichable à l'utilisateur)."""
    values = {"rule_severity": rule_severity,
              "host_criticality": CRITICALITY.get(criticality, 50),
              "exposure": exposure,
              "confidence": confidence}
    weights = dict(WEIGHTS)
    if cvss is None:
        weights.pop("cvss")  # facteur absent : on renormalise les autres poids
    else:
        values["cvss"] = min(cvss * 10, 100)
    total = sum(weights.values())
    factors, score = [], 0.0
    for name, w in weights.items():
        nw = w / total
        contribution = values[name] * nw
        score += contribution
        factors.append({"factor": name, "value": values[name],
                        "weight": round(nw, 3), "contribution": round(contribution, 1)})
    score = max(0, min(100, round(score)))
    return score, level_for(score), factors
