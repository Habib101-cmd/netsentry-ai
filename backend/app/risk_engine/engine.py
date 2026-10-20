from pathlib import Path

import yaml

from app.risk_engine.scoring import compute_score

RULES_PATH = Path(__file__).parent / "rules.yaml"
REQUIRED = {"id", "version", "title", "severity", "risk", "recommendation"}


def load_rules(path: Path = RULES_PATH) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        rules = yaml.safe_load(f)
    for r in rules:
        missing = REQUIRED - set(r)
        if missing:
            raise ValueError(f"Règle {r.get('id')} incomplète : {missing}")
    return rules


def rule_matches(rule: dict, svc: dict) -> bool:
    if svc["state"] != "open":
        return False
    if rule.get("protocol") and rule["protocol"] != svc["protocol"]:
        return False
    name = (svc["name"] or "").lower()
    if rule.get("unidentified"):
        return name in ("", "unknown", "tcpwrapped")
    return svc["port"] in rule.get("ports", []) or name in rule.get("names", [])


def _evidence(svc: dict) -> str:
    parts = [f"{svc['port']}/{svc['protocol']} {svc['state']}", f"service={svc['name'] or 'inconnu'}"]
    if svc.get("product"):
        parts.append(f"produit={svc['product']}")
    if svc.get("version"):
        parts.append(f"version={svc['version']}")
    parts.append(f"confiance={svc['confidence']}%")
    return " ".join(parts)


def _draft(*, rule_id, version, title, severity, exposure, risk, recommendation,
           criticality, svc, cvss=None, extra=""):
    score, level, factors = compute_score(severity, criticality, exposure, svc["confidence"], cvss)
    return {"rule_id": rule_id, "rule_version": version, "title": title, "score": score,
            "level": level, "factors": factors, "justification": risk,
            "evidence": _evidence(svc) + extra, "recommendation": recommendation}


def evaluate(rules: list[dict], host_criticality: str, svc: dict) -> list[dict]:
    drafts = []
    for rule in rules:
        if rule_matches(rule, svc):
            drafts.append(_draft(
                rule_id=rule["id"], version=rule["version"], title=rule["title"],
                severity=rule["severity"], exposure=rule.get("exposure", 50),
                risk=rule["risk"], recommendation=rule["recommendation"],
                criticality=host_criticality, svc=svc))
    if svc.get("cves"):
        top = sorted(svc["cves"], key=lambda c: -(c["cvss"] or 0))
        listing = ", ".join(f"{c['cve']} ({c['cvss']})" for c in top[:5])
        drafts.append(_draft(
            rule_id="R100", version=1, title="Version associée à des CVE connues (potentiel)",
            severity=50, exposure=50,
            risk="Vulnérabilité potentielle : correspondance par version, faux positifs possibles",
            recommendation="Vérifier le produit, la version et les avis de sécurité ; mettre à jour si nécessaire.",
            criticality=host_criticality, svc=svc, cvss=top[0]["cvss"],
            extra=f" | CVE potentielles : {listing}"))
    return drafts
