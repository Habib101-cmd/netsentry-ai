from app.risk_engine.engine import evaluate, load_rules
from app.risk_engine.scoring import compute_score, level_for

RULES = load_rules()


def svc(port, name, state="open", conf=100, cves=None):
    return {
        "port": port,
        "protocol": "tcp",
        "state": state,
        "name": name,
        "product": None,
        "version": None,
        "confidence": conf,
        "cves": cves or [],
    }


def ids(drafts):
    return {d["rule_id"] for d in drafts}


def test_ssh_positive_and_negative():
    assert "R001" in ids(evaluate(RULES, "normal", svc(22, "ssh")))
    assert evaluate(RULES, "normal", svc(22, "ssh", state="closed")) == []


def test_ssh_detected_on_other_port_by_name():
    assert "R001" in ids(evaluate(RULES, "normal", svc(2222, "ssh")))


def test_telnet_is_high():
    d = evaluate(RULES, "normal", svc(23, "telnet"))
    assert d and d[0]["level"] in ("high", "critical")


def test_http_vs_https():
    assert "R005" in ids(evaluate(RULES, "normal", svc(80, "http")))
    assert "R005" not in ids(evaluate(RULES, "normal", svc(443, "https")))


def test_database_exposed():
    assert "R006" in ids(evaluate(RULES, "normal", svc(5432, "postgresql")))


def test_ftp_and_rdp():
    assert "R004" in ids(evaluate(RULES, "normal", svc(21, "ftp")))
    assert "R003" in ids(evaluate(RULES, "normal", svc(3389, "ms-wbt-server")))


def test_unidentified_service():
    assert "R007" in ids(evaluate(RULES, "normal", svc(9999, None, conf=30)))
    assert "R007" not in ids(evaluate(RULES, "normal", svc(80, "http")))


def test_cve_finding_is_labelled_potential():
    d = evaluate(RULES, "normal", svc(80, "http", cves=[{"cve": "CVE-2021-41773", "cvss": 9.8}]))
    cve = [x for x in d if x["rule_id"] == "R100"][0]
    assert "potentiel" in cve["title"] and cve["level"] in ("high", "critical")
    assert "CVE-2021-41773" in cve["evidence"]


def test_score_is_explainable():
    score, level, factors = compute_score(85, "normal", 80, 100)
    assert abs(sum(f["contribution"] for f in factors) - score) <= 1
    assert abs(sum(f["weight"] for f in factors) - 1) < 0.01


def test_criticality_raises_score():
    low = compute_score(40, "low", 60, 100)[0]
    high = compute_score(40, "high", 60, 100)[0]
    assert high > low


def test_level_bounds():
    assert [level_for(s) for s in (0, 19, 20, 39, 40, 59, 60, 79, 80, 100)] == [
        "info",
        "info",
        "low",
        "low",
        "medium",
        "medium",
        "high",
        "high",
        "critical",
        "critical",
    ]
