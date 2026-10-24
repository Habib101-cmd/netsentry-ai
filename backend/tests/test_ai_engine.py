from helpers import mk_host, mk_scan
from sqlalchemy import select

from app.ai_engine.evaluate import evaluate, robustness
from app.ai_engine.features import extract_features
from app.ai_engine.model import get_model
from app.ai_engine.service import analyze_anomalies, missing_reason
from app.ai_engine.synthetic import simulate
from app.models.anomaly import AnomalyResult

WEB = {(80, "tcp"): "http", (443, "tcp"): "https"}


def test_no_history_means_no_features():
    assert extract_features([], {"1.1.1.1": WEB}) == {}


def test_new_port_and_unusual_service_features():
    hist = [{"1.1.1.1": WEB}] * 3
    f = extract_features(hist, {"1.1.1.1": {**WEB, (23, "tcp"): "telnet"}})["1.1.1.1"]
    assert f["open_ports"] == 3 and f["new_services"] == 1 and abs(f["unusual_ratio"] - 1 / 3) < 0.01


def test_flapping_port_is_not_new():
    hist = [{"1.1.1.1": WEB}, {"1.1.1.1": {(80, "tcp"): "http"}}, {"1.1.1.1": WEB}]
    assert extract_features(hist, {"1.1.1.1": {(80, "tcp"): "http"}})["1.1.1.1"]["new_services"] == 0
    hist = [{"1.1.1.1": WEB}, {"1.1.1.1": {(80, "tcp"): "http"}}]
    assert extract_features(hist, {"1.1.1.1": WEB})["1.1.1.1"]["new_services"] == 0


def test_new_host_has_everything_new():
    f = extract_features([{"1.1.1.1": WEB}] * 3, {"1.1.1.1": WEB, "2.2.2.2": WEB})["2.2.2.2"]
    assert f["new_services"] == 2 and f["unusual_ratio"] == 1.0 and f["hosts_delta"] == 1.0


def test_hosts_delta_and_change_freq():
    a, b = {"1.1.1.1": WEB}, {"1.1.1.1": {(80, "tcp"): "http"}}
    f = extract_features([a, b, a, b], a)["1.1.1.1"]
    assert f["change_freq"] == 1.0


def test_simulation_is_deterministic_and_labelled():
    a, b = simulate(7, inject=True), simulate(7, inject=True)
    assert a.snapshots == b.snapshots and a.labels == b.labels
    assert sum(len(x) for x in a.labels) > 5
    assert all(not x for x in a.labels[:21])  # aucune injection pendant l'historique
    assert all(not x for x in simulate(7, inject=False).labels)


def test_model_flags_spike_not_normal():
    m = get_model()
    hist = [{"1.1.1.1": WEB, "2.2.2.2": {(22, "tcp"): "ssh"}}] * 4
    spike = {(p, "tcp"): "unknown" for p in range(3000, 3025)}
    cur = {"1.1.1.1": WEB, "2.2.2.2": {(22, "tcp"): "ssh", **spike}}
    r = m.score(extract_features(hist, cur))
    assert r["2.2.2.2"]["is_anomaly"] and not r["1.1.1.1"]["is_anomaly"]
    text = r["2.2.2.2"]["explanation"]["summary"]
    assert "atypique à vérifier" in text and "attaque" not in text.lower()
    assert abs(sum(d["contribution"] for d in r["2.2.2.2"]["explanation"]["details"]) - 1) < 0.01


def test_evaluation_metrics():  # CA-09 : jeu distinct, métriques, comparaison règles vs règles+ML
    res = evaluate()
    rules = res["systems"]["Règles seules (comparaison de scans)"]
    both = res["systems"]["Règles ET ML (changement confirmé comme atypique)"]
    assert rules["recall"] == 1.0 and res["n_anomalies"] > 5
    rb = robustness(get_model())
    r, b = rb["Règles seules (comparaison de scans)"], rb["Règles ET ML (changement confirmé comme atypique)"]
    assert b["fp"] < r["fp"] and b["recall"] >= 0.6
    assert both["fpr"] <= rules["fpr"]


def test_service_end_to_end(db_session):
    for _ in range(4):
        s = mk_scan(db_session)
        mk_host(db_session, s, "172.30.0.11", [(80, "http", None)])
        mk_host(db_session, s, "172.30.0.12", [(22, "ssh", None)])
    last = mk_scan(db_session)
    mk_host(db_session, last, "172.30.0.11", [(80, "http", None)])
    mk_host(db_session, last, "172.30.0.12", [(22, "ssh", None)] + [(p, "unknown", None) for p in range(3000, 3025)])
    assert analyze_anomalies(db_session, last) == 2
    db_session.commit()
    rows = {r.host.ip: r for r in db_session.scalars(select(AnomalyResult))}
    assert rows["172.30.0.12"].is_anomaly and not rows["172.30.0.11"].is_anomaly
    assert analyze_anomalies(db_session, last) == 2  # idempotent
    db_session.commit()
    assert db_session.query(AnomalyResult).count() == 2


def test_skip_reasons(db_session):
    d = mk_scan(db_session, profile="discovery")
    assert analyze_anomalies(db_session, d) == 0 and "Découverte" in missing_reason(db_session, d)
    s = mk_scan(db_session)
    assert analyze_anomalies(db_session, s) == 0 and "Historique insuffisant" in missing_reason(db_session, s)
