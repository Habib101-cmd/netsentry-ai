from helpers import mk_finding, mk_host, mk_scan

from app.services.compare import compare_scans


def test_new_and_missing_hosts(db_session):
    a, b = mk_scan(db_session), mk_scan(db_session)
    mk_host(db_session, a, "172.30.0.11")
    mk_host(db_session, a, "172.30.0.12")
    mk_host(db_session, b, "172.30.0.11")
    mk_host(db_session, b, "172.30.0.13", [(80, "http", None)])
    r = compare_scans(db_session, a, b)
    assert [h["ip"] for h in r["new_hosts"]] == ["172.30.0.13"]
    assert r["new_hosts"][0]["open_ports"] == [80]
    assert [h["ip"] for h in r["missing_hosts"]] == ["172.30.0.12"]
    assert "ne prouve pas" in r["missing_hosts"][0]["note"]


def test_ports_and_service_changes(db_session):
    a, b = mk_scan(db_session), mk_scan(db_session)
    mk_host(db_session, a, "172.30.0.11", [(80, "http", "1.0"), (21, "ftp", None)])
    mk_host(db_session, b, "172.30.0.11", [(80, "http", "2.0"), (5432, "postgresql", None)])
    r = compare_scans(db_session, a, b)
    assert [x["port"] for x in r["new_ports"]] == [5432]
    assert [x["port"] for x in r["closed_ports"]] == [21]
    assert r["service_changes"][0]["port"] == 80
    assert r["service_changes"][0]["before"]["version"] == "1.0"
    assert r["service_changes"][0]["after"]["version"] == "2.0"


def test_discovery_scan_skips_ports_and_findings(db_session):
    a, b = mk_scan(db_session, profile="discovery"), mk_scan(db_session)
    mk_host(db_session, a, "172.30.0.11")
    mk_host(db_session, b, "172.30.0.11", [(80, "http", None)])
    r = compare_scans(db_session, a, b)
    assert r["new_ports"] == [] and r["findings"]["compared"] is False and r["notes"]


def test_hosts_outside_other_target_are_not_missing_or_new(db_session):
    a = mk_scan(db_session, target="172.30.0.0/24")
    b = mk_scan(db_session, target="172.30.0.0/25")
    mk_host(db_session, a, "172.30.0.11")
    mk_host(db_session, a, "172.30.0.200")
    mk_host(db_session, b, "172.30.0.11")
    assert compare_scans(db_session, a, b)["missing_hosts"] == []
    assert compare_scans(db_session, b, a)["new_hosts"] == []


def test_findings_evolution(db_session):
    a, b = mk_scan(db_session), mk_scan(db_session)
    ha = mk_host(db_session, a, "172.30.0.11")
    hb = mk_host(db_session, b, "172.30.0.11")
    mk_finding(db_session, a, ha, "R004", 21, 60)
    mk_finding(db_session, a, ha, "R005", 80, 30)
    mk_finding(db_session, b, hb, "R005", 80, 40)
    mk_finding(db_session, b, hb, "R006", 5432, 70)
    f = compare_scans(db_session, a, b)["findings"]
    assert [x["rule_id"] for x in f["new"]] == ["R006"]
    assert [x["rule_id"] for x in f["resolved"]] == ["R004"]
    assert f["changed"][0]["score_before"] == 30 and f["changed"][0]["score_after"] == 40


def test_resolved_ignores_hosts_that_did_not_answer(db_session):
    a, b = mk_scan(db_session), mk_scan(db_session)
    ha = mk_host(db_session, a, "172.30.0.13")
    mk_host(db_session, b, "172.30.0.11")
    mk_finding(db_session, a, ha, "R004", 21, 60)
    assert compare_scans(db_session, a, b)["findings"]["resolved"] == []
