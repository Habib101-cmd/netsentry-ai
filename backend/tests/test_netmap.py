from helpers import mk_finding, mk_host, mk_scan

from app.services.netmap import build_map, build_timeline


def test_map_structure(db_session):
    s = mk_scan(db_session)
    gw = mk_host(db_session, s, "172.30.0.1")
    h1 = mk_host(db_session, s, "172.30.0.11", [(80, "http", None)])
    mk_host(db_session, s, "172.30.0.12", state="down")
    mk_finding(db_session, s, h1, "R005", 80, 30, level="low")
    mk_finding(db_session, s, h1, "R004", 21, 60, level="high")
    m = build_map(db_session, s)
    hosts = [n for n in m["nodes"] if n["type"] == "host"]
    assert {n["ip"] for n in hosts} == {"172.30.0.1", "172.30.0.11"}  # l'hôte "down" est exclu
    n1 = next(n for n in hosts if n["ip"] == "172.30.0.11")
    assert n1["worst_level"] == "high" and n1["open_ports"] == 1 and n1["parent"] == "net:172.30.0.0/24"
    observed = [e for e in m["edges"] if e["kind"] == "observed"]
    assumed = [e for e in m["edges"] if e["kind"] == "assumed"]
    assert len(observed) == 2
    assert len(assumed) == 1 and assumed[0]["source"] == f"h{h1.id}" and assumed[0]["target"] == f"h{gw.id}"
    assert any("topologie physique" in n for n in m["notes"])


def test_map_without_gateway_has_no_assumed_edge(db_session):
    s = mk_scan(db_session)
    mk_host(db_session, s, "172.30.0.11")
    mk_host(db_session, s, "172.30.0.12")
    assert [e for e in build_map(db_session, s)["edges"] if e["kind"] == "assumed"] == []


def test_timeline(db_session):
    a = mk_scan(db_session)
    b = mk_scan(db_session, profile="discovery")
    ha = mk_host(db_session, a, "172.30.0.11", [(80, "http", None), (21, "ftp", None)])
    mk_finding(db_session, a, ha, "R005", 80, 30, level="low")
    mk_host(db_session, b, "172.30.0.11")
    t = build_timeline(db_session)
    assert [r["id"] for r in t] == [a.id, b.id]
    assert t[0]["open_ports"] == 2 and t[0]["findings"] == 1 and t[0]["by_level"]["low"] == 1
    assert t[0]["hosts_up"] == 1 and t[0]["total_score"] == 30
    assert [r["id"] for r in build_timeline(db_session, profile="discovery")] == [b.id]
    assert build_timeline(db_session, profile="deep") == []
