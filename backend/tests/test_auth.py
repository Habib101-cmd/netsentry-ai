import re

from app.main import app
from app.models.auth import AuditLog, User
from app.security import hash_password

PWD = "Correct-Horse-42"
PUBLIC = {"/health", "/health/db", "/auth/login", "/auth/refresh",
          "/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}


def make_user(db, username, role="analyst", password=PWD, must_change=False):
    user = User(username=username, password_hash=hash_password(password), role=role,
                must_change_password=must_change)
    db.add(user)
    db.commit()
    return user


def login(client, username, password=PWD):
    return client.post("/auth/login", json={"username": username, "password": password})


def headers(client, username):
    r = login(client, username)
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_all_routes_require_token(client):  # ENF-01
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None) or set()
        if path is None or path in PUBLIC:
            continue
        url = re.sub(r"\{[^}]+\}", "1", path)
        for method in methods - {"HEAD", "OPTIONS"}:
            r = client.request(method, url)
            assert r.status_code == 401, f"{method} {path} -> {r.status_code}"


def test_wrong_role_is_403(client, db_session):
    make_user(db_session, "analyst1", "analyst")
    r = client.get("/users", headers=headers(client, "analyst1"))
    assert r.status_code == 403


def test_admin_can_list_users(client, db_session):
    make_user(db_session, "admin1", "admin")
    r = client.get("/users", headers=headers(client, "admin1"))
    assert r.status_code == 200 and len(r.json()) == 1


def test_must_change_password_blocks_access(client, db_session):
    make_user(db_session, "admin1", "admin", must_change=True)
    r = client.get("/users", headers=headers(client, "admin1"))
    assert r.status_code == 403 and r.json()["detail"] == "password_change_required"


def test_change_password_flow(client, db_session):
    make_user(db_session, "admin1", "admin", must_change=True)
    h = headers(client, "admin1")
    r = client.post("/auth/change-password", headers=h,
                    json={"current_password": PWD, "new_password": "Another-Strong-Pass-9"})
    assert r.status_code == 200
    assert login(client, "admin1", "Another-Strong-Pass-9").status_code == 200


def test_weak_password_rejected(client, db_session):
    make_user(db_session, "admin1", "admin")
    r = client.post("/users", headers=headers(client, "admin1"),
                    json={"username": "bob", "password": "short", "role": "analyst"})
    assert r.status_code == 400


def test_lockout_after_5_failures(client, db_session):
    make_user(db_session, "victim")
    for _ in range(5):
        assert login(client, "victim", "wrong-password-xx").status_code == 401
    assert login(client, "victim").status_code == 429  # même avec le bon mot de passe


def test_refresh_rotation(client, db_session):
    make_user(db_session, "u1")
    tokens = login(client, "u1").json()
    r1 = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r1.status_code == 200
    r2 = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r2.status_code == 401  # ancien jeton révoqué


def test_login_is_audited(client, db_session):
    make_user(db_session, "u1")
    login(client, "u1")
    login(client, "u1", "wrong-password-xx")
    results = {a.result for a in db_session.query(AuditLog).filter_by(action="login")}
    assert results == {"success", "failure"}
