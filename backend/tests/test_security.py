import os
import re
import stat

import pytest
from fastapi.testclient import TestClient

from app.core.config import Config
from app.main import create_app

PW = "correct horse battery"
NEW_PW = "a-brand-new-password"
PUBLIC = {("GET", "/api/health"), ("GET", "/api/auth/state"), ("POST", "/api/auth/setup"),
          ("POST", "/api/auth/login"), ("POST", "/api/auth/login/mfa"), ("POST", "/api/auth/logout")}


def make_client(tmp_path, **cfg):
    return TestClient(create_app(Config(data_dir=tmp_path, frontend_dir=tmp_path / "none", scheduler_enabled=False, **cfg)))


# ---- every route is protected --------------------------------------------------------------
def test_every_api_route_requires_authentication(app, client):
    """Fails if someone adds an endpoint and forgets the auth dependency."""
    checked = 0
    # The OpenAPI document lists every documented route (included routers are not flattened in app.routes).
    for path, methods in app.openapi()["paths"].items():
        for method in methods:
            if (method.upper(), path) in PUBLIC:
                continue
            url = re.sub(r"\{[^}]+\}", "1", path)
            r = client.request(method.upper(), url, json={})
            assert r.status_code == 401, f"{method.upper()} {path} answered {r.status_code} without a session"
            checked += 1
    assert checked >= 30  # 30 authenticated endpoints today; guards against the loop silently checking nothing


# ---- headers -------------------------------------------------------------------------------
def test_security_headers_on_api_responses(client):
    h = client.get("/api/health").headers
    assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY" and h["referrer-policy"] == "no-referrer"
    assert h["cache-control"] == "no-store"
    csp = h["content-security-policy"]
    assert "frame-ancestors 'none'" in csp and "script-src 'self'" in csp and "default-src 'self'" in csp
    assert "unsafe-eval" not in csp and "strict-transport-security" not in h  # HSTS only when served over HTTPS


def test_hsts_and_secure_cookie_when_https_is_declared(tmp_path):
    with make_client(tmp_path, secure_cookies=True) as c:
        assert "max-age" in c.get("/api/health").headers["strict-transport-security"]
        r = c.post("/api/auth/setup", json={"username": "admin", "password": PW})
        assert "secure" in r.headers["set-cookie"].lower()


def test_spa_pages_get_the_headers_too(tmp_path):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><title>x</title>")
    with TestClient(create_app(Config(data_dir=tmp_path, frontend_dir=dist, scheduler_enabled=False))) as c:
        r = c.get("/devices/5")
        assert r.status_code == 200 and "frame-ancestors 'none'" in r.headers["content-security-policy"]
        assert c.get("/api/does-not-exist").status_code == 404  # the SPA fallback never swallows API paths
        traversal = c.get("/..%2f..%2fetc/passwd")
        assert "root:" not in traversal.text  # never serves files outside the build directory


# ---- API docs ------------------------------------------------------------------------------
def test_api_docs_are_behind_login(authed):
    authed.post("/api/auth/logout")
    assert authed.get("/api/docs").status_code == 401
    assert authed.get("/api/openapi.json").status_code == 401
    assert authed.get("/docs").status_code == 404 and authed.get("/openapi.json").status_code == 404
    authed.post("/api/auth/login", json={"username": "admin", "password": PW})
    page = authed.get("/api/docs")
    assert page.status_code == 200 and "swagger" in page.text.lower()
    assert "content-security-policy" not in page.headers  # Swagger UI loads its script from a CDN
    schema = authed.get("/api/openapi.json").json()
    assert "/api/devices" in schema["paths"] and "/api/docs" not in schema["paths"]


# ---- first-run setup token ------------------------------------------------------------------
def test_setup_token_blocks_takeover_of_a_fresh_install(tmp_path):
    with make_client(tmp_path, setup_token="a-long-random-setup-token") as c:
        assert c.get("/api/auth/state").json()["setup_token_required"] is True
        body = {"username": "attacker", "password": "attacker-password-1"}
        assert c.post("/api/auth/setup", json=body).status_code == 403
        assert c.post("/api/auth/setup", json={**body, "setup_token": "wrong"}).status_code == 403
        assert c.get("/api/auth/state").json()["setup_required"] is True  # nothing was created
        ok = c.post("/api/auth/setup", json={"username": "admin", "password": PW, "setup_token": "a-long-random-setup-token"})
        assert ok.status_code == 201 and c.get("/api/devices").status_code == 200
        assert c.get("/api/auth/state").json()["setup_token_required"] is False  # only relevant before the first user


def test_setup_token_guesses_are_throttled(tmp_path):
    with make_client(tmp_path, setup_token="the-real-token-123") as c:
        for i in range(5):
            assert c.post("/api/auth/setup", json={"username": "x-user", "password": PW, "setup_token": f"guess{i}"}).status_code == 403
        right = {"username": "admin", "password": PW, "setup_token": "the-real-token-123"}
        assert c.post("/api/auth/setup", json=right).status_code == 429  # brute force is cut off even with a correct guess


def test_without_a_setup_token_setup_still_works(client):
    assert client.get("/api/auth/state").json()["setup_token_required"] is False
    assert client.post("/api/auth/setup", json={"username": "admin", "password": PW}).status_code == 201


# ---- password change & session invalidation -------------------------------------------------
def test_password_change_validation(authed):
    url = "/api/auth/password"
    assert authed.post(url, json={"current_password": "nope", "new_password": NEW_PW}).status_code == 403
    assert authed.post(url, json={"current_password": PW, "new_password": PW}).status_code == 422
    assert authed.post(url, json={"current_password": PW, "new_password": "short"}).status_code == 422
    assert authed.post("/api/auth/logout").status_code == 204
    assert authed.post("/api/auth/login", json={"username": "admin", "password": PW}).status_code == 200  # nothing changed


def test_password_change_signs_out_other_sessions_but_not_this_one(authed, app):
    other = TestClient(app)  # a second browser: same app, separate cookie jar
    assert other.post("/api/auth/login", json={"username": "admin", "password": PW}).status_code == 200
    assert other.get("/api/devices").status_code == 200

    assert authed.post("/api/auth/password", json={"current_password": PW, "new_password": NEW_PW}).status_code == 204
    assert authed.get("/api/devices").status_code == 200  # this session was re-issued
    assert other.get("/api/devices").status_code == 401   # a stolen/stale cookie no longer works
    assert other.get("/api/auth/state").json()["authenticated"] is False

    authed.post("/api/auth/logout")
    assert authed.post("/api/auth/login", json={"username": "admin", "password": PW}).status_code == 401
    assert authed.post("/api/auth/login", json={"username": "admin", "password": NEW_PW}).status_code == 200


def test_wrong_current_password_attempts_are_throttled(authed):
    for _ in range(5):
        assert authed.post("/api/auth/password", json={"current_password": "bad", "new_password": NEW_PW}).status_code == 403
    assert authed.post("/api/auth/password", json={"current_password": PW, "new_password": NEW_PW}).status_code == 429


# ---- request hardening ---------------------------------------------------------------------
def test_state_changing_endpoints_do_not_accept_form_or_text_bodies(authed):
    """With SameSite=Strict cookies this is a second layer: a cross-site <form> cannot send JSON."""
    for ctype, body in (("application/x-www-form-urlencoded", "scanner=1"), ("text/plain", '{"scanner": {}}')):
        r = authed.put("/api/settings", content=body, headers={"content-type": ctype})
        assert r.status_code == 422, ctype


def test_search_input_cannot_inject_sql(authed, seed):
    for evil in ("' OR 1=1 --", "'; DROP TABLE devices; --", '" OR ""="', "%' UNION SELECT * FROM users --"):
        r = authed.get("/api/devices", params={"q": evil})
        assert r.status_code == 200 and r.json()["total"] == 0
    assert authed.get("/api/devices").json()["total"] == 3  # table intact


def test_api_returns_attacker_controlled_names_as_plain_json_data(authed, app):
    from app.models import Device

    with app.state.session_factory() as db:
        db.add(Device(mac_address="aa:bb:cc:00:00:01", hostname="<img src=x onerror=alert(1)>", is_known=True))
        db.commit()
    r = authed.get("/api/devices")
    assert r.headers["content-type"].startswith("application/json") and r.headers["x-content-type-options"] == "nosniff"
    assert r.json()["items"][0]["hostname"] == "<img src=x onerror=alert(1)>"  # stored verbatim; the UI renders it as text


# ---- secrets at rest -----------------------------------------------------------------------
def test_database_and_secret_key_are_owner_only(app, client, tmp_path):
    for name in ("lanwarden.db", "secret_key"):
        mode = stat.S_IMODE(os.stat(tmp_path / name).st_mode)
        assert mode & 0o077 == 0, f"{name} is accessible by group/others: {oct(mode)}"


@pytest.mark.parametrize("bad", [{"password": "x"}, {"username": "ad min", "password": PW}, {"username": "a", "password": PW}])
def test_setup_input_is_validated(client, bad):
    assert client.post("/api/auth/setup", json={"username": "admin", **bad}).status_code == 422


# ---- found by API fuzzing (tests/fuzz_api.py): oversized integers must be a clean 422, never a driver error ----
@pytest.mark.parametrize("path", [
    "/api/devices?offset=9223372036854775808", "/api/devices?offset=2147483648", "/api/devices/9223372036854775808",
    "/api/devices/2147483648/events", "/api/devices/99999999999999999999/sessions", "/api/devices/2147483648/presence",
    "/api/devices/2147483648/network", "/api/devices/2147483648/adguard", "/api/events?device_id=9223372036854775808",
    "/api/events?offset=9223372036854775808", "/api/devices/0", "/api/devices/-1",
])
def test_oversized_or_invalid_integers_are_rejected_cleanly(authed, path):
    assert authed.get(path).status_code == 422


def test_oversized_ids_are_rejected_on_write_endpoints_too(authed):
    big = 2**63
    assert authed.patch(f"/api/devices/{big}", json={"is_favorite": True}).status_code == 422
    assert authed.delete(f"/api/notifications/rules/{big}").status_code == 422
    assert authed.post(f"/api/notifications/rules/{big}/test").status_code == 422
    assert authed.get("/api/devices", params={"offset": 2**31 - 1}).status_code == 200  # the largest legal value still works
