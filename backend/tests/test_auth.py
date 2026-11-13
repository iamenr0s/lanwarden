def test_api_requires_auth(client):
    assert client.get("/api/devices").status_code == 401
    assert client.get("/api/settings").status_code == 401
    assert client.get("/api/health").json() == {"ok": True}


def test_setup_once_then_login_logout(client):
    state = client.get("/api/auth/state").json()
    assert state.items() >= {
        "setup_required": True, "setup_token_required": False, "insecure_transport": True,  # http://testserver is not loopback
        "authenticated": False, "username": None, "mfa_enabled": False, "mfa_enrolment_required": False}.items()
    assert client.post("/api/auth/setup", json={"username": "admin", "password": "short"}).status_code == 422
    assert client.post("/api/auth/setup", json={"username": "admin", "password": "long enough pass"}).status_code == 201
    assert client.post("/api/auth/setup", json={"username": "x-evil", "password": "long enough pass"}).status_code == 409
    assert client.get("/api/devices").status_code == 200

    assert client.post("/api/auth/logout").status_code == 204
    assert client.get("/api/devices").status_code == 401
    assert client.post("/api/auth/login", json={"username": "admin", "password": "nope"}).status_code == 401
    ok = client.post("/api/auth/login", json={"username": "admin", "password": "long enough pass"})
    assert ok.status_code == 200 and ok.json()["authenticated"] is True


def test_login_throttle(authed):
    authed.post("/api/auth/logout")
    for _ in range(5):
        assert authed.post("/api/auth/login", json={"username": "admin", "password": "bad"}).status_code == 401
    r = authed.post("/api/auth/login", json={"username": "admin", "password": "correct horse battery"})
    assert r.status_code == 429


def test_session_cookie_flags(client):
    r = client.post("/api/auth/setup", json={"username": "admin", "password": "long enough pass"})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
