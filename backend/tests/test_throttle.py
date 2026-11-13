from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.config import Config
from app.db.types import utcnow
from app.main import create_app
from app.models.system import LoginAttempt
from app.services.throttle import MAX_LOCK_S, WINDOW, Throttle

PW = "correct horse battery"


def clock(start):
    t = {"now": start}
    return t, lambda: t["now"]


@pytest.fixture()
def db(app, client):
    with app.state.session_factory() as session:
        yield session


# ---- the service: progressive lockout, windows, independence of keys ---------------------------
def test_ip_lockout_grows_and_expires(db):
    t, now = clock(utcnow())
    th = Throttle(now)
    for _ in range(4):
        th.fail(db, "1.1.1.1")
    assert th.retry_after(db, "1.1.1.1") == 0  # four failures: still allowed
    th.fail(db, "1.1.1.1")
    assert th.retry_after(db, "1.1.1.1") == 30  # fifth starts a 30 s lock

    t["now"] += timedelta(seconds=31)
    assert th.retry_after(db, "1.1.1.1") == 0  # expired
    th.fail(db, "1.1.1.1")
    assert th.retry_after(db, "1.1.1.1") == 60  # next failure doubles it
    t["now"] += timedelta(seconds=61)
    th.fail(db, "1.1.1.1")
    assert th.retry_after(db, "1.1.1.1") == 120
    for _ in range(20):  # a burst of further failures keeps doubling, but the lock is capped at 15 minutes
        t["now"] += timedelta(seconds=1)
        th.fail(db, "1.1.1.1")
    assert th.retry_after(db, "1.1.1.1") == MAX_LOCK_S

    t["now"] += WINDOW + timedelta(seconds=1)  # failures spaced out beyond the window never accumulate
    th.fail(db, "1.1.1.1")
    assert th.retry_after(db, "1.1.1.1") == 0


def test_other_addresses_are_unaffected_and_success_clears_only_the_ip(db):
    _, now = clock(utcnow())
    th = Throttle(now)
    for _ in range(5):
        th.fail(db, "1.1.1.1", "admin")
    assert th.retry_after(db, "1.1.1.1") > 0
    assert th.retry_after(db, "2.2.2.2") == 0  # a different address is fine
    assert th.retry_after(db, "2.2.2.2", "admin") == 0  # and one failing user key (5 < 20) is not a lock yet
    th.success(db, "1.1.1.1")
    assert th.retry_after(db, "1.1.1.1") == 0
    assert db.scalar(select(func.count()).select_from(LoginAttempt).where(LoginAttempt.key == "user:admin")) == 5  # kept


def test_username_cap_applies_across_addresses_and_is_case_insensitive(db):
    _, now = clock(utcnow())
    th = Throttle(now)
    for i in range(20):  # 20 different addresses, one failure each: no address is ever limited
        th.fail(db, f"10.0.0.{i}", "Admin")
        assert th.retry_after(db, f"10.0.0.{i}") == 0
    assert th.retry_after(db, "10.9.9.9", "admin") > 0  # but the account is now capped for everyone
    assert th.retry_after(db, "10.9.9.9", "someone-else") == 0


def test_old_failures_age_out_and_are_pruned(db):
    t, now = clock(utcnow())
    th = Throttle(now)
    for _ in range(5):
        th.fail(db, "1.1.1.1")
    t["now"] += WINDOW + timedelta(seconds=1)
    assert th.retry_after(db, "1.1.1.1") == 0
    th.fail(db, "1.1.1.1")  # a new failure prunes the expired rows
    assert db.scalar(select(func.count()).select_from(LoginAttempt)) == 1


# ---- through the API ---------------------------------------------------------------------------
def test_lockout_returns_retry_after_and_blocked_attempts_do_not_extend_it(authed, app):
    authed.post("/api/auth/logout")
    for _ in range(5):
        assert authed.post("/api/auth/login", json={"username": "admin", "password": "nope"}).status_code == 401
    first = authed.post("/api/auth/login", json={"username": "admin", "password": PW})
    assert first.status_code == 429 and 0 < int(first.headers["retry-after"]) <= 30
    for _ in range(10):  # hammering while locked out records nothing
        assert authed.post("/api/auth/login", json={"username": "admin", "password": "x"}).status_code == 429
    with app.state.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(LoginAttempt).where(LoginAttempt.key == "ip:testclient")) == 5


def test_lockout_survives_a_restart(tmp_path):
    def boot():
        return TestClient(create_app(Config(data_dir=tmp_path, frontend_dir=tmp_path / "none", scheduler_enabled=False)))

    with boot() as first:
        first.post("/api/auth/setup", json={"username": "admin", "password": PW})
        first.post("/api/auth/logout")
        for _ in range(5):
            first.post("/api/auth/login", json={"username": "admin", "password": "nope"})
        assert first.post("/api/auth/login", json={"username": "admin", "password": PW}).status_code == 429
    with boot() as second:  # new process, same database
        r = second.post("/api/auth/login", json={"username": "admin", "password": PW})
        assert r.status_code == 429, "an in-memory counter would have been forgotten here"


def test_distributed_guessing_against_one_account_is_capped(app, client):
    client.post("/api/auth/setup", json={"username": "admin", "password": PW})
    clients = [TestClient(app, client=(f"10.1.0.{i}", 40000)) for i in range(5)]
    for c in clients:  # 5 addresses x 4 failures = 20, each address stays under its own limit
        for _ in range(4):
            assert c.post("/api/auth/login", json={"username": "admin", "password": "guess"}).status_code == 401
    fresh = TestClient(app, client=("10.1.1.1", 40000))
    assert fresh.post("/api/auth/login", json={"username": "admin", "password": PW}).status_code == 429
    # ...yet other accounts and the rest of the API are unaffected
    assert fresh.post("/api/auth/login", json={"username": "nobody-else", "password": "x"}).status_code == 401
    assert fresh.get("/api/health").status_code == 200


def test_setup_uses_the_same_throttle(tmp_path):
    cfg = Config(data_dir=tmp_path, frontend_dir=tmp_path / "none", scheduler_enabled=False, setup_token="tok-123456")
    with TestClient(create_app(cfg)) as c:
        for _ in range(5):
            assert c.post("/api/auth/setup", json={"username": "admin", "password": PW, "setup_token": "wrong"}).status_code == 403
        r = c.post("/api/auth/setup", json={"username": "admin", "password": PW, "setup_token": "tok-123456"})
        assert r.status_code == 429 and "retry-after" in r.headers
