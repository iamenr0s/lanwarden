import base64
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.__main__ import main, reset_mfa, reset_password
from app.api import auth as auth_api
from app.core import totp
from app.core.config import Config
from app.main import create_app
from app.models.system import User

PW = "correct horse battery"


# ---- TOTP primitives ----------------------------------------------------------------------------
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")


@pytest.mark.parametrize("at, expected", [(59, "287082"), (1111111109, "081804"), (1111111111, "050471"),
                                          (1234567890, "005924"), (2000000000, "279037")])
def test_rfc_6238_sha1_test_vectors(at, expected):
    """RFC 6238 Appendix B lists 8 digits (94287082, 07081804, ...); the 6-digit code is their last six."""
    assert totp.code_at(RFC_SECRET, at) == expected


@pytest.fixture()
def clock(monkeypatch):
    state = {"t": 1_700_000_010.0}
    monkeypatch.setattr(totp, "_now", lambda: state["t"])
    return state


def test_verify_accepts_adjacent_steps_only_and_rejects_replay(clock):
    secret = totp.new_secret()
    now_step = int(clock["t"] // 30)
    assert totp.verify(secret, totp.code_at(secret, clock["t"])) == now_step
    assert totp.verify(secret, totp.code_at(secret, clock["t"] - 30)) == now_step - 1  # phone slightly behind
    assert totp.verify(secret, totp.code_at(secret, clock["t"] + 30)) == now_step + 1  # or ahead
    assert totp.verify(secret, totp.code_at(secret, clock["t"] - 90)) is None          # 3 steps away
    code = totp.code_at(secret, clock["t"])
    assert totp.verify(secret, code, last_step=now_step) is None      # already used
    assert totp.verify(secret, code, last_step=now_step - 1) == now_step
    for junk in ("", "12345", "1234567", "abcdef", "12 34 5"):
        assert totp.verify(secret, junk) is None
    assert totp.verify(secret, " ".join([code[:3], code[3:]])) == now_step  # apps display "123 456"


def test_secrets_codes_and_uri_have_the_expected_shape():
    assert len(totp.new_secret()) == 32 and totp.new_secret() != totp.new_secret()  # 160 bits of base32
    codes = totp.new_recovery_codes()
    assert len(codes) == len(set(codes)) == 10 and all(len(c) == 11 and c[5] == "-" for c in codes)
    assert totp.hash_recovery(codes[0].upper(), "k") == totp.hash_recovery(codes[0].replace("-", " "), "k")  # forgiving input
    assert totp.hash_recovery(codes[0], "k") != totp.hash_recovery(codes[0], "other-key")  # keyed: no offline guessing
    uri = totp.otpauth_uri("ABC234", "admin")
    assert uri.startswith("otpauth://totp/LanWarden:admin?") and "secret=ABC234" in uri and "period=30" in uri


# ---- helpers for the API flows --------------------------------------------------------------------
def enroll(client, clock):
    secret = client.post("/api/auth/mfa/setup", json={"password": PW}).json()["secret"]
    r = client.post("/api/auth/mfa/enable", json={"code": totp.code_at(secret)})
    assert r.status_code == 200, r.text
    return secret, r.json()["recovery_codes"]


def sign_in(client, code):
    """Password step then code step; returns the second response."""
    first = client.post("/api/auth/login", json={"username": "admin", "password": PW}).json()
    assert first["mfa_required"] is True and first["authenticated"] is False and first["mfa_token"]
    return client.post("/api/auth/login/mfa", json={"mfa_token": first["mfa_token"], "code": code})


# ---- enrolment -----------------------------------------------------------------------------------
def test_enrolment_requires_password_and_a_valid_code(authed, clock, app):
    assert authed.post("/api/auth/mfa/setup", json={"password": "wrong"}).status_code == 403
    setup = authed.post("/api/auth/mfa/setup", json={"password": PW}).json()
    assert setup["otpauth_uri"].startswith("otpauth://totp/") and setup["secret"] in setup["otpauth_uri"]

    authed.post("/api/auth/logout")  # not enforced until a code verifies: password-only sign-in still works
    assert authed.post("/api/auth/login", json={"username": "admin", "password": PW}).json()["authenticated"] is True

    assert authed.post("/api/auth/mfa/enable", json={"code": "000000"}).status_code == 400
    assert authed.get("/api/auth/state").json()["mfa_enabled"] is False
    ok = authed.post("/api/auth/mfa/enable", json={"code": totp.code_at(setup["secret"])})
    assert ok.status_code == 200 and len(ok.json()["recovery_codes"]) == 10
    assert authed.get("/api/auth/state").json()["mfa_enabled"] is True and authed.get("/api/devices").status_code == 200  # session re-issued
    assert authed.post("/api/auth/mfa/setup", json={"password": PW}).status_code == 409  # already on
    assert authed.post("/api/auth/mfa/enable", json={"code": "123456"}).status_code == 409

    with app.state.session_factory() as db:
        user = db.scalar(select(User))
    assert setup["secret"] not in (user.totp_secret_enc or "") and app.state.box.decrypt(user.totp_secret_enc) == setup["secret"]
    stored = " ".join(user.recovery_codes)
    assert not any(c in stored for c in ok.json()["recovery_codes"])  # recovery codes exist only as hashes


def test_enable_without_setup_is_refused(authed):
    assert authed.post("/api/auth/mfa/enable", json={"code": "123456"}).status_code == 409


def test_enabling_mfa_signs_out_other_sessions(authed, app, clock):
    other = TestClient(app)
    other.post("/api/auth/login", json={"username": "admin", "password": PW})
    assert other.get("/api/devices").status_code == 200
    enroll(authed, clock)
    assert other.get("/api/devices").status_code == 401 and authed.get("/api/devices").status_code == 200


# ---- two-step sign-in ----------------------------------------------------------------------------
def test_two_step_login_and_code_replay_protection(authed, clock):
    secret, _ = enroll(authed, clock)
    authed.post("/api/auth/logout")
    clock["t"] += 30
    r = sign_in(authed, totp.code_at(secret))
    assert r.status_code == 200 and r.json()["authenticated"] is True and authed.get("/api/devices").status_code == 200

    authed.post("/api/auth/logout")
    replay = sign_in(authed, totp.code_at(secret))  # same 30 s step again: a seen code is dead
    assert replay.status_code == 401 and authed.get("/api/devices").status_code == 401
    clock["t"] += 30
    assert sign_in(authed, totp.code_at(secret)).status_code == 200


def test_password_alone_gives_no_session_and_wrong_codes_are_throttled(authed, clock):
    secret, _ = enroll(authed, clock)
    authed.post("/api/auth/logout")
    first = authed.post("/api/auth/login", json={"username": "admin", "password": PW}).json()
    assert authed.get("/api/devices").status_code == 401  # a correct password is not enough
    for _ in range(5):
        assert authed.post("/api/auth/login/mfa", json={"mfa_token": first["mfa_token"], "code": "000000"}).status_code == 401
    locked = authed.post("/api/auth/login/mfa", json={"mfa_token": first["mfa_token"], "code": totp.code_at(secret) })
    assert locked.status_code == 429 and "retry-after" in locked.headers  # guessing codes is capped like guessing passwords


def test_mfa_token_cannot_be_forged_expired_or_reused_after_changes(authed, app, clock, monkeypatch):
    secret, _ = enroll(authed, clock)
    authed.post("/api/auth/logout")
    token = authed.post("/api/auth/login", json={"username": "admin", "password": PW}).json()["mfa_token"]
    code = totp.code_at(secret, clock["t"] + 30)
    clock["t"] += 30

    assert authed.post("/api/auth/login/mfa", json={"mfa_token": token[:-2] + "xx", "code": code}).status_code == 401  # tampered
    assert authed.post("/api/auth/login/mfa", json={"mfa_token": "garbage", "code": code}).status_code == 401
    monkeypatch.setattr(auth_api, "MFA_TOKEN_TTL", -1)
    assert authed.post("/api/auth/login/mfa", json={"mfa_token": token, "code": code}).status_code == 401  # expired
    monkeypatch.undo()
    monkeypatch.setattr(totp, "_now", lambda: clock["t"])

    with app.state.session_factory() as db:  # the password changed after the token was issued
        user = db.scalar(select(User))
        from app.core.security import hash_password
        user.password_hash = hash_password("some other password 1")
        db.commit()
    assert authed.post("/api/auth/login/mfa", json={"mfa_token": token, "code": code}).status_code == 401


# ---- recovery codes ------------------------------------------------------------------------------
def test_recovery_code_works_once_and_is_case_and_format_insensitive(authed, app, clock):
    _, codes = enroll(authed, clock)
    authed.post("/api/auth/logout")
    assert sign_in(authed, codes[0].upper().replace("-", " ")).status_code == 200
    authed.post("/api/auth/logout")
    assert sign_in(authed, codes[0]).status_code == 401  # burned
    assert sign_in(authed, codes[1]).status_code == 200
    with app.state.session_factory() as db:
        assert len(db.scalar(select(User)).recovery_codes) == 8


def test_regenerating_recovery_codes_invalidates_the_old_ones(authed, clock):
    secret, old = enroll(authed, clock)
    clock["t"] += 30
    bad = authed.post("/api/auth/mfa/recovery-codes", json={"password": PW, "code": "000000"})
    assert bad.status_code == 400
    assert authed.post("/api/auth/mfa/recovery-codes", json={"password": "nope", "code": totp.code_at(secret)}).status_code == 403
    new = authed.post("/api/auth/mfa/recovery-codes", json={"password": PW, "code": totp.code_at(secret)}).json()["recovery_codes"]
    assert len(new) == 10 and not set(new) & set(old)
    authed.post("/api/auth/logout")
    assert sign_in(authed, old[0]).status_code == 401
    assert sign_in(authed, new[0]).status_code == 200


# ---- disabling -----------------------------------------------------------------------------------
def test_disable_needs_password_and_a_second_factor(authed, clock):
    secret, _ = enroll(authed, clock)
    clock["t"] += 30
    assert authed.post("/api/auth/mfa/disable", json={"password": "nope", "code": totp.code_at(secret)}).status_code == 403
    assert authed.post("/api/auth/mfa/disable", json={"password": PW, "code": "000000"}).status_code == 400
    assert authed.get("/api/auth/state").json()["mfa_enabled"] is True
    assert authed.post("/api/auth/mfa/disable", json={"password": PW, "code": totp.code_at(secret)}).status_code == 204
    assert authed.get("/api/auth/state").json()["mfa_enabled"] is False and authed.get("/api/devices").status_code == 200
    authed.post("/api/auth/logout")
    assert authed.post("/api/auth/login", json={"username": "admin", "password": PW}).json()["authenticated"] is True  # one step again
    assert authed.post("/api/auth/mfa/disable", json={"password": PW, "code": "123456"}).status_code == 409


# ---- LANWARDEN_REQUIRE_MFA ----------------------------------------------------------------------
def test_require_mfa_blocks_the_app_until_enrolled(tmp_path, clock):
    cfg = Config(data_dir=tmp_path, frontend_dir=tmp_path / "none", scheduler_enabled=False, require_mfa=True)
    with TestClient(create_app(cfg)) as c:
        assert c.post("/api/auth/setup", json={"username": "admin", "password": PW}).status_code == 201
        state = c.get("/api/auth/state").json()
        assert state["authenticated"] and state["mfa_enrolment_required"] is True
        blocked = c.get("/api/devices")
        assert blocked.status_code == 403 and blocked.json()["detail"] == "mfa_enrolment_required"
        assert c.get("/api/dashboard").status_code == 403 and c.get("/api/settings").status_code == 403

        secret, _ = enroll(c, clock)  # the enrolment endpoints themselves stay reachable
        assert c.get("/api/devices").status_code == 200
        assert c.get("/api/auth/state").json()["mfa_enrolment_required"] is False
        clock["t"] += 30
        assert c.post("/api/auth/mfa/disable", json={"password": PW, "code": totp.code_at(secret)}).status_code == 409  # cannot opt out


# ---- operator lockout recovery -------------------------------------------------------------------
@pytest.fixture()
def cli(tmp_path, monkeypatch, app, client):
    monkeypatch.setenv("LANWARDEN_DATA_DIR", str(tmp_path))
    return client


def test_reset_mfa_cli_restores_password_only_login(cli, clock, capsys):
    cli.post("/api/auth/setup", json={"username": "admin", "password": PW})
    enroll(cli, clock)
    assert reset_mfa("admin") == 0 and "removed" in capsys.readouterr().out
    assert cli.get("/api/devices").status_code == 401  # the old session is no longer valid (MFA state is part of it)
    r = cli.post("/api/auth/login", json={"username": "admin", "password": PW}).json()
    assert r["authenticated"] is True and r["mfa_required"] is False
    assert reset_mfa("nobody") == 1


def test_reset_password_cli_changes_password_and_lifts_lockouts(cli, monkeypatch, capsys):
    cli.post("/api/auth/setup", json={"username": "admin", "password": PW})
    cli.post("/api/auth/logout")
    for _ in range(5):
        cli.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert cli.post("/api/auth/login", json={"username": "admin", "password": PW}).status_code == 429

    answers = iter(["a fresh long password", "a fresh long password"])
    monkeypatch.setattr("app.__main__.getpass.getpass", lambda prompt="": next(answers))
    assert reset_password("admin") == 0
    assert cli.post("/api/auth/login", json={"username": "admin", "password": PW}).status_code == 401  # old one is gone
    assert cli.post("/api/auth/login", json={"username": "admin", "password": "a fresh long password"}).status_code == 200  # lockout lifted

    mismatch = iter(["a fresh long password", "something else entirely"])
    monkeypatch.setattr("app.__main__.getpass.getpass", lambda prompt="": next(mismatch))
    assert reset_password("admin") == 1 and "nothing changed" in capsys.readouterr().err
    short = iter(["short", "short"])
    monkeypatch.setattr("app.__main__.getpass.getpass", lambda prompt="": next(short))
    assert reset_password("admin") == 1


def test_cli_dispatch(capsys):
    assert main(["reset-mfa"]) == 2 and "usage" in capsys.readouterr().err  # missing the username
    assert time.time() > 0
