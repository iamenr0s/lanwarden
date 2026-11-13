import base64
import hashlib
import logging
import os

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import select, text

from app.__main__ import encrypt_db, main, rotate_key
from app.core.config import Config
from app.main import create_app
from app.models import Device
from app.models.system import NotificationRule, Setting, User
from app.notifications.webhook import WebhookProvider
from app.services import notification_rules as rules
from app.services import rotation
from app.services.crypto import SecretBox, derive_key

KEY_A = "a" * 48
KEY_B = "b" * 48
HOOK_URL = "https://hooks.example.com/services/T000/B000/XXXXTOKEN"
MAC, HOST = "b8:27:eb:12:34:56", "very-secret-hostname"


# ---- SecretBox -------------------------------------------------------------------------------
def test_new_tokens_are_versioned_and_legacy_tokens_still_decrypt():
    box = SecretBox(KEY_A)
    token = box.encrypt("hunter2")
    assert token.startswith("v2:") and box.decrypt(token) == "hunter2"
    legacy_key = hashlib.sha256(b"guardalert-secretbox-v1:" + KEY_A.encode()).digest()  # what earlier versions did
    legacy_token = Fernet(base64.urlsafe_b64encode(legacy_key)).encrypt(b"old secret").decode()
    assert box.decrypt(legacy_token) == "old secret"
    assert SecretBox(KEY_B).decrypt(token) is None and SecretBox(KEY_B).decrypt(legacy_token) is None
    assert box.decrypt("v2:garbage") is None and box.decrypt("garbage") is None


def test_derived_keys_are_independent_per_purpose():
    assert derive_key(KEY_A, "secretbox-v2") != derive_key(KEY_A, "database-v1")
    assert derive_key(KEY_A, "database-v1") == derive_key(KEY_A, "database-v1") != derive_key(KEY_B, "database-v1")


# ---- where the key comes from -------------------------------------------------------------
def test_key_length_rules(tmp_path, caplog):
    with pytest.raises(ValueError, match="at least 16"):
        Config(data_dir=tmp_path, secret_key="short").resolve_secret_key()
    with caplog.at_level(logging.WARNING, logger="lanwarden.config"):
        assert Config(data_dir=tmp_path, secret_key="x" * 20).resolve_secret_key() == "x" * 20
    assert "shorter than 32" in caplog.text


def test_key_file_precedence_permissions_and_errors(tmp_path, caplog):
    keyfile = tmp_path / "k"
    keyfile.write_text(KEY_A + "\n")
    keyfile.chmod(0o600)
    cfg = Config(data_dir=tmp_path / "data", secret_key_file=keyfile)
    assert cfg.secret_key_source == "file" and cfg.resolve_secret_key() == KEY_A
    assert not (tmp_path / "data" / "secret_key").exists()  # nothing generated beside the database
    assert Config(data_dir=tmp_path, secret_key=KEY_B, secret_key_file=keyfile).resolve_secret_key() == KEY_B  # env wins
    assert Config(data_dir=tmp_path).secret_key_source == "data_dir"
    keyfile.chmod(0o644)
    with caplog.at_level(logging.WARNING, logger="lanwarden.config"):
        cfg.resolve_secret_key()
    assert "readable by group/others" in caplog.text
    keyfile.write_text("")
    with pytest.raises(ValueError, match="empty"):
        cfg.resolve_secret_key()
    with pytest.raises(ValueError, match="cannot read"):
        Config(data_dir=tmp_path, secret_key_file=tmp_path / "missing").resolve_secret_key()


# ---- webhook URL --------------------------------------------------------------------------
def test_webhook_url_is_required_on_create_but_optional_on_edit(authed, app):
    body = {"name": "h", "provider": "webhook", "event_types": ["DEVICE_DISCOVERED"], "config": {"verify_tls": True}}
    assert authed.post("/api/notifications/rules", json=body).status_code == 422
    body["config"]["url"] = HOOK_URL
    rid = authed.post("/api/notifications/rules", json=body).json()["id"]
    body["config"] = {"verify_tls": False}  # edit without the URL keeps the stored one
    out = authed.put(f"/api/notifications/rules/{rid}", json=body).json()
    assert out["config"]["url_set"] is True and out["config"]["verify_tls"] is False
    with app.state.session_factory() as db:
        rule = db.get(NotificationRule, rid)
        cfg = rules.runtime_config(rule, WebhookProvider(), app.state.box)
    assert cfg.url == HOOK_URL  # decrypted for sending only


def test_legacy_plaintext_webhook_url_is_encrypted_at_startup(app, client):
    box = app.state.box
    providers = {"webhook": WebhookProvider()}
    with app.state.session_factory() as db:
        db.add(NotificationRule(name="old", provider="webhook", event_types=["DEVICE_DISCOVERED"], enabled=True,
                                config={"url": HOOK_URL, "secret_enc": "", "verify_tls": True}))
        db.commit()
        assert rules.encrypt_legacy_fields(db, box, providers) == 1
        assert rules.encrypt_legacy_fields(db, box, providers) == 0  # idempotent
        stored = db.scalar(select(NotificationRule)).config
        assert "XXXXTOKEN" not in str(stored) and "url" not in stored
        assert stored["url_hint"] == "https://hooks.example.com/…"
        assert rules.runtime_config(db.scalar(select(NotificationRule)), providers["webhook"], box).url == HOOK_URL


# ---- rotation ---------------------------------------------------------------------------
def seed_secrets(app):
    box = app.state.box
    with app.state.session_factory() as db:
        db.add(Setting(key="adguard", value={"url": "http://x", "password_enc": box.encrypt("agpw")}))
        db.add(NotificationRule(name="r", provider="webhook", event_types=["DEVICE_DISCOVERED"], enabled=True,
                                config={"url_enc": box.encrypt(HOOK_URL), "secret_enc": box.encrypt("sig"), "verify_tls": True}))
        user = db.scalar(select(User))
        user.totp_secret_enc, user.totp_enabled, user.recovery_codes = box.encrypt("JBSWY3DPEHPK3PXP"), True, ["h1", "h2"]
        db.commit()


def test_reencrypt_all_moves_secrets_and_clears_recovery_codes(authed, app):
    seed_secrets(app)
    old, new = app.state.box, SecretBox(KEY_B)
    with app.state.session_factory() as db:
        counts = rotation.reencrypt_all(db, old, new)
        db.commit()
    assert counts == {"secrets": 4, "recovery_code_sets_cleared": 1}
    with app.state.session_factory() as db:
        user = db.scalar(select(User))
        assert new.decrypt(user.totp_secret_enc) == "JBSWY3DPEHPK3PXP" and old.decrypt(user.totp_secret_enc) is None
        assert user.recovery_codes is None
        assert new.decrypt(db.get(Setting, "adguard").value["password_enc"]) == "agpw"
        assert new.decrypt(db.scalar(select(NotificationRule)).config["url_enc"]) == HOOK_URL


def test_reencrypt_all_changes_nothing_if_any_secret_cannot_be_read(authed, app):
    seed_secrets(app)
    with app.state.session_factory() as db:
        with pytest.raises(rotation.RotationError, match="cannot be decrypted"):
            rotation.reencrypt_all(db, SecretBox(KEY_B), SecretBox(KEY_A))  # wrong "current" key
        db.rollback()
        assert app.state.box.decrypt(db.get(Setting, "adguard").value["password_enc"]) == "agpw"


def test_rotate_key_command_end_to_end(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("LANWARDEN_DATA_DIR", str(tmp_path))
    cfg = Config(data_dir=tmp_path, frontend_dir=tmp_path / "none", scheduler_enabled=False)
    with TestClient(create_app(cfg)) as c:
        assert c.post("/api/auth/setup", json={"username": "admin", "password": "correct horse battery"}).status_code == 201
    app = create_app(cfg)
    with TestClient(app):
        seed_secrets(app)
    old_key = (tmp_path / "secret_key").read_text()
    assert rotate_key(dry_run=True) == 0 and (tmp_path / "secret_key").read_text() == old_key  # nothing written
    monkeypatch.setenv("LANWARDEN_NEW_SECRET_KEY", "short")
    assert rotate_key() == 1  # refused: too short
    monkeypatch.delenv("LANWARDEN_NEW_SECRET_KEY")
    assert main(["rotate-key"]) == 0
    new_key = (tmp_path / "secret_key").read_text()
    assert new_key != old_key and len(new_key) >= 32 and not (tmp_path / "secret_key.new").exists()
    assert oct((tmp_path / "secret_key").stat().st_mode & 0o777) == "0o600"
    app2 = create_app(cfg)  # restarts on the new key
    with TestClient(app2):
        with app2.state.session_factory() as db:
            assert app2.state.box.decrypt(db.get(Setting, "adguard").value["password_enc"]) == "agpw"
    assert "signed out" in capsys.readouterr().out


# ---- encrypted database (SQLCipher) -----------------------------------------------------------
def encrypted_cfg(tmp_path, key=KEY_A):
    return Config(data_dir=tmp_path, frontend_dir=tmp_path / "none", scheduler_enabled=False, secret_key=key, db_encryption="sqlcipher")  # gitleaks:allow (a test fixture, not a secret)


def seed_device(app):
    with app.state.session_factory() as db:
        db.add(Device(mac_address=MAC, hostname=HOST, vendor="SecretVendorCorp", current_ip="192.168.7.7", status="ONLINE"))
        db.commit()


def raw_bytes(tmp_path):
    return b"".join(p.read_bytes() for p in tmp_path.glob("lanwarden.db*") if p.is_file())


def test_encrypted_database_hides_the_inventory_and_still_works(tmp_path):
    app = create_app(encrypted_cfg(tmp_path))
    with TestClient(app) as c:
        assert c.post("/api/auth/setup", json={"username": "admin", "password": "correct horse battery"}).status_code == 201
        seed_device(app)
        assert c.get("/api/devices", params={"q": "secret-host"}).json()["total"] == 1  # queries are unaffected
    assert not rotation.is_plain_sqlite(tmp_path / "lanwarden.db")
    blob = raw_bytes(tmp_path)  # includes the -wal file if there is one
    for needle in (MAC, HOST, "SecretVendorCorp", "192.168.7.7", "SQLite format 3"):
        assert needle.encode() not in blob


def test_wrong_key_and_data_dir_key_are_refused(tmp_path):
    TestClient(create_app(encrypted_cfg(tmp_path))).__enter__()
    with pytest.raises(RuntimeError, match="wrong key"):
        create_app(encrypted_cfg(tmp_path, key=KEY_B))
    with pytest.raises(ValueError, match="next to the database"):
        create_app(Config(data_dir=tmp_path / "other", frontend_dir=tmp_path, scheduler_enabled=False, db_encryption="sqlcipher"))


def test_encrypt_and_decrypt_database_commands_preserve_every_row(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("LANWARDEN_DATA_DIR", str(tmp_path))
    plain = Config(data_dir=tmp_path, frontend_dir=tmp_path / "none", scheduler_enabled=False, secret_key=KEY_A)
    app = create_app(plain)
    with TestClient(app) as c:
        c.post("/api/auth/setup", json={"username": "admin", "password": "correct horse battery"})
        seed_device(app)
    app.state.session_factory.kw["bind"].dispose()
    assert encrypt_db() == 1  # refused until encryption is switched on
    monkeypatch.setenv("LANWARDEN_SECRET_KEY", KEY_A)
    monkeypatch.setenv("LANWARDEN_DB_ENCRYPTION", "sqlcipher")
    assert main(["encrypt-db"]) == 0 and "UNENCRYPTED" in capsys.readouterr().out
    assert (tmp_path / "lanwarden.db.bak").exists() and not rotation.is_plain_sqlite(tmp_path / "lanwarden.db")
    assert encrypt_db() == 1  # already encrypted
    app2 = create_app(encrypted_cfg(tmp_path))
    with TestClient(app2):
        with app2.state.session_factory() as db:
            assert db.scalar(select(Device.hostname)) == HOST and db.scalar(select(User.username)) == "admin"
    app2.state.session_factory.kw["bind"].dispose()
    assert main(["decrypt-db"]) == 0 and rotation.is_plain_sqlite(tmp_path / "lanwarden.db")


def test_rotate_key_also_rekeys_an_encrypted_database(tmp_path, monkeypatch):
    monkeypatch.setenv("LANWARDEN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("LANWARDEN_SECRET_KEY", KEY_A)
    monkeypatch.setenv("LANWARDEN_DB_ENCRYPTION", "sqlcipher")
    app = create_app(encrypted_cfg(tmp_path))
    with TestClient(app) as c:
        c.post("/api/auth/setup", json={"username": "admin", "password": "correct horse battery"})
        seed_secrets(app)
        seed_device(app)
    app.state.session_factory.kw["bind"].dispose()
    monkeypatch.setenv("LANWARDEN_NEW_SECRET_KEY", KEY_B)
    assert rotate_key() == 0
    with pytest.raises(RuntimeError, match="wrong key"):
        create_app(encrypted_cfg(tmp_path, key=KEY_A))  # the old key no longer opens the file
    app2 = create_app(encrypted_cfg(tmp_path, key=KEY_B))
    with TestClient(app2):
        with app2.state.session_factory() as db:
            assert app2.state.box.decrypt(db.get(Setting, "adguard").value["password_enc"]) == "agpw"
            assert db.scalar(text("select count(*) from devices")) == 1
    assert os.environ["LANWARDEN_SECRET_KEY"] == KEY_A  # env keys are never rewritten by the tool


def test_configuration_errors_print_a_message_not_a_traceback(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("LANWARDEN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("LANWARDEN_DB_ENCRYPTION", "sqlcipher")  # with the key in the data dir: refused
    assert main(["encrypt-db"]) == 1
    assert "error:" in capsys.readouterr().err


def test_rotate_key_with_env_key_saves_the_generated_key_to_a_file_not_stdout(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("LANWARDEN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("LANWARDEN_SECRET_KEY", "k" * 40)
    cfg = Config(data_dir=tmp_path, frontend_dir=tmp_path / "none", scheduler_enabled=False)
    with TestClient(create_app(cfg)):
        pass
    assert rotate_key() == 0
    saved = (tmp_path / "secret_key.new").read_text()
    assert len(saved) >= 32 and oct((tmp_path / "secret_key.new").stat().st_mode & 0o777) == "0o600"
    assert saved not in capsys.readouterr().out
