import os

from app.core.config import Config, _adopt_legacy_env


def test_legacy_env_is_adopted_and_new_wins(monkeypatch):
    monkeypatch.setenv("GUARDALERT_SETUP_TOKEN", "old-token")
    monkeypatch.setenv("GUARDALERT_REQUIRE_MFA", "true")
    monkeypatch.setenv("LANWARDEN_REQUIRE_MFA", "false")
    monkeypatch.delenv("LANWARDEN_SETUP_TOKEN", raising=False)
    _adopt_legacy_env()
    cfg = Config()
    assert cfg.setup_token == "old-token" and cfg.require_mfa is False
    os.environ.pop("LANWARDEN_SETUP_TOKEN", None)  # written by the adopt step; monkeypatch does not know about it


def test_existing_pre_rename_database_is_kept(tmp_path):
    assert Config(data_dir=tmp_path).db_url.endswith("lanwarden.db")
    (tmp_path / "guardalert.db").write_bytes(b"")
    assert Config(data_dir=tmp_path).db_url.endswith("guardalert.db")
    (tmp_path / "lanwarden.db").write_bytes(b"")
    assert Config(data_dir=tmp_path).db_url.endswith("lanwarden.db")  # once the new one exists it wins
