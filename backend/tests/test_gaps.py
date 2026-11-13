import subprocess
import threading
import time
from datetime import timedelta

import httpx
import pytest
from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import create_engine, inspect

from app.core.security import hash_password, verify_password
from app.db.types import utcnow
from app.discovery.base import DiscoveryProvider, ProviderResult
from app.integrations.adguard import AdGuardClient, AdGuardConfig, AdGuardError
from app.main import MIGRATIONS_DIR
from app.models import DeviceSession, Event
from app.services import netinfo
from tests.adguard_mock import FakeAdGuard


# ---- scheduler loop ------------------------------------------------------------------------
class Counting(DiscoveryProvider):
    name = "counting"

    def __init__(self):
        self.scans = 0

    def enabled(self, s):
        return True

    def scan(self, ctx):
        self.scans += 1
        return ProviderResult()


def wait_for(predicate, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def test_scheduler_runs_periodically_reschedules_without_scanning_and_stops(app, client, monkeypatch):
    from app.services import scanner as scanner_mod

    monkeypatch.setattr(scanner_mod, "FIRST_SCAN_DELAY_S", 0.05)
    scanner = app.state.scanner
    probe = Counting()
    scanner.providers = [probe]
    monkeypatch.setattr(scanner, "_interval", lambda: 0.1)

    scanner.start()
    try:
        assert wait_for(lambda: probe.scans >= 3), "scheduled scans did not repeat"
        assert all(r["trigger"] == "schedule" for r in scanner.runs)

        monkeypatch.setattr(scanner, "_interval", lambda: 60)  # user raised the interval in Settings
        scanner.reschedule()
        time.sleep(0.4)  # let the in-flight wait notice
        after_change = probe.scans
        time.sleep(0.5)
        assert probe.scans == after_change, "changing the interval must not trigger an immediate extra scan loop"
    finally:
        scanner.stop()
    assert not scanner._thread.is_alive()
    stopped_at = probe.scans
    time.sleep(0.3)
    assert probe.scans == stopped_at


def test_scan_failure_is_reported_releases_the_lock_and_skips_notifications(app, client, monkeypatch):
    from app.services import scanner as scanner_mod

    notified = []
    scanner = app.state.scanner
    scanner._notify = notified.append
    scanner.providers = [Counting()]

    def boom(*a, **k):
        raise RuntimeError("db exploded: secret detail")

    monkeypatch.setattr(scanner_mod, "process_scan", boom)
    run = scanner.run_once("manual")
    assert run["error"] == "Scan failed (see server log)" and "secret detail" not in run["error"]
    assert not scanner.running and notified == []  # lock released; nothing notified about a failed scan
    monkeypatch.undo()
    assert scanner.run_once("manual")["error"] is None and notified  # next scan works and notifies


def test_only_one_scan_runs_at_a_time_under_contention(app, client):
    release, entered = threading.Event(), threading.Event()

    class Slow(Counting):
        def scan(self, ctx):
            entered.set()
            release.wait(5)
            return ProviderResult()

    scanner = app.state.scanner
    scanner.providers = [Slow()]
    t = threading.Thread(target=scanner.run_once, args=("manual",))
    t.start()
    assert entered.wait(5) and scanner.running
    assert scanner.trigger_manual() is False and scanner.run_once("schedule") is None
    release.set()
    t.join(5)
    assert not scanner.running


# ---- migrations ----------------------------------------------------------------------------
def test_migrations_upgrade_downgrade_upgrade(tmp_path):
    url = f"sqlite:///{tmp_path / 'm.db'}"
    cfg = AlembicConfig()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.attributes["url"] = url

    def tables():
        engine = create_engine(url)
        try:
            return set(inspect(engine).get_table_names()) - {"alembic_version"}
        finally:
            engine.dispose()  # no leaked connections

    command.upgrade(cfg, "head")
    full = tables()
    assert {"devices", "events", "device_sessions", "settings", "notification_rules", "users"} <= full
    command.downgrade(cfg, "0004")  # undo only the devices.type_guess and model columns
    assert tables() == full
    command.downgrade(cfg, "0002")  # undo the MFA columns and the login_attempts table
    assert tables() == full - {"login_attempts"}
    command.downgrade(cfg, "0001")  # then only the column widening
    assert tables() == full - {"login_attempts"}
    command.downgrade(cfg, "base")
    assert tables() == set()
    command.upgrade(cfg, "head")  # and forward again
    assert tables() == full


# ---- sessions & events endpoints with real data --------------------------------------------
def test_sessions_endpoint_durations_order_and_since(authed, app, seed):
    dev, now = seed[0], utcnow()
    with app.state.session_factory() as db:
        db.add_all([
            DeviceSession(device_id=dev, connected_at=now - timedelta(days=3), disconnected_at=now - timedelta(days=3) + timedelta(hours=2),
                          last_seen=now - timedelta(days=3) + timedelta(hours=2), source="arp_scan"),
            DeviceSession(device_id=dev, connected_at=now - timedelta(hours=1), disconnected_at=None, last_seen=now - timedelta(minutes=5),
                          source="arp_scan"),
        ])
        db.commit()
    rows = authed.get(f"/api/devices/{dev}/sessions").json()
    assert [r["duration_seconds"] for r in rows] == [55 * 60, 2 * 3600]  # newest first; open one counts up to last_seen
    assert rows[0]["disconnected_at"] is None
    recent = authed.get(f"/api/devices/{dev}/sessions", params={"since": (now - timedelta(days=1)).isoformat()}).json()
    assert len(recent) == 1 and recent[0]["disconnected_at"] is None


def test_event_filters_and_paging(authed, app, seed):
    laptop, nas, now = seed[0], seed[1], utcnow()
    with app.state.session_factory() as db:
        db.add_all([
            Event(device_id=nas, event_type="DEVICE_DISCONNECTED", old_value="ONLINE", new_value="OFFLINE", timestamp=now - timedelta(days=2)),
            Event(device_id=nas, event_type="DEVICE_CONNECTED", old_value="OFFLINE", new_value="ONLINE", timestamp=now - timedelta(hours=1)),
        ])
        db.commit()
    ids = lambda **p: sorted(e["event_type"] for e in authed.get("/api/events", params=p).json()["items"])  # noqa: E731
    assert len(ids()) == 3
    assert ids(device_id=nas) == ["DEVICE_CONNECTED", "DEVICE_DISCONNECTED"]
    assert ids(device_id=laptop) == ["DEVICE_DISCOVERED"]
    assert ids(since=(now - timedelta(days=1)).isoformat()) == ["DEVICE_CONNECTED", "DEVICE_DISCOVERED"]
    assert ids(until=(now - timedelta(days=1)).isoformat()) == ["DEVICE_DISCONNECTED"]
    assert ids(q="OFFLINE") == ["DEVICE_CONNECTED", "DEVICE_DISCONNECTED"]  # matches old/new values
    assert ids(q="nas") == ["DEVICE_CONNECTED", "DEVICE_DISCONNECTED"]      # and the device name
    page = authed.get("/api/events", params={"limit": 1, "offset": 1}).json()
    assert page["total"] == 3 and len(page["items"]) == 1


# ---- error branches ------------------------------------------------------------------------
def test_verify_password_rejects_malformed_hashes():
    good = hash_password("hunter2-hunter2")
    assert verify_password("hunter2-hunter2", good) and not verify_password("wrong", good)
    for bad in ("", "plaintext", "bcrypt$1$2$3$4$5", "scrypt$x$8$1$AAAA$AAAA", "scrypt$16384$8$1$!!!$!!!"):
        assert verify_password("anything", bad) is False


def test_detect_networks_returns_empty_when_ip_is_unavailable(monkeypatch):
    def missing(*a, **k):
        raise FileNotFoundError("ip")

    monkeypatch.setattr(subprocess, "run", missing)
    assert netinfo.detect_networks() == []

    def failing(*a, **k):
        raise subprocess.CalledProcessError(1, "ip")

    monkeypatch.setattr(subprocess, "run", failing)
    assert netinfo.detect_networks() == []


@pytest.mark.parametrize("route, kind", [
    ((400, {"message": "bad request"}), "bad_response"),
    ((418, "teapot"), "bad_response"),
])
def test_adguard_client_other_4xx_is_bad_response(route, kind):
    cfg = AdGuardConfig(url="http://192.168.0.2:3000", username="admin", password="s3cret-pw")
    fake = FakeAdGuard({"GET /status": route})
    with pytest.raises(AdGuardError) as e:
        AdGuardClient(cfg, transport=httpx.MockTransport(fake.handler)).status()
    assert e.value.kind == kind


def test_adguard_client_generic_transport_error_is_unavailable():
    cfg = AdGuardConfig(url="http://192.168.0.2:3000", username="admin", password="s3cret-pw")
    fake = FakeAdGuard({"GET /status": httpx.RemoteProtocolError("server disconnected")})
    with pytest.raises(AdGuardError) as e:
        AdGuardClient(cfg, transport=httpx.MockTransport(fake.handler)).status()
    assert e.value.kind == "unavailable" and "RemoteProtocolError" in e.value.message
