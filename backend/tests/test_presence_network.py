from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from app.db.types import utcnow
from app.discovery.base import DeviceObservation
from app.models import Device, DeviceAddress, DeviceName, DeviceSession
from app.models.event import DiscoveryObservation
from app.schemas.settings import ScannerSettings
from app.services.inventory import process_scan
from app.services.presence import online_segments


def t(h, m=0):
    return datetime(2026, 1, 1, h, m, tzinfo=timezone.utc)


# ---- pure timeline function ---------------------------------------------------------------
def test_online_segments_clip_merge_and_drop():
    intervals = [(t(1), t(3)), (t(2), t(5)), (t(5), t(6)), (t(8), t(9)), (t(20), t(22)), (t(0), t(1))]
    assert online_segments(intervals, t(2, 30), t(8, 30)) == [(t(2, 30), t(6)), (t(8), t(8, 30))]
    assert online_segments([], t(0), t(1)) == []
    assert online_segments([(t(1), t(2))], t(2), t(3)) == []  # ends exactly at window start


# ---- presence API -------------------------------------------------------------------------
def add_sessions(app, device_id, spans, last_seen=None):
    with app.state.session_factory() as db:
        for start, end in spans:
            db.add(DeviceSession(device_id=device_id, connected_at=start, disconnected_at=end,
                                 last_seen=end or last_seen or utcnow(), source="arp_scan"))
        db.commit()


def test_presence_ranges_and_totals(authed, app, seed):
    dev = seed[1]  # first_seen 9 days ago
    now = utcnow()
    add_sessions(app, dev, [
        (now - timedelta(days=20), now - timedelta(days=19)),                      # only in 30d
        (now - timedelta(days=3), now - timedelta(days=3) + timedelta(hours=2)),   # 7d and 30d
        (now - timedelta(hours=5), now - timedelta(hours=3)),                      # all ranges
        (now - timedelta(hours=1), None),                                          # open session
    ], last_seen=now - timedelta(minutes=1))

    day = authed.get(f"/api/devices/{dev}/presence", params={"range": "24h"}).json()
    assert len(day["segments"]) == 2 and day["session_count"] == 2
    assert day["online_seconds"] == pytest.approx(2 * 3600 + 59 * 60, abs=2)
    assert day["tracked_seconds"] == pytest.approx(24 * 3600, abs=5) and day["online_percent"] == pytest.approx(12.4, abs=0.1)  # 10740 s of 86400 s

    assert len(authed.get(f"/api/devices/{dev}/presence", params={"range": "7d"}).json()["segments"]) == 3
    month = authed.get(f"/api/devices/{dev}/presence", params={"range": "30d"}).json()
    assert len(month["segments"]) == 4
    # first seen 9 days ago, so the empty days before that are not held against the device
    assert month["tracked_seconds"] == pytest.approx(9 * 86400, abs=5)


def test_presence_today_uses_client_timezone(authed, app, seed):
    dev = seed[0]
    for offset in (-720, 0, 840):
        r = authed.get(f"/api/devices/{dev}/presence", params={"range": "today", "tz_offset_minutes": offset}).json()
        start = datetime.fromisoformat(r["start"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(r["end"].replace("Z", "+00:00"))
        local_start = (start + timedelta(minutes=offset)).replace(tzinfo=None)
        assert (local_start.hour, local_start.minute, local_start.second) == (0, 0, 0)  # local midnight
        assert timedelta(0) <= end - start < timedelta(days=1)
        assert r["range"] == "today"


def test_presence_empty_and_validation(authed, seed):
    r = authed.get(f"/api/devices/{seed[2]}/presence").json()
    assert r["segments"] == [] and r["online_seconds"] == 0 and r["session_count"] == 0
    assert authed.get(f"/api/devices/{seed[2]}/presence", params={"range": "1y"}).status_code == 422
    assert authed.get(f"/api/devices/{seed[2]}/presence", params={"tz_offset_minutes": 9999}).status_code == 422
    assert authed.get("/api/devices/999/presence").status_code == 404


# ---- network API --------------------------------------------------------------------------
def test_network_history(authed, app, seed):
    dev = seed[0]  # current_ip 192.168.1.10
    now = utcnow()
    with app.state.session_factory() as db:
        db.add_all([
            DeviceAddress(device_id=dev, ip="192.168.1.10", first_seen=now - timedelta(days=1), last_seen=now, source="arp_scan"),
            DeviceAddress(device_id=dev, ip="192.168.1.77", first_seen=now - timedelta(days=9), last_seen=now - timedelta(days=5), source="neighbor"),
            DeviceName(device_id=dev, name="laptop", source="adguard_dhcp", first_seen=now - timedelta(days=9), last_seen=now),
            DeviceName(device_id=dev, name="old-laptop", source="adguard_clients", first_seen=now - timedelta(days=9), last_seen=now - timedelta(days=6)),
            DiscoveryObservation(device_id=dev, source="arp_scan", mac="aa:bb:cc:00:00:01", ip="192.168.1.10", observed_at=now - timedelta(hours=2)),
            DiscoveryObservation(device_id=dev, source="arp_scan", mac="aa:bb:cc:00:00:01", ip="192.168.1.10", observed_at=now),
            DiscoveryObservation(device_id=dev, source="neighbor", mac="aa:bb:cc:00:00:01", ip="192.168.1.10", observed_at=now - timedelta(hours=1)),
            DiscoveryObservation(device_id=seed[1], source="arp_scan", mac="aa:bb:cc:00:00:02", ip="192.168.1.2", observed_at=now),
        ])
        db.commit()
    n = authed.get(f"/api/devices/{dev}/network").json()
    assert [(a["ip"], a["current"]) for a in n["addresses"]] == [("192.168.1.10", True), ("192.168.1.77", False)]
    assert [x["name"] for x in n["names"]] == ["laptop", "old-laptop"]
    assert [(s["source"], s["observations"]) for s in n["sources"]] == [("arp_scan", 2), ("neighbor", 1)]  # other device excluded
    assert n["observation_retention_days"] == 7
    assert authed.get("/api/devices/999/network").status_code == 404


def test_network_empty_for_device_without_history(authed, seed):
    n = authed.get(f"/api/devices/{seed[2]}/network").json()
    assert n["addresses"] == n["names"] == n["sources"] == []


# ---- retention setting --------------------------------------------------------------------
def test_observation_retention_is_configurable_and_validated(authed):
    s = authed.get("/api/settings").json()["settings"]
    assert s["scanner"]["observation_retention_days"] == 7
    s["scanner"]["observation_retention_days"] = 30
    assert authed.put("/api/settings", json=s).json()["settings"]["scanner"]["observation_retention_days"] == 30
    for bad in (0, 366):
        s["scanner"]["observation_retention_days"] = bad
        assert authed.put("/api/settings", json=s).status_code == 422


def test_scan_prunes_by_configured_retention_and_keeps_devices(app, client):
    now = utcnow()
    old = now - timedelta(days=10)
    with app.state.session_factory() as db:
        process_scan(db, [DeviceObservation(source="arp_scan", mac="aa:bb:cc:00:00:0a", ip="192.168.1.10", seen_at=old)],
                     True, ScannerSettings(), old)
        process_scan(db, [], True, ScannerSettings(observation_retention_days=30), now)  # kept: 10d < 30d
        assert db.scalar(select(func.count()).select_from(DiscoveryObservation)) == 1
        process_scan(db, [], True, ScannerSettings(observation_retention_days=7), now)  # pruned: 10d > 7d
        assert db.scalar(select(func.count()).select_from(DiscoveryObservation)) == 0
        assert db.scalar(select(func.count()).select_from(Device)) == 1  # devices themselves are never pruned


def test_open_session_of_online_device_runs_to_now(authed, app, seed):
    online, offline = seed[0], seed[1]  # seed: device 0 is_online, device 1 is not
    now = utcnow()
    add_sessions(app, online, [(now - timedelta(minutes=30), None)], last_seen=now - timedelta(minutes=4))
    add_sessions(app, offline, [(now - timedelta(minutes=30), None)], last_seen=now - timedelta(minutes=10))
    on = authed.get(f"/api/devices/{online}/presence", params={"range": "24h"}).json()
    off = authed.get(f"/api/devices/{offline}/presence", params={"range": "24h"}).json()
    assert on["online_seconds"] == pytest.approx(30 * 60, abs=3)   # to now, not to the last sighting
    assert off["online_seconds"] == pytest.approx(20 * 60, abs=3)  # offline: only up to last_seen
