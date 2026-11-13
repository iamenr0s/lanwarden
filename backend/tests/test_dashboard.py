from datetime import datetime, timedelta, timezone

import pytest

from app.db.types import utcnow
from app.models import Device, DeviceSession
from app.services.analytics import online_series


def t(h, m=0):
    return datetime(2026, 1, 1, h, m, tzinfo=timezone.utc)


def test_online_series_counts_overlap_and_known_devices():
    intervals = [(t(0), t(4)), (t(2), t(6)), (t(8), t(10))]
    series = online_series(intervals, [t(0), t(3), t(9)], t(0), t(10), 5)  # samples at 0,2,4,6,8,10
    assert [(p[0].hour, p[1], p[2]) for p in series] == [(0, 1, 1), (2, 2, 1), (4, 2, 2), (6, 1, 2), (8, 1, 2), (10, 1, 3)]
    assert online_series([], [], t(0), t(1), 2) == [(t(0), 0, 0), (t(0, 30), 0, 0), (t(1), 0, 0)]


def add(app, mac, **kw):
    with app.state.session_factory() as db:
        d = Device(mac_address=mac, **kw)
        db.add(d)
        db.commit()
        return d.id


def test_dashboard_requires_auth_and_validates_range(client, authed):
    authed.post("/api/auth/logout")
    assert client.get("/api/dashboard").status_code == 401
    authed.post("/api/auth/login", json={"username": "admin", "password": "correct horse battery"})
    assert authed.get("/api/dashboard", params={"range": "1y"}).status_code == 422


def test_dashboard_empty_database(authed):
    d = authed.get("/api/dashboard").json()
    assert len(d["series"]) == 25 and all(p["online"] == 0 and p["total"] == 0 for p in d["series"])
    assert d["type_distribution"] == [] and d["recently_disconnected"] == []


@pytest.mark.parametrize("rng, points", [("24h", 25), ("7d", 29), ("30d", 31)])
def test_series_length_per_range(authed, rng, points):
    assert len(authed.get("/api/dashboard", params={"range": rng}).json()["series"]) == points


def test_dashboard_series_types_and_recent_disconnects(authed, app):
    now = utcnow()
    a = add(app, "aa:bb:cc:00:00:01", device_type="router", is_online=True, first_seen=now - timedelta(hours=20), last_seen=now)
    b = add(app, "aa:bb:cc:00:00:02", device_type="phone", is_online=False, first_seen=now - timedelta(hours=10),
            last_seen=now - timedelta(hours=2), last_disconnection=now - timedelta(hours=2))
    c = add(app, "aa:bb:cc:00:00:03", is_online=False, first_seen=now - timedelta(hours=5), last_seen=now - timedelta(hours=1),
            last_disconnection=now - timedelta(hours=1))
    ignored = add(app, "aa:bb:cc:00:00:04", device_type="router", is_ignored=True, is_online=True,
                  first_seen=now - timedelta(hours=20), last_seen=now)
    with app.state.session_factory() as db:
        db.add_all([
            DeviceSession(device_id=a, connected_at=now - timedelta(hours=20), disconnected_at=None, last_seen=now),
            DeviceSession(device_id=b, connected_at=now - timedelta(hours=10), disconnected_at=now - timedelta(hours=2),
                          last_seen=now - timedelta(hours=2)),
            DeviceSession(device_id=c, connected_at=now - timedelta(hours=5), disconnected_at=now - timedelta(hours=1),
                          last_seen=now - timedelta(hours=1)),
            DeviceSession(device_id=ignored, connected_at=now - timedelta(hours=20), disconnected_at=None, last_seen=now),
        ])
        db.commit()

    d = authed.get("/api/dashboard", params={"range": "24h"}).json()
    s = d["series"]
    assert (s[0]["online"], s[0]["total"]) == (0, 0)    # 24h ago: nothing known yet
    assert (s[-1]["online"], s[-1]["total"]) == (1, 3)  # now: only `a` online; the ignored device is excluded everywhere
    assert max(p["online"] for p in s) == 3 and max(p["total"] for p in s) == 3  # peak while a, b and c overlapped
    assert {(x["type"], x["count"]) for x in d["type_distribution"]} == {("router", 1), ("phone", 1), ("Unclassified", 1)}
    assert [x["id"] for x in d["recently_disconnected"]] == [c, b]  # newest first; online and ignored devices excluded
