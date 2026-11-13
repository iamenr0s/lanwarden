from datetime import timedelta

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import StatementError

from app.db.types import utcnow
from app.models import Device, DeviceStatus
from app.services.presence import compute_status


def dev(**kw) -> Device:
    return Device(is_known=kw.pop("is_known", False), **kw)


def test_status_unknown_when_never_seen():
    assert compute_status(dev(), utcnow(), 900, 24) == DeviceStatus.UNKNOWN


def test_status_new_then_online_offline():
    now = utcnow()
    fresh = dev(first_seen=now - timedelta(hours=1), last_seen=now)
    assert compute_status(fresh, now, 900, 24) == DeviceStatus.NEW
    old = dev(first_seen=now - timedelta(days=3), last_seen=now - timedelta(seconds=60))
    assert compute_status(old, now, 900, 24) == DeviceStatus.ONLINE
    # one missed scan (< threshold) is still online; silence beyond threshold is offline
    assert compute_status(dev(first_seen=now - timedelta(days=3), last_seen=now - timedelta(seconds=899)), now, 900, 24) == DeviceStatus.ONLINE
    assert compute_status(dev(first_seen=now - timedelta(days=3), last_seen=now - timedelta(seconds=901)), now, 900, 24) == DeviceStatus.OFFLINE


def test_known_device_is_never_new():
    now = utcnow()
    d = dev(is_known=True, first_seen=now, last_seen=now)
    assert compute_status(d, now, 900, 24) == DeviceStatus.ONLINE


def test_migration_creates_expected_tables_and_indexes(app, client):  # client => lifespan ran migrations
    insp = inspect(app.state.session_factory.kw["bind"])
    assert {"devices", "device_addresses", "device_names", "device_sessions", "events",
            "discovery_observations", "settings", "notification_rules", "users"} <= set(insp.get_table_names())
    dev_idx = {c for i in insp.get_indexes("devices") for c in i["column_names"]}
    assert {"mac_address", "current_ip", "hostname", "last_seen"} <= dev_idx
    assert any("timestamp" in i["column_names"] for i in insp.get_indexes("events"))


def test_naive_datetime_rejected(app, client):
    from datetime import datetime

    with app.state.session_factory() as db:
        db.add(Device(first_seen=datetime(2024, 1, 1)))
        with pytest.raises(StatementError, match="naive datetime"):
            db.commit()
