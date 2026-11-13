from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app.core.config import Config
from app.db.types import utcnow
from app.main import create_app
from app.models import Device, Event, EventType


@pytest.fixture()
def app(tmp_path):
    return create_app(Config(data_dir=tmp_path, frontend_dir=tmp_path / "none", scheduler_enabled=False))


@pytest.fixture()
def client(app):
    with TestClient(app) as c:  # context manager runs lifespan -> migrations
        yield c


@pytest.fixture()
def authed(client):
    r = client.post("/api/auth/setup", json={"username": "admin", "password": "correct horse battery"})
    assert r.status_code == 201
    return client


@pytest.fixture()
def seed(app, client):
    """Three devices: online+new, offline+known, MAC-less. Depends on `client` so migrations have run."""
    now = utcnow()
    with app.state.session_factory() as db:
        devices = [
            Device(mac_address="aa:bb:cc:00:00:01", current_ip="192.168.1.10", hostname="laptop",
                   vendor="Dell", status="NEW", is_online=True, first_seen=now, last_seen=now),
            Device(mac_address="aa:bb:cc:00:00:02", current_ip="192.168.1.2", hostname="nas",
                   vendor="Synology", status="OFFLINE", is_online=False, is_known=True,
                   always_connected=True, first_seen=now - timedelta(days=9), last_seen=now - timedelta(hours=2)),
            Device(current_ip="192.168.1.50", hostname="100%_odd", status="ONLINE", is_online=True,
                   is_known=True, first_seen=now - timedelta(days=3), last_seen=now),
        ]
        db.add_all(devices)
        db.flush()
        db.add(Event(device_id=devices[0].id, event_type=EventType.DEVICE_DISCOVERED.value,
                     new_value="192.168.1.10", source="arp_scan"))
        db.commit()
        return [d.id for d in devices]
