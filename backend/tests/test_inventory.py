from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app.db.types import utcnow
from app.discovery.base import DeviceObservation
from app.models import Device, DeviceAddress, DeviceSession, Event
from app.models.event import DiscoveryObservation
from app.schemas.settings import ScannerSettings
from app.services.inventory import process_scan

SETTINGS = ScannerSettings()  # interval 300, offline 900, always-connected 300, new window 24h
T0 = utcnow()
MAC_A, MAC_B = "aa:bb:cc:00:00:0a", "aa:bb:cc:00:00:0b"


def obs(mac=MAC_A, ip="192.168.1.10", source="arp_scan", **kw):
    return DeviceObservation(source=source, mac=mac, ip=ip, **kw)


@pytest.fixture()
def db(app, client):  # client => migrations ran
    with app.state.session_factory() as session:
        yield session


def scan(db, observations, at=T0, evidence=True):
    summary = process_scan(db, observations, evidence, SETTINGS, T0 + timedelta(seconds=at) if isinstance(at, (int, float)) else at)
    db.commit()
    return summary


def types(db, device_id=None):
    q = select(Event.event_type).order_by(Event.id)
    if device_id:
        q = q.where(Event.device_id == device_id)
    return list(db.scalars(q))


def device(db, mac=MAC_A):
    return db.scalar(select(Device).where(Device.mac_address == mac))


def test_new_device_discovered(db):
    s = scan(db, [obs(hostname="laptop", vendor="Dell")])
    d = device(db)
    assert (s.discovered, s.observed) == (1, 1)
    assert (d.status, d.is_online, d.is_known) == ("NEW", True, False)
    assert (d.current_ip, d.hostname, d.vendor, d.first_seen) == ("192.168.1.10", "laptop", "Dell", T0)
    assert types(db) == ["DEVICE_DISCOVERED"]
    sessions = db.scalars(select(DeviceSession)).all()
    assert len(sessions) == 1 and sessions[0].disconnected_at is None


def test_rescan_same_device_is_quiet(db):
    scan(db, [obs()])
    s = scan(db, [obs()], at=300)
    assert (s.discovered, s.connected, s.ip_changed) == (0, 0, 0)
    assert db.scalar(select(func.count()).select_from(Device)) == 1
    assert types(db) == ["DEVICE_DISCOVERED"]
    assert device(db).last_seen == T0 + timedelta(seconds=300)


def test_same_mac_new_ip(db):
    scan(db, [obs(ip="192.168.1.10")])
    s = scan(db, [obs(ip="192.168.1.77")], at=300)
    d = device(db)
    assert s.ip_changed == 1 and db.scalar(select(func.count()).select_from(Device)) == 1
    assert d.current_ip == "192.168.1.77"
    ev = db.scalar(select(Event).where(Event.event_type == "DEVICE_IP_CHANGED"))
    assert (ev.old_value, ev.new_value) == ("192.168.1.10", "192.168.1.77")
    assert {a.ip for a in db.scalars(select(DeviceAddress).where(DeviceAddress.device_id == d.id))} == {"192.168.1.10", "192.168.1.77"}


def test_same_ip_reused_by_another_mac_does_not_merge(db):
    scan(db, [obs(MAC_A, "192.168.1.10")])
    scan(db, [obs(MAC_B, "192.168.1.10")], at=1000)  # A gone, B takes its IP
    a, b = device(db, MAC_A), device(db, MAC_B)
    assert a.id != b.id and db.scalar(select(func.count()).select_from(Device)) == 2
    assert "DEVICE_IP_CHANGED" not in types(db)  # neither device "moved"
    assert (a.is_online, b.is_online) == (False, True)  # A silent 1000s > 900s
    assert (a.current_ip, b.current_ip) == ("192.168.1.10", "192.168.1.10")


def test_single_missed_scan_is_not_a_disconnect(db):
    scan(db, [obs()])
    s = scan(db, [], at=600)  # one missed scan, silence 600s < 900s
    assert s.disconnected == 0 and device(db).is_online


def test_offline_then_reconnect_creates_sessions(db):
    scan(db, [obs()])
    s = scan(db, [], at=901)
    d = device(db)
    assert s.disconnected == 1 and d.is_online is False and d.status in ("OFFLINE", "NEW")
    first = db.scalar(select(DeviceSession).order_by(DeviceSession.id))
    assert first.disconnected_at == T0  # ends at last sighting, not at detection time
    assert d.last_disconnection == T0

    scan(db, [], at=1200)  # still gone: no duplicate disconnect
    assert types(db).count("DEVICE_DISCONNECTED") == 1

    s = scan(db, [obs()], at=2000)
    assert s.connected == 1 and device(db).is_online
    assert types(db) == ["DEVICE_DISCOVERED", "DEVICE_DISCONNECTED", "DEVICE_CONNECTED"]
    sessions = db.scalars(select(DeviceSession).order_by(DeviceSession.id)).all()
    assert len(sessions) == 2 and sessions[1].disconnected_at is None


def test_always_connected_down_and_recovered(db):
    scan(db, [obs()])
    d = device(db)
    d.always_connected = True
    db.commit()

    scan(db, [], at=299)
    assert "ALWAYS_CONNECTED_DEVICE_DOWN" not in types(db)
    s = scan(db, [], at=301)
    assert s.always_connected_down == 1
    scan(db, [], at=600)
    assert types(db).count("ALWAYS_CONNECTED_DEVICE_DOWN") == 1  # alert fires once

    s = scan(db, [obs()], at=700)  # back before the offline threshold: recovery still fires
    assert s.always_connected_recovered == 1
    scan(db, [obs()], at=800)
    assert types(db).count("ALWAYS_CONNECTED_DEVICE_RECOVERED") == 1

    scan(db, [], at=1200)  # goes down again -> a second alert is allowed
    assert types(db).count("ALWAYS_CONNECTED_DEVICE_DOWN") == 2


def test_duplicate_observations_from_multiple_providers_merge(db):
    s = scan(db, [
        obs(source="arp_scan", vendor="Dell"),
        obs(source="neighbor", hostname="laptop"),
        DeviceObservation(source="adguard_dhcp", mac=None, ip="192.168.1.10", hostname="ignored-second-name"),
    ])
    d = device(db)
    assert (s.observed, s.discovered) == (1, 1)
    assert db.scalar(select(func.count()).select_from(Device)) == 1
    assert (d.vendor, d.hostname) == ("Dell", "laptop")
    ev = db.scalar(select(Event))
    assert set(ev.source.split(",")) == {"arp_scan", "neighbor", "adguard_dhcp"}
    assert db.scalar(select(func.count()).select_from(DiscoveryObservation)) == 3  # raw sightings kept


def test_manual_values_survive_scans(db):
    scan(db, [obs(hostname="old-name", vendor="Dell")])
    d = device(db)
    d.friendly_name, d.vendor_override, d.device_type, d.device_group, d.notes = "Work laptop", "ACME", "laptop", "Office", "n"
    d.is_known = d.is_favorite = d.always_connected = True
    db.commit()

    s = scan(db, [obs(hostname="new-name", vendor="Dell Inc", ip="192.168.1.99")], at=300)
    d = device(db)
    assert s.name_changed == 1 and d.hostname == "new-name" and d.vendor == "Dell Inc"
    assert (d.friendly_name, d.vendor_override, d.device_type, d.device_group, d.notes) == ("Work laptop", "ACME", "laptop", "Office", "n")
    assert d.is_known and d.is_favorite and d.always_connected
    assert d.status == "ONLINE"  # known device is never NEW


def test_all_providers_failing_does_not_mark_devices_offline(db):
    scan(db, [obs()])
    s = scan(db, [], at=5000, evidence=False)
    assert s.disconnected == 0 and device(db).is_online
    assert types(db) == ["DEVICE_DISCOVERED"]


def ip_only(ip, **kw):
    return DeviceObservation(source="adguard_querylog", ip=ip, **kw)


def test_ip_only_observation_never_creates_a_device(db):
    s = scan(db, [ip_only("192.168.1.99", hostname="ghost")])
    assert db.scalar(select(func.count()).select_from(Device)) == 0 and s.observed == 0 and s.discovered == 0


def test_ip_only_observation_extends_presence_of_the_one_online_holder(db):
    scan(db, [obs(MAC_A, "192.168.1.10")])
    s = scan(db, [ip_only("192.168.1.10", hostname="laptop")], at=600)  # ARP missed it, DNS saw it
    d = device(db)
    assert s.observed == 1 and d.last_seen == T0 + timedelta(seconds=600) and d.hostname == "laptop"
    assert db.scalar(select(func.count()).select_from(Device)) == 1
    scan(db, [], at=600 + 899)
    assert device(db).is_online  # the DNS sighting kept it online


def test_ip_only_observation_does_not_revive_or_hit_ambiguous_ips(db):
    scan(db, [obs(MAC_A, "192.168.1.10")])
    scan(db, [], at=2000)  # A goes offline
    scan(db, [ip_only("192.168.1.10")], at=2100)  # IP maybe reused: must not bring A back
    assert device(db).is_online is False and types(db).count("DEVICE_CONNECTED") == 0
    # two online devices claiming one IP: ambiguous, so ignored
    scan(db, [obs(MAC_A, "192.168.1.20"), obs(MAC_B, "192.168.1.20")], at=3000)
    a_seen = device(db).last_seen
    scan(db, [ip_only("192.168.1.20")], at=3100)
    assert device(db).last_seen == a_seen


def test_identity_only_observation_creates_unknown_device_never_online(db):
    lease = DeviceObservation(source="adguard_dhcp", mac=MAC_A, ip="192.168.1.10", hostname="phone", presence=False)
    s = scan(db, [lease])
    d = device(db)
    assert s.discovered == 1
    assert (d.status, d.is_online, d.last_seen, d.hostname, d.current_ip) == ("UNKNOWN", False, None, "phone", "192.168.1.10")
    assert types(db) == ["DEVICE_DISCOVERED"] and db.scalar(select(func.count()).select_from(DeviceSession)) == 0
    scan(db, [lease], at=1000)  # still only a lease: nothing changes, no spurious events
    assert types(db) == ["DEVICE_DISCOVERED"] and not device(db).is_online
    # later proof of life turns it into a normal device and records the connection
    scan(db, [obs(MAC_A, "192.168.1.10")], at=2000)
    assert device(db).is_online and types(db) == ["DEVICE_DISCOVERED", "DEVICE_CONNECTED"]


def test_identity_only_observation_enriches_but_never_moves_ip_or_extends_presence(db):
    scan(db, [obs(MAC_A, "192.168.1.10")])
    lease = DeviceObservation(source="adguard_dhcp", mac=MAC_A, ip="192.168.1.77", hostname="from-lease", presence=False)
    scan(db, [lease], at=100)
    d = device(db)
    assert d.current_ip == "192.168.1.10" and d.hostname == "from-lease" and d.last_seen == T0
    assert "DEVICE_IP_CHANGED" not in types(db)
    scan(db, [lease], at=1000)  # lease keeps arriving, device is silent: still goes offline
    assert device(db).is_online is False


def test_old_observations_are_pruned(db):
    scan(db, [obs()])
    later = utcnow() + timedelta(days=8)
    scan(db, [obs(seen_at=later)], at=later)  # first sighting is now 8 days old, the new one is not
    assert db.scalar(select(func.count()).select_from(DiscoveryObservation)) == 1
