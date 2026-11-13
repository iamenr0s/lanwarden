import json
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select

from app.db.types import utcnow
from app.discovery import arp_scan
from app.discovery.base import DeviceObservation
from app.models import Device, Event
from app.schemas.settings import ScannerSettings
from app.services.inventory import ANOMALY_REPEAT_AFTER, process_scan

SETTINGS = ScannerSettings()
T0 = utcnow()
A, B = "aa:bb:cc:00:00:0a", "aa:bb:cc:00:00:0b"


@pytest.fixture()
def db(app, client):
    with app.state.session_factory() as session:
        yield session


def seen(mac, ip, source="arp_scan", **kw):
    return DeviceObservation(source=source, mac=mac, ip=ip, **kw)


def scan(db, observations, at=0):
    s = process_scan(db, observations, True, SETTINGS, T0 + timedelta(seconds=at))
    db.commit()
    return s


def anomalies(db, mac=None):
    q = select(Event).where(Event.event_type == "DEVICE_ANOMALY").order_by(Event.id)
    rows = list(db.scalars(q).unique())
    return [e for e in rows if mac is None or e.device.mac_address == mac]


def trust(db, mac):
    db.scalar(select(Device).where(Device.mac_address == mac)).is_trusted = True
    db.commit()


# ---- parser: pairs, not just MACs -------------------------------------------------------------
def test_arp_scan_parse_keeps_every_address_a_mac_answers_from():
    out = "192.168.1.5\taa:bb:cc:00:00:0a\tV\n192.168.1.6\taa:bb:cc:00:00:0a\tV\n192.168.1.5\taa:bb:cc:00:00:0a\tV (DUP: 2)\n"
    assert [(o.mac, o.ip) for o in arp_scan.parse_output(out)] == [(A, "192.168.1.5"), (A, "192.168.1.6")]


# ---- ip_conflict ------------------------------------------------------------------------------
def test_two_macs_claiming_one_ip_raise_an_anomaly_on_both_devices(db):
    s = scan(db, [seen(A, "192.168.1.5"), seen(B, "192.168.1.5")])
    assert s.anomalies == 2 and s.discovered == 2  # brand-new devices are covered too
    for mac, other in ((A, B), (B, A)):
        (e,) = anomalies(db, mac)
        assert e.meta == {"kind": "ip_conflict", "key": "192.168.1.5"} and other in e.new_value and "192.168.1.5" in e.new_value


def test_cross_provider_disagreement_is_a_conflict(db):
    scan(db, [seen(A, "192.168.1.5", "arp_scan"), seen(B, "192.168.1.5", "neighbor")])
    assert len(anomalies(db)) == 2


def test_one_device_reported_by_both_providers_is_not_a_conflict(db):
    s = scan(db, [seen(A, "192.168.1.5", "arp_scan"), seen(A, "192.168.1.5", "neighbor")])
    assert s.anomalies == 0 and anomalies(db) == []


def test_the_same_finding_is_reported_once_per_window_then_again(db):
    obs = [seen(A, "192.168.1.5"), seen(B, "192.168.1.5")]
    scan(db, obs, 0)
    scan(db, obs, 300)
    scan(db, obs, 600)
    assert len(anomalies(db, A)) == 1  # not once per scan
    later = int(ANOMALY_REPEAT_AFTER.total_seconds()) + 700
    scan(db, obs, later)
    assert len(anomalies(db, A)) == 2  # still happening hours later: say so again


def test_dns_only_sightings_never_create_conflicts(db):
    s = scan(db, [seen(A, "192.168.1.5"), DeviceObservation(source="adguard_querylog", ip="192.168.1.5")])
    assert s.anomalies == 0


# ---- mac_multi_ip (trusted devices only) --------------------------------------------------------
def test_trusted_device_answering_at_two_addresses_is_flagged_but_others_are_not(db):
    scan(db, [seen(A, "192.168.1.5"), seen(B, "192.168.1.9")])
    trust(db, A)
    two_ips = [seen(A, "192.168.1.5"), seen(A, "192.168.1.6"), seen(B, "192.168.1.9"), seen(B, "192.168.1.10")]
    s = scan(db, two_ips, 60)
    assert s.anomalies == 1
    (e,) = anomalies(db)
    assert e.device.mac_address == A and e.meta["kind"] == "mac_multi_ip" and "192.168.1.6" in e.new_value  # untrusted B: silent


# ---- identity drift (trusted devices only) -------------------------------------------------------
def lease(mac, ip, hostname="nas"):
    return DeviceObservation(source="adguard_dhcp", mac=mac, ip=ip, hostname=hostname, presence=False)


def test_trusted_device_seen_away_from_its_dhcp_lease_is_flagged(db):
    scan(db, [seen(A, "192.168.1.5"), lease(A, "192.168.1.5")])
    trust(db, A)
    assert scan(db, [seen(A, "192.168.1.5"), lease(A, "192.168.1.5")], 60).anomalies == 0  # lease agrees: fine
    s = scan(db, [seen(A, "192.168.1.77"), lease(A, "192.168.1.5")], 120)
    assert s.anomalies == 1
    (e,) = anomalies(db)
    assert e.meta["kind"] == "identity_drift" and "192.168.1.5" in e.new_value and "192.168.1.77" in e.new_value


def test_untrusted_device_away_from_its_lease_is_not_flagged(db):
    scan(db, [seen(A, "192.168.1.5"), lease(A, "192.168.1.5")])
    assert scan(db, [seen(A, "192.168.1.77"), lease(A, "192.168.1.5")], 60).anomalies == 0


def test_hostname_change_is_an_anomaly_only_for_trusted_devices(db):
    scan(db, [seen(A, "192.168.1.5", hostname="printer"), seen(B, "192.168.1.9", hostname="tv")])
    trust(db, A)
    s = scan(db, [seen(A, "192.168.1.5", hostname="definitely-not-a-printer"), seen(B, "192.168.1.9", hostname="other-tv")], 60)
    assert s.name_changed == 2 and s.anomalies == 1  # both renamed; only the trusted one is suspicious
    (e,) = anomalies(db)
    assert e.device.mac_address == A and e.meta["kind"] == "hostname_changed" and "definitely-not-a-printer" in e.new_value


# ---- API surface ----------------------------------------------------------------------------
def test_status_counts_recent_anomalies_and_devices_flag_randomised_macs(authed, app):
    with app.state.session_factory() as db:
        scan(db, [seen("02:00:00:00:00:01", "192.168.1.5"), seen("00:11:22:33:44:55", "192.168.1.5")])
        db.add(Event(device_id=None, event_type="DEVICE_ANOMALY", new_value="old", timestamp=utcnow() - timedelta(days=9)))
        db.commit()
    assert authed.get("/api/status").json()["anomalies_7d"] == 2  # the 9-day-old one is outside the window
    flags = {d["mac_address"]: d["is_randomized_mac"] for d in authed.get("/api/devices").json()["items"]}
    assert flags == {"02:00:00:00:00:01": True, "00:11:22:33:44:55": False}  # locally-administered bit is 0x02
    assert authed.get("/api/events", params={"event_type": "DEVICE_ANOMALY"}).json()["total"] == 3


def test_anomaly_notifications_use_clear_wording_and_respect_the_device_alert_switch(authed, app):
    delivered = []

    def handler(request):
        delivered.append(json.loads(request.content))
        return httpx.Response(200)

    app.state.notifier.providers["webhook"].transport = httpx.MockTransport(handler)
    rule = {"name": "r", "provider": "webhook", "event_types": ["DEVICE_ANOMALY"], "config": {"url": "https://hooks.example.com/x"}}
    assert authed.post("/api/notifications/rules", json=rule).status_code == 201

    with app.state.session_factory() as db:
        scan(db, [seen(A, "192.168.1.5"), seen(B, "192.168.1.5")])
    app.state.notifier.dispatch(0)
    assert len(delivered) == 1 and delivered[0]["title"] == "LanWarden: 2 network events"
    assert "possible spoofing or IP conflict" in delivered[0]["events"][0]["label"]
    assert "also claimed by" in delivered[0]["text"]

    delivered.clear()
    with app.state.session_factory() as db:
        for d in db.scalars(select(Device)):
            d.alert_enabled = False
        db.commit()
    app.state.notifier.dispatch(0)
    assert delivered == []  # anomalies are still recorded, but a device with alerts off stays quiet
