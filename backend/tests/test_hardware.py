from datetime import timedelta

import pytest
from sqlalchemy import select

from app.db.types import utcnow
from app.discovery.base import DeviceObservation
from app.models import Device
from app.schemas.settings import ScannerSettings
from app.services import oui
from app.services.devicetype import guess
from app.services.inventory import process_scan

T0 = utcnow()
PI = "b8:27:eb:00:00:01"  # Raspberry Pi Foundation OUI
PRIVATE = "aa:bb:cc:00:00:09"  # locally-administered bit set


@pytest.fixture()
def db(app, client):
    with app.state.session_factory() as session:
        yield session


def scan(db, obs, at=0):
    process_scan(db, obs, True, ScannerSettings(), T0 + timedelta(seconds=at))
    db.commit()


def test_oui_known_private_and_missing(monkeypatch, tmp_path):
    assert "Raspberry" in oui.lookup(PI)
    assert oui.lookup(PI.upper().replace(":", "-")) == oui.lookup(PI)
    assert oui.lookup(PRIVATE) == "Private MAC"
    assert oui.lookup(None) is None and oui.lookup("not-a-mac") is None
    oui._table.cache_clear()
    monkeypatch.setenv("LANWARDEN_OUI_DIR", str(tmp_path))  # no csv there ...
    monkeypatch.setattr(oui, "_DIRS", ())
    monkeypatch.setattr(oui, "_TXT", str(tmp_path / "none.txt"))  # ... and no fallback file
    assert oui.lookup("00:11:22:33:44:55") is None  # no data: no vendor, no error
    oui._table.cache_clear()


def test_oui_longest_prefix_and_private_entries(tmp_path, monkeypatch):
    hdr = "Registry,Assignment,Organization Name,Organization Address\n"
    (tmp_path / "oui.csv").write_text(hdr + 'MA-L,001122,Acme Corp,"1 Road, Town"\nMA-L,AABB00,Private,\n')
    (tmp_path / "mam.csv").write_text(hdr + "MA-M,0011223,Acme Widgets,\n")
    (tmp_path / "oui36.csv").write_text(hdr + "MA-S,001122345,Acme Sensors,\n")
    monkeypatch.setenv("LANWARDEN_OUI_DIR", str(tmp_path))
    oui._table.cache_clear()
    assert oui.lookup("00:11:22:99:00:00") == "Acme Corp"  # 24-bit block
    assert oui.lookup("00:11:22:30:00:00") == "Acme Widgets"  # 28-bit block beats the 24-bit one
    assert oui.lookup("00:11:22:34:50:00") == "Acme Sensors"  # 36-bit block beats both
    assert oui.lookup("00:11:22:34:60:00") == "Acme Widgets"
    assert oui.lookup("a8:bb:00:00:00:01") is None  # "Private" registrations are unknown, not a vendor
    oui._table.cache_clear()


def test_oui_txt_fallback(tmp_path, monkeypatch):
    f = tmp_path / "oui.txt"
    f.write_text("# c\n001122\tAcme Corp\nbad line\n")
    monkeypatch.setenv("LANWARDEN_OUI_DIR", str(tmp_path / "empty"))
    monkeypatch.setattr(oui, "_DIRS", ())
    monkeypatch.setattr(oui, "_TXT", str(f))
    oui._table.cache_clear()
    assert oui.lookup("00:11:22:33:44:55") == "Acme Corp"
    oui._table.cache_clear()


@pytest.mark.parametrize("vendor,host,expected", [
    (None, "Johns-iPhone", "phone"),
    ("Ubiquiti Networks", None, "network"),
    ("Ubiquiti Networks", "living-room-tv", "tv"),  # hostname beats vendor
    ("Espressif Inc.", None, "iot"),
    ("Apple, Inc.", "mystery", None),  # weak evidence: no guess
    (None, None, None),
])
def test_guess(vendor, host, expected):
    assert guess(vendor, host) == expected


def test_neighbour_only_device_gets_vendor_and_type(db):
    scan(db, [DeviceObservation(source="neighbor", mac=PI, ip="192.168.1.5", hostname="pi-hole-box")])
    d = db.scalar(select(Device).where(Device.mac_address == PI))
    assert "Raspberry" in d.vendor and d.type_guess == "computer"  # vendor rule (hostname has no hint)


def test_provider_vendor_wins_and_private_label(db):
    scan(db, [DeviceObservation(source="arp_scan", mac=PI, ip="192.168.1.5", vendor="Custom Vendor"),
              DeviceObservation(source="neighbor", mac=PRIVATE, ip="192.168.1.6", hostname="Pixel-8")])
    assert db.scalar(select(Device.vendor).where(Device.mac_address == PI)) == "Custom Vendor"
    p = db.scalar(select(Device).where(Device.mac_address == PRIVATE))
    assert p.vendor == "Private MAC" and p.type_guess == "phone"


def test_manual_type_is_never_overwritten_and_wins(db, authed):
    scan(db, [DeviceObservation(source="neighbor", mac=PI, ip="192.168.1.5")])
    d = db.scalar(select(Device).where(Device.mac_address == PI))
    d.device_type = "my-server"
    db.commit()
    scan(db, [DeviceObservation(source="neighbor", mac=PI, ip="192.168.1.5")], at=60)
    db.refresh(d)
    assert d.device_type == "my-server" and d.type_guess == "computer"
    item = authed.get(f"/api/devices/{d.id}").json()
    assert item["effective_type"] == "my-server"
    assert authed.get("/api/devices", params={"type": "my-server"}).json()["total"] == 1
    assert authed.get("/api/devices", params={"type": "computer"}).json()["total"] == 0


def test_guessed_type_in_api_filter_and_dashboard(db, authed):
    scan(db, [DeviceObservation(source="neighbor", mac=PI, ip="192.168.1.5")])
    assert authed.get("/api/devices", params={"type": "computer"}).json()["total"] == 1
    assert authed.get("/api/devices", params={"sort": "type"}).status_code == 200
    types = {t["type"]: t["count"] for t in authed.get("/api/dashboard").json()["type_distribution"]}
    assert types.get("computer") == 1


def test_existing_vendorless_device_is_backfilled(db):
    db.add(Device(mac_address=PI, hostname="old", status="OFFLINE"))
    db.commit()
    scan(db, [])  # nothing seen this scan
    d = db.scalar(select(Device).where(Device.mac_address == PI))
    assert "Raspberry" in d.vendor and d.type_guess == "computer"
