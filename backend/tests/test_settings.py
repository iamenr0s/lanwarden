import json

import pytest
from pydantic import ValidationError

from app.schemas.settings import ScannerSettings
from app.services.netinfo import parse_ip_addr_json


def test_settings_roundtrip(authed):
    r = authed.get("/api/settings").json()
    assert r["settings"]["scanner"]["scan_interval_seconds"] == 300
    new = r["settings"]
    new["scanner"].update(networks=["192.168.1.17/24"], interfaces=["eth0"], offline_threshold_seconds=600)
    out = authed.put("/api/settings", json=new).json()
    assert out["settings"]["scanner"]["networks"] == ["192.168.1.0/24"]  # normalised
    assert authed.get("/api/settings").json()["settings"]["scanner"]["interfaces"] == ["eth0"]


@pytest.mark.parametrize(
    "patch",
    [
        {"interfaces": ["eth0; rm -rf /"]},
        {"interfaces": ["--help"]},
        {"networks": ["not-a-cidr"]},
        {"networks": ["10.0.0.0/8"]},
        {"networks": ["fe80::/64"]},
        {"scan_interval_seconds": 5},
        {"scan_interval_seconds": 600, "offline_threshold_seconds": 300},
        {"unexpected": 1},
    ],
)
def test_invalid_scanner_settings_rejected(patch):
    with pytest.raises(ValidationError):
        ScannerSettings(**patch)


def test_put_invalid_settings_is_422(authed):
    assert authed.put("/api/settings", json={"scanner": {"networks": ["10.0.0.0/8"]}}).status_code == 422


def test_parse_ip_addr_json():
    raw = json.dumps([
        {"ifname": "lo", "flags": ["LOOPBACK", "UP"], "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
        {"ifname": "eth0", "flags": ["UP"], "addr_info": [{"family": "inet", "local": "192.168.1.5", "prefixlen": 24}]},
        {"ifname": "wlan0", "flags": ["BROADCAST"], "addr_info": [{"family": "inet", "local": "10.0.0.2", "prefixlen": 24}]},
    ])
    assert [(n.interface, n.cidr) for n in parse_ip_addr_json(raw)] == [("eth0", "192.168.1.0/24")]
