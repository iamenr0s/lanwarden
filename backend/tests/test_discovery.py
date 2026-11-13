import ipaddress
import json

import pytest

from app.discovery import arp_scan, base, neighbor
from app.discovery.base import ProviderError, ScanContext, ScanTarget, normalize_mac, resolve_targets
from app.schemas.settings import ScannerSettings
from app.services.netinfo import DetectedNetwork

ETH = DetectedNetwork("eth0", "192.168.1.0/24")
VIRB = DetectedNetwork("virbr0", "192.168.122.0/24")


def ctx(detected=(ETH,), **settings):
    return ScanContext(ScannerSettings(**settings), list(detected))


def test_normalize_mac():
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    for bad in (None, "", "zz:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff; ls"):
        assert normalize_mac(bad) is None


def test_arp_scan_parse_skips_noise_and_dups():
    out = (
        "192.168.1.1\taa:bb:cc:00:00:01\tTP-Link Technologies\n"
        "192.168.1.9\tAA:BB:CC:00:00:02\t(Unknown: locally administered)\n"
        "192.168.1.1\taa:bb:cc:00:00:01\tTP-Link Technologies (DUP: 2)\n"
        "not an ip\taa:bb:cc:00:00:03\tX\n"
        "192.168.1.5\tbad-mac\tX\n"
        "WARNING: something\n"
    )
    obs = arp_scan.parse_output(out)
    assert [(o.mac, o.ip, o.vendor) for o in obs] == [
        ("aa:bb:cc:00:00:01", "192.168.1.1", "TP-Link Technologies"),
        ("aa:bb:cc:00:00:02", "192.168.1.9", None),
    ]


def test_arp_scan_command_is_a_plain_argv():
    t = ScanTarget(ipaddress.ip_network("192.168.1.0/24"), "eth0")
    assert arp_scan.build_command(t) == ["arp-scan", "--plain", "--retry=2", "--interface", "eth0", "192.168.1.0/24"]
    assert "--interface" not in arp_scan.build_command(ScanTarget(t.network, None))


def test_resolve_targets_rules():
    # single detected network: used automatically
    assert [(str(t.network), t.interface) for t in resolve_targets(ctx())] == [("192.168.1.0/24", "eth0")]
    # ambiguous or nothing detected: explicit configuration required
    with pytest.raises(ProviderError, match="2 networks detected"):
        resolve_targets(ctx(detected=(ETH, VIRB)))
    with pytest.raises(ProviderError, match="No IPv4 network"):
        resolve_targets(ctx(detected=()))
    # configured networks win and pick the matching interface
    t = resolve_targets(ctx(detected=(ETH, VIRB), networks=["192.168.122.0/24"]))
    assert [(str(x.network), x.interface) for x in t] == [("192.168.122.0/24", "virbr0")]
    # interfaces only: their detected networks
    t = resolve_targets(ctx(detected=(ETH, VIRB), interfaces=["eth0"]))
    assert [(str(x.network), x.interface) for x in t] == [("192.168.1.0/24", "eth0")]
    with pytest.raises(ProviderError, match="no detected IPv4 network"):
        resolve_targets(ctx(detected=(ETH,), interfaces=["wlan9"]))


def test_neighbor_parse_filters_state_network_and_mac():
    raw = json.dumps([
        {"dst": "192.168.1.10", "lladdr": "aa:bb:cc:00:00:01", "dev": "eth0", "state": ["REACHABLE"]},
        {"dst": "192.168.1.11", "lladdr": "aa:bb:cc:00:00:02", "dev": "eth0", "state": ["STALE"]},
        {"dst": "192.168.1.12", "dev": "eth0", "state": ["FAILED"]},
        {"dst": "10.9.9.9", "lladdr": "aa:bb:cc:00:00:03", "dev": "eth0", "state": ["REACHABLE"]},
        {"dst": "192.168.1.13", "lladdr": "aa:bb:cc:00:00:04", "dev": "eth0", "state": ["DELAY"]},
    ])
    targets = [ScanTarget(ipaddress.ip_network("192.168.1.0/24"), "eth0")]
    assert [o.ip for o in neighbor.parse_output(raw, targets)] == ["192.168.1.10", "192.168.1.13"]
    with pytest.raises(ProviderError):
        neighbor.parse_output("{not json", targets)


@pytest.mark.parametrize("provider", [arp_scan.ArpScanProvider(), neighbor.NeighborProvider()])
def test_provider_failures_become_errors_not_exceptions(provider, monkeypatch):
    def boom(argv, timeout):
        raise ProviderError(f"{argv[0]} is not installed")

    monkeypatch.setattr(arp_scan, "run_command", boom)
    monkeypatch.setattr(neighbor, "run_command", boom)
    r = provider.scan(ctx())
    assert r.observations == [] and "not installed" in r.error
    # misconfiguration is reported the same way
    assert "networks detected" in provider.scan(ctx(detected=(ETH, VIRB))).error


def test_run_command_maps_failures():
    with pytest.raises(ProviderError, match="is not installed"):
        base.run_command(["definitely-not-a-real-binary-xyz"], 5)
    with pytest.raises(ProviderError, match="failed"):
        base.run_command(["false"], 5)
