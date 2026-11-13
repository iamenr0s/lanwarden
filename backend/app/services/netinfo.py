import ipaddress
import json
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class DetectedNetwork:
    interface: str
    cidr: str


def parse_ip_addr_json(raw: str) -> list[DetectedNetwork]:
    """Parse `ip -j -4 addr show`; skips loopback, down and container-bridge-less interfaces."""
    found: list[DetectedNetwork] = []
    for iface in json.loads(raw):
        name = iface.get("ifname", "")
        if name == "lo" or "UP" not in iface.get("flags", []):
            continue
        for addr in iface.get("addr_info", []):
            if addr.get("family") == "inet" and addr.get("local") and addr.get("prefixlen") is not None:
                # network address, not host address, so the suggestion is a valid scan target
                net = ipaddress.ip_network(f"{addr['local']}/{addr['prefixlen']}", strict=False)
                found.append(DetectedNetwork(name, str(net)))
    return found


def parse_local_ips(raw: str) -> list[str]:
    """Host addresses (not networks) of up, non-loopback interfaces, from `ip -j -4 addr show`."""
    ips = []
    for iface in json.loads(raw):
        if iface.get("ifname") == "lo" or "UP" not in iface.get("flags", []):
            continue
        ips += [a["local"] for a in iface.get("addr_info", []) if a.get("family") == "inet" and a.get("local")]
    return ips


def detect_local_ips() -> list[str]:
    """Best effort, like detect_networks(): [] if iproute2 is missing or fails."""
    try:
        out = subprocess.run(
            ["ip", "-j", "-4", "addr", "show"], capture_output=True, text=True, timeout=5, check=True  # noqa: S603, S607  (fixed argv)
        ).stdout
        return parse_local_ips(out)
    except (OSError, subprocess.SubprocessError, ValueError):
        return []


def detect_networks() -> list[DetectedNetwork]:
    """Best effort; returns [] if iproute2 is missing or fails. No shell, fixed argv."""
    try:
        out = subprocess.run(
            ["ip", "-j", "-4", "addr", "show"], capture_output=True, text=True, timeout=5, check=True  # noqa: S603, S607  (fixed argv)
        ).stdout
        return parse_ip_addr_json(out)
    except (OSError, subprocess.SubprocessError, ValueError):
        return []
