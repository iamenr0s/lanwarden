import ipaddress

from app.db.types import utcnow
from app.discovery.base import (
    DeviceObservation,
    DiscoveryProvider,
    ProviderError,
    ProviderResult,
    ScanContext,
    ScanTarget,
    clean_text,
    normalize_mac,
    resolve_targets,
    run_command,
)
from app.schemas.settings import ScannerSettings

SOURCE = "arp_scan"
TIMEOUT_S = 600  # a /16 at arp-scan's default bandwidth takes minutes


def build_command(target: ScanTarget) -> list[str]:
    """Values were validated by ScannerSettings (alphanumeric-first interface, IPv4 CIDR)."""
    argv = ["arp-scan", "--plain", "--retry=2"]
    if target.interface:
        argv += ["--interface", target.interface]
    return argv + [str(target.network)]


def parse_output(text: str) -> list[DeviceObservation]:
    """--plain lines are `ip<TAB>mac<TAB>vendor`; anything else (DUP notes etc.) is skipped."""
    # one observation per (mac, ip) pair: a MAC answering for several addresses, or several MACs answering
    # for one address, is exactly what the engine's anomaly detection needs to see
    found: dict[tuple[str, str], DeviceObservation] = {}
    now = utcnow()
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        try:
            ip = str(ipaddress.IPv4Address(parts[0].strip()))
        except ValueError:
            continue
        mac = normalize_mac(parts[1])
        if mac is None:
            continue
        vendor = clean_text(parts[2]) if len(parts) > 2 else None
        if vendor and vendor.startswith("(Unknown"):
            vendor = None
        found.setdefault((mac, ip), DeviceObservation(source=SOURCE, mac=mac, ip=ip, vendor=vendor, seen_at=now))
    return list(found.values())


class ArpScanProvider(DiscoveryProvider):
    name = SOURCE

    def enabled(self, scanner: ScannerSettings) -> bool:
        return scanner.arp_scan_enabled

    def scan(self, ctx: ScanContext) -> ProviderResult:
        try:
            observations: list[DeviceObservation] = []
            for target in resolve_targets(ctx):
                observations += parse_output(run_command(build_command(target), TIMEOUT_S))
            return ProviderResult(observations)
        except ProviderError as e:
            return ProviderResult(error=str(e))
