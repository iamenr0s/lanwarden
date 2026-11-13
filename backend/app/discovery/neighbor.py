import ipaddress
import json

from app.db.types import utcnow
from app.discovery.base import (
    DeviceObservation,
    DiscoveryProvider,
    ProviderError,
    ProviderResult,
    ScanContext,
    ScanTarget,
    normalize_mac,
    resolve_targets,
    run_command,
)
from app.schemas.settings import ScannerSettings

SOURCE = "neighbor"
# STALE is deliberately excluded: it lingers after a device leaves, so it is not evidence of presence.
LIVE_STATES = {"REACHABLE", "DELAY", "PROBE"}


def parse_output(raw: str, targets: list[ScanTarget]) -> list[DeviceObservation]:
    """Parse `ip -j -4 neigh show`, keeping live entries that fall inside a scanned network."""
    try:
        entries = json.loads(raw or "[]")
    except json.JSONDecodeError as e:
        raise ProviderError("ip neigh returned invalid JSON") from e
    nets = [t.network for t in targets]
    found: dict[str, DeviceObservation] = {}
    now = utcnow()
    for e in entries:
        if not LIVE_STATES.intersection(e.get("state", [])):
            continue
        mac = normalize_mac(e.get("lladdr"))
        try:
            ip = ipaddress.IPv4Address(e.get("dst", ""))
        except ValueError:
            continue
        if mac is None or not any(ip in n for n in nets):
            continue
        found.setdefault(
            mac, DeviceObservation(source=SOURCE, mac=mac, ip=str(ip), seen_at=now, metadata={"state": e["state"]})
        )
    return list(found.values())


class NeighborProvider(DiscoveryProvider):
    name = SOURCE

    def enabled(self, scanner: ScannerSettings) -> bool:
        return scanner.neighbor_discovery_enabled

    def scan(self, ctx: ScanContext) -> ProviderResult:
        try:
            targets = resolve_targets(ctx)
            return ProviderResult(parse_output(run_command(["ip", "-j", "-4", "neigh", "show"], 10), targets))
        except ProviderError as e:
            return ProviderResult(error=str(e))
