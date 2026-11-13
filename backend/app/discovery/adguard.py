"""AdGuard Home discovery. Three documented endpoints, three kinds of evidence:

DHCP leases  (mac+ip+hostname)  identity only: who holds an address; a lease outlives the device
clients      (mac|ip -> name)   identity only: names; configured clients and runtime auto-clients
query log    (client ip, name)  presence: the device made a DNS query during the last scan window
IP-only records (auto-clients, query log) can only enrich/confirm a device the inventory already
knows at that IP; the engine never creates a device from them.
"""

import ipaddress
import logging
import re
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from app.db.types import utcnow
from app.discovery.base import (
    DeviceObservation,
    DiscoveryProvider,
    ProviderError,
    ProviderResult,
    ScanContext,
    clean_text,
    normalize_mac,
    resolve_targets,
)
from app.integrations.adguard import AdGuardClient, AdGuardConfig, AdGuardError
from app.schemas.settings import ScannerSettings

log = logging.getLogger("lanwarden.adguard")
QUERYLOG_LIMIT = 500
_FRACTION = re.compile(r"(\.\d{6})\d+")


def parse_time(raw: str | None) -> datetime | None:
    """AdGuard timestamps are RFC 3339, sometimes with nanosecond fractions."""
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(_FRACTION.sub(r"\1", raw.strip()).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _ipv4(raw: object) -> str | None:
    try:
        ip = ipaddress.IPv4Address(str(raw))
    except ValueError:
        return None
    return None if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast else str(ip)


def _name(raw: object, ip: str | None = None) -> str | None:
    name = clean_text(raw if isinstance(raw, str) else None)
    return None if name is None or name == ip else name


def dhcp_observations(status: dict, now: datetime) -> list[DeviceObservation]:
    out = []
    for lease in [*(status.get("leases") or []), *(status.get("static_leases") or [])]:
        mac, ip = normalize_mac(lease.get("mac")), _ipv4(lease.get("ip"))
        expires = parse_time(lease.get("expires"))  # static leases have none
        if not mac or not ip or (expires and expires < now):
            continue
        out.append(DeviceObservation(source="adguard_dhcp", mac=mac, ip=ip, hostname=_name(lease.get("hostname"), ip),
                                     presence=False, metadata={"expires": lease.get("expires")}))
    return out


def client_observations(data: dict) -> list[DeviceObservation]:
    out = []
    for c in data.get("clients") or []:  # persistent clients: ids may mix MACs and IPs
        ids = c.get("ids") or []
        macs = [m for m in map(normalize_mac, ids) if m]
        ips = [i for i in map(_ipv4, ids) if i]
        name = _name(c.get("name"))
        if not name:
            continue
        for mac in macs:
            out.append(DeviceObservation(source="adguard_clients", mac=mac, ip=ips[0] if ips else None,
                                         hostname=name, presence=False))
        if not macs:
            out += [DeviceObservation(source="adguard_clients", ip=ip, hostname=name, presence=False) for ip in ips]
    for c in data.get("auto_clients") or []:  # runtime clients (rDNS, hosts file, ...)
        ip = _ipv4(c.get("ip"))
        if ip:
            out.append(DeviceObservation(source="adguard_clients", ip=ip, hostname=_name(c.get("name"), ip), presence=False))
    return out


def querylog_observations(log_doc: dict, since: datetime, allowed: Callable[[str], bool]) -> list[DeviceObservation]:
    """One presence observation per client that queried DNS since `since`."""
    seen: dict[str, DeviceObservation] = {}
    for item in log_doc.get("data") or []:
        t = parse_time(item.get("time"))
        ip = _ipv4(item.get("client"))
        if not ip or not t or t < since or ip in seen or not allowed(ip):
            continue
        name = _name((item.get("client_info") or {}).get("name"), ip)
        seen[ip] = DeviceObservation(source="adguard_querylog", ip=ip, hostname=name, seen_at=t)
    return list(seen.values())


class AdGuardProvider(DiscoveryProvider):
    name = "adguard"

    def __init__(self, client_factory: Callable[[AdGuardConfig], AdGuardClient]):
        self._factory = client_factory

    def enabled(self, scanner: ScannerSettings) -> bool:
        return scanner.adguard_discovery_enabled

    def scan(self, ctx: ScanContext) -> ProviderResult:
        if ctx.adguard is None:
            return ProviderResult(error=ctx.adguard_problem or "AdGuard Home is not configured")
        now = utcnow()
        window = timedelta(seconds=ctx.scanner.scan_interval_seconds + 60)
        try:
            targets = [t.network for t in resolve_targets(ctx)]
        except ProviderError:
            targets = []  # ambiguous network: still useful, just not filtered to one subnet
        allowed = (lambda ip: any(ipaddress.IPv4Address(ip) in n for n in targets)) if targets else (lambda ip: True)
        try:
            with self._factory(ctx.adguard) as client:
                client.status()  # connectivity + credentials; failure here fails the whole provider
                steps = (
                    ("dhcp", lambda: dhcp_observations(client.dhcp_status(), now)),
                    ("clients", lambda: client_observations(client.clients())),
                    ("querylog", lambda: querylog_observations(client.querylog(limit=QUERYLOG_LIMIT), now - window, allowed)),
                )
                observations, failed = [], []
                for label, step in steps:
                    try:
                        observations += step()
                    except AdGuardError as e:  # e.g. DHCP server not available on this platform
                        failed.append(label)
                        log.warning("AdGuard %s unavailable: %s", label, e.message)
        except AdGuardError as e:
            return ProviderResult(error=f"AdGuard Home: {e.message}")
        if len(failed) == len(steps):
            return ProviderResult(error="AdGuard Home is reachable but DHCP, clients and query log could not be read")
        return ProviderResult(observations)
