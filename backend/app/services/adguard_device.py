from collections import Counter

from app.discovery.adguard import parse_time
from app.integrations.adguard import AdGuardClient, AdGuardError
from app.models.device import Device
from app.schemas.adguard import AdGuardDomainCount, AdGuardQuery, DeviceAdGuard

SAMPLE = 200
RECENT = 25


def device_intel(client: AdGuardClient, device: Device) -> DeviceAdGuard:
    """DNS-side view of one device. Raises AdGuardError if AdGuard cannot be queried."""
    out = DeviceAdGuard(configured=True, available=True)

    ids = [i for i in (device.current_ip, device.mac_address) if i]
    if ids:
        for entry in client.clients_search(ids) or []:
            for info in (entry or {}).values():
                if isinstance(info, dict) and info.get("name"):
                    out.recognized, out.client_name, out.client_ids = True, info["name"], list(info.get("ids") or [])

    ip = device.current_ip
    if not ip:
        return out
    # `search` also matches domain names, so keep only entries whose client really is this IP
    items = [i for i in (client.querylog(limit=SAMPLE, search=ip).get("data") or []) if i.get("client") == ip]
    out.sample_size = len(items)
    blocked = lambda i: str(i.get("reason", "")).startswith("Filtered")  # noqa: E731  (FilteringReason enum)
    out.sample_blocked = sum(1 for i in items if blocked(i))
    out.last_query = parse_time(items[0].get("time")) if items else None
    out.top_domains = [
        AdGuardDomainCount(domain=d, count=n)
        for d, n in Counter((i.get("question") or {}).get("name") for i in items if (i.get("question") or {}).get("name")).most_common(10)
    ]
    out.recent = [
        AdGuardQuery(time=parse_time(i.get("time")), domain=(i.get("question") or {}).get("name") or "?",
                     type=(i.get("question") or {}).get("type"), blocked=blocked(i), reason=i.get("reason") or None)
        for i in items[:RECENT]
    ]
    try:  # per-client totals over AdGuard's statistics window, when it reports them
        for entry in client.stats().get("top_clients") or []:
            if ip in entry:
                out.stats_queries = int(entry[ip])
    except (AdGuardError, ValueError, TypeError):
        pass
    return out
