"""Model names from mDNS (DNS-SD TXT records) and SSDP/UPnP device descriptions.

Both are LAN multicast protocols answered by the devices themselves, so everything here is hostile
input: the identity of a reply is its UDP source address (never an address named inside it), packets are
parsed defensively, and the only HTTP fetch (the UPnP description) is limited to the address that
answered. The result is identity-only (`presence=False`, no hostname, no vendor): it can enrich a device
the engine already knows at that IP and never creates one or proves presence.
"""

import ipaddress
import re
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

import httpx

from app.db.types import utcnow
from app.discovery.base import (
    DeviceObservation,
    DiscoveryProvider,
    ProviderError,
    ProviderResult,
    ScanContext,
    clean_text,
    resolve_targets,
)
from app.schemas.settings import ScannerSettings
from app.services.netinfo import detect_local_ips

LISTEN_SECONDS = 3.0
MAX_DEVICES = 64
MAX_DESCRIPTION_BYTES = 64 * 1024
MDNS_GROUP, MDNS_PORT = "224.0.0.251", 5353
SSDP_GROUP, SSDP_PORT = "239.255.255.250", 1900

# Common DNS-SD services whose TXT records carry a model. Asked directly: one packet, no browse round-trip.
MDNS_SERVICES = ["_googlecast._tcp", "_airplay._tcp", "_raop._tcp", "_companion-link._tcp", "_device-info._tcp",
                 "_ipp._tcp", "_printer._tcp", "_hap._tcp", "_spotify-connect._tcp", "_smb._tcp", "_http._tcp"]
# TXT keys holding a model, best first (googlecast md, airplay model/am, companion-link rpMd, IPP ty/product).
MODEL_KEYS = ("md", "model", "am", "rpmd", "ty", "usb_mdl", "product")


# ---- mDNS ---------------------------------------------------------------------------------
def build_mdns_query(services: list[str] = MDNS_SERVICES) -> bytes:
    """One packet of PTR questions (ordinary multicast questions: replies are multicast, which hosts accept)."""
    out = struct.pack("!6H", 0, 0, len(services), 0, 0, 0)
    for svc in services:
        for label in (*svc.split("."), "local"):
            out += bytes([len(label)]) + label.encode()
        out += b"\x00" + struct.pack("!HH", 12, 1)
    return out


def _skip_name(data: bytes, off: int) -> int:
    """Offset just past a (possibly compressed) name; names are never needed, only skipped."""
    while True:
        if off >= len(data):
            raise ValueError("truncated name")
        n = data[off]
        if n == 0:
            return off + 1
        if n & 0xC0 == 0xC0:
            return off + 2
        if n & 0xC0:
            raise ValueError("bad label")
        off += 1 + n


def _txt_pairs(rdata: bytes) -> dict[str, str]:
    pairs, i = {}, 0
    while i < len(rdata):
        n = rdata[i]
        item = rdata[i + 1:i + 1 + n].decode("utf-8", "replace")
        i += 1 + n
        key, sep, value = item.partition("=")
        if sep:
            pairs.setdefault(key.lower(), value)
    return pairs


def parse_mdns_model(packet: bytes) -> str | None:
    """Model from the TXT records of one mDNS response; None for anything else or anything malformed."""
    try:
        _id, flags, qd, an, ns, ar = struct.unpack("!6H", packet[:12])
        if not flags & 0x8000:  # a query, not a response
            return None
        off = 12
        for _ in range(qd):
            off = _skip_name(packet, off) + 4
        for _ in range(min(an + ns + ar, 200)):
            off = _skip_name(packet, off)
            rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", packet[off:off + 10])
            off += 10
            rdata = packet[off:off + rdlen]
            if len(rdata) != rdlen:
                return None
            off += rdlen
            if rtype == 16:
                pairs = _txt_pairs(rdata)
                for key in MODEL_KEYS:
                    value = clean_text(pairs.get(key, "").strip("() "), 120)
                    if value:
                        return value
    except (struct.error, ValueError, IndexError):
        return None
    return None


# ---- SSDP / UPnP --------------------------------------------------------------------------
SSDP_SEARCH = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
_LOCATION = re.compile(rb"^location:\s*(\S+)\s*$", re.I | re.M)
_MODEL_TAGS = (re.compile(r"<modelName>([^<]{1,120})</modelName>", re.I), re.compile(r"<modelNumber>([^<]{1,120})</modelNumber>", re.I))


def parse_ssdp_location(packet: bytes, source_ip: str) -> str | None:
    """The description URL, only if it is plain http and names the very host that sent the reply
    (a device may not point us at a third party)."""
    m = _LOCATION.search(packet[:2048])
    if not m:
        return None
    try:
        url = m.group(1).decode("ascii")
        parts = urlsplit(url)
        if parts.scheme != "http" or parts.hostname != source_ip or parts.port == 0:
            return None
    except (UnicodeDecodeError, ValueError):
        return None
    return url


def parse_upnp_model(xml: str) -> str | None:
    """modelName, else modelNumber. Plain regex rather than an XML parser: no entity expansion to worry about."""
    for rx in _MODEL_TAGS:
        m = rx.search(xml)
        if m and (value := clean_text(m.group(1), 120)):
            return value
    return None


def fetch_description(url: str) -> str | None:
    """GET with a short timeout, no redirects and a hard size cap. Any failure is just 'no model'."""
    try:
        with httpx.Client(timeout=2.0, follow_redirects=False) as client, client.stream("GET", url) as r:
            if r.status_code != 200:
                return None
            body = b""
            for chunk in r.iter_bytes():
                body += chunk
                if len(body) > MAX_DESCRIPTION_BYTES:
                    return None
            return body.decode("utf-8", "replace")
    except (httpx.HTTPError, ValueError):
        return None


# ---- sockets ------------------------------------------------------------------------------
def _collect(payload: bytes, group: str, port: int, local_ips: list[str]) -> list[tuple[bytes, str]]:
    """Send `payload` to the multicast group out of each local address, return (packet, source ip) replies."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # nosemgrep: python.lang.security.audit.network.bind.avoid-bind-to-all-interfaces  (wildcard needed to receive multicast groups; senders are filtered to the scanned networks)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255 if port == MDNS_PORT else 2)
        # Ask from the protocol's own port, sharing it with any local mDNS/SSDP daemon: host firewalls
        # commonly drop unicast replies to a random port but accept the well-known one. An ephemeral port
        # (if the shared bind fails) still works on hosts without such a firewall.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            sock.bind(("", port))
        except OSError:
            sock.bind(("", 0))
        sent = False
        for local in local_ips:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(group) + socket.inet_aton(local))
            except OSError:
                pass  # already a member, or no multicast on this interface: sending below decides
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local))
                sock.sendto(payload, (group, port))
                sent = True
            except OSError:
                continue
        if not sent:
            raise ProviderError("could not send multicast on any scanned interface")
        replies, end = [], time.monotonic() + LISTEN_SECONDS
        while (left := end - time.monotonic()) > 0 and len(replies) < 512:
            sock.settimeout(left)
            try:
                data, (src, _p) = sock.recvfrom(9000)
            except (TimeoutError, OSError):
                break
            replies.append((data, src))
        return replies
    finally:
        sock.close()


def _locals_for(ctx: ScanContext) -> tuple[list[ipaddress.IPv4Network], list[str]]:
    nets = [t.network for t in resolve_targets(ctx)]
    ips = [ip for ip in detect_local_ips() if any(ipaddress.ip_address(ip) in n for n in nets)]
    if not ips:
        raise ProviderError("no local address on the scanned networks")
    return nets, ips


def _inside(ip: str, nets: list[ipaddress.IPv4Network]) -> bool:
    try:
        return any(ipaddress.ip_address(ip) in n for n in nets)
    except ValueError:
        return False


def _observation(source: str, ip: str, model: str) -> DeviceObservation:
    return DeviceObservation(source=source, ip=ip, model=model, seen_at=utcnow(), presence=False)


class MdnsProvider(DiscoveryProvider):
    name = "mdns"
    gives_evidence = False

    def enabled(self, scanner: ScannerSettings) -> bool:
        return scanner.service_discovery_enabled

    def scan(self, ctx: ScanContext) -> ProviderResult:
        try:
            nets, local_ips = _locals_for(ctx)
            found: dict[str, str] = {}
            for data, src in _collect(build_mdns_query(), MDNS_GROUP, MDNS_PORT, local_ips):
                if _inside(src, nets) and src not in local_ips and len(found) < MAX_DEVICES:
                    if model := parse_mdns_model(data):
                        found.setdefault(src, model)
            return ProviderResult([_observation(self.name, ip, model) for ip, model in found.items()])
        except ProviderError as e:
            return ProviderResult(error=str(e))


class SsdpProvider(DiscoveryProvider):
    name = "ssdp"
    gives_evidence = False

    def enabled(self, scanner: ScannerSettings) -> bool:
        return scanner.service_discovery_enabled

    def scan(self, ctx: ScanContext) -> ProviderResult:
        try:
            nets, local_ips = _locals_for(ctx)
            urls: dict[str, str] = {}
            for data, src in _collect(SSDP_SEARCH, SSDP_GROUP, SSDP_PORT, local_ips):
                if _inside(src, nets) and src not in local_ips and src not in urls and len(urls) < MAX_DEVICES:
                    if url := parse_ssdp_location(data, src):
                        urls[src] = url
            with ThreadPoolExecutor(max_workers=8) as pool:
                bodies = list(pool.map(fetch_description, urls.values()))
            obs = [_observation(self.name, ip, model) for ip, body in zip(urls, bodies, strict=True)
                   if body and (model := parse_upnp_model(body))]
            return ProviderResult(obs)
        except ProviderError as e:
            return ProviderResult(error=str(e))
