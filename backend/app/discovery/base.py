import ipaddress
import re
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime

from app.db.types import utcnow
from app.integrations.adguard import AdGuardConfig
from app.schemas.settings import ScannerSettings
from app.services.netinfo import DetectedNetwork

_MAC_RE = re.compile(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$", re.IGNORECASE)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class ProviderError(Exception):
    """A provider could not run; the message is shown in the UI, so keep it short and secret-free."""


def normalize_mac(raw: str | None) -> str | None:
    """Lower-case colon form; None for malformed, all-zero and broadcast addresses."""
    if not raw or not _MAC_RE.match(raw.strip()):
        return None
    mac = raw.strip().lower().replace("-", ":")
    return None if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") else mac


def clean_text(raw: str | None, max_len: int = 255) -> str | None:
    if raw is None:
        return None
    return _CONTROL.sub("", raw).strip()[:max_len] or None


@dataclass(frozen=True)
class DeviceObservation:
    """One provider's sighting of one device during one scan."""

    source: str
    mac: str | None = None
    ip: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    model: str | None = None  # hardware model from the device itself (mDNS/SSDP); never an identity
    seen_at: datetime = field(default_factory=utcnow)
    metadata: dict = field(default_factory=dict)
    # False for identity-only evidence (a DHCP lease says who holds an address, not that the
    # device is online). Such observations enrich or create records but never prove presence.
    presence: bool = True


@dataclass
class ProviderResult:
    observations: list[DeviceObservation] = field(default_factory=list)
    error: str | None = None


@dataclass(frozen=True)
class ScanTarget:
    network: ipaddress.IPv4Network
    interface: str | None


@dataclass(frozen=True)
class ScanContext:
    scanner: ScannerSettings
    detected: list[DetectedNetwork]
    adguard: AdGuardConfig | None = None
    adguard_problem: str | None = None  # why adguard is None despite being enabled (e.g. undecryptable password)


def resolve_targets(ctx: ScanContext) -> list[ScanTarget]:
    """Decide what to scan. Ambiguity is an error: the user must choose explicitly."""
    s = ctx.scanner
    if s.networks:
        targets = []
        for cidr in s.networks:
            net = ipaddress.ip_network(cidr)
            iface = next(
                (
                    d.interface
                    for d in ctx.detected
                    if ipaddress.ip_network(d.cidr).overlaps(net) and (not s.interfaces or d.interface in s.interfaces)
                ),
                None,
            )
            if iface is None and len(s.interfaces) == 1:
                iface = s.interfaces[0]
            targets.append(ScanTarget(net, iface))
        return targets
    if s.interfaces:
        targets = [ScanTarget(ipaddress.ip_network(d.cidr), d.interface) for d in ctx.detected if d.interface in s.interfaces]
        if targets:
            return targets
        raise ProviderError("Configured interfaces have no detected IPv4 network; set CIDR networks in Settings")
    if len(ctx.detected) == 1:
        d = ctx.detected[0]
        return [ScanTarget(ipaddress.ip_network(d.cidr), d.interface)]
    if not ctx.detected:
        raise ProviderError("No IPv4 network detected; set CIDR networks in Settings")
    raise ProviderError(f"{len(ctx.detected)} networks detected; choose which to scan in Settings")


def run_command(argv: list[str], timeout: int) -> str:
    """Fixed argv, no shell. Failures become ProviderError with a short message."""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603  (argv list, validated inputs, no shell)
    except FileNotFoundError as e:
        raise ProviderError(f"{argv[0]} is not installed") from e
    except subprocess.TimeoutExpired as e:
        raise ProviderError(f"{argv[0]} timed out after {timeout}s") from e
    except OSError as e:
        raise ProviderError(f"{argv[0]} could not run: {e.strerror}") from e
    if proc.returncode != 0:
        detail = (proc.stderr.strip().splitlines() or [f"exit code {proc.returncode}"])[0][:200]
        raise ProviderError(f"{argv[0]} failed: {detail}")
    return proc.stdout


class DiscoveryProvider(ABC):
    """Providers only observe; they never touch the database."""

    name: str
    # False for providers that only describe devices: their success must not count as proof that
    # absence means "gone" (see Scanner.run_once).
    gives_evidence: bool = True

    @abstractmethod
    def enabled(self, scanner: ScannerSettings) -> bool: ...

    @abstractmethod
    def scan(self, ctx: ScanContext) -> ProviderResult:
        """Must not raise for expected failures: return ProviderResult(error=...)."""
