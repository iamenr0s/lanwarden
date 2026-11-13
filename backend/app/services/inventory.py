"""Inventory engine: merges provider observations into devices, presence, sessions and events.

Identity rules
* MAC is the durable identity. An observation with a MAC only ever matches that MAC.
* An observation without a MAC never creates a device. It may only match a MAC-less device at
  that IP, or the single online MAC-identified device currently holding that IP.
* A reused IP never merges devices: the new MAC becomes (or stays) its own device.
Presence rules
* Only observations with presence=True (ARP, neighbour table, DNS queries) update last_seen and
  online state. Identity-only observations (DHCP leases, AdGuard client names) enrich a device, or
  create one as UNKNOWN (known to exist, never seen alive).
Ownership: this module writes scanner-owned columns only; friendly_name, vendor_override,
device_type, device_group, flags and notes are never touched.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.discovery.base import DeviceObservation, clean_text
from app.models import Device, EventType
from app.models.device import DeviceAddress, DeviceName, DeviceSession
from app.models.event import DiscoveryObservation, Event
from app.schemas.settings import ScannerSettings
from app.services import oui
from app.services.devicetype import guess as guess_type
from app.services.presence import compute_status, is_online

_ALERT_STATE = (EventType.ALWAYS_CONNECTED_DEVICE_DOWN.value, EventType.ALWAYS_CONNECTED_DEVICE_RECOVERED.value)


@dataclass
class ScanSummary:
    observed: int = 0
    discovered: int = 0
    connected: int = 0
    disconnected: int = 0
    ip_changed: int = 0
    name_changed: int = 0
    always_connected_down: int = 0
    always_connected_recovered: int = 0
    anomalies: int = 0


ANOMALY_REPEAT_AFTER = timedelta(hours=6)  # the same finding is not re-reported more often than this
LIVE_SOURCES = ("arp_scan", "neighbor")  # evidence a device answered on the wire (unlike leases or DNS logs)


@dataclass
class _Merged:
    mac: str | None
    ip: str | None
    hostname: str | None = None
    hostname_source: str | None = None
    vendor: str | None = None
    model: str | None = None
    presence: bool = False
    sources: list[str] = field(default_factory=list)
    raw: list[DeviceObservation] = field(default_factory=list)


def _absorb(m: _Merged, o: DeviceObservation) -> None:
    m.ip = m.ip or o.ip
    hostname = clean_text(o.hostname)
    if hostname and not m.hostname:
        m.hostname, m.hostname_source = hostname, o.source
    m.vendor = m.vendor or clean_text(o.vendor)
    m.model = m.model or clean_text(o.model, 120)
    m.presence = m.presence or o.presence
    if o.source not in m.sources:
        m.sources.append(o.source)
    m.raw.append(o)


def merge_observations(observations: list[DeviceObservation]) -> list[_Merged]:
    """Collapse duplicate sightings (several providers, same device) into one record per device."""
    by_mac: dict[str, _Merged] = {}
    ip_only: list[DeviceObservation] = []
    for o in observations:
        if o.mac:
            _absorb(by_mac.setdefault(o.mac, _Merged(mac=o.mac, ip=o.ip)), o)
        elif o.ip:
            ip_only.append(o)
    # an IP-only sighting of an IP a MAC-identified record already holds is the same sighting
    by_ip = {m.ip: m for m in by_mac.values() if m.ip}
    standalone: dict[str, _Merged] = {}
    for o in ip_only:
        _absorb(by_ip.get(o.ip) or standalone.setdefault(o.ip, _Merged(mac=None, ip=o.ip)), o)
    return [*by_mac.values(), *standalone.values()]


class _Engine:
    def __init__(self, db: Session, scanner: ScannerSettings, now: datetime):
        self.db, self.s, self.now = db, scanner, now
        self.summary = ScanSummary()
        self.all = list(db.scalars(select(Device)).all())
        self.by_mac = {d.mac_address: d for d in self.all if d.mac_address}
        self.by_ip_macless = {d.current_ip: d for d in self.all if not d.mac_address and d.current_ip}
        self.reported = {  # (device, kind, key) of anomalies already raised recently
            (e.device_id, (e.meta or {}).get("kind"), (e.meta or {}).get("key"))
            for e in db.scalars(
                select(Event).where(Event.event_type == EventType.DEVICE_ANOMALY.value, Event.timestamp > now - ANOMALY_REPEAT_AFTER)
            ).unique()
        }

    # -- helpers ---------------------------------------------------------------------------
    def anomaly(self, device: Device, kind: str, key: str, detail: str, source: str | None = None) -> None:
        sig = (device.id, kind, key)
        if sig in self.reported:
            return
        self.reported.add(sig)
        self.event(device, EventType.DEVICE_ANOMALY, new=detail[:500], source=source, meta={"kind": kind, "key": key})
        self.summary.anomalies += 1

    def event(self, device: Device, etype: EventType, old=None, new=None, source=None, meta=None) -> None:
        self.db.add(
            Event(device_id=device.id, timestamp=self.now, event_type=etype.value, old_value=old, new_value=new,
                  source=source, meta=meta)
        )

    def alert_state(self, device: Device) -> str | None:
        return self.db.scalar(
            select(Event.event_type)
            .where(Event.device_id == device.id, Event.event_type.in_(_ALERT_STATE))
            .order_by(Event.timestamp.desc(), Event.id.desc())
            .limit(1)
        )

    def open_session(self, device: Device) -> DeviceSession | None:
        return self.db.scalar(
            select(DeviceSession)
            .where(DeviceSession.device_id == device.id, DeviceSession.disconnected_at.is_(None))
            .order_by(DeviceSession.connected_at.desc())
            .limit(1)
        )

    def touch_address(self, device: Device, ip: str, source: str) -> None:
        row = self.db.scalar(select(DeviceAddress).where(DeviceAddress.device_id == device.id, DeviceAddress.ip == ip))
        if row:
            row.last_seen = self.now
        else:
            self.db.add(DeviceAddress(device_id=device.id, ip=ip, first_seen=self.now, last_seen=self.now, source=source))

    def touch_name(self, device: Device, name: str, source: str) -> None:
        row = self.db.scalar(
            select(DeviceName).where(DeviceName.device_id == device.id, DeviceName.name == name, DeviceName.source == source)
        )
        if row:
            row.last_seen = self.now
        else:
            self.db.add(DeviceName(device_id=device.id, name=name, source=source, first_seen=self.now, last_seen=self.now))

    def describe(self, device: Device) -> None:
        """Scanner-owned hardware hints. device_type (user-owned) is never touched."""
        device.vendor = device.vendor or oui.lookup(device.mac_address)
        device.type_guess = guess_type(device.vendor, device.hostname, device.model)

    def set_status(self, device: Device) -> None:
        device.status = compute_status(
            device, self.now, self.s.offline_threshold_seconds, self.s.new_device_window_hours
        ).value

    def holder(self, ip: str) -> Device | None:
        """The one online MAC-identified device currently at `ip`; None if absent or ambiguous."""
        held = [d for d in self.all if d.mac_address and d.current_ip == ip and d.is_online]
        return held[0] if len(held) == 1 else None

    def register(self, device: Device) -> None:
        self.all.append(device)
        if device.mac_address:
            self.by_mac[device.mac_address] = device
        elif device.current_ip:
            self.by_ip_macless[device.current_ip] = device

    # -- observed devices ------------------------------------------------------------------
    def apply(self, m: _Merged) -> tuple[Device | None, bool]:
        """Returns (device, presence_proven). IP-only evidence never creates a device."""
        src = ",".join(m.sources)
        m.vendor = m.vendor or oui.lookup(m.mac)
        device = self.by_mac.get(m.mac) if m.mac else (self.by_ip_macless.get(m.ip) or self.holder(m.ip))
        if device is None and not m.mac:
            return None, False
        device = self._apply_presence(m, device, src) if m.presence else self._apply_identity(m, device, src)
        if m.ip:
            self.touch_address(device, m.ip, src)
        if m.hostname:
            self.touch_name(device, m.hostname, m.hostname_source or src)
        for o in m.raw:
            self.db.add(DiscoveryObservation(observed_at=o.seen_at, source=o.source, mac=o.mac, ip=o.ip,
                                             hostname=o.hostname, vendor=o.vendor, device_id=device.id,
                                             meta=o.metadata or None))
        self.describe(device)
        self.set_status(device)
        return device, m.presence

    def _new_device(self, m: _Merged, src: str, alive: bool) -> Device:
        device = Device(
            mac_address=m.mac, current_ip=m.ip, hostname=m.hostname, vendor=m.vendor, model=m.model, is_known=False,
            is_online=alive, first_seen=self.now,
            # identity-only discoveries stay UNKNOWN until something proves the device is alive
            last_seen=self.now if alive else None, last_connection=self.now if alive else None,
        )
        self.db.add(device)
        self.db.flush()
        self.register(device)
        self.event(device, EventType.DEVICE_DISCOVERED, new=m.ip, source=src,
                   meta={"mac": m.mac, "hostname": m.hostname, "vendor": m.vendor, "presence": alive})
        self.summary.discovered += 1
        return device

    def _apply_presence(self, m: _Merged, device: Device | None, src: str) -> Device:
        if device is None:
            device = self._new_device(m, src, alive=True)
            self.db.add(DeviceSession(device_id=device.id, connected_at=self.now, last_seen=self.now, source=src))
            return device
        self._enrich(device, m, src, move_ip=True)
        was_online = device.is_online
        device.last_seen = self.now
        session = self.open_session(device)
        if not was_online:
            device.is_online = True
            device.last_connection = self.now
            self.event(device, EventType.DEVICE_CONNECTED, old="OFFLINE", new="ONLINE", source=src)
            self.summary.connected += 1
        if session is None:
            self.db.add(DeviceSession(device_id=device.id, connected_at=self.now, last_seen=self.now, source=src))
        else:
            session.last_seen = self.now
        # recovery is independent of the offline flag: the down alert can fire before the offline threshold
        if device.always_connected and self.alert_state(device) == EventType.ALWAYS_CONNECTED_DEVICE_DOWN.value:
            self.event(device, EventType.ALWAYS_CONNECTED_DEVICE_RECOVERED, old="DOWN", new="UP", source=src)
            self.summary.always_connected_recovered += 1
        return device

    def _apply_identity(self, m: _Merged, device: Device | None, src: str) -> Device:
        if device is None:
            return self._new_device(m, src, alive=False)
        self._enrich(device, m, src, move_ip=False)
        return device

    def _enrich(self, device: Device, m: _Merged, src: str, move_ip: bool) -> None:
        """Update scanner-owned descriptive fields. A lease or name hint must not move a device's IP."""
        if m.ip and device.current_ip != m.ip and (move_ip or device.current_ip is None):
            if device.current_ip:
                self.event(device, EventType.DEVICE_IP_CHANGED, old=device.current_ip, new=m.ip, source=src)
                self.summary.ip_changed += 1
            device.current_ip = m.ip
        if m.hostname and device.hostname != m.hostname:
            if device.hostname:
                self.event(device, EventType.DEVICE_NAME_CHANGED, old=device.hostname, new=m.hostname, source=src)
                self.summary.name_changed += 1
                if device.is_trusted:  # a device you vouched for changing identity is worth a second look
                    self.anomaly(device, "hostname_changed", m.hostname,
                                 f"Hostname of a trusted device changed: {device.hostname} -> {m.hostname}", src)
            device.hostname = m.hostname
        if m.vendor and device.vendor != m.vendor:
            device.vendor = m.vendor
        if m.model and device.model != m.model:
            device.model = m.model

    # -- anomaly detection -----------------------------------------------------------------
    def detect_anomalies(self, observations: list[DeviceObservation]) -> None:
        """Heuristics over one scan's raw sightings. ARP cannot authenticate anything, so these flag
        inconsistencies a spoofer or misconfiguration produces; they cannot prove or rule out spoofing."""
        live = [o for o in observations if o.presence and o.mac and o.ip and o.source in LIVE_SOURCES]
        macs_at_ip: dict[str, set[str]] = defaultdict(set)
        ips_of_mac: dict[str, set[str]] = defaultdict(set)
        arp_ips_of_mac: dict[str, set[str]] = defaultdict(set)
        for o in live:
            macs_at_ip[o.ip].add(o.mac)
            ips_of_mac[o.mac].add(o.ip)
            if o.source == "arp_scan":
                arp_ips_of_mac[o.mac].add(o.ip)

        # one address answered by several hardware addresses at the same moment
        for ip, macs in macs_at_ip.items():
            if len(macs) > 1:
                for mac in sorted(macs):
                    device = self.by_mac.get(mac)
                    if device:
                        others = ", ".join(sorted(macs - {mac}))
                        self.anomaly(device, "ip_conflict", ip, f"{ip} is also claimed by {others}", "arp_scan,neighbor")

        # one trusted device answering at several addresses (aliases make this too noisy for everyone else)
        for mac, ips in arp_ips_of_mac.items():
            device = self.by_mac.get(mac)
            if device and device.is_trusted and len(ips) > 1:
                self.anomaly(device, "mac_multi_ip", mac, f"Answered at several addresses at once: {', '.join(sorted(ips))}", "arp_scan")

        # trusted device seen somewhere other than where DHCP says it lives
        for o in observations:
            if o.source == "adguard_dhcp" and o.mac and o.ip and o.mac in ips_of_mac and o.ip not in ips_of_mac[o.mac]:
                device = self.by_mac.get(o.mac)
                if device and device.is_trusted:
                    seen = ", ".join(sorted(ips_of_mac[o.mac]))
                    self.anomaly(device, "identity_drift", f"{o.ip}->{seen}", f"DHCP lease says {o.ip} but the device answered at {seen}", "adguard_dhcp")

    # -- devices not seen this scan --------------------------------------------------------
    def apply_absent(self, device: Device) -> None:
        if device.last_seen is None:
            return
        silent = self.now - device.last_seen
        if device.is_online and not is_online(device, self.now, self.s.offline_threshold_seconds):
            device.is_online = False
            device.last_disconnection = device.last_seen
            session = self.open_session(device)
            if session:
                session.disconnected_at = device.last_seen
            self.event(device, EventType.DEVICE_DISCONNECTED, old="ONLINE", new="OFFLINE",
                       meta={"last_seen": device.last_seen.isoformat()})
            self.summary.disconnected += 1
        if (
            device.always_connected
            and silent >= timedelta(seconds=self.s.always_connected_offline_threshold_seconds)
            and self.alert_state(device) != EventType.ALWAYS_CONNECTED_DEVICE_DOWN.value
        ):
            self.event(device, EventType.ALWAYS_CONNECTED_DEVICE_DOWN, old="UP", new="DOWN",
                       meta={"silent_seconds": int(silent.total_seconds())})
            self.summary.always_connected_down += 1
        self.set_status(device)


def process_scan(
    db: Session,
    observations: list[DeviceObservation],
    evidence: bool,
    scanner: ScannerSettings,
    now: datetime,
) -> ScanSummary:
    """Apply one scan. `evidence` is False when every provider failed: absence then proves nothing,
    so nobody is marked offline because the scanner itself is broken."""
    engine = _Engine(db, scanner, now)
    present: set[int] = set()
    for device in engine.all:  # backfill devices recorded before hardware hints existed
        if device.vendor is None or device.type_guess is None:
            engine.describe(device)
    for merged in merge_observations(observations):
        device, alive = engine.apply(merged)
        if device is None:
            continue
        if alive:
            present.add(device.id)
        engine.summary.observed += 1
    engine.detect_anomalies(observations)
    if evidence:
        for device in list(engine.all):
            if device.id not in present:
                engine.apply_absent(device)
    cutoff = now - timedelta(days=scanner.observation_retention_days)
    db.execute(delete(DiscoveryObservation).where(DiscoveryObservation.observed_at < cutoff))
    return engine.summary
