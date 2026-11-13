from datetime import datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import ItemId, Offset, get_db, require_user
from app.db.types import utcnow
from app.integrations.adguard import AdGuardError
from app.models.device import Device, DeviceAddress, DeviceName, DeviceSession
from app.models.enums import DeviceStatus
from app.models.event import DiscoveryObservation, Event
from app.schemas.adguard import DeviceAdGuard, ErrorInfo
from app.schemas.device import (
    AddressHistory,
    DeviceOut,
    DevicePage,
    DeviceUpdate,
    NameHistory,
    NetworkOut,
    PresenceOut,
    PresenceSegment,
    SourceHistory,
)
from app.schemas.event import EventOut, EventPage, SessionOut
from app.services import adguard_config
from app.services.adguard_device import device_intel
from app.services.presence import compute_status, online_segments
from app.services.settings import load_settings

router = APIRouter(prefix="/api/devices", tags=["devices"], dependencies=[Depends(require_user)])

_NAME = func.lower(func.coalesce(Device.friendly_name, Device.hostname, Device.mac_address, Device.current_ip, ""))
# shortcut: IP sorts lexicographically (192.168.1.10 < 192.168.1.9); fine until it bothers someone.
SORT_COLUMNS = {
    "name": _NAME,
    "ip": Device.current_ip,
    "mac": Device.mac_address,
    "vendor": func.lower(func.coalesce(Device.vendor_override, Device.vendor, "")),
    "type": func.lower(func.coalesce(Device.device_type, Device.type_guess, "")),
    "status": Device.status,
    "last_seen": Device.last_seen,
    "first_seen": Device.first_seen,
}


def like_escape(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def get_device_or_404(db: Session, device_id: ItemId) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(404, "Device not found")
    return device


@router.get("", response_model=DevicePage)
def list_devices(
    q: str | None = Query(None, max_length=100),
    status: DeviceStatus | None = None,
    online: bool | None = None,
    known: bool | None = None,
    favorite: bool | None = None,
    always_connected: bool | None = None,
    group: str | None = Query(None, max_length=50),
    type: str | None = Query(None, max_length=50),
    include_ignored: bool = False,
    sort: Literal["name", "ip", "mac", "vendor", "type", "status", "last_seen", "first_seen"] = "last_seen",
    order: Literal["asc", "desc"] = "desc",
    limit: int = Query(50, ge=1, le=500),
    offset: Offset = 0,
    db: Session = Depends(get_db),
):
    conds = []
    if q and q.strip():
        pat = f"%{like_escape(q.strip())}%"
        conds.append(
            func.coalesce(Device.friendly_name, "").ilike(pat, escape="\\")
            | func.coalesce(Device.hostname, "").ilike(pat, escape="\\")
            | func.coalesce(Device.current_ip, "").ilike(pat, escape="\\")
            | func.coalesce(Device.mac_address, "").ilike(pat, escape="\\")
            | func.coalesce(Device.vendor, "").ilike(pat, escape="\\")
            | func.coalesce(Device.vendor_override, "").ilike(pat, escape="\\")
        )
    for value, col in (
        (status.value if status else None, Device.status),
        (online, Device.is_online),
        (known, Device.is_known),
        (favorite, Device.is_favorite),
        (always_connected, Device.always_connected),
        (group, Device.device_group),
        (type, func.coalesce(Device.device_type, Device.type_guess)),
    ):
        if value is not None:
            conds.append(col == value)
    if not include_ignored:
        conds.append(Device.is_ignored.is_(False))

    total = db.scalar(select(func.count()).select_from(Device).where(*conds)) or 0
    col = SORT_COLUMNS[sort]
    ordering = (col.asc() if order == "asc" else col.desc()).nulls_last()
    rows = db.scalars(select(Device).where(*conds).order_by(ordering, Device.id).limit(limit).offset(offset)).all()
    return DevicePage(items=rows, total=total)


@router.get("/{device_id}", response_model=DeviceOut)
def get_device(device_id: ItemId, db: Session = Depends(get_db)):
    return get_device_or_404(db, device_id)


@router.patch("/{device_id}", response_model=DeviceOut)
def update_device(device_id: ItemId, body: DeviceUpdate, db: Session = Depends(get_db)):
    device = get_device_or_404(db, device_id)
    changes = body.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(device, field, value)
    if "is_known" in changes:  # acknowledging a NEW device must clear NEW immediately
        scanner = load_settings(db).scanner
        now = utcnow()
        device.status = compute_status(
            device, now, scanner.offline_threshold_seconds, scanner.new_device_window_hours
        ).value
    db.commit()
    return device


@router.get("/{device_id}/events", response_model=EventPage)
def device_events(
    device_id: ItemId,
    limit: int = Query(50, ge=1, le=500),
    offset: Offset = 0,
    db: Session = Depends(get_db),
):
    get_device_or_404(db, device_id)
    where = Event.device_id == device_id
    total = db.scalar(select(func.count()).select_from(Event).where(where)) or 0
    rows = db.scalars(
        select(Event).where(where).order_by(Event.timestamp.desc(), Event.id.desc()).limit(limit).offset(offset)
    ).unique()
    return EventPage(items=[_event_out(e) for e in rows], total=total)


@router.get("/{device_id}/sessions", response_model=list[SessionOut])
def device_sessions(
    device_id: ItemId,
    since: datetime | None = None,
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    get_device_or_404(db, device_id)
    stmt = select(DeviceSession).where(DeviceSession.device_id == device_id)
    if since is not None:
        stmt = stmt.where(
            (DeviceSession.disconnected_at.is_(None)) | (DeviceSession.disconnected_at >= since)
        )
    rows = db.scalars(stmt.order_by(DeviceSession.connected_at.desc()).limit(limit)).all()
    out = []
    for s in rows:
        end = s.disconnected_at or s.last_seen
        item = SessionOut.model_validate(s)
        item.duration_seconds = max(0, int((end - s.connected_at).total_seconds()))
        out.append(item)
    return out


RANGES = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}


@router.get("/{device_id}/presence", response_model=PresenceOut)
def device_presence(
    device_id: ItemId,
    range: Literal["today", "24h", "7d", "30d"] = "24h",
    tz_offset_minutes: int = Query(0, ge=-840, le=840, description="Client's UTC offset; defines 'today'"),
    db: Session = Depends(get_db),
):
    """Online intervals for a timeline, built from the device's sessions."""
    device = get_device_or_404(db, device_id)
    end = utcnow()
    if range == "today":
        offset = timedelta(minutes=tz_offset_minutes)
        start = (end + offset).replace(hour=0, minute=0, second=0, microsecond=0) - offset
    else:
        start = end - RANGES[range]
    rows = db.scalars(
        select(DeviceSession).where(
            DeviceSession.device_id == device_id,
            DeviceSession.connected_at < end,
            (DeviceSession.disconnected_at.is_(None)) | (DeviceSession.disconnected_at > start),
        )
    ).all()
    # Closed sessions end when the device went silent. An open session runs to now while the device
    # is online (bounded by the offline threshold), else only as far as its last sighting.
    spans = [(s.connected_at, s.disconnected_at or (end if device.is_online else s.last_seen)) for s in rows]
    segments = online_segments(spans, start, end)
    online = sum(int((b - a).total_seconds()) for a, b in segments)
    tracked_from = max(start, device.first_seen) if device.first_seen else start
    tracked = max(0, int((end - tracked_from).total_seconds()))
    return PresenceOut(
        range=range, start=start, end=end, segments=[PresenceSegment(start=a, end=b) for a, b in segments],
        session_count=sum(1 for _, b in spans if b > start),
        online_seconds=online, tracked_seconds=tracked,
        online_percent=round(100 * online / tracked, 1) if tracked else None,
    )


@router.get("/{device_id}/network", response_model=NetworkOut)
def device_network(device_id: ItemId, db: Session = Depends(get_db)):
    """IP history, observed hostnames and which discovery sources have seen the device."""
    device = get_device_or_404(db, device_id)
    addresses = [
        AddressHistory.model_validate(a).model_copy(update={"current": a.ip == device.current_ip})
        for a in db.scalars(select(DeviceAddress).where(DeviceAddress.device_id == device_id).order_by(DeviceAddress.last_seen.desc()))
    ]
    names = db.scalars(select(DeviceName).where(DeviceName.device_id == device_id).order_by(DeviceName.last_seen.desc())).all()
    sources = db.execute(
        select(
            DiscoveryObservation.source, func.min(DiscoveryObservation.observed_at),
            func.max(DiscoveryObservation.observed_at), func.count(),
        )
        .where(DiscoveryObservation.device_id == device_id)
        .group_by(DiscoveryObservation.source)
        .order_by(func.max(DiscoveryObservation.observed_at).desc())
    ).all()
    return NetworkOut(
        addresses=addresses,
        names=[NameHistory.model_validate(n) for n in names],
        sources=[SourceHistory(source=s, first_observed=lo, last_observed=hi, observations=n) for s, lo, hi, n in sources],
        observation_retention_days=load_settings(db).scanner.observation_retention_days,
    )


@router.get("/{device_id}/adguard", response_model=DeviceAdGuard)
def device_adguard(device_id: ItemId, request: Request, db: Session = Depends(get_db)):
    """DNS-side view of a device. Devices unknown to AdGuard, or no AdGuard at all, still work."""
    device = get_device_or_404(db, device_id)
    if not adguard_config.get_public(db).configured:
        return DeviceAdGuard(configured=False)
    try:
        cfg = adguard_config.runtime_config(db, request.app.state.box)
        with request.app.state.adguard_client_factory(cfg) as client:
            return device_intel(client, device)
    except AdGuardError as e:
        return DeviceAdGuard(configured=True, error=ErrorInfo(kind=e.kind, message=e.message))


def _event_out(e: Event) -> EventOut:
    out = EventOut.model_validate(e)
    out.device_name = DeviceOut.model_validate(e.device).display_name if e.device else None
    return out
