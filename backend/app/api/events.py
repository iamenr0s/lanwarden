from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import OptionalId, Offset, get_db, require_user
from app.api.devices import _event_out, like_escape
from app.models.device import Device
from app.models.enums import EventType
from app.models.event import Event
from app.schemas.event import EventPage

router = APIRouter(prefix="/api/events", tags=["events"], dependencies=[Depends(require_user)])


@router.get("", response_model=EventPage)
def list_events(
    device_id: OptionalId = None,
    event_type: EventType | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    q: str | None = Query(None, max_length=100, description="Matches device name/IP/MAC and old/new values"),
    limit: int = Query(50, ge=1, le=500),
    offset: Offset = 0,
    db: Session = Depends(get_db),
):
    conds = []
    if device_id is not None:
        conds.append(Event.device_id == device_id)
    if event_type is not None:
        conds.append(Event.event_type == event_type.value)
    if since is not None:
        conds.append(Event.timestamp >= since)
    if until is not None:
        conds.append(Event.timestamp <= until)
    stmt = select(Event).outerjoin(Device, Event.device_id == Device.id)
    count = select(func.count()).select_from(Event).outerjoin(Device, Event.device_id == Device.id)
    if q and q.strip():
        pat = f"%{like_escape(q.strip())}%"
        match = (
            func.coalesce(Device.friendly_name, "").ilike(pat, escape="\\")
            | func.coalesce(Device.hostname, "").ilike(pat, escape="\\")
            | func.coalesce(Device.current_ip, "").ilike(pat, escape="\\")
            | func.coalesce(Device.mac_address, "").ilike(pat, escape="\\")
            | func.coalesce(Event.old_value, "").ilike(pat, escape="\\")
            | func.coalesce(Event.new_value, "").ilike(pat, escape="\\")
        )
        conds.append(match)
    total = db.scalar(count.where(*conds)) or 0
    rows = db.scalars(
        stmt.where(*conds).order_by(Event.timestamp.desc(), Event.id.desc()).limit(limit).offset(offset)
    ).unique()
    return EventPage(items=[_event_out(e) for e in rows], total=total)
