from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_user
from app.db.types import utcnow
from app.models.device import Device, DeviceSession
from app.schemas.dashboard import DashboardOut, SeriesPoint, TypeCount
from app.schemas.device import DeviceOut
from app.services.analytics import online_series

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"], dependencies=[Depends(require_user)])

# range -> (window, number of sampling intervals): hourly, 6-hourly, daily
RANGES = {"24h": (timedelta(hours=24), 24), "7d": (timedelta(days=7), 28), "30d": (timedelta(days=30), 30)}


@router.get("", response_model=DashboardOut)
def dashboard(range: Literal["24h", "7d", "30d"] = "24h", db: Session = Depends(get_db)):
    """Chart data for the dashboard. History only exists from when LanWarden started recording."""
    window, points = RANGES[range]
    end = utcnow()
    start = end - window
    visible = Device.is_ignored.is_(False)

    rows = db.execute(
        select(DeviceSession.connected_at, DeviceSession.disconnected_at, DeviceSession.last_seen, Device.is_online)
        .join(Device, Device.id == DeviceSession.device_id)
        .where(visible, DeviceSession.connected_at < end,
               or_(DeviceSession.disconnected_at.is_(None), DeviceSession.disconnected_at > start))
    ).all()
    # an open session of an online device runs to now; otherwise it ends at its last sighting
    intervals = [(c, d or (end if online else seen)) for c, d, seen, online in rows]
    first_seen = list(db.scalars(select(Device.first_seen).where(visible, Device.first_seen.is_not(None))))

    type_col = func.coalesce(Device.device_type, Device.type_guess, "")
    types = db.execute(select(type_col, func.count()).where(visible).group_by(type_col).order_by(func.count().desc())).all()
    disconnected = db.scalars(
        select(Device).where(visible, Device.is_online.is_(False), Device.last_disconnection.is_not(None))
        .order_by(Device.last_disconnection.desc()).limit(6)
    ).all()

    return DashboardOut(
        range=range, start=start, end=end,
        series=[SeriesPoint(time=t, online=o, total=n) for t, o, n in online_series(intervals, first_seen, start, end, points)],
        type_distribution=[TypeCount(type=t or "Unclassified", count=n) for t, n in types],
        recently_disconnected=[DeviceOut.model_validate(d) for d in disconnected],
    )
