from datetime import datetime

from pydantic import BaseModel

from app.schemas.device import DeviceOut


class SeriesPoint(BaseModel):
    time: datetime
    online: int
    total: int  # devices known at that time (first seen on or before it)


class TypeCount(BaseModel):
    type: str  # "Unclassified" when the user has not set a type
    count: int


class DashboardOut(BaseModel):
    range: str
    start: datetime
    end: datetime
    series: list[SeriesPoint]
    type_distribution: list[TypeCount]
    recently_disconnected: list[DeviceOut]
