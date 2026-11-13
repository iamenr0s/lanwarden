from collections.abc import Iterable
from datetime import datetime, timedelta

from app.models.device import Device
from app.models.enums import DeviceStatus


def online_segments(
    intervals: Iterable[tuple[datetime, datetime]], start: datetime, end: datetime
) -> list[tuple[datetime, datetime]]:
    """Clip (connected, disconnected) intervals to [start, end] and merge overlaps/touching ones."""
    clipped = sorted((max(a, start), min(b, end)) for a, b in intervals if b > start and a < end)
    merged: list[tuple[datetime, datetime]] = []
    for a, b in clipped:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


def is_online(device: Device, now: datetime, offline_threshold_s: int) -> bool:
    """A single missed scan does not mean offline: only silence beyond the threshold does."""
    return device.last_seen is not None and now - device.last_seen <= timedelta(seconds=offline_threshold_s)


def compute_status(
    device: Device, now: datetime, offline_threshold_s: int, new_window_hours: int
) -> DeviceStatus:
    """UNKNOWN: never observed. NEW: unacknowledged and recently first seen. Else ONLINE/OFFLINE."""
    if device.last_seen is None:
        return DeviceStatus.UNKNOWN
    if (
        not device.is_known
        and device.first_seen is not None
        and now - device.first_seen <= timedelta(hours=new_window_hours)
    ):
        return DeviceStatus.NEW
    return DeviceStatus.ONLINE if is_online(device, now, offline_threshold_s) else DeviceStatus.OFFLINE
