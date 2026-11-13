from collections.abc import Sequence
from datetime import datetime


def online_series(
    intervals: Sequence[tuple[datetime, datetime]],
    first_seen: Sequence[datetime],
    start: datetime,
    end: datetime,
    points: int,
) -> list[tuple[datetime, int, int]]:
    """Sample (time, devices online, devices known) at `points`+1 evenly spaced instants.

    A device is online at t when one of its (connected, disconnected) intervals covers t, and
    known once first_seen <= t. shortcut: O(intervals x points); fine for a home network's
    history, index by time if sessions ever reach millions.
    """
    out = []
    for i in range(points + 1):
        t = start + (end - start) * i / points
        out.append((t, sum(1 for a, b in intervals if a <= t <= b), sum(1 for f in first_seen if f <= t)))
    return out
