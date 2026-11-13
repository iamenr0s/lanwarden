"""Brute-force throttling for login, first-run setup and password change.

Two independent keys per attempt:
* ip:<addr>      5 failures in 15 min start a lockout that doubles with each further failure
                 (30 s, 60 s, 120 s ... capped at 15 min)
* user:<name>    20 failures in 15 min, from any addresses, start the same progression. Higher on
                 purpose: it caps distributed guessing without making it trivial to lock the admin out.
Failures live in the database, so lockouts survive restarts. Attempts made while locked out are
refused without being recorded, so a legitimate retry never extends the lock.
"""

import math
from collections.abc import Callable
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.db.types import utcnow
from app.models.system import LoginAttempt

WINDOW = timedelta(minutes=15)
LIMITS = {"ip": 5, "user": 20}
BASE_LOCK_S, MAX_LOCK_S = 30, 900


class Throttle:
    def __init__(self, now: Callable[[], datetime] = utcnow):
        self._now = now  # injectable so tests can move time without sleeping

    @staticmethod
    def _keys(ip: str, username: str | None) -> list[str]:
        keys = [f"ip:{ip}"]
        if username:
            keys.append(f"user:{username.strip().lower()[:64]}")
        return keys

    def _lock_remaining(self, db: Session, key: str) -> int:
        now = self._now()
        limit = LIMITS[key.split(":", 1)[0]]
        count, last = db.execute(
            select(func.count(), func.max(LoginAttempt.at)).where(LoginAttempt.key == key, LoginAttempt.at > now - WINDOW)
        ).one()
        if count < limit:
            return 0
        lock = min(MAX_LOCK_S, BASE_LOCK_S * 2 ** min(count - limit, 10))
        return max(0, math.ceil((last + timedelta(seconds=lock) - now).total_seconds()))

    def retry_after(self, db: Session, ip: str, username: str | None = None) -> int:
        """Seconds until another attempt is allowed; 0 when not locked out."""
        return max(self._lock_remaining(db, k) for k in self._keys(ip, username))

    def fail(self, db: Session, ip: str, username: str | None = None) -> None:
        now = self._now()
        db.execute(delete(LoginAttempt).where(LoginAttempt.at < now - WINDOW))  # nothing older can matter
        db.add_all(LoginAttempt(key=k, at=now) for k in self._keys(ip, username))
        db.commit()

    def success(self, db: Session, ip: str) -> None:
        """A correct login clears the address's history, not the username's (that cap is for distributed guessing)."""
        db.execute(delete(LoginAttempt).where(LoginAttempt.key == f"ip:{ip}"))
        db.commit()
