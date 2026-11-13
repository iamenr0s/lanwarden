from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, HTTPException, Path, Query, Request, status
from sqlalchemy.orm import Session

from app.core.security import session_version
from app.models.system import User


def get_db(request: Request) -> Iterator[Session]:
    with request.app.state.session_factory() as session:
        yield session


def current_user(request: Request, db: Session) -> User | None:
    """The logged-in user, or None. A session issued before the last password change is rejected."""
    user_id = request.session.get("user_id")
    user = db.get(User, user_id) if user_id else None
    if user is None or request.session.get("pv") != session_version(user.password_hash, user.totp_enabled):
        return None
    return user


def require_session(request: Request, db: Session = Depends(get_db)) -> User:
    """Logged in. Used by the account/MFA endpoints, which must stay reachable while MFA enrolment is pending."""
    user = current_user(request, db)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    return user


def require_user(request: Request, user: User = Depends(require_session)) -> User:
    """Logged in, and (when the server requires MFA) enrolled in it."""
    if request.app.state.config.require_mfa and not user.totp_enabled:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "mfa_enrolment_required")
    return user


MAX_INT = 2**31 - 1  # the largest value a database INTEGER can hold on every supported engine
ItemId = Annotated[int, Path(ge=1, le=MAX_INT)]  # path parameters naming a row (device, rule)
Offset = Annotated[int, Query(ge=0, le=MAX_INT)]
OptionalId = Annotated[int | None, Query(ge=1, le=MAX_INT)]
