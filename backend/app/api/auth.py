import hmac

from fastapi import APIRouter, Depends, HTTPException, Request, status
from itsdangerous import BadSignature, SignatureExpired
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import current_user, get_db, require_session
from app.core import totp
from app.core.security import hash_password, session_version, verify_password
from app.models.system import User
from app.schemas.auth import (
    AuthState,
    Credentials,
    MfaConfirm,
    MfaEnable,
    MfaLogin,
    MfaPassword,
    MfaSetupOut,
    PasswordChange,
    RecoveryCodesOut,
    SetupRequest,
)
from app.services.throttle import Throttle

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Failures are stored in the database (see services/throttle.py): lockouts survive restarts.
# Behind a reverse proxy every client shares the proxy's address unless uvicorn trusts it
# (FORWARDED_ALLOW_IPS), in which case the per-IP key is the real client.
throttle = Throttle()
# Dummy hash so unknown usernames cost the same as wrong passwords (no timing oracle).
_DUMMY_HASH = hash_password("lanwarden-dummy")
MFA_TOKEN_TTL = 300  # seconds between a correct password and the code that completes sign-in


def _client(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _guard(request: Request, db: Session, username: str | None = None) -> str:
    """Refuse the attempt while locked out (without recording it). Returns the client key."""
    ip = _client(request)
    wait = throttle.retry_after(db, ip, username)
    if wait:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed attempts; try again later", headers={"Retry-After": str(wait)}
        )
    return ip


def _start_session(request: Request, user: User) -> None:
    request.session.clear()  # always a fresh session on privilege change (no fixation)
    request.session["user_id"] = user.id
    request.session["pv"] = session_version(user.password_hash, user.totp_enabled)


def _transport_insecure(request: Request) -> bool:
    return request.url.scheme == "http" and request.url.hostname not in ("localhost", "127.0.0.1", "::1")


def _state(request: Request, db: Session) -> AuthState:
    has_users = db.scalar(select(func.count()).select_from(User)) > 0
    user = current_user(request, db)
    required = request.app.state.config.require_mfa
    return AuthState(
        setup_required=not has_users,
        setup_token_required=not has_users and bool(request.app.state.config.setup_token),
        insecure_transport=_transport_insecure(request),
        authenticated=user is not None,
        username=user.username if user else None,
        mfa_enabled=bool(user and user.totp_enabled),
        mfa_enrolment_required=bool(user and required and not user.totp_enabled),
    )


@router.get("/state", response_model=AuthState)
def auth_state(request: Request, db: Session = Depends(get_db)):
    return _state(request, db)


@router.post("/setup", response_model=AuthState, status_code=status.HTTP_201_CREATED)
def setup(body: SetupRequest, request: Request, db: Session = Depends(get_db)):
    """Create the first admin. Refused once any user exists; needs the setup token if one is configured."""
    ip = _guard(request, db)
    if db.scalar(select(func.count()).select_from(User)) > 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "Setup already completed")
    expected = request.app.state.config.setup_token
    if expected and not hmac.compare_digest((body.setup_token or "").encode(), expected.encode()):
        throttle.fail(db, ip)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid setup token")
    user = User(username=body.username, password_hash=hash_password(body.password))
    db.add(user)
    db.commit()
    _start_session(request, user)
    return _state(request, db)


@router.post("/login", response_model=AuthState)
def login(body: Credentials, request: Request, db: Session = Depends(get_db)):
    ip = _guard(request, db, body.username)
    user = db.scalar(select(User).where(User.username == body.username))
    ok = verify_password(body.password, user.password_hash if user else _DUMMY_HASH)
    if not (user and ok):
        throttle.fail(db, ip, body.username)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    if user.totp_enabled:
        # Password is right but sign-in is not finished: no session until a code is presented.
        # The address's failure history is NOT cleared yet, so guessing codes stays throttled.
        token = request.app.state.mfa_signer.dumps({"uid": user.id, "pv": session_version(user.password_hash, True)})
        return AuthState(setup_required=False, authenticated=False, insecure_transport=_transport_insecure(request),
                         mfa_required=True, mfa_token=token)
    throttle.success(db, ip)
    _start_session(request, user)
    return _state(request, db)


def _consume_factor(request: Request, user: User, code: str) -> bool:
    """Check a TOTP code (once only) or a single-use recovery code. Mutates `user` only on success."""
    stripped = "".join(code.split())
    if stripped.isdigit() and len(stripped) == totp.DIGITS:
        secret = request.app.state.box.decrypt(user.totp_secret_enc) if user.totp_secret_enc else None
        step = totp.verify(secret, stripped, user.totp_last_step) if secret else None
        if step is None:
            return False
        user.totp_last_step = step
        return True
    digest = totp.hash_recovery(code, request.app.state.secret_key)
    remaining = list(user.recovery_codes or [])
    matched = None
    for stored in remaining:  # no early exit: every code is compared
        if hmac.compare_digest(stored, digest):
            matched = stored
    if matched is None:
        return False
    remaining.remove(matched)
    user.recovery_codes = remaining  # a new list, so the JSON column registers the change
    return True


@router.post("/login/mfa", response_model=AuthState)
def login_mfa(body: MfaLogin, request: Request, db: Session = Depends(get_db)):
    """Second step of sign-in for accounts with MFA: the token from /login plus a TOTP or recovery code."""
    expired = HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign-in expired; enter your password again")
    try:
        data = request.app.state.mfa_signer.loads(body.mfa_token, max_age=MFA_TOKEN_TTL)
    except (BadSignature, SignatureExpired):
        raise expired from None
    user = db.get(User, data.get("uid"))
    if user is None or not user.totp_enabled or data.get("pv") != session_version(user.password_hash, True):
        raise expired
    ip = _guard(request, db, user.username)
    if not _consume_factor(request, user, body.code):
        throttle.fail(db, ip, user.username)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid code")
    db.commit()
    throttle.success(db, ip)
    _start_session(request, user)
    return _state(request, db)


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(body: PasswordChange, request: Request, user: User = Depends(require_session), db: Session = Depends(get_db)):
    """Changing the password signs out every other session (their cookies carry the old version)."""
    ip = _guard(request, db, user.username)
    if not verify_password(body.current_password, user.password_hash):
        throttle.fail(db, ip, user.username)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Current password is incorrect")
    if body.new_password == body.current_password:
        raise HTTPException(422, "The new password must be different")
    user.password_hash = hash_password(body.new_password)
    db.commit()
    _start_session(request, user)


# ---- MFA enrolment and management (all need a session and the current password) --------------------
def _check_password(request: Request, db: Session, user: User, password: str) -> str:
    ip = _guard(request, db, user.username)
    if not verify_password(password, user.password_hash):
        throttle.fail(db, ip, user.username)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Password is incorrect")
    return ip


def _issue_recovery_codes(request: Request, user: User) -> list[str]:
    codes = totp.new_recovery_codes()
    user.recovery_codes = [totp.hash_recovery(c, request.app.state.secret_key) for c in codes]
    return codes


@router.post("/mfa/setup", response_model=MfaSetupOut)
def mfa_setup(body: MfaPassword, request: Request, user: User = Depends(require_session), db: Session = Depends(get_db)):
    """Start enrolment: returns a fresh secret. Nothing is enforced until /mfa/enable verifies a code."""
    if user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is already enabled")
    _check_password(request, db, user, body.password)
    secret = totp.new_secret()
    user.totp_secret_enc = request.app.state.box.encrypt(secret)
    user.totp_last_step = None
    db.commit()
    return MfaSetupOut(secret=secret, otpauth_uri=totp.otpauth_uri(secret, user.username))


@router.post("/mfa/enable", response_model=RecoveryCodesOut)
def mfa_enable(body: MfaEnable, request: Request, user: User = Depends(require_session), db: Session = Depends(get_db)):
    if user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is already enabled")
    if not user.totp_secret_enc:
        raise HTTPException(status.HTTP_409_CONFLICT, "Start setup first")
    ip = _guard(request, db, user.username)
    step = totp.verify(request.app.state.box.decrypt(user.totp_secret_enc) or "", body.code)
    if step is None:
        throttle.fail(db, ip, user.username)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That code is not valid; check the time on your phone and try again")
    user.totp_enabled, user.totp_last_step = True, step
    codes = _issue_recovery_codes(request, user)
    db.commit()
    _start_session(request, user)  # MFA state is part of the session version: every other session is signed out
    return RecoveryCodesOut(recovery_codes=codes)


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT)
def mfa_disable(body: MfaConfirm, request: Request, user: User = Depends(require_session), db: Session = Depends(get_db)):
    if not user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is not enabled")
    if request.app.state.config.require_mfa:
        raise HTTPException(status.HTTP_409_CONFLICT, "This server requires MFA; it cannot be turned off")
    ip = _check_password(request, db, user, body.password)
    if not _consume_factor(request, user, body.code):
        throttle.fail(db, ip, user.username)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That code is not valid")
    user.totp_enabled, user.totp_secret_enc, user.totp_last_step, user.recovery_codes = False, None, None, None
    db.commit()
    _start_session(request, user)


@router.post("/mfa/recovery-codes", response_model=RecoveryCodesOut)
def mfa_new_recovery_codes(body: MfaConfirm, request: Request, user: User = Depends(require_session), db: Session = Depends(get_db)):
    """Replace all recovery codes (the old ones stop working)."""
    if not user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is not enabled")
    ip = _check_password(request, db, user, body.password)
    if not _consume_factor(request, user, body.code):
        throttle.fail(db, ip, user.username)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That code is not valid")
    codes = _issue_recovery_codes(request, user)
    db.commit()
    return RecoveryCodesOut(recovery_codes=codes)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request):
    request.session.clear()
