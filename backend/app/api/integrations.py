from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_user
from app.integrations.adguard import AdGuardConfig, AdGuardError
from app.schemas.adguard import (
    AdGuardConfigIn,
    AdGuardConfigOut,
    AdGuardHealth,
    AdGuardTestIn,
    AdGuardTestResult,
    ErrorInfo,
    ServerInfo,
)
from app.services import adguard_config

router = APIRouter(prefix="/api/integrations/adguard", tags=["integrations"], dependencies=[Depends(require_user)])


def server_info(status: dict) -> ServerInfo:
    return ServerInfo(
        version=str(status.get("version", "unknown")), running=status.get("running"),
        protection_enabled=status.get("protection_enabled"), dns_addresses=list(status.get("dns_addresses") or []),
        dns_port=status.get("dns_port"), http_port=status.get("http_port"), language=status.get("language"),
    )


@router.get("", response_model=AdGuardConfigOut)
def get_config(db: Session = Depends(get_db)):
    """Never includes the password, only whether one is stored."""
    return adguard_config.get_public(db)


@router.put("", response_model=AdGuardConfigOut)
def put_config(body: AdGuardConfigIn, request: Request, db: Session = Depends(get_db)):
    adguard_config.save(db, request.app.state.box, body)
    return adguard_config.get_public(db)


@router.get("/status", response_model=AdGuardHealth)
def status(request: Request, db: Session = Depends(get_db)):
    """Live reachability of the saved configuration, for the dashboard card."""
    if not adguard_config.get_public(db).configured:
        return AdGuardHealth(configured=False)
    try:
        cfg = adguard_config.runtime_config(db, request.app.state.box)
        with request.app.state.adguard_client_factory(cfg) as client:
            return AdGuardHealth(configured=True, reachable=True, server=server_info(client.status()))
    except AdGuardError as e:
        return AdGuardHealth(configured=True, error=ErrorInfo(kind=e.kind, message=e.message))


def _effective_config(db: Session, request: Request, body: AdGuardTestIn) -> AdGuardConfig:
    """Form values win; omitted ones fall back to the saved config. The saved password is only
    reused when the URL and username are unchanged, so it can never be sent to a new destination."""
    try:
        saved = adguard_config.runtime_config(db, request.app.state.box)
    except AdGuardError:
        saved = None
    url = body.url or (saved.url if saved else None)
    if not url:
        raise AdGuardError("not_configured", "Enter the AdGuard Home URL")
    username = body.username if body.username is not None else (saved.username if saved else "")
    unchanged = saved is not None and saved.url == url and saved.username == username
    password = body.password if body.password is not None else (saved.password if unchanged else "")
    return AdGuardConfig(
        url=url, username=username, password=password,
        verify_tls=body.verify_tls if body.verify_tls is not None else (saved.verify_tls if saved else True),
        timeout_seconds=body.timeout_seconds or (saved.timeout_seconds if saved else 10),
    )


@router.post("/test", response_model=AdGuardTestResult)
def test_connection(request: Request, body: AdGuardTestIn | None = None, db: Session = Depends(get_db)):
    """Always answers 200 with ok=false and a typed error, never a stack trace."""
    try:
        cfg = _effective_config(db, request, body or AdGuardTestIn())
        with request.app.state.adguard_client_factory(cfg) as client:
            result = AdGuardTestResult(ok=True, server=server_info(client.status()))
            try:  # extras are best effort: DHCP is unavailable on some platforms
                dhcp = client.dhcp_status()
                result.dhcp_enabled, result.dhcp_leases = bool(dhcp.get("enabled")), len(dhcp.get("leases") or [])
                result.configured_clients = len(client.clients().get("clients") or [])
            except AdGuardError:
                pass
            return result
    except AdGuardError as e:
        return AdGuardTestResult(ok=False, error=ErrorInfo(kind=e.kind, message=e.message))
