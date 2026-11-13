from datetime import timedelta

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import __version__
from app.api.deps import get_db, require_user
from app.db.types import utcnow
from app.models.device import Device
from app.models.enums import DeviceStatus, EventType
from app.models.event import Event
from app.schemas.device import DeviceCounts, StatusOut
from app.schemas.settings import AppSettings, DetectedNetworkOut, SettingsOut
from app.services.netinfo import detect_networks
from app.services.settings import load_settings, save_settings

router = APIRouter(prefix="/api", tags=["system"])


@router.get("/health")
def health():
    """Unauthenticated liveness probe (used by the container healthcheck)."""
    return {"ok": True}


@router.get("/status", response_model=StatusOut, dependencies=[Depends(require_user)])
def status(db: Session = Depends(get_db)):
    visible = Device.is_ignored.is_(False)

    def count(*conds) -> int:
        return db.scalar(select(func.count()).select_from(Device).where(visible, *conds)) or 0

    anomalies = db.scalar(
        select(func.count()).select_from(Event).where(
            Event.event_type == EventType.DEVICE_ANOMALY.value, Event.timestamp >= utcnow() - timedelta(days=7)
        )
    ) or 0
    return StatusOut(
        version=__version__,
        anomalies_7d=anomalies,
        devices=DeviceCounts(
            total=count(),
            online=count(Device.is_online.is_(True)),
            offline=count(Device.is_online.is_(False), Device.status != DeviceStatus.UNKNOWN.value),
            new=count(Device.status == DeviceStatus.NEW.value),
            unknown=count(Device.is_known.is_(False)),
            always_connected_down=count(Device.always_connected.is_(True), Device.is_online.is_(False)),
        ),
    )


def _settings_out(db: Session) -> SettingsOut:
    nets = [DetectedNetworkOut(interface=n.interface, cidr=n.cidr) for n in detect_networks()]
    return SettingsOut(settings=load_settings(db), detected_networks=nets, detection_ambiguous=len(nets) != 1)


@router.get("/settings", response_model=SettingsOut, dependencies=[Depends(require_user)])
def get_settings(db: Session = Depends(get_db)):
    return _settings_out(db)


@router.put("/settings", response_model=SettingsOut, dependencies=[Depends(require_user)])
def put_settings(body: AppSettings, request: Request, db: Session = Depends(get_db)):
    save_settings(db, body)
    request.app.state.scanner.reschedule()  # pick up a new scan interval
    return _settings_out(db)
