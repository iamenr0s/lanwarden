from sqlalchemy.orm import Session

from app.models.system import Setting
from app.schemas.settings import AppSettings, ScannerSettings


def load_settings(db: Session) -> AppSettings:
    row = db.get(Setting, "scanner")
    return AppSettings(scanner=ScannerSettings(**row.value) if row else ScannerSettings())


def save_settings(db: Session, settings: AppSettings) -> None:
    value = settings.scanner.model_dump()
    row = db.get(Setting, "scanner")
    if row:
        row.value = value
    else:
        db.add(Setting(key="scanner", value=value))
    db.commit()
