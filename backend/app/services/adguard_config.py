from sqlalchemy.orm import Session

from app.integrations.adguard import AdGuardConfig, AdGuardError
from app.models.system import Setting
from app.schemas.adguard import AdGuardConfigIn, AdGuardConfigOut
from app.services.crypto import SecretBox

KEY = "adguard"


def get_public(db: Session) -> AdGuardConfigOut:
    row = db.get(Setting, KEY)
    if not row:
        return AdGuardConfigOut(configured=False)
    v = row.value
    return AdGuardConfigOut(
        configured=True, url=v["url"], username=v.get("username", ""), verify_tls=v.get("verify_tls", True),
        timeout_seconds=v.get("timeout_seconds", 10), password_set=bool(v.get("password_enc")),
    )


def save(db: Session, box: SecretBox, body: AdGuardConfigIn) -> None:
    row = db.get(Setting, KEY)
    value = body.model_dump(exclude={"password"})
    if body.password is not None:
        value["password_enc"] = box.encrypt(body.password) if body.password else ""
    elif row:
        value["password_enc"] = row.value.get("password_enc", "")
    else:
        value["password_enc"] = ""
    if row:
        row.value = value
    else:
        db.add(Setting(key=KEY, value=value))
    db.commit()


def runtime_config(db: Session, box: SecretBox) -> AdGuardConfig:
    """Decrypted config for server-side use only. Raises AdGuardError if absent or unreadable."""
    row = db.get(Setting, KEY)
    if not row:
        raise AdGuardError("not_configured", "AdGuard Home is not configured")
    v = row.value
    password = ""
    if v.get("password_enc"):
        password = box.decrypt(v["password_enc"])
        if password is None:
            raise AdGuardError("not_configured", "The stored password cannot be decrypted (secret key changed?); enter it again")
    return AdGuardConfig(
        url=v["url"], username=v.get("username", ""), password=password,
        verify_tls=v.get("verify_tls", True), timeout_seconds=v.get("timeout_seconds", 10),
    )
