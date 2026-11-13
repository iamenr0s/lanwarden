"""Rule storage. Provider secrets (SMTP password, webhook signing secret) are encrypted at rest:
config JSON holds `<field>_enc` instead of `<field>`, and the API only ever sees `<field>_set`."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.system import NotificationRule
from app.notifications.base import NotificationProvider
from app.schemas.notifications import RuleIn, RuleOut
from app.services.crypto import SecretBox


def _store_config(provider: NotificationProvider, incoming: dict, existing: dict | None, box: SecretBox) -> dict:
    out = {k: v for k, v in incoming.items() if k not in provider.secrets}
    for field in provider.secrets:
        value = incoming.get(field)
        if value:  # a new secret
            out[f"{field}_enc"] = box.encrypt(value)
            if field in provider.hints:
                out[f"{field}_hint"] = provider.hints[field](value)
        else:  # omitted/empty: keep what is stored
            out[f"{field}_enc"] = (existing or {}).get(f"{field}_enc", "")
            if (existing or {}).get(f"{field}_hint"):
                out[f"{field}_hint"] = existing[f"{field}_hint"]
    return out


def missing_required(provider: NotificationProvider, incoming: dict, existing: dict | None) -> list[str]:
    """Secret fields that must be present (now or already stored) but are not."""
    return [f for f in provider.required_secrets if not incoming.get(f) and not (existing or {}).get(f"{f}_enc")]


def encrypt_legacy_fields(db: Session, box: SecretBox, providers: dict[str, NotificationProvider]) -> int:
    """Rules saved before a field became a secret (webhook URLs) hold it in plaintext: encrypt in place.
    Idempotent; returns how many rules changed."""
    changed = 0
    for rule in db.scalars(select(NotificationRule)):
        provider = providers.get(rule.provider)
        legacy = [f for f in (provider.secrets if provider else ()) if rule.config.get(f) and not rule.config.get(f"{f}_enc")]
        if legacy:
            plain = {f: rule.config[f] for f in legacy}
            stored = _store_config(provider, plain, rule.config, box)
            rule.config = {**{k: v for k, v in rule.config.items() if k not in legacy}, **stored}  # new dict: JSON change detection
            changed += 1
    if changed:
        db.commit()
    return changed


def create(db: Session, box: SecretBox, provider: NotificationProvider, body: RuleIn) -> NotificationRule:
    rule = NotificationRule(
        name=body.name, provider=body.provider, event_types=[e.value for e in body.event_types], enabled=body.enabled,
        config=_store_config(provider, body.config, None, box),
    )
    db.add(rule)
    db.commit()
    return rule


def update(db: Session, box: SecretBox, provider: NotificationProvider, rule: NotificationRule, body: RuleIn) -> NotificationRule:
    rule.name, rule.enabled = body.name, body.enabled
    rule.event_types = [e.value for e in body.event_types]
    rule.config = _store_config(provider, body.config, rule.config, box)  # new dict: JSON column change detection
    db.commit()
    return rule


def to_public(rule: NotificationRule, provider: NotificationProvider | None) -> RuleOut:
    secrets = provider.secrets if provider else ()
    cfg = {k: v for k, v in rule.config.items() if not k.endswith("_enc") and k not in secrets}
    for field in secrets:
        cfg[f"{field}_set"] = bool(rule.config.get(f"{field}_enc"))
    return RuleOut(id=rule.id, name=rule.name, provider=rule.provider, event_types=rule.event_types,
                   enabled=rule.enabled, config=cfg)


def runtime_config(rule: NotificationRule, provider: NotificationProvider, box: SecretBox):
    """Validated provider config with secrets decrypted; for server-side sending only.
    Raises ValueError if a stored secret can no longer be decrypted."""
    data = {k: v for k, v in rule.config.items() if not k.endswith(("_enc", "_hint"))}
    for field in provider.secrets:
        token = rule.config.get(f"{field}_enc")
        if token:
            plain = box.decrypt(token)
            if plain is None:
                raise ValueError(f"stored {field} cannot be decrypted (secret key changed?); enter it again")
            data[field] = plain
    return provider.Config.model_validate(data)
