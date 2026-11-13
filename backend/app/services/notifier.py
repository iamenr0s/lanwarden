import logging
from collections import deque

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.db.types import utcnow
from app.models import EventType
from app.models.event import Event
from app.models.system import NotificationRule
from app.notifications.base import Message, NotificationError, NotificationProvider
from app.services.crypto import SecretBox
from app.services.notification_rules import runtime_config

log = logging.getLogger("lanwarden.notifier")

LABELS = {
    EventType.DEVICE_DISCOVERED.value: "New device discovered",
    EventType.DEVICE_CONNECTED.value: "Device connected",
    EventType.DEVICE_DISCONNECTED.value: "Device disconnected",
    EventType.DEVICE_IP_CHANGED.value: "Device IP changed",
    EventType.DEVICE_NAME_CHANGED.value: "Device name changed",
    EventType.ALWAYS_CONNECTED_DEVICE_DOWN.value: "Always-connected device is DOWN",
    EventType.ALWAYS_CONNECTED_DEVICE_RECOVERED.value: "Always-connected device recovered",
    EventType.DEVICE_ANOMALY.value: "Network anomaly (possible spoofing or IP conflict)",
}
MAX_LINES = 30  # a first scan can discover a whole network; keep the message readable


def _device_name(event: Event) -> str:
    d = event.device
    return (d.friendly_name or d.hostname or d.mac_address or d.current_ip or f"device {d.id}") if d else "(deleted device)"


def _event_dict(event: Event) -> dict:
    d = event.device
    return {
        "id": event.id, "type": event.event_type, "label": LABELS.get(event.event_type, event.event_type),
        "timestamp": event.timestamp.isoformat(), "old_value": event.old_value, "new_value": event.new_value,
        "source": event.source,
        "device": {"id": d.id, "name": _device_name(event), "ip": d.current_ip, "mac": d.mac_address} if d else None,
    }


def build_message(events: list[Event]) -> Message:
    """One digest per rule per scan, so discovering 50 devices at once is one message, not 50."""
    lines = []
    for e in events[:MAX_LINES]:
        d = e.device
        where = ", ".join(x for x in (d.current_ip if d else None, d.mac_address if d else None) if x)
        if e.event_type in (EventType.DEVICE_IP_CHANGED.value, EventType.DEVICE_NAME_CHANGED.value):
            change = f" ({e.old_value} -> {e.new_value})"
        elif e.event_type == EventType.DEVICE_ANOMALY.value:
            change = f" ({e.new_value})"
        else:
            change = ""
        lines.append(f"- {LABELS.get(e.event_type, e.event_type)}: {_device_name(e)}{f' [{where}]' if where else ''}{change}")
    if len(events) > MAX_LINES:
        lines.append(f"... and {len(events) - MAX_LINES} more")
    if len(events) == 1:
        title = f"LanWarden: {LABELS.get(events[0].event_type, events[0].event_type)} - {_device_name(events[0])}"
    else:
        title = f"LanWarden: {len(events)} network events"
    return Message(title=title, body="\n".join(lines), events=[_event_dict(e) for e in events])


class Notifier:
    def __init__(self, session_factory: sessionmaker[Session], providers: dict[str, NotificationProvider], box: SecretBox):
        self._sf, self.providers, self._box = session_factory, providers, box
        self.deliveries: deque[dict] = deque(maxlen=50)  # in memory, newest first
        self._next_id = 1

    def _record(self, rule: NotificationRule, count: int, error: str | None) -> None:
        self.deliveries.appendleft({"id": self._next_id, "time": utcnow(), "rule_id": rule.id, "rule_name": rule.name,
                                    "provider": rule.provider, "events": count, "ok": error is None, "error": error})
        self._next_id += 1

    def deliver(self, rule: NotificationRule, message: Message, count: int) -> str | None:
        """Send and record. Returns the error text, or None on success. Never raises."""
        provider = self.providers.get(rule.provider)
        try:
            if provider is None:
                raise NotificationError(f"unknown provider {rule.provider!r}")
            provider.send(runtime_config(rule, provider, self._box), message)
            error = None
        except NotificationError as e:
            error = str(e)[:300]
        except ValueError as e:  # undecryptable secret / invalid stored config
            error = str(e)[:300]
        except Exception:  # a provider bug must not break scanning
            log.exception("notification provider %s crashed", rule.provider)
            error = "unexpected error (see server log)"
        if error:
            log.warning("notification rule %s (%s) failed: %s", rule.id, rule.provider, error)
        self._record(rule, count, error)
        return error

    def dispatch(self, since_event_id: int) -> None:
        """Notify about events created after `since_event_id` (called after each scan commits)."""
        with self._sf() as db:
            rules = db.scalars(select(NotificationRule).where(NotificationRule.enabled.is_(True))).all()
            if not rules:
                return
            events = db.scalars(select(Event).where(Event.id > since_event_id).order_by(Event.id)).unique().all()
            # per-device switches: ignored devices and devices with alerts off are silent
            events = [e for e in events if e.device and e.device.alert_enabled and not e.device.is_ignored]
            for rule in rules:
                matching = [e for e in events if e.event_type in rule.event_types]
                if matching:
                    self.deliver(rule, build_message(matching), len(matching))
