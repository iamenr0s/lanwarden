import hashlib
import hmac
import json
import smtplib
import ssl
from datetime import timedelta

import httpx
import pytest
from pydantic import ValidationError
from sqlalchemy import select

from app.db.types import utcnow
from app.discovery.base import DeviceObservation, DiscoveryProvider, ProviderResult
from app.models import Device, Event
from app.models.system import NotificationRule
from app.notifications.base import Message, NotificationError
from app.notifications.email_provider import EmailConfig, EmailProvider
from app.notifications.webhook import WebhookConfig, WebhookProvider
from app.schemas.settings import ScannerSettings
from app.services.inventory import process_scan
from app.services.notifier import MAX_LINES, build_message

SMTP_PW, HOOK_SECRET = "smtp-s3cret", "hook-s3cret"
EMAIL = {"host": "smtp.example.com", "port": 587, "security": "starttls", "username": "bot", "password": SMTP_PW,
         "from_addr": "guard@example.com", "to_addrs": ["me@example.com"], "verify_tls": True}
HOOK = {"url": "https://hooks.example.com/services/T000/B000/XXXXTOKEN", "secret": HOOK_SECRET, "verify_tls": True}
ALL = ["DEVICE_DISCOVERED", "DEVICE_CONNECTED", "DEVICE_DISCONNECTED", "DEVICE_IP_CHANGED", "DEVICE_NAME_CHANGED",
       "ALWAYS_CONNECTED_DEVICE_DOWN", "ALWAYS_CONNECTED_DEVICE_RECOVERED"]
MSG = Message(title="Title\r\nBcc: evil@example.com", body="body line", events=[{"id": 1}])


class FakeSMTP:
    instances: list = []
    fail_login = False

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port, self.timeout, self.context = host, port, timeout, context
        self.calls, self.sent = [], []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        self.calls.append("starttls")

    def login(self, user, pw):
        if FakeSMTP.fail_login:
            raise smtplib.SMTPAuthenticationError(535, b"bad credentials")
        self.calls.append(("login", user, pw))

    def send_message(self, msg):
        self.sent.append(msg)


@pytest.fixture(autouse=True)
def _reset_smtp():
    FakeSMTP.instances, FakeSMTP.fail_login = [], False


def raising(exc):
    class Raises(FakeSMTP):
        def __init__(self, *a, **k):
            raise exc

    return Raises


# ---- providers ----------------------------------------------------------------------------
def email_provider(factory=FakeSMTP):
    p = EmailProvider()
    p.smtp_factory = p.smtp_ssl_factory = factory
    return p


def test_email_starttls_login_and_header_injection_blocked():
    email_provider().send(EmailConfig(**EMAIL), MSG)
    smtp = FakeSMTP.instances[0]
    assert smtp.calls == ["starttls", ("login", "bot", SMTP_PW)] and smtp.timeout == 10
    msg = smtp.sent[0]
    assert "\n" not in msg["Subject"] and msg["Bcc"] is None  # CRLF stripped: no injected header
    assert msg["To"] == "me@example.com" and "body line" in msg.get_content()


def test_email_ssl_mode_skips_starttls_and_no_login_without_username():
    email_provider().send(EmailConfig(**{**EMAIL, "security": "ssl", "username": "", "password": None}), MSG)
    assert FakeSMTP.instances[0].calls == []


def test_email_failures_become_notification_errors():
    FakeSMTP.fail_login = True
    with pytest.raises(NotificationError, match="authentication failed") as e:
        email_provider().send(EmailConfig(**EMAIL), MSG)
    assert SMTP_PW not in str(e.value)
    FakeSMTP.fail_login = False
    for exc, text in [(ConnectionRefusedError(), "SMTP error"), (TimeoutError(), "Timed out"), (ssl.SSLError(1, "bad cert"), "TLS")]:
        with pytest.raises(NotificationError, match=text):
            email_provider(raising(exc)).send(EmailConfig(**EMAIL), MSG)


@pytest.mark.parametrize("patch", [
    {"from_addr": "a@b.co\nBcc: x@y.zz"}, {"to_addrs": ["not-an-address"]}, {"to_addrs": []},
    {"to_addrs": ["a@b.co, c@d.ee"]}, {"host": "bad host;rm"}, {"port": 0}, {"security": "magic"}, {"extra": 1},
])
def test_email_config_validation(patch):
    with pytest.raises(ValidationError):
        EmailConfig(**{**EMAIL, **patch})


def test_webhook_payload_and_signature():
    seen = {}

    def handler(request):
        seen["body"], seen["sig"] = request.content, request.headers.get("x-lanwarden-signature")
        return httpx.Response(200)

    p = WebhookProvider()
    p.transport = httpx.MockTransport(handler)
    p.send(WebhookConfig(**HOOK), Message("T", "B", [{"id": 7}]))
    assert json.loads(seen["body"]) == {"source": "lanwarden", "title": "T", "text": "T\nB", "events": [{"id": 7}]}
    assert seen["sig"] == "sha256=" + hmac.new(HOOK_SECRET.encode(), seen["body"], hashlib.sha256).hexdigest()
    p.send(WebhookConfig(url=HOOK["url"]), Message("T", "B"))  # unsigned without a secret
    assert seen["sig"] is None


def _raise(exc):
    def handler(request):
        raise exc

    return handler


@pytest.mark.parametrize("handler, text", [
    (lambda r: httpx.Response(500), "HTTP 500"),
    (lambda r: httpx.Response(302, headers={"location": "http://elsewhere"}), "HTTP 302"),
    (_raise(httpx.ReadTimeout("t")), "Timed out"),
    (_raise(httpx.ConnectError("refused")), "Could not reach"),
])
def test_webhook_failures_never_leak_the_url_token(handler, text):
    p = WebhookProvider()
    p.transport = httpx.MockTransport(handler)
    with pytest.raises(NotificationError, match=text) as e:
        p.send(WebhookConfig(**HOOK), MSG)
    assert "XXXXTOKEN" not in str(e.value) and HOOK_SECRET not in str(e.value)


@pytest.mark.parametrize("url", ["ftp://x", "not a url", "http://", "https://user:pw@host/x"])
def test_webhook_url_validation(url):
    with pytest.raises(ValidationError):
        WebhookConfig(url=url)


# ---- rules API ----------------------------------------------------------------------------
def rule(provider="webhook", config=None, events=("DEVICE_DISCOVERED",), **kw):
    return {"name": "r", "provider": provider, "event_types": list(events),
            "config": config or (HOOK if provider == "webhook" else EMAIL), **kw}


def test_rules_require_auth(client):
    assert client.get("/api/notifications/rules").status_code == 401
    assert client.post("/api/notifications/rules", json=rule()).status_code == 401
    assert client.get("/api/notifications/deliveries").status_code == 401


def test_secrets_are_encrypted_at_rest_and_never_returned(authed, app):
    for body in (rule("webhook"), rule("email")):
        r = authed.post("/api/notifications/rules", json=body)
        assert r.status_code == 201
        assert HOOK_SECRET not in r.text and SMTP_PW not in r.text
    listed = authed.get("/api/notifications/rules")
    assert HOOK_SECRET not in listed.text and SMTP_PW not in listed.text
    hook, mail = listed.json()
    assert hook["config"]["secret_set"] is True and "secret" not in hook["config"]
    # the URL is a bearer token: never returned, only a hint of where it points
    assert hook["config"]["url_set"] is True and "url" not in hook["config"] and "XXXXTOKEN" not in listed.text
    assert hook["config"]["url_hint"] == "https://hooks.example.com/\u2026"
    assert mail["config"]["password_set"] is True and "password" not in mail["config"]
    with app.state.session_factory() as db:
        stored = [r.config for r in db.scalars(select(NotificationRule).order_by(NotificationRule.id))]
    assert HOOK_SECRET not in str(stored) and SMTP_PW not in str(stored) and "XXXXTOKEN" not in str(stored)
    assert "url" not in stored[0] and stored[0]["url_enc"].startswith("v2:gAAAA")
    assert stored[0]["secret_enc"].startswith("v2:gAAAA") and stored[1]["password_enc"].startswith("v2:gAAAA")


def test_update_keeps_secret_when_omitted_replaces_when_given(authed, app):
    rid = authed.post("/api/notifications/rules", json=rule("webhook")).json()["id"]
    sent = {}

    def handler(request):
        sent.update(sig=request.headers.get("x-lanwarden-signature"), body=request.content)
        return httpx.Response(200)

    app.state.notifier.providers["webhook"].transport = httpx.MockTransport(handler)
    no_secret = {"verify_tls": True}  # the stored URL is kept when it is omitted
    out = authed.put(f"/api/notifications/rules/{rid}", json=rule("webhook", no_secret, events=ALL, name="renamed")).json()
    assert out["name"] == "renamed" and out["config"]["secret_set"] is True and len(out["event_types"]) == 7
    assert authed.post(f"/api/notifications/rules/{rid}/test").json() == {"ok": True, "error": None}
    assert sent["sig"] == "sha256=" + hmac.new(HOOK_SECRET.encode(), sent["body"], hashlib.sha256).hexdigest()  # old secret kept

    authed.put(f"/api/notifications/rules/{rid}", json=rule("webhook", {**no_secret, "secret": "rotated"}))
    authed.post(f"/api/notifications/rules/{rid}/test")
    assert sent["sig"] == "sha256=" + hmac.new(b"rotated", sent["body"], hashlib.sha256).hexdigest()


def test_rule_validation_and_lifecycle(authed):
    bad = [
        rule(events=[]), rule(events=["NOT_AN_EVENT"]), rule(name=""), rule(provider="telegram"),
        rule("email", {**EMAIL, "to_addrs": ["bad"]}), rule("webhook", {"url": "ftp://x"}), {**rule(), "extra": 1},
    ]
    assert [authed.post("/api/notifications/rules", json=b).status_code for b in bad] == [422] * len(bad)
    rid = authed.post("/api/notifications/rules", json=rule()).json()["id"]
    assert authed.put(f"/api/notifications/rules/{rid}", json=rule("email")).status_code == 422  # provider is fixed
    assert authed.put("/api/notifications/rules/999", json=rule()).status_code == 404
    assert authed.delete(f"/api/notifications/rules/{rid}").status_code == 204
    assert authed.delete(f"/api/notifications/rules/{rid}").status_code == 404
    assert authed.post(f"/api/notifications/rules/{rid}/test").status_code == 404
    assert authed.get("/api/notifications/rules").json() == []


def test_test_endpoint_reports_failure_without_crashing(authed, app):
    rid = authed.post("/api/notifications/rules", json=rule()).json()["id"]
    app.state.notifier.providers["webhook"].transport = httpx.MockTransport(lambda r: httpx.Response(503))
    r = authed.post(f"/api/notifications/rules/{rid}/test")
    assert r.status_code == 200 and r.json()["ok"] is False and "HTTP 503" in r.json()["error"] and "XXXXTOKEN" not in r.text
    d = authed.get("/api/notifications/deliveries").json()
    assert d[0]["ok"] is False and d[0]["rule_id"] == rid and d[0]["events"] == 0


def test_undecryptable_secret_is_reported(authed, app):
    rid = authed.post("/api/notifications/rules", json=rule("email")).json()["id"]
    with app.state.session_factory() as db:
        r = db.get(NotificationRule, rid)
        r.config = {**r.config, "password_enc": "gAAAAAgarbage"}
        db.commit()
    res = authed.post(f"/api/notifications/rules/{rid}/test").json()
    assert res["ok"] is False and "cannot be decrypted" in res["error"]


# ---- message building ---------------------------------------------------------------------
def make_events(app, n, etype="DEVICE_DISCOVERED"):
    with app.state.session_factory() as db:
        for i in range(n):
            d = Device(mac_address=f"aa:bb:cc:00:01:{i:02x}", current_ip=f"192.168.1.{i + 10}", hostname=f"dev{i}")
            db.add(d)
            db.flush()
            db.add(Event(device_id=d.id, event_type=etype, new_value=d.current_ip, source="arp_scan"))
        db.commit()
        return list(db.scalars(select(Event).order_by(Event.id)).unique())


def test_build_message_single_multiple_and_truncated(app, client):
    one = build_message(make_events(app, 1))
    assert one.title == "LanWarden: New device discovered - dev0" and "192.168.1.10" in one.body and len(one.events) == 1


def test_build_message_truncates_text_but_keeps_all_structured_events(app, client):
    many = build_message(make_events(app, MAX_LINES + 6))
    assert many.title == f"LanWarden: {MAX_LINES + 6} network events" and many.body.splitlines()[-1] == "... and 6 more"
    assert len(many.events) == MAX_LINES + 6


# ---- dispatch through the scanner ---------------------------------------------------------
class Fake(DiscoveryProvider):
    name = "fake"

    def __init__(self, obs=()):
        self.obs = list(obs)

    def enabled(self, s):
        return True

    def scan(self, ctx):
        return ProviderResult(self.obs)


def seen(*pairs):
    return [DeviceObservation(source="fake", mac=m, ip=ip) for m, ip in pairs]


@pytest.fixture()
def hook(authed, app):
    """A webhook rule (discovered + down) and a transport that records every delivery."""
    delivered = []

    def handler(request):
        delivered.append(json.loads(request.content))
        return httpx.Response(200)

    app.state.notifier.providers["webhook"].transport = httpx.MockTransport(handler)
    authed.post("/api/notifications/rules", json=rule(events=["DEVICE_DISCOVERED", "ALWAYS_CONNECTED_DEVICE_DOWN"]))
    return delivered


def test_first_scan_sends_one_digest_not_one_message_per_device(authed, app, hook):
    app.state.scanner.providers = [Fake(seen(("aa:bb:cc:00:00:01", "192.168.1.1"), ("aa:bb:cc:00:00:02", "192.168.1.2"),
                                             ("aa:bb:cc:00:00:03", "192.168.1.3")))]
    app.state.scanner.run_once("manual")
    assert len(hook) == 1 and len(hook[0]["events"]) == 3 and hook[0]["title"] == "LanWarden: 3 network events"
    assert {e["type"] for e in hook[0]["events"]} == {"DEVICE_DISCOVERED"}
    app.state.scanner.run_once("manual")  # nothing new happened
    assert len(hook) == 1


def test_only_new_events_are_sent_and_only_matching_types(authed, app, hook):
    app.state.scanner.providers = [Fake(seen(("aa:bb:cc:00:00:01", "192.168.1.1")))]
    app.state.scanner.run_once("manual")
    app.state.scanner.providers = [Fake(seen(("aa:bb:cc:00:00:01", "192.168.1.99"), ("aa:bb:cc:00:00:02", "192.168.1.2")))]
    app.state.scanner.run_once("manual")  # IP change is NOT in the rule's types; the new device is
    assert len(hook) == 2 and [e["type"] for e in hook[1]["events"]] == ["DEVICE_DISCOVERED"]
    assert hook[1]["events"][0]["device"]["ip"] == "192.168.1.2"


def test_per_device_alert_switch_ignore_and_disabled_rules_silence_notifications(authed, app, hook):
    old = utcnow() - timedelta(hours=1)
    with app.state.session_factory() as db:
        db.add_all([
            Device(mac_address="aa:bb:cc:00:00:01", current_ip="192.168.1.1", alert_enabled=False, always_connected=True,
                   is_known=True, is_online=True, first_seen=old, last_seen=old, status="ONLINE"),
            Device(mac_address="aa:bb:cc:00:00:02", current_ip="192.168.1.2", is_ignored=True, always_connected=True,
                   is_known=True, is_online=True, first_seen=old, last_seen=old, status="ONLINE"),
        ])
        db.commit()
    app.state.scanner.providers = [Fake()]  # both devices are silent: DOWN events are recorded...
    app.state.scanner.run_once("manual")
    with app.state.session_factory() as db:
        assert list(db.scalars(select(Event.event_type))).count("ALWAYS_CONNECTED_DEVICE_DOWN") == 2
    assert hook == []  # ...but neither device may notify

    rid = authed.get("/api/notifications/rules").json()[0]["id"]
    authed.put(f"/api/notifications/rules/{rid}", json=rule(enabled=False))
    app.state.scanner.providers = [Fake(seen(("aa:bb:cc:00:00:09", "192.168.1.9")))]
    app.state.scanner.run_once("manual")
    assert hook == []  # disabled rule


def test_always_connected_down_and_recovered_notify(authed, app):
    delivered = []

    def handler(request):
        delivered.append(json.loads(request.content))
        return httpx.Response(200)

    app.state.notifier.providers["webhook"].transport = httpx.MockTransport(handler)
    authed.post("/api/notifications/rules", json=rule(events=["ALWAYS_CONNECTED_DEVICE_DOWN", "ALWAYS_CONNECTED_DEVICE_RECOVERED"]))
    t0, settings = utcnow(), ScannerSettings()
    obs = seen(("aa:bb:cc:00:00:01", "192.168.1.1"))
    with app.state.session_factory() as db:
        process_scan(db, obs, True, settings, t0)
        db.scalar(select(Device)).always_connected = True
        db.commit()
        process_scan(db, [], True, settings, t0 + timedelta(seconds=400))
        db.commit()
    app.state.notifier.dispatch(0)
    with app.state.session_factory() as db:
        last = db.scalar(select(Event.id).order_by(Event.id.desc()))
        process_scan(db, obs, True, settings, t0 + timedelta(seconds=500))
        db.commit()
    app.state.notifier.dispatch(last)
    assert [d["events"][0]["type"] for d in delivered] == ["ALWAYS_CONNECTED_DEVICE_DOWN", "ALWAYS_CONNECTED_DEVICE_RECOVERED"]
    assert delivered[0]["title"].startswith("LanWarden: Always-connected device is DOWN")


def test_failing_notification_is_recorded_and_never_breaks_the_scan(authed, app):
    app.state.notifier.providers["webhook"].transport = httpx.MockTransport(lambda r: httpx.Response(500))
    authed.post("/api/notifications/rules", json=rule())
    app.state.scanner.providers = [Fake(seen(("aa:bb:cc:00:00:01", "192.168.1.1")))]
    run = app.state.scanner.run_once("manual")
    assert run["error"] is None and run["summary"]["discovered"] == 1  # scan result kept
    d = authed.get("/api/notifications/deliveries").json()[0]
    assert d["ok"] is False and "HTTP 500" in d["error"] and d["events"] == 1
    assert authed.get("/api/devices").json()["total"] == 1


def test_crashing_provider_does_not_break_scan_or_leak(authed, app):
    class Crashy(WebhookProvider):
        def send(self, cfg, message):
            raise RuntimeError("secret internal detail")

    app.state.notifier.providers["webhook"] = Crashy()
    authed.post("/api/notifications/rules", json=rule())
    app.state.scanner.providers = [Fake(seen(("aa:bb:cc:00:00:01", "192.168.1.1")))]
    assert app.state.scanner.run_once("manual")["error"] is None
    d = authed.get("/api/notifications/deliveries").json()[0]
    assert d["ok"] is False and "secret internal detail" not in d["error"]
