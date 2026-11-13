from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select

from app.db.types import utcnow
from app.discovery import adguard as ag
from app.discovery.base import ScanContext
from app.integrations.adguard import AdGuardClient, AdGuardConfig, AdGuardError
from app.models import Device, Event
from app.models.system import Setting
from app.schemas.settings import ScannerSettings
from app.services.netinfo import DetectedNetwork
from tests.adguard_mock import CONFIG, PASSWORD, FakeAdGuard, install, query

CFG = AdGuardConfig(url="http://192.168.0.2:3000", username="admin", password=PASSWORD, timeout_seconds=5)
LAN = [DetectedNetwork("eth0", "192.168.0.0/24")]


def client_for(fake):
    return AdGuardClient(CFG, transport=httpx.MockTransport(fake.handler))


# ---- client error mapping -----------------------------------------------------------------
@pytest.mark.parametrize(
    "route, kind",
    [
        ((401, "no"), "auth"),
        ((429, "slow down"), "auth"),
        ((503, "down"), "unavailable"),
        ((302, ""), "bad_response"),
        ((404, ""), "bad_response"),
        ((200, "<html>not json</html>"), "bad_response"),
        ((200, {"unexpected": True}), "bad_response"),
        (httpx.ReadTimeout("slow"), "timeout"),
        (httpx.ConnectError("connection refused"), "unavailable"),
        (httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] self-signed"), "tls"),
    ],
)
def test_client_maps_failures_to_typed_errors(route, kind):
    with pytest.raises(AdGuardError) as e:
        client_for(FakeAdGuard({"GET /status": route})).status()
    assert e.value.kind == kind
    assert PASSWORD not in e.value.message  # credentials never appear in errors


def test_client_wrong_password_is_auth_error():
    with pytest.raises(AdGuardError) as e:
        client_for(FakeAdGuard(password="different")).status()
    assert e.value.kind == "auth"


def test_client_uses_control_base_path_and_basic_auth():
    fake = FakeAdGuard()
    client_for(fake).status()
    assert fake.requests[0].url.path == "/control/status"


# ---- parsing ------------------------------------------------------------------------------
def test_parse_time_handles_nanoseconds_and_offsets():
    assert ag.parse_time("2024-05-01T10:00:00.123456789Z").hour == 10
    assert ag.parse_time("2018-11-26T00:02:41+03:00").hour == 21  # converted to UTC
    assert ag.parse_time("garbage") is None and ag.parse_time(None) is None


def test_dhcp_observations_skip_expired_and_invalid_and_are_identity_only():
    now = utcnow()
    status = {
        "leases": [
            {"mac": "AA:BB:CC:00:00:01", "ip": "192.168.0.20", "hostname": "pixel", "expires": (now + timedelta(hours=1)).isoformat()},
            {"mac": "aa:bb:cc:00:00:02", "ip": "192.168.0.21", "hostname": "old", "expires": (now - timedelta(hours=1)).isoformat()},
            {"mac": "bad", "ip": "192.168.0.22", "hostname": "x", "expires": (now + timedelta(hours=1)).isoformat()},
        ],
        "static_leases": [{"mac": "aa:bb:cc:00:00:03", "ip": "192.168.0.3", "hostname": "nas"}],
    }
    obs = ag.dhcp_observations(status, now)
    assert [(o.mac, o.ip, o.hostname) for o in obs] == [
        ("aa:bb:cc:00:00:01", "192.168.0.20", "pixel"), ("aa:bb:cc:00:00:03", "192.168.0.3", "nas")]
    assert all(o.presence is False for o in obs)


def test_client_observations():
    obs = ag.client_observations({
        "clients": [{"name": "Kitchen tablet", "ids": ["aa:bb:cc:00:00:09", "192.168.0.9"]},
                    {"name": "IP only", "ids": ["192.168.0.30", "client-id-x"]},
                    {"name": "", "ids": ["192.168.0.31"]}],
        "auto_clients": [{"ip": "192.168.0.40", "name": "printer.lan", "source": "rDNS"},
                         {"ip": "127.0.0.1", "name": "localhost"}, {"ip": "192.168.0.41", "name": "192.168.0.41"}],
    })
    assert [(o.mac, o.ip, o.hostname) for o in obs] == [
        ("aa:bb:cc:00:00:09", "192.168.0.9", "Kitchen tablet"), (None, "192.168.0.30", "IP only"),
        (None, "192.168.0.40", "printer.lan"), (None, "192.168.0.41", None)]
    assert all(o.presence is False for o in obs)


def test_querylog_observations_window_dedup_and_filter():
    doc = {"data": [query("192.168.0.20", "a.com", name="pixel"), query("192.168.0.20", "b.com"),
                    query("192.168.0.21", "old.com", ago=3600), query("10.9.9.9", "x.com"), query("127.0.0.1", "y.com")]}
    allowed = lambda ip: ip.startswith("192.168.0.")  # noqa: E731
    obs = ag.querylog_observations(doc, utcnow() - timedelta(seconds=360), allowed)
    assert [(o.ip, o.hostname, o.presence) for o in obs] == [("192.168.0.20", "pixel", True)]


# ---- provider ------------------------------------------------------------------------------
def ctx(adguard=CFG, **kw):
    return ScanContext(ScannerSettings(adguard_discovery_enabled=True, **kw), LAN, adguard)


def provider(fake):
    return ag.AdGuardProvider(lambda cfg: AdGuardClient(cfg, transport=httpx.MockTransport(fake.handler)))


def test_provider_collects_all_three_sources():
    fake = FakeAdGuard({
        "GET /dhcp/status": (200, {"leases": [{"mac": "aa:bb:cc:00:00:01", "ip": "192.168.0.20", "hostname": "pixel",
                                               "expires": (utcnow() + timedelta(hours=1)).isoformat()}], "static_leases": []}),
        "GET /clients": (200, {"clients": [], "auto_clients": [{"ip": "192.168.0.20", "name": "pixel.lan", "source": "rDNS"}]}),
        "GET /querylog": (200, {"data": [query("192.168.0.20", "a.com")]}),
    })
    r = provider(fake).scan(ctx())
    assert r.error is None
    assert sorted(o.source for o in r.observations) == ["adguard_clients", "adguard_dhcp", "adguard_querylog"]


def test_provider_unavailable_and_auth_errors_do_not_raise():
    assert "not configured" in ag.AdGuardProvider(None).scan(ctx(adguard=None)).error
    r = provider(FakeAdGuard({"GET /status": httpx.ConnectError("refused")})).scan(ctx())
    assert r.observations == [] and "Cannot connect" in r.error
    r = provider(FakeAdGuard(password="other")).scan(ctx())
    assert "rejected the username or password" in r.error and PASSWORD not in r.error


def test_provider_tolerates_one_failing_endpoint_but_not_all():
    fake = FakeAdGuard({"GET /dhcp/status": (500, {"message": "not implemented"}),
                        "GET /querylog": (200, {"data": [query("192.168.0.20", "a.com")]})})
    r = provider(fake).scan(ctx())
    assert r.error is None and [o.source for o in r.observations] == ["adguard_querylog"]
    fake = FakeAdGuard({"GET /dhcp/status": (500, {}), "GET /clients": (500, {}), "GET /querylog": (500, {})})
    assert "could not be read" in provider(fake).scan(ctx()).error


# ---- settings / connection API ------------------------------------------------------------
def test_config_roundtrip_never_exposes_or_stores_plaintext_password(authed, app):
    assert authed.get("/api/integrations/adguard").json() == {
        "configured": False, "url": None, "username": "", "verify_tls": True, "timeout_seconds": 10, "password_set": False}
    r = authed.put("/api/integrations/adguard", json=CONFIG)
    assert r.status_code == 200 and "password" not in r.json() and r.json()["password_set"] is True
    assert PASSWORD not in authed.get("/api/integrations/adguard").text
    with app.state.session_factory() as db:
        stored = db.get(Setting, "adguard").value
    assert PASSWORD not in str(stored) and stored["password_enc"].startswith("v2:gAAAA")  # Fernet token

    # saving without a password keeps the stored one
    authed.put("/api/integrations/adguard", json={**{k: v for k, v in CONFIG.items() if k != "password"}, "timeout_seconds": 7})
    out = authed.get("/api/integrations/adguard").json()
    assert out["password_set"] is True and out["timeout_seconds"] == 7


@pytest.mark.parametrize("bad", ["ftp://host", "not a url", "http://", "http://user:pw@host:3000", "http://h/?a=1", "http://h:99999"])
def test_config_rejects_bad_urls(authed, bad):
    assert authed.put("/api/integrations/adguard", json={**CONFIG, "url": bad}).status_code == 422


def test_integration_endpoints_require_auth(client):
    assert client.get("/api/integrations/adguard").status_code == 401
    assert client.post("/api/integrations/adguard/test").status_code == 401


def test_test_connection_success_shows_server_info(authed, app):
    install(app, FakeAdGuard({"GET /dhcp/status": (200, {"enabled": True, "leases": [{}, {}], "static_leases": []}),
                              "GET /clients": (200, {"clients": [{"name": "a", "ids": ["1.2.3.4"]}], "auto_clients": []})}))
    r = authed.post("/api/integrations/adguard/test", json=CONFIG).json()
    assert r["ok"] is True and r["error"] is None
    assert r["server"]["version"] == "v0.107.52" and r["server"]["dns_addresses"] == ["192.168.0.2"]
    assert (r["dhcp_enabled"], r["dhcp_leases"], r["configured_clients"]) == (True, 2, 1)


@pytest.mark.parametrize(
    "fake, kind",
    [
        (FakeAdGuard(password="different"), "auth"),
        (FakeAdGuard({"GET /status": httpx.ReadTimeout("t")}), "timeout"),
        (FakeAdGuard({"GET /status": httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED]")}), "tls"),
        (FakeAdGuard({"GET /status": httpx.ConnectError("refused")}), "unavailable"),
        (FakeAdGuard({"GET /status": (500, "boom")}), "unavailable"),
    ],
)
def test_test_connection_failures_are_200_with_typed_error(authed, app, fake, kind):
    install(app, fake)
    r = authed.post("/api/integrations/adguard/test", json=CONFIG)
    assert r.status_code == 200 and r.json()["ok"] is False and r.json()["error"]["kind"] == kind
    assert PASSWORD not in r.text


def test_test_without_body_uses_saved_config_and_needs_one(authed, app):
    fake = install(app, FakeAdGuard())
    assert authed.post("/api/integrations/adguard/test").json()["error"]["kind"] == "not_configured"
    authed.put("/api/integrations/adguard", json=CONFIG)
    assert authed.post("/api/integrations/adguard/test").json()["ok"] is True
    assert fake.requests  # used the saved (decrypted) password


def test_saved_password_is_never_sent_to_a_changed_url(authed, app):
    fake = install(app, FakeAdGuard())
    authed.put("/api/integrations/adguard", json=CONFIG)
    fake.requests.clear()
    r = authed.post("/api/integrations/adguard/test", json={"url": "http://evil.example:3000"}).json()
    assert r["ok"] is False and r["error"]["kind"] == "auth"  # sent without the stored password
    sent = {x.headers.get("authorization") for x in fake.requests}
    assert all(PASSWORD not in (h or "") for h in sent)
    import base64
    assert base64.b64encode(f"admin:{PASSWORD}".encode()).decode() not in str(sent)


def test_health_status(authed, app):
    install(app, FakeAdGuard())
    assert authed.get("/api/integrations/adguard/status").json() == {
        "configured": False, "reachable": False, "server": None, "error": None}
    authed.put("/api/integrations/adguard", json=CONFIG)
    ok = authed.get("/api/integrations/adguard/status").json()
    assert ok["configured"] and ok["reachable"] and ok["server"]["version"] == "v0.107.52"
    install(app, FakeAdGuard({"GET /status": httpx.ConnectError("refused")}))
    down = authed.get("/api/integrations/adguard/status").json()
    assert down["configured"] and not down["reachable"] and down["error"]["kind"] == "unavailable"


def test_undecryptable_password_is_reported_not_crashed(authed, app):
    authed.put("/api/integrations/adguard", json=CONFIG)
    with app.state.session_factory() as db:
        row = db.get(Setting, "adguard")
        row.value = {**row.value, "password_enc": "gAAAAAgarbage"}
        db.commit()
    r = authed.get("/api/integrations/adguard/status").json()
    assert r["configured"] and not r["reachable"] and "cannot be decrypted" in r["error"]["message"]


# ---- device AdGuard tab --------------------------------------------------------------------
def test_device_adguard_tab(authed, app, seed):
    laptop = seed[0]  # 192.168.1.10
    assert authed.get(f"/api/devices/{laptop}/adguard").json()["configured"] is False  # works without AdGuard

    fake = install(app, FakeAdGuard({
        "POST /clients/search": (200, [{"192.168.1.10": {"name": "Work laptop", "ids": ["192.168.1.10", "aa:bb:cc:00:00:01"]}}]),
        "GET /querylog": (200, {"data": [
            query("192.168.1.10", "example.com"), query("192.168.1.10", "ads.tracker.net", reason="FilteredBlackList"),
            query("192.168.1.10", "example.com"), query("192.168.1.100", "other-device.com")]}),
        "GET /stats": (200, {"top_clients": [{"192.168.1.99": 5}, {"192.168.1.10": 321}]}),
    }))
    authed.put("/api/integrations/adguard", json=CONFIG)
    d = authed.get(f"/api/devices/{laptop}/adguard").json()
    assert d["configured"] and d["available"] and d["recognized"] and d["client_name"] == "Work laptop"
    assert (d["sample_size"], d["sample_blocked"], d["stats_queries"]) == (3, 1, 321)  # .100 entry excluded
    assert d["top_domains"][0] == {"domain": "example.com", "count": 2}
    assert [q["blocked"] for q in d["recent"]] == [False, True, False] and d["last_query"]
    body = next(r for r in fake.requests if r.url.path.endswith("/clients/search")).content
    assert b"192.168.1.10" in body and b"aa:bb:cc:00:00:01" in body


def test_device_adguard_tab_for_unrecognised_device_and_outage(authed, app, seed):
    macless = seed[2]  # no MAC, 192.168.1.50
    install(app, FakeAdGuard())
    authed.put("/api/integrations/adguard", json=CONFIG)
    d = authed.get(f"/api/devices/{macless}/adguard").json()
    assert d["available"] and not d["recognized"] and d["sample_size"] == 0

    install(app, FakeAdGuard({"POST /clients/search": httpx.ReadTimeout("t")}))
    d = authed.get(f"/api/devices/{macless}/adguard").json()
    assert d["configured"] and not d["available"] and d["error"]["kind"] == "timeout"
    assert authed.get("/api/devices/9999/adguard").status_code == 404


# ---- end to end through the scanner --------------------------------------------------------
def test_scan_with_only_adguard_enforces_identity_and_presence_rules(authed, app):
    now = utcnow()
    with app.state.session_factory() as db:
        online = Device(mac_address="aa:bb:cc:00:00:aa", current_ip="192.168.0.50", hostname="tv", is_online=True,
                        is_known=True, status="ONLINE", first_seen=now - timedelta(days=5), last_seen=now - timedelta(minutes=2))
        offline = Device(mac_address="aa:bb:cc:00:00:bb", current_ip="192.168.0.51", is_online=False, is_known=True,
                         status="OFFLINE", first_seen=now - timedelta(days=5), last_seen=now - timedelta(hours=5))
        db.add_all([online, offline])
        db.commit()
        online_id, offline_id = online.id, offline.id

    fake = install(app, FakeAdGuard({
        "GET /dhcp/status": (200, {"leases": [
            {"mac": "aa:bb:cc:00:00:cc", "ip": "192.168.0.60", "hostname": "new-phone", "expires": (now + timedelta(hours=1)).isoformat()},
            {"mac": "aa:bb:cc:00:00:bb", "ip": "192.168.0.51", "hostname": "lease-name", "expires": (now + timedelta(hours=1)).isoformat()}],
            "static_leases": []}),
        "GET /querylog": (200, {"data": [
            query("192.168.0.50", "a.com"),             # online device: DNS activity extends presence
            query("192.168.0.77", "ghost.com"),          # unknown IP: must NOT create a device
            ]}),
    }))
    s = authed.get("/api/settings").json()["settings"]
    s["scanner"].update(arp_scan_enabled=False, neighbor_discovery_enabled=False, adguard_discovery_enabled=True,
                        networks=["192.168.0.0/24"])
    authed.put("/api/settings", json=s)
    authed.put("/api/integrations/adguard", json=CONFIG)

    run = app.state.scanner.run_once("manual")
    assert run["error"] is None and run["providers"][0]["name"] == "adguard" and run["providers"][0]["error"] is None

    with app.state.session_factory() as db:
        by = {d.mac_address: d for d in db.scalars(select(Device)) if d.mac_address}
        assert db.scalar(select(Device).where(Device.current_ip == "192.168.0.77")) is None  # no device from an IP-only sighting
        phone = by["aa:bb:cc:00:00:cc"]  # DHCP lease only: exists, never seen alive
        assert (phone.status, phone.is_online, phone.last_seen, phone.hostname) == ("UNKNOWN", False, None, "new-phone")
        assert by["aa:bb:cc:00:00:aa"].last_seen > now - timedelta(seconds=30)  # DNS query proved presence
        stale = by["aa:bb:cc:00:00:bb"]  # a lease must not revive an offline device
        assert (stale.is_online, stale.status, stale.hostname) == (False, "OFFLINE", "lease-name")
        assert abs((stale.last_seen - (now - timedelta(hours=5))).total_seconds()) < 1  # last_seen untouched
        types = [e.event_type for e in db.scalars(select(Event).where(Event.device_id == phone.id))]
        assert types == ["DEVICE_DISCOVERED"]
        assert stale.current_ip == "192.168.0.51" and offline_id == stale.id and online_id == by["aa:bb:cc:00:00:aa"].id
    assert fake.requests


def test_scan_reports_adguard_problems_without_marking_devices_offline(authed, app):
    now = utcnow()
    with app.state.session_factory() as db:
        db.add(Device(mac_address="aa:bb:cc:00:00:aa", current_ip="192.168.0.50", is_online=True, is_known=True,
                      status="ONLINE", first_seen=now - timedelta(days=5), last_seen=now - timedelta(hours=3)))
        db.commit()
    s = authed.get("/api/settings").json()["settings"]
    s["scanner"].update(arp_scan_enabled=False, neighbor_discovery_enabled=False, adguard_discovery_enabled=True)
    authed.put("/api/settings", json=s)

    run = app.state.scanner.run_once("manual")  # enabled but never configured
    assert "not configured" in run["providers"][0]["error"] and "All discovery providers failed" in run["error"]

    authed.put("/api/integrations/adguard", json=CONFIG)
    install(app, FakeAdGuard(password="rotated"))
    run = app.state.scanner.run_once("manual")
    assert "rejected the username or password" in run["providers"][0]["error"]
    with app.state.session_factory() as db:
        assert db.scalar(select(Device)).is_online is True  # broken provider => no evidence => no false disconnect
