import time

from app.discovery.base import DeviceObservation, DiscoveryProvider, ProviderResult
from app.services.netinfo import DetectedNetwork


class Fake(DiscoveryProvider):
    def __init__(self, name, observations=(), error=None, enabled=True, crash=False):
        self.name, self._obs, self._err, self._enabled, self._crash = name, list(observations), error, enabled, crash

    def enabled(self, scanner):
        return self._enabled

    def scan(self, ctx):
        if self._crash:
            raise RuntimeError("secret internal detail")
        return ProviderResult(self._obs, self._err)


def one(mac="aa:bb:cc:00:00:01", ip="192.168.1.5"):
    return DeviceObservation(source="fake", mac=mac, ip=ip)


def wait_idle(client, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        body = client.get("/api/scanner/runs").json()
        if not body["running"] and body["runs"] and body["runs"][0]["finished_at"]:
            return body
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


def test_run_endpoint_scans_and_reports(authed, app):
    app.state.scanner.providers = [Fake("fake", [one()])]
    assert authed.post("/api/scanner/run").status_code == 202
    run = wait_idle(authed)["runs"][0]
    assert run["trigger"] == "manual" and run["error"] is None
    assert run["summary"]["discovered"] == 1
    assert run["providers"] == [{"name": "fake", "observations": 1, "error": None}]
    devices = authed.get("/api/devices").json()
    assert devices["total"] == 1 and devices["items"][0]["status"] == "NEW"
    assert authed.get("/api/events").json()["items"][0]["event_type"] == "DEVICE_DISCOVERED"


def test_scanner_endpoints_require_auth(client):
    assert client.post("/api/scanner/run").status_code == 401
    assert client.get("/api/scanner/runs").status_code == 401


def test_concurrent_run_is_rejected(authed, app):
    scanner = app.state.scanner
    assert scanner._lock.acquire(blocking=False)
    try:
        assert authed.post("/api/scanner/run").status_code == 409
        assert authed.get("/api/scanner/runs").json()["running"] is True
        assert scanner.run_once("schedule") is None
    finally:
        scanner._lock.release()


def test_provider_errors_are_reported_and_isolated(authed, app):
    scanner = app.state.scanner
    scanner.providers = [Fake("broken", error="arp-scan is not installed"), Fake("crashy", crash=True), Fake("ok", [one()])]
    run = scanner.run_once("manual")
    assert run["error"] is None and run["summary"]["discovered"] == 1  # the healthy provider still counted
    by_name = {p["name"]: p for p in run["providers"]}
    assert by_name["broken"]["error"] == "arp-scan is not installed"
    assert "secret internal detail" not in by_name["crashy"]["error"]  # exception text is not exposed


def test_all_failing_and_none_enabled(authed, app):
    scanner = app.state.scanner
    scanner.providers = [Fake("a", error="boom")]
    assert "All discovery providers failed" in scanner.run_once("manual")["error"]
    scanner.providers = [Fake("a", enabled=False)]
    assert "No discovery providers" in scanner.run_once("manual")["error"]


def test_settings_toggle_disables_provider(authed, app):
    app.state.scanner.providers = [Fake("a", [one()])]
    s = authed.get("/api/settings").json()["settings"]
    s["scanner"]["arp_scan_enabled"] = False

    class Gated(Fake):
        def enabled(self, scanner):
            return scanner.arp_scan_enabled

    app.state.scanner.providers = [Gated("a", [one()])]
    authed.put("/api/settings", json=s)
    assert "No discovery providers" in app.state.scanner.run_once("manual")["error"]


def test_detection_passed_to_providers(authed, app):
    seen = {}

    class Spy(Fake):
        def scan(self, ctx):
            seen["detected"] = ctx.detected
            return ProviderResult()

    scanner = app.state.scanner
    scanner._detect = lambda: [DetectedNetwork("eth0", "10.0.0.0/24")]
    scanner.providers = [Spy("spy")]
    scanner.run_once("manual")
    assert seen["detected"][0].cidr == "10.0.0.0/24"
