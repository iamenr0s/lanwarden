"""Mocked AdGuard Home API (httpx.MockTransport). Responses follow AdGuard's openapi.yaml."""

import base64
from datetime import timedelta

import httpx

from app.db.types import utcnow
from app.integrations.adguard import AdGuardClient

USER, PASSWORD = "admin", "s3cret-pw"

STATUS = {
    "version": "v0.107.52", "running": True, "protection_enabled": True, "dns_addresses": ["192.168.0.2"],
    "dns_port": 53, "http_port": 3000, "language": "en", "protection_disabled_duration": 0,
}


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "000Z"  # nanosecond-style fraction, as AdGuard emits


def query(client, domain, reason="NotFilteredNotFound", ago=10, name=""):
    return {"client": client, "client_info": {"name": name, "disallowed": False, "disallowed_rule": "", "whois": {}},
            "question": {"name": domain, "type": "A", "class": "IN"}, "reason": reason, "status": "NOERROR",
            "time": iso(utcnow() - timedelta(seconds=ago))}


class FakeAdGuard:
    """routes: {"METHOD /path": (status, json) | Exception | callable(request) -> (status, json)}.
    Records requests; rejects any request without the right Basic credentials with 401."""

    def __init__(self, routes=None, user=USER, password=PASSWORD):
        self.routes = {"GET /status": (200, STATUS), "GET /dhcp/status": (200, {"enabled": True, "leases": [], "static_leases": []}),
                       "GET /clients": (200, {"clients": [], "auto_clients": []}),
                       "GET /querylog": (200, {"data": []}), "GET /stats": (200, {"top_clients": []}),
                       "POST /clients/search": (200, [])}
        self.routes.update(routes or {})
        self.user, self.password = user, password
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        expected = "Basic " + base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        if request.headers.get("authorization") != expected:
            return httpx.Response(401, text="Unauthorized")
        route = self.routes.get(f"{request.method} {request.url.path.removeprefix('/control')}")
        if route is None:
            return httpx.Response(404)
        if isinstance(route, Exception):
            raise route
        status, body = route(request) if callable(route) else route
        return httpx.Response(status, text=body) if isinstance(body, str) else httpx.Response(status, json=body)

    def factory(self):
        return lambda cfg: AdGuardClient(cfg, transport=httpx.MockTransport(self.handler))


def install(app, fake: FakeAdGuard) -> FakeAdGuard:
    app.state.adguard_client_factory = fake.factory()
    return fake


CONFIG = {"url": "http://192.168.0.2:3000", "username": USER, "password": PASSWORD, "verify_tls": True, "timeout_seconds": 5}
