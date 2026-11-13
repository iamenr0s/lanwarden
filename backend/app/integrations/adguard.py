"""AdGuard Home API client. Only endpoints documented in AdGuard Home's openapi.yaml are used
(base path /control, HTTP Basic auth). All failures become AdGuardError with a short,
credential-free message and a machine-readable kind."""

import ssl
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True)
class AdGuardConfig:
    url: str
    username: str
    password: str = ""
    verify_tls: bool = True
    timeout_seconds: int = 10


class AdGuardError(Exception):
    """kind: not_configured | timeout | auth | tls | unavailable | bad_response"""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind, self.message = kind, message


class AdGuardClient:
    def __init__(self, cfg: AdGuardConfig, transport: httpx.BaseTransport | None = None):
        self._cfg = cfg
        self._http = httpx.Client(
            base_url=cfg.url.rstrip("/") + "/control",
            auth=(cfg.username, cfg.password) if cfg.username else None,
            verify=cfg.verify_tls,
            timeout=cfg.timeout_seconds,
            follow_redirects=False,  # an un-installed AdGuard redirects to /install.html
            transport=transport,
        )

    def __enter__(self) -> "AdGuardClient":
        return self

    def __exit__(self, *exc) -> None:
        self._http.close()

    def _request(self, method: str, path: str, **kwargs) -> Any:
        host = httpx.URL(self._cfg.url).host
        try:
            resp = self._http.request(method, path, **kwargs)
        except httpx.TimeoutException as e:
            raise AdGuardError("timeout", f"No response from {host} within {self._cfg.timeout_seconds}s") from e
        except httpx.ConnectError as e:
            if isinstance(e.__cause__, ssl.SSLError) or "CERTIFICATE" in str(e).upper():
                raise AdGuardError("tls", f"TLS verification failed for {host}; check the certificate or disable 'Verify TLS'") from e
            raise AdGuardError("unavailable", f"Cannot connect to {host}") from e
        except httpx.HTTPError as e:
            raise AdGuardError("unavailable", f"Request to {host} failed ({type(e).__name__})") from e

        code = resp.status_code
        if code in (401, 403):
            raise AdGuardError("auth", "AdGuard Home rejected the username or password")
        if code == 429:
            raise AdGuardError("auth", "AdGuard Home is rate-limiting logins; wait a few minutes and retry")
        if 300 <= code < 400:
            raise AdGuardError("bad_response", "Unexpected redirect: is AdGuard Home set up, and is the URL right?")
        if code == 404:
            raise AdGuardError("bad_response", "Not found: this URL does not look like AdGuard Home")
        if code >= 500:
            raise AdGuardError("unavailable", f"AdGuard Home returned HTTP {code}")
        if code >= 400:
            raise AdGuardError("bad_response", f"AdGuard Home returned HTTP {code}")
        try:
            return resp.json()
        except ValueError as e:
            raise AdGuardError("bad_response", "AdGuard Home returned a non-JSON response") from e

    # GET /status -> ServerStatus {version, running, protection_enabled, dns_addresses, dns_port, http_port, language}
    def status(self) -> dict:
        data = self._request("GET", "/status")
        if not isinstance(data, dict) or "version" not in data:
            raise AdGuardError("bad_response", "Response is not an AdGuard Home status document")
        return data

    # GET /dhcp/status -> DhcpStatus {enabled, leases[{mac, ip, hostname, expires}], static_leases[...]}
    def dhcp_status(self) -> dict:
        return self._request("GET", "/dhcp/status")

    # GET /clients -> {clients[{name, ids[]}], auto_clients[{ip, name, source}]}
    def clients(self) -> dict:
        return self._request("GET", "/clients")

    # POST /clients/search {"clients":[{"id": ip|mac|cidr|clientid}]} -> [{id: ClientFindSubEntry}]
    def clients_search(self, ids: list[str]) -> list[dict]:
        return self._request("POST", "/clients/search", json={"clients": [{"id": i} for i in ids]})

    # GET /querylog?limit&search -> {data[{client, client_info{name}, question{name,type}, reason, time}]}
    def querylog(self, limit: int = 100, search: str | None = None) -> dict:
        params: dict[str, Any] = {"limit": limit}
        if search:
            params["search"] = search
        return self._request("GET", "/querylog", params=params)

    # GET /stats -> {num_dns_queries, num_blocked_filtering, top_clients[{ip: count}], ...}
    def stats(self) -> dict:
        return self._request("GET", "/stats")
