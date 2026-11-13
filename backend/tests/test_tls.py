import ipaddress
import os
import socket
import ssl
import stat
import threading
import time
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography import x509
from fastapi.testclient import TestClient

from app.__main__ import main, make_server
from app.core.config import Config
from app.core.tls import ensure_selfsigned
from app.main import create_app
from app.services.netinfo import parse_local_ips


def load(path):
    return x509.load_pem_x509_certificate(path.read_bytes())


def sans(cert):
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return set(san.get_values_for_type(x509.DNSName)), {str(i) for i in san.get_values_for_type(x509.IPAddress)}


def trust(cert):
    return ssl.create_default_context(cafile=str(cert))  # trust only this certificate


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---- certificate generation -----------------------------------------------------------------
def test_selfsigned_certificate_contents_and_key_permissions(tmp_path):
    cert_path, key_path = ensure_selfsigned(tmp_path, ["guard.home.lan", "192.168.1.20"])
    cert = load(cert_path)
    dns, ips = sans(cert)
    assert {"localhost", "guard.home.lan"} <= dns and {"127.0.0.1", "192.168.1.20"} <= ips
    assert cert.not_valid_after_utc - datetime.now(timezone.utc) > timedelta(days=800)
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False  # a leaf, never a CA
    assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600 and "BEGIN PRIVATE KEY" in key_path.read_text()


def test_certificate_is_reused_until_names_change_or_expiry_nears(tmp_path):
    first, _ = ensure_selfsigned(tmp_path, ["a.lan"])
    serial = load(first).serial_number
    assert load(ensure_selfsigned(tmp_path, ["a.lan"])[0]).serial_number == serial  # unchanged: reused
    assert load(ensure_selfsigned(tmp_path, ["a.lan", "10.0.0.5"])[0]).serial_number != serial  # new address: reissued
    assert "10.0.0.5" in sans(load(tmp_path / "tls" / "cert.pem"))[1]

    short = tmp_path / "short"
    serial = load(ensure_selfsigned(short, [], days=10)[0]).serial_number  # expires inside the 30-day renewal window
    assert load(ensure_selfsigned(short, [])[0]).serial_number != serial


def test_unreadable_certificate_is_replaced(tmp_path):
    cert_path, _ = ensure_selfsigned(tmp_path, [])
    cert_path.write_text("not a certificate")
    assert load(ensure_selfsigned(tmp_path, [])[0]).subject  # regenerated rather than crashing


def test_parse_local_ips_skips_loopback_and_down_interfaces():
    raw = ('[{"ifname":"lo","flags":["UP"],"addr_info":[{"family":"inet","local":"127.0.0.1"}]},'
           '{"ifname":"eth0","flags":["UP"],"addr_info":[{"family":"inet","local":"192.168.1.5"}]},'
           '{"ifname":"wlan0","flags":["BROADCAST"],"addr_info":[{"family":"inet","local":"10.0.0.2"}]}]')
    assert parse_local_ips(raw) == ["192.168.1.5"]


# ---- configuration decisions ----------------------------------------------------------------
def test_cookies_are_secure_when_declared_or_when_we_terminate_tls():
    assert Config().cookies_secure is False
    assert Config(secure_cookies=True).cookies_secure is True  # a proxy does the TLS
    assert Config(tls_mode="selfsigned").cookies_secure is True and Config(tls_mode="selfsigned").tls_enabled
    assert Config(tls_cert="c.pem", tls_key="k.pem").cookies_secure is True
    assert Config(tls_cert="c.pem").tls_enabled is False  # a certificate without a key is not TLS


def test_plain_http_to_a_remote_host_is_flagged_but_loopback_is_not(app, client):
    assert client.get("/api/auth/state").json()["insecure_transport"] is True  # http://testserver
    local = TestClient(app, base_url="http://localhost")
    assert local.get("/api/auth/state").json()["insecure_transport"] is False
    secure = TestClient(app, base_url="https://guard.home.lan")
    assert secure.get("/api/auth/state").json()["insecure_transport"] is False


# ---- the real thing: a TLS handshake against the actual startup code ------------------------------
@pytest.fixture()
def tls_server(tmp_path):
    port = free_port()
    cfg = Config(data_dir=tmp_path, frontend_dir=tmp_path / "none", scheduler_enabled=False, host="127.0.0.1", port=port, tls_mode="selfsigned")
    server = make_server(cfg)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 15
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started, "server did not start"
    yield port, tmp_path / "tls" / "cert.pem"
    server.should_exit = True
    thread.join(10)


def test_server_speaks_https_with_hsts_and_secure_cookies(tls_server):
    port, cert = tls_server
    base = f"https://127.0.0.1:{port}"
    r = httpx.get(f"{base}/api/health", verify=trust(cert))  # trusting only the generated certificate
    assert r.status_code == 200 and "max-age" in r.headers["strict-transport-security"]
    setup = httpx.post(f"{base}/api/auth/setup", json={"username": "admin", "password": "correct horse battery"}, verify=trust(cert))
    assert setup.status_code == 201 and "secure" in setup.headers["set-cookie"].lower()
    assert setup.json()["insecure_transport"] is False

    with pytest.raises(httpx.ConnectError):  # without trusting it, verification fails: it really is a self-signed cert
        httpx.get(f"{base}/api/health")
    with pytest.raises(httpx.HTTPError):  # and the TLS port does not answer plain HTTP
        httpx.get(f"http://127.0.0.1:{port}/api/health", timeout=3)


def test_bring_your_own_certificate_is_used_as_is(tmp_path):
    cert, key = ensure_selfsigned(tmp_path / "pki", ["byo.lan"])
    port = free_port()
    cfg = Config(data_dir=tmp_path / "data", frontend_dir=tmp_path / "none", scheduler_enabled=False, host="127.0.0.1", port=port,
                 tls_cert=cert, tls_key=key)
    server = make_server(cfg)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 15
        while not server.started and time.time() < deadline:
            time.sleep(0.05)
        assert httpx.get(f"https://127.0.0.1:{port}/api/health", verify=trust(cert)).status_code == 200
        assert not (tmp_path / "data" / "tls").exists()  # nothing was generated: your files, your rules
    finally:
        server.should_exit = True
        thread.join(10)


def test_entrypoint_rejects_unknown_commands(capsys):
    assert main(["bogus"]) == 2 and "usage" in capsys.readouterr().err
    assert isinstance(ipaddress.ip_address("127.0.0.1"), ipaddress.IPv4Address)  # keeps the import honest for linters
    assert create_app  # the factory remains importable for `uvicorn --factory` users
