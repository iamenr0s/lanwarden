import socket
import struct
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from sqlalchemy import select

from app.db.types import utcnow
from app.discovery import services
from app.discovery.base import DeviceObservation, ScanContext
from app.models import Device
from app.schemas.settings import ScannerSettings
from app.services.inventory import process_scan
from app.services.netinfo import DetectedNetwork

PI = "b8:27:eb:00:00:01"


def name(*labels):
    return b"".join(bytes([len(x)]) + x.encode() for x in labels) + b"\x00"


def txt(*pairs):
    return b"".join(bytes([len(p)]) + p.encode() for p in pairs)


def mdns_response(rdata, rtype=16, flags=0x8400):
    rr = name("Living-Room", "_googlecast", "_tcp", "local") + struct.pack("!HHIH", rtype, 1, 120, len(rdata)) + rdata
    return struct.pack("!6H", 0, flags, 0, 1, 0, 0) + rr


def test_mdns_query_is_well_formed():
    q = services.build_mdns_query(["_ipp._tcp"])
    assert struct.unpack("!6H", q[:12]) == (0, 0, 1, 0, 0, 0) and q.endswith(struct.pack("!HH", 12, 1))


@pytest.mark.parametrize("pairs,expected", [
    (("id=abc", "md=Chromecast Ultra", "fn=Living Room"), "Chromecast Ultra"),
    (("model=AppleTV6,2",), "AppleTV6,2"),
    (("ty=HP LaserJet Pro", "product=(HP)"), "HP LaserJet Pro"),
    (("product=(Brother HL-L2350DW)",), "Brother HL-L2350DW"),
    (("fn=just a name",), None),
])
def test_parse_mdns_model(pairs, expected):
    assert services.parse_mdns_model(mdns_response(txt(*pairs))) == expected


def test_parse_mdns_ignores_queries_and_garbage():
    assert services.parse_mdns_model(mdns_response(txt("md=X"), flags=0)) is None  # a query, not a response
    for junk in (b"", b"\x00" * 5, b"\xff" * 40, mdns_response(txt("md=X"))[:-3], mdns_response(b"\x09ab")):
        assert services.parse_mdns_model(junk) is None  # never raises
    pointer_loop = struct.pack("!6H", 0, 0x8400, 0, 1, 0, 0) + b"\xc0\x0c" + b"\x00" * 10
    assert services.parse_mdns_model(pointer_loop) is None


def test_ssdp_location_must_name_the_responder():
    reply = b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.9:8008/desc.xml\r\nST: x\r\n\r\n"
    assert services.parse_ssdp_location(reply, "192.168.1.9") == "http://192.168.1.9:8008/desc.xml"
    assert services.parse_ssdp_location(reply, "192.168.1.10") is None  # points at someone else
    assert services.parse_ssdp_location(reply.replace(b"http:", b"https:"), "192.168.1.9") is None
    assert services.parse_ssdp_location(b"HTTP/1.1 200 OK\r\n\r\n", "192.168.1.9") is None
    assert services.parse_ssdp_location(b"LOCATION: http://192.168.1.9:0/x\r\n", "192.168.1.9") is None


def test_parse_upnp_model():
    xml = "<root><device><manufacturer>Sony</manufacturer><modelName>BRAVIA KD-55</modelName><modelNumber>X1</modelNumber></device></root>"
    assert services.parse_upnp_model(xml) == "BRAVIA KD-55"
    assert services.parse_upnp_model("<modelNumber>X1</modelNumber>") == "X1"
    assert services.parse_upnp_model("<!DOCTYPE x [<!ENTITY a 'b'>]><root/>") is None


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/desc.xml")
            self.end_headers()
        elif self.path == "/big":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"x" * (services.MAX_DESCRIPTION_BYTES + 10))
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<modelName>Test Model</modelName>")

    def log_message(self, *a):
        pass


def test_fetch_description_limits():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        assert "Test Model" in services.fetch_description(base + "/desc.xml")
        assert services.fetch_description(base + "/redirect") is None  # redirects are not followed
        assert services.fetch_description(base + "/big") is None  # size cap
    finally:
        srv.shutdown()
        srv.server_close()
    assert services.fetch_description("http://127.0.0.1:1/") is None  # connection refused


CTX = ScanContext(ScannerSettings(), [DetectedNetwork("eth0", "192.168.1.0/24")])


def test_providers_use_packet_source_and_report_errors(monkeypatch):
    monkeypatch.setattr(services, "detect_local_ips", lambda: ["192.168.1.2"])
    replies = [(mdns_response(txt("md=Chromecast")), "192.168.1.9"),
               (mdns_response(txt("md=Spoof")), "10.9.9.9"),  # outside the scanned network
               (mdns_response(txt("md=Me")), "192.168.1.2")]  # our own address
    monkeypatch.setattr(services, "_collect", lambda *a: replies)
    r = services.MdnsProvider().scan(CTX)
    assert [(o.ip, o.model, o.presence, o.mac) for o in r.observations] == [("192.168.1.9", "Chromecast", False, None)]

    ssdp = [(b"LOCATION: http://192.168.1.9/d.xml\r\n", "192.168.1.9")]
    monkeypatch.setattr(services, "_collect", lambda *a: ssdp)
    monkeypatch.setattr(services, "fetch_description", lambda url: "<modelName>Bravia</modelName>")
    assert [(o.ip, o.model) for o in services.SsdpProvider().scan(CTX).observations] == [("192.168.1.9", "Bravia")]

    monkeypatch.setattr(services, "detect_local_ips", lambda: [])
    assert "no local address" in services.MdnsProvider().scan(CTX).error
    assert not services.MdnsProvider.gives_evidence and not services.SsdpProvider.gives_evidence


def test_collect_over_real_udp_loopback(monkeypatch):
    """Real socket path: a reply sent to the probe's port is collected with its source address."""
    monkeypatch.setattr(services, "LISTEN_SECONDS", 0.5)
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    port = rx.getsockname()[1]

    def answer():
        data, addr = rx.recvfrom(2048)
        rx.sendto(b"pong:" + data[:4], addr)

    t = threading.Thread(target=answer, daemon=True)
    t.start()
    got = services._collect(b"ping", "127.0.0.1", port, ["127.0.0.1"])
    t.join(2)
    rx.close()
    assert got == [(b"pong:ping", "127.0.0.1")]
    with pytest.raises(services.ProviderError):
        services._collect(b"x", "127.0.0.1", port, ["203.0.113.250"])  # cannot send from that address


# ---- engine ---------------------------------------------------------------------------------
@pytest.fixture()
def db(app, client):
    with app.state.session_factory() as session:
        yield session


def test_model_enriches_known_device_and_never_creates_or_revives(db):
    T0 = utcnow()
    s = ScannerSettings()
    process_scan(db, [DeviceObservation(source="neighbor", mac=PI, ip="192.168.1.5", hostname="box")], True, s, T0)
    obs = [DeviceObservation(source="mdns", ip="192.168.1.5", model="Chromecast Ultra", presence=False),
           DeviceObservation(source="ssdp", ip="192.168.1.77", model="Ghost", presence=False)]
    process_scan(db, obs, True, s, T0 + timedelta(seconds=30))
    db.commit()
    devices = list(db.scalars(select(Device)))
    assert len(devices) == 1  # the unknown IP created nothing
    assert devices[0].model == "Chromecast Ultra" and devices[0].type_guess == "tv"
    assert devices[0].last_seen == T0  # identity-only: presence not refreshed


def test_service_provider_success_is_not_evidence(app, client, monkeypatch):
    """If the presence providers fail but mDNS answers, nobody may be marked offline."""
    from app.discovery.base import ProviderResult
    from app.services.scanner import Scanner

    class Fail:
        name, gives_evidence = "neighbor", True
        enabled = staticmethod(lambda s: True)
        scan = staticmethod(lambda ctx: ProviderResult(error="boom"))

    class Ok:
        name, gives_evidence = "mdns", False
        enabled = staticmethod(lambda s: True)
        scan = staticmethod(lambda ctx: ProviderResult([]))

    sc = Scanner(app.state.session_factory, [Fail(), Ok()], app.state.box, detect=lambda: [])
    run = sc.run_once("test")
    assert run["error"] == "All discovery providers failed; device presence was not updated"
