"""Self-signed certificate for LanWarden's built-in HTTPS.

A self-signed certificate gives encryption, not identity: the browser warns until you trust it
(or pin it). On a shared network a reverse proxy with a real certificate is still the better choice.
"""

import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

VALID_DAYS = 825
RENEW_WITHIN = timedelta(days=30)


def _split_names(names: list[str]) -> tuple[list[str], list[ipaddress.IPv4Address | ipaddress.IPv6Address]]:
    dns, ips = ["localhost"], [ipaddress.ip_address("127.0.0.1")]
    for raw in names:
        raw = raw.strip()
        if not raw:
            continue
        try:
            ip = ipaddress.ip_address(raw)
            if ip not in ips:
                ips.append(ip)
        except ValueError:
            if raw not in dns:
                dns.append(raw)
    return dns, ips


def _covers(cert: x509.Certificate, dns: list[str], ips: list) -> bool:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    have_dns, have_ips = set(san.get_values_for_type(x509.DNSName)), set(san.get_values_for_type(x509.IPAddress))
    return set(dns) <= have_dns and set(ips) <= have_ips


def ensure_selfsigned(data_dir: Path, names: list[str], days: int = VALID_DAYS) -> tuple[Path, Path]:
    """Return (cert, key) paths under data_dir/tls, generating them if missing, expiring within 30 days,
    or no longer covering the requested names/addresses. The private key is written 0600."""
    out = Path(data_dir) / "tls"
    out.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = out / "cert.pem", out / "key.pem"
    dns, ips = _split_names(names)

    if cert_path.exists() and key_path.exists():
        try:
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            if cert.not_valid_after_utc - datetime.now(timezone.utc) > RENEW_WITHIN and _covers(cert, dns, ips):
                return cert_path, key_path
        except ValueError:
            pass  # unreadable: regenerate

    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "LanWarden"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LanWarden (self-signed)"),
    ])
    key_usage = x509.KeyUsage(
        digital_signature=True, key_encipherment=False, content_commitment=False, data_encipherment=False,
        key_agreement=True, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False,
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([*(x509.DNSName(d) for d in dns), *(x509.IPAddress(i) for i in ips)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(key_usage, critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    os.chmod(key_path, 0o600)  # O_CREAT honours the mode only for new files
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path
