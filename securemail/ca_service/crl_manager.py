"""Tạo CRL từ danh sách cert bị thu hồi."""
import datetime as dt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from . import ca_core


def build_crl() -> bytes:
    ca_priv, ca_cert = ca_core.load_ca()
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + dt.timedelta(days=1))
    )
    for item in ca_core.list_revoked():
        serial = int(item["serial"], 16)
        revoked_at = dt.datetime.fromisoformat(item["revoked_at"])
        entry = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(revoked_at)
            .build()
        )
        builder = builder.add_revoked_certificate(entry)
    crl = builder.sign(private_key=ca_priv, algorithm=hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM)
