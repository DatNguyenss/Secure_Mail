"""Root CA: tạo Root cert, ký CSR (X.509v3 với extensions), thu hồi cert."""
import datetime as dt
import os
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from securemail.crypto import rsa_handler
from securemail.db_conn import get_conn


CA_DIR = Path("data/ca")
CA_KEY_FILE = CA_DIR / "ca_key.pem"
CA_CERT_FILE = CA_DIR / "ca_cert.pem"
CA_PASSPHRASE = os.environ.get("CA_PASSPHRASE", "securemail-root-ca-2026").encode("utf-8")


def _audit(event: str, details: str = ""):
    """Ghi một dòng audit log vào SQL Server."""
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO ca.audit_log(ts, event, details) VALUES (%s, %s, %s)",
        (dt.datetime.now(dt.timezone.utc), event, details),
    )
    conn.close()


def init_root_ca(common_name: str = "SecureMail Root CA", org: str = "SecureMail Demo"):
    """Tạo Root CA lần đầu. Idempotent."""
    CA_DIR.mkdir(parents=True, exist_ok=True)
    if CA_KEY_FILE.exists() and CA_CERT_FILE.exists():
        return  # đã có
    priv = rsa_handler.generate_keypair(2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(priv.public_key()), critical=False)
        .sign(priv, hashes.SHA256())
    )
    CA_KEY_FILE.write_bytes(rsa_handler.serialize_private_pem(priv, CA_PASSPHRASE))
    CA_CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _audit("INIT_ROOT_CA", f"cn={common_name} org={org}")
    print(f"[CA] Root CA created: {common_name}")


def load_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    priv = rsa_handler.load_private_pem(CA_KEY_FILE.read_bytes(), CA_PASSPHRASE)
    cert = x509.load_pem_x509_certificate(CA_CERT_FILE.read_bytes())
    return priv, cert


def sign_csr(csr_pem: bytes, email: str, days_valid: int = 365) -> bytes:
    """Ký CSR, trả về cert PEM. Ghi DB."""
    csr = x509.load_pem_x509_csr(csr_pem)
    if not csr.is_signature_valid:
        raise ValueError("CSR signature invalid")

    ca_priv, ca_cert = load_ca()
    now = dt.datetime.now(dt.timezone.utc)
    serial = x509.random_serial_number()

    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=True,
                key_encipherment=True, data_encipherment=True,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(email)]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://localhost:9000/crl")],
                    relative_name=None, reasons=None, crl_issuer=None,
                )
            ]),
            critical=False,
        )
        .sign(ca_priv, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO ca.issued(serial, email, subject, not_before, not_after, cert_pem) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (hex(serial), email, csr.subject.rfc4514_string(),
         cert.not_valid_before_utc, cert.not_valid_after_utc,
         bytearray(cert_pem)),
    )
    conn.close()
    _audit("SIGN_CSR", f"email={email} serial={hex(serial)}")
    print(f"[CA] Signed cert for {email}, serial={hex(serial)}")
    return cert_pem


def revoke_cert(serial_hex: str) -> bool:
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE ca.issued SET status='revoked', revoked_at=%s WHERE serial=%s",
        (dt.datetime.now(dt.timezone.utc), serial_hex),
    )
    ok = cursor.rowcount > 0
    conn.close()
    if ok:
        _audit("REVOKE", f"serial={serial_hex}")
        print(f"[CA] Revoked cert {serial_hex}")
    return ok


def list_revoked() -> list[dict]:
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT serial, revoked_at FROM ca.issued WHERE status='revoked'"
    )
    rows = cursor.fetchall()
    conn.close()
    return [{"serial": s, "revoked_at": r} for s, r in rows]


def check_status(serial_hex: str) -> str:
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM ca.issued WHERE serial=%s", (serial_hex,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return "unknown"
    return row[0]
