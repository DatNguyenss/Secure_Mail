"""Root CA: tạo Root cert, ký CSR (X.509v3 với extensions), thu hồi cert."""
import datetime as dt
import os
import sqlite3
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from securemail.crypto import rsa_handler


CA_DIR = Path("data/ca")
CA_DB = CA_DIR / "ca.db"
CA_KEY_FILE = CA_DIR / "ca_key.pem"
CA_CERT_FILE = CA_DIR / "ca_cert.pem"
CA_PASSPHRASE = b"securemail-root-ca-2026"  # demo; production dùng HSM


def _ensure_db():
    CA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(CA_DB)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS issued (
        serial TEXT PRIMARY KEY,
        email TEXT,
        subject TEXT,
        not_before TEXT,
        not_after TEXT,
        cert_pem BLOB,
        status TEXT DEFAULT 'good',  -- good | revoked
        revoked_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_email ON issued(email);
    """)
    conn.commit()
    conn.close()


def init_root_ca(common_name: str = "SecureMail Root CA", org: str = "SecureMail Demo"):
    """Tạo Root CA lần đầu. Idempotent."""
    _ensure_db()
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
    print(f"[CA] Root CA created: {common_name}")


def load_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    priv = rsa_handler.load_private_pem(CA_KEY_FILE.read_bytes(), CA_PASSPHRASE)
    cert = x509.load_pem_x509_certificate(CA_CERT_FILE.read_bytes())
    return priv, cert


def sign_csr(csr_pem: bytes, email: str, days_valid: int = 365) -> bytes:
    """Ký CSR, trả về cert PEM. Ghi DB."""
    _ensure_db()
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

    conn = sqlite3.connect(CA_DB)
    conn.execute(
        "INSERT INTO issued(serial, email, subject, not_before, not_after, cert_pem) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (hex(serial), email, csr.subject.rfc4514_string(),
         cert.not_valid_before_utc.isoformat(), cert.not_valid_after_utc.isoformat(),
         cert_pem),
    )
    conn.commit()
    conn.close()
    print(f"[CA] Signed cert for {email}, serial={hex(serial)}")
    return cert_pem


def revoke_cert(serial_hex: str) -> bool:
    _ensure_db()
    conn = sqlite3.connect(CA_DB)
    cur = conn.execute("UPDATE issued SET status='revoked', revoked_at=? WHERE serial=?",
                       (dt.datetime.now(dt.timezone.utc).isoformat(), serial_hex))
    conn.commit()
    ok = cur.rowcount > 0
    conn.close()
    if ok:
        print(f"[CA] Revoked cert {serial_hex}")
    return ok


def list_revoked() -> list[dict]:
    _ensure_db()
    conn = sqlite3.connect(CA_DB)
    rows = conn.execute(
        "SELECT serial, revoked_at FROM issued WHERE status='revoked'"
    ).fetchall()
    conn.close()
    return [{"serial": s, "revoked_at": r} for s, r in rows]


def check_status(serial_hex: str) -> str:
    _ensure_db()
    conn = sqlite3.connect(CA_DB)
    row = conn.execute("SELECT status FROM issued WHERE serial=?", (serial_hex,)).fetchone()
    conn.close()
    if not row:
        return "unknown"
    return row[0]
