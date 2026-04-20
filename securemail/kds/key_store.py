"""SQLite CRUD cho certificates + CRL cache."""
import sqlite3
import datetime as dt
from pathlib import Path

KDS_DIR = Path("data/kds")
KDS_DB = KDS_DIR / "kds.db"


def _ensure_db():
    KDS_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(KDS_DB)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS certs (
        email TEXT PRIMARY KEY,
        serial TEXT,
        cert_pem BLOB,
        registered_at TEXT
    );
    CREATE TABLE IF NOT EXISTS crl_cache (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        crl_pem BLOB,
        updated_at TEXT
    );
    """)
    conn.commit()
    conn.close()


def put_cert(email: str, serial_hex: str, cert_pem: bytes):
    _ensure_db()
    conn = sqlite3.connect(KDS_DB)
    conn.execute(
        "INSERT INTO certs(email, serial, cert_pem, registered_at) VALUES(?, ?, ?, ?) "
        "ON CONFLICT(email) DO UPDATE SET serial=excluded.serial, cert_pem=excluded.cert_pem, "
        "registered_at=excluded.registered_at",
        (email, serial_hex, cert_pem, dt.datetime.now(dt.timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()


def get_cert(email: str) -> dict | None:
    _ensure_db()
    conn = sqlite3.connect(KDS_DB)
    row = conn.execute("SELECT email, serial, cert_pem FROM certs WHERE email=?", (email,)).fetchone()
    conn.close()
    if not row:
        return None
    return {"email": row[0], "serial": row[1], "cert_pem": row[2]}


def list_emails() -> list[str]:
    _ensure_db()
    conn = sqlite3.connect(KDS_DB)
    rows = conn.execute("SELECT email FROM certs").fetchall()
    conn.close()
    return [r[0] for r in rows]


def put_crl(crl_pem: bytes):
    _ensure_db()
    conn = sqlite3.connect(KDS_DB)
    conn.execute(
        "INSERT INTO crl_cache(id, crl_pem, updated_at) VALUES (1, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET crl_pem=excluded.crl_pem, updated_at=excluded.updated_at",
        (crl_pem, dt.datetime.now(dt.timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()


def get_crl() -> bytes | None:
    _ensure_db()
    conn = sqlite3.connect(KDS_DB)
    row = conn.execute("SELECT crl_pem FROM crl_cache WHERE id=1").fetchone()
    conn.close()
    return row[0] if row else None
