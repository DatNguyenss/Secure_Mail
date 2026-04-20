"""SPF-lite: mỗi domain đăng ký danh sách IP được phép gửi."""
import sqlite3
from pathlib import Path

POLICY_DIR = Path("data/policy")
POLICY_DB = POLICY_DIR / "policy.db"


def _ensure_db():
    POLICY_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(POLICY_DB)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS spf (
        domain TEXT,
        ip TEXT,
        PRIMARY KEY (domain, ip)
    );
    CREATE TABLE IF NOT EXISTS dmarc (
        domain TEXT PRIMARY KEY,
        policy TEXT  -- none | quarantine | reject
    );
    """)
    conn.commit()
    conn.close()


def add_spf(domain: str, ip: str):
    _ensure_db()
    conn = sqlite3.connect(POLICY_DB)
    conn.execute("INSERT OR IGNORE INTO spf(domain, ip) VALUES (?, ?)", (domain, ip))
    conn.commit()
    conn.close()


def check(domain: str, ip: str) -> bool:
    _ensure_db()
    conn = sqlite3.connect(POLICY_DB)
    row = conn.execute("SELECT 1 FROM spf WHERE domain=? AND ip=?", (domain, ip)).fetchone()
    conn.close()
    return row is not None


def domain_has_spf(domain: str) -> bool:
    _ensure_db()
    conn = sqlite3.connect(POLICY_DB)
    row = conn.execute("SELECT 1 FROM spf WHERE domain=?", (domain,)).fetchone()
    conn.close()
    return row is not None
